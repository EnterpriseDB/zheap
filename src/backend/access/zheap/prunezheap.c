/*-------------------------------------------------------------------------
 *
 * prunezheap.c
 *	  zheap page pruning
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/prunezheap.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/zheap.h"
#include "access/zheapam_xlog.h"
#include "catalog/catalog.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "storage/procarray.h"

/* Working data for zheap_page_prune and subroutines */
typedef struct
{
	TransactionId new_prune_xid;	/* new prune hint value for page */
	TransactionId latestRemovedXid; /* latest xid to be removed by this prune */
	int			ndeleted;		/* numbers of entries in arrays below */
	int			ndead;
	int			nunused;
	/* arrays that accumulate indexes of items to be changed */

	/*
	 * Fixme - arrays must use MaxZHeapTuplesPerPage, once we have constant
	 * value for the same.  we can get maximum 1164 tuples considering no
	 * alignment, so using 1200 seems sane.
	 */
	OffsetNumber nowdeleted[1200];
	OffsetNumber nowdead[1200];
	OffsetNumber nowunused[1200];
	/* marked[i] is TRUE if item i is entered in one of the above arrays */
	bool		marked[1200 + 1];
}			ZPruneState;

static int zheap_page_prune_guts(Relation relation, Buffer buffer,
					  TransactionId OldestXmin, TransactionId *latestRemovedXid);
static int zheap_prune_item(Relation relation, Buffer buffer,
				 OffsetNumber rootoffnum, TransactionId OldestXmin,
				 ZPruneState * prstate);
static void zheap_prune_record_prunable(ZPruneState * prstate,
							TransactionId xid);
static void zheap_prune_record_dead(ZPruneState * prstate, OffsetNumber offnum);
static void zheap_prune_record_deleted(ZPruneState * prstate,
						   OffsetNumber offnum);

/*
 * Optionally prune and repair fragmentation in the specified page.
 *
 * Caller must have exclusive lock on the page.
 *
 * OldestXmin is the cutoff XID used to distinguish whether tuples are DEAD
 * or RECENTLY_DEAD (see ZHeapTupleSatisfiesOldestXmin).
 *
 * This is an opportunistic function.  It will perform housekeeping only if
 * the page has effect of transaction thas has modified data which can be
 * pruned.
 *
 * Note: this is called only when we need some space in page to perform the
 * action which otherwise would need a different page.  It is called when an
 * update statement has to update the existing tuple such that new tuple is
 * bigger than old tuple and the same can't fit on page.  Now, if we are able
 * to free up some space in page such that the new tuple can fit into same page
 * then we can make it an in-place update.
 */
void
zheap_page_prune_opt(Relation relation, Buffer buffer)
{
	int     slot_no;
	bool    can_prune = true;
	ZHeapPageOpaque opaque;
	Page	page;
	TransactionId OldestXmin;
	TransactionId ignore = InvalidTransactionId;

	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * While pruning if we have move the non committed tuple to a new place within
	 * page then rollback of such tuple to old size might fail because of
	 * insufficient space.  To avoid the same, we could do one of the following:
	 *
	 * a. During PageRepairFragmentation, check if the tuple is inplace updated
	 * and the transaction is not committed, then fetch the length of largest
	 * previous tuple from undo chain, so that we can reserve that much space.
	 *
	 * b. Write an undo record for PageRepairFragmentation such that it can be
	 * rolledback. I think this can generate much more data both in undo and WAL.
	 *
	 * c. For such tuples always reserve the maxtuplesize space.
	 *
	 * d. Don't allow page rearrangement if we have any such tuple on a page.
	 *
	 * e. Allow page rearrangement considering the current length of tuple and
	 * later during rollback if we don't find enough space, make a
	 * non-inplace-update.
	 *
	 * For now we choose the simplest option which is to allow pruning if there
	 * are no open transaction on a page.
	 */
	for (slot_no = 0; slot_no < MAX_PAGE_TRANS_INFO_SLOTS; slot_no++)
	{
		if (TransactionIdIsInProgress(opaque->transinfo[slot_no].xid))
		{
			can_prune = false;
			break;
		}
	}

	if (!can_prune)
		return;

	/*
	 * We can't write WAL in recovery mode, so there's no point trying to
	 * clean the page. The master will likely issue a cleaning WAL record soon
	 * anyway, so this is no particular loss.
	 */
	if (RecoveryInProgress())
		return;

	/*
	 * Use the appropriate xmin horizon for this relation. If it's a proper
	 * catalog relation or a user defined, additional, catalog relation, we
	 * need to use the horizon that includes slots, otherwise the data-only
	 * horizon can be used. Note that the toast relation of user defined
	 * relations are *not* considered catalog relations.
	 *
	 * It is OK to apply the old snapshot limit before acquiring the cleanup
	 * lock because the worst that can happen is that we are not quite as
	 * aggressive about the cleanup (by however many transaction IDs are
	 * consumed between this point and acquiring the lock).  This allows us to
	 * save significant overhead in the case where the page is found not to be
	 * prunable.
	 */
	if (IsCatalogRelation(relation) ||
		RelationIsAccessibleInLogicalDecoding(relation))
		OldestXmin = RecentGlobalXmin;
	else
		OldestXmin = RecentGlobalDataXmin;

	Assert(TransactionIdIsValid(OldestXmin));

	/*
	 * Let's see if we really need pruning.
	 *
	 * Forget it if page is not hinted to contain something prunable that's
	 * committed.
	 */
	if (!ZPageIsPrunable(page))
		return;

	(void) zheap_page_prune_guts(relation, buffer, OldestXmin, &ignore);
}

/*
 * Prune and repair fragmentation in the specified page.
 *
 * Caller must have pin and buffer cleanup lock on the page.
 *
 * OldestXmin is the cutoff XID used to distinguish whether tuples are DEAD
 * or RECENTLY_DEAD (see ZHeapTupleSatisfiesVacuum).
 *
 * Send the number of reclaimed tuples to pgstats.
 *
 * Returns the number of tuples deleted from the page and sets
 * latestRemovedXid.
 */
static int
zheap_page_prune_guts(Relation relation, Buffer buffer, TransactionId OldestXmin,
					  TransactionId *latestRemovedXid)
{
	int			ndeleted = 0;
	Page		page = BufferGetPage(buffer);
	OffsetNumber offnum,
				maxoff;
	ZPruneState prstate;

	/*
	 * Our strategy is to scan the page and make lists of items to change,
	 * then apply the changes within a critical section.  This keeps as much
	 * logic as possible out of the critical section, and also ensures that
	 * WAL replay will work the same as the normal case.
	 *
	 * First, initialize the new pd_prune_xid value to zero (indicating no
	 * prunable tuples).  If we find any tuples which may soon become
	 * prunable, we will save the lowest relevant XID in new_prune_xid. Also
	 * initialize the rest of our working state.
	 */
	prstate.new_prune_xid = InvalidTransactionId;
	prstate.latestRemovedXid = *latestRemovedXid;
	prstate.ndeleted = prstate.ndead = prstate.nunused = 0;
	memset(prstate.marked, 0, sizeof(prstate.marked));

	/* Scan the page */
	maxoff = PageGetMaxOffsetNumber(page);
	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
	{
		ItemId		itemid;

		/* Ignore items already processed as part of an earlier chain */
		if (prstate.marked[offnum])
			continue;

		/* Nothing to do if slot is empty, already dead or marked as deleted */
		itemid = PageGetItemId(page, offnum);
		if (!ItemIdIsUsed(itemid) || ItemIdIsDead(itemid) ||
			ItemIdIsDeleted(itemid))
			continue;

		/* Process this item or chain of items */
		ndeleted += zheap_prune_item(relation, buffer, offnum,
									 OldestXmin,
									 &prstate);
	}

	/* Any error while applying the changes is critical */
	START_CRIT_SECTION();

	/* Have we found any prunable items? */
	if (prstate.ndeleted > 0 || prstate.ndead > 0 || prstate.nunused > 0)
	{
		/*
		 * Apply the planned item changes, then repair page fragmentation, and
		 * update the page's hint bit about whether it has free line pointers.
		 */
		zheap_page_prune_execute(buffer,
								 prstate.nowdeleted, prstate.ndeleted,
								 prstate.nowdead, prstate.ndead,
								 prstate.nowunused, prstate.nunused);

		/*
		 * Update the page's pd_prune_xid field to either zero, or the lowest
		 * XID of any soon-prunable tuple.
		 */
		((PageHeader) page)->pd_prune_xid = prstate.new_prune_xid;

		/*
		 * Also clear the "page is full" flag, since there's no point in
		 * repeating the prune/defrag process until something else happens to
		 * the page.
		 */
		PageClearFull(page);

		MarkBufferDirty(buffer);

		/*
		 * Emit a WAL ZHEAP_CLEAN record showing what we did
		 */
		if (RelationNeedsWAL(relation))
		{
			XLogRecPtr      recptr;
			xl_zheap_clean	xl_rec;

			xl_rec.latestRemovedXid = prstate.latestRemovedXid;
			xl_rec.ndeleted = prstate.ndeleted;
			xl_rec.ndead = prstate.ndead;
			XLogBeginInsert();
			XLogRegisterData((char *) &xl_rec, SizeOfZHeapClean);
			XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

			/*
			 * The OffsetNumber arrays are not actually in the buffer, but we pretend
			 * that they are.  When XLogInsert stores the whole buffer, the offset
			 * arrays need not be stored too.  Note that even if all three arrays are
			 * empty, we want to expose the buffer as a candidate for whole-page
			 * storage, since this record type implies a defragmentation operation
			 * even if no item pointers changed state.
			 */
			if (prstate.ndeleted > 0)
				XLogRegisterBufData(0, (char *) prstate.nowdeleted,
							prstate.ndeleted * sizeof(OffsetNumber) * 2);

			if (prstate.ndead > 0)
				XLogRegisterBufData(0, (char *) prstate.nowdead,
							prstate.ndead * sizeof(OffsetNumber));

			if (prstate.nunused > 0)
				XLogRegisterBufData(0, (char *) prstate.nowunused,
							prstate.nunused * sizeof(OffsetNumber));

			recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_CLEAN);
			PageSetLSN(BufferGetPage(buffer), recptr);
		}
	}
	else
	{
		/*
		 * If we didn't prune anything, but have found a new value for the
		 * pd_prune_xid field, update it and mark the buffer dirty. This is
		 * treated as a non-WAL-logged hint.
		 *
		 * Also clear the "page is full" flag if it is set, since there's no
		 * point in repeating the prune/defrag process until something else
		 * happens to the page.
		 */
		if (((PageHeader) page)->pd_prune_xid != prstate.new_prune_xid ||
			PageIsFull(page))
		{
			((PageHeader) page)->pd_prune_xid = prstate.new_prune_xid;
			PageClearFull(page);
			MarkBufferDirtyHint(buffer, true);
		}
	}

	END_CRIT_SECTION();

	/*
	 * Report the number of tuples reclaimed to pgstats. This is ndeleted
	 * minus ndead, because we don't want to count a now-DEAD item or a
	 * now-DELETED item as a deletion for this purpose.
	 */
	if (ndeleted > (prstate.ndead + prstate.ndeleted))
		pgstat_update_heap_dead_tuples(relation, ndeleted - (prstate.ndead + prstate.ndeleted));

	*latestRemovedXid = prstate.latestRemovedXid;

	/*
	 * XXX Should we update FSM information for this?  Not doing so will
	 * increase the chances of in-place updates.  See heap_page_prune for a
	 * detailed reason.
	 */

	return ndeleted;
}

/*
 * Perform the actual page changes needed by zheap_page_prune_guts.
 * It is expected that the caller has suitable pin and lock on the
 * buffer, and is inside a critical section.
 */
void
zheap_page_prune_execute(Buffer buffer, OffsetNumber *deleted, int ndeleted,
						 OffsetNumber *nowdead, int ndead,
						 OffsetNumber *nowunused, int nunused)
{
	Page		page = (Page) BufferGetPage(buffer);
	OffsetNumber *offnum;
	int			i;

	/* Update all deleted line pointers */
	offnum = deleted;
	for (i = 0; i < ndeleted; i++)
	{
		ZHeapTupleHeader tup;
		int			trans_slot;
		uint8		vis_info = 0;
		OffsetNumber off = *offnum++;
		ItemId		lp = PageGetItemId(page, off);

		tup = (ZHeapTupleHeader) PageGetItem(page, lp);
		trans_slot = ZHeapTupleHeaderGetXactSlot(tup);

		/*
		 * The frozen slot indicates tuple is dead, so we must not see them in
		 * the array of tuples to be marked as deleted.
		 */
		Assert(trans_slot != ZHTUP_SLOT_FROZEN);

		if (ZHeapTupleDeleted(tup))
			vis_info = ITEMID_DELETED;
		if (ZHeapTupleHasInvalidXact(tup))
			vis_info |= ITEMID_XACT_INVALID;

		/*
		 * Mark the Item as deleted and copy the visibility info and
		 * transaction slot information from tuple to ItemId.
		 */
		ItemIdSetDeleted(lp, trans_slot, vis_info);
	}

	/* Update all now-dead line pointers */
	offnum = nowdead;
	for (i = 0; i < ndead; i++)
	{
		OffsetNumber off = *offnum++;
		ItemId		lp = PageGetItemId(page, off);

		ItemIdSetDead(lp);
	}

	/* Update all now-unused line pointers */
	offnum = nowunused;
	for (i = 0; i < nunused; i++)
	{
		OffsetNumber off = *offnum++;
		ItemId		lp = PageGetItemId(page, off);

		ItemIdSetUnused(lp);
	}

	/*
	 * Finally, repair any fragmentation, and update the page's hint bit about
	 * whether it has free pointers.
	 */
	PageRepairFragmentation(page);
}

/*
 * Prune specified item pointer.
 *
 * OldestXmin is the cutoff XID used to identify dead tuples.
 *
 * We don't actually change the page here.  We just add entries to the arrays in
 * prstate showing the changes to be made.  Items to be set to LP_DEAD state are
 * added to nowdead[]; items to be set to LP_DELETED are added to nowdeleted[];
 * and items to be set to LP_UNUSED state are added to nowunused[].
 *
 * Returns the number of tuples (to be) deleted from the page.
 */
static int
zheap_prune_item(Relation relation, Buffer buffer, OffsetNumber offnum,
				 TransactionId OldestXmin, ZPruneState * prstate)
{
	ZHeapTupleData tup;
	ItemId		lp;
	Page		dp = (Page) BufferGetPage(buffer);
	int			ndeleted = 0;
	TransactionId xid;
	bool		tupdead,
				recent_dead;

	lp = PageGetItemId(dp, offnum);

	Assert(ItemIdIsNormal(lp));

	tup.t_data = (ZHeapTupleHeader) PageGetItem(dp, lp);
	tup.t_len = ItemIdGetLength(lp);
	ItemPointerSet(&(tup.t_self), BufferGetBlockNumber(buffer), offnum);
	tup.t_tableOid = RelationGetRelid(relation);

	/*
	 * Check tuple's visibility status.
	 */
	tupdead = recent_dead = false;

	switch (ZHeapTupleSatisfiesOldestXmin(&tup, OldestXmin, buffer, &xid))
	{
		case HEAPTUPLE_DEAD:
			tupdead = true;
			break;

		case HEAPTUPLE_RECENTLY_DEAD:
			recent_dead = true;
			break;

		case HEAPTUPLE_DELETE_IN_PROGRESS:

			/*
			 * This tuple may soon become DEAD.  Update the hint field so that
			 * the page is reconsidered for pruning in future.
			 */
			zheap_prune_record_prunable(prstate, xid);
			break;

		case HEAPTUPLE_LIVE:
		case HEAPTUPLE_INSERT_IN_PROGRESS:

			/*
			 * If we wanted to optimize for aborts, we might consider marking
			 * the page prunable when we see INSERT_IN_PROGRESS. But we don't.
			 * See related decisions about when to mark the page prunable in
			 * heapam.c.
			 */
			break;

		default:
			elog(ERROR, "unexpected ZHeapTupleSatisfiesOldestXmin result");
			break;
	}

	if (tupdead || recent_dead)
	{
		ZHeapTupleHeaderAdvanceLatestRemovedXid(tup.t_data, xid, &prstate->latestRemovedXid);

		/* count dead or recently dead tuple in result */
		ndeleted++;
	}

	/* Record dead item */
	if (tupdead)
		zheap_prune_record_dead(prstate, offnum);

	/* Record deleted item */
	if (recent_dead)
		zheap_prune_record_deleted(prstate, offnum);

	return ndeleted;
}

/* Record lowest soon-prunable XID */
static void
zheap_prune_record_prunable(ZPruneState * prstate, TransactionId xid)
{
	/*
	 * This should exactly match the PageSetPrunable macro.  We can't store
	 * directly into the page header yet, so we update working state.
	 */
	Assert(TransactionIdIsNormal(xid));
	if (!TransactionIdIsValid(prstate->new_prune_xid) ||
		TransactionIdPrecedes(xid, prstate->new_prune_xid))
		prstate->new_prune_xid = xid;
}

/* Record item pointer to be marked dead */
static void
zheap_prune_record_dead(ZPruneState * prstate, OffsetNumber offnum)
{
	Assert(prstate->ndead < 1200);
	prstate->nowdead[prstate->ndead] = offnum;
	prstate->ndead++;
	Assert(!prstate->marked[offnum]);
	prstate->marked[offnum] = true;
}

/* Record item pointer to be deleted */
static void
zheap_prune_record_deleted(ZPruneState * prstate, OffsetNumber offnum)
{
	Assert(prstate->ndead < 1200);
	prstate->nowdeleted[prstate->ndeleted] = offnum;
	prstate->ndeleted++;
	Assert(!prstate->marked[offnum]);
	prstate->marked[offnum] = true;
}
