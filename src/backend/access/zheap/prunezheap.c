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
 * In Zheap, we can reclaim space on following operations
 * a. non-inplace updates, when committed or rolled back.
 * b. inplace updates that reduces the tuple length, when commited.
 * c. deletes, when committed.
 * d. inserts, when rolled back.
 *
 * Since we only store xid which changed the page in pd_prune_xid, to prune
 * the page, we can check if pd_prune_xid is in progress.  This can sometimes
 * lead to unwanted page pruning calls as a side effect, example in case of
 * rolled back deletes.  If there is nothing to prune, then the call to prune
 * is cheap, so we don't want to optimize it at this stage.
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/zheap.h"
#include "access/zheapam_xlog.h"
#include "access/zheaputils.h"
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
	 * value for the same.
	 */
	OffsetNumber nowdeleted[MaxZHeapTuplesPerPage];
	OffsetNumber nowdead[MaxZHeapTuplesPerPage];
	OffsetNumber nowunused[MaxZHeapTuplesPerPage];
	/* marked[i] is TRUE if item i is entered in one of the above arrays */
	bool		marked[MaxZHeapTuplesPerPage + 1];
}			ZPruneState;

static int zheap_prune_item(Relation relation, Buffer buffer,
				 OffsetNumber rootoffnum, TransactionId OldestXmin,
				 ZPruneState *prstate, int *space_freed);
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
 * Note: This is called only when we need some space in page to perform the
 * action which otherwise would need a different page.  It is called when an
 * update statement has to update the existing tuple such that new tuple is
 * bigger than old tuple and the same can't fit on page.
 *
 * Returns true, if we are able to free up the space such that the new tuple
 * can fit into same page, otherwise, false.
 */
bool
zheap_page_prune_opt(Relation relation, Buffer buffer,
					 OffsetNumber offnum, Size space_required)
{
	Page	page;
	TransactionId OldestXmin;
	TransactionId ignore = InvalidTransactionId;
	Size	pagefree;
	bool	force_prune = false;
	bool	pruned;

	page = BufferGetPage(buffer);

	/*
	 * We can't write WAL in recovery mode, so there's no point trying to
	 * clean the page. The master will likely issue a cleaning WAL record soon
	 * anyway, so this is no particular loss.
	 */
	if (RecoveryInProgress())
		return false;

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

	if (OffsetNumberIsValid(offnum))
	{
		pagefree = PageGetExactFreeSpace(page);

		/*
		 * We want to forcefully prune the page if we are sure that the
		 * required space is available.  This will help in rearranging the
		 * page such that we will be able to make space adjacent to required
		 * offset number.
		 */
		if (space_required < pagefree)
			force_prune = true;
	}


	/*
	 * Let's see if we really need pruning.
	 *
	 * Forget it if page is not hinted to contain something prunable that's
	 * committed and we don't want to forcefully prune the page.
	 */
	if (!ZPageIsPrunable(page) && !force_prune)
		return false;

	zheap_page_prune_guts(relation, buffer, OldestXmin, offnum,
									 space_required, true, force_prune,
									 &ignore, &pruned);
	if (pruned)
		return true;

	return false;
}

/*
 * Prune and repair fragmentation in the specified page.
 *
 * Caller must have pin and buffer cleanup lock on the page.
 *
 * OldestXmin is the cutoff XID used to distinguish whether tuples are DEAD
 * or RECENTLY_DEAD (see ZHeapTupleSatisfiesVacuum).
 *
 * To perform pruning, we make the copy of the page.  We don't scribble on
 * that copy, rather it is only used during repair fragmentation to copy
 * the tuples.  So, we need to ensure that after making the copy, we operate
 * on tuples, otherwise, the temporary copy will become useless.  It is okay
 * scribble on itemid's or special space of page.
 *
 * If report_stats is true then we send the number of reclaimed tuples to
 * pgstats.  (This must be false during vacuum, since vacuum will send its own
 * own new total to pgstats, and we don't want this delta applied on top of
 * that.)
 *
 * Returns the number of tuples deleted from the page and sets
 * latestRemovedXid.  It returns 0, when removed the dead tuples can't free up
 * the space required.
 */
int
zheap_page_prune_guts(Relation relation, Buffer buffer,
					  TransactionId OldestXmin, OffsetNumber target_offnum,
					  Size space_required, bool report_stats,
					  bool force_prune, TransactionId *latestRemovedXid,
					  bool *pruned)
{
	int			ndeleted = 0;
	int			space_freed = 0;
	Page		page = BufferGetPage(buffer);
	Page		tmppage = NULL;
	OffsetNumber offnum,
				maxoff;
	ZPruneState prstate;
	bool		execute_pruning = false;

	if (pruned)
		*pruned = false;

	/* initialize the space_free with already existing free space in page */
	space_freed = PageGetExactFreeSpace(page);

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

	/*
	 * If caller has asked to rearrange the page and page is not marked for
	 * pruning, then skip scanning the page.
	 *
	 * XXX We might want to remove this check once we have some optimal
	 * strategy to rearrange the page where we anyway need to traverse all
	 * rows.
	 */
	if (force_prune && !ZPageIsPrunable(page))
	{
		; /* no need to scan */
	}
	else
	{
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

			/* Process this item */
			ndeleted += zheap_prune_item(relation, buffer, offnum,
				OldestXmin,
				&prstate,
				&space_freed);
		}
	}

	/*
	 * There is not much advantage in continuing, if we can't free the space
	 * required by the caller or we are not asked to forcefully prune the
	 * page.
	 *
	 * XXX - In theory, we can still continue and perform pruning in the hope
	 * that some future update in this page will be able to use that space.
	 * However, it will lead to additional writes without any guaranteed
	 * benefit, so we skip the pruning for now.
	 */
	if (space_freed < space_required)
		return 0;

	/* Do we want to prune? */
	if (prstate.ndeleted > 0 || prstate.ndead > 0 ||
		prstate.nunused > 0 || force_prune)
	{
		PageHeader	phdr;

		execute_pruning = true;

		/*
		 * We prepare the temporary copy of the page so that during page
		 * repair fragmentation we can use it to copy the actual tuples.
		 */
		tmppage = PageGetTempPageCopy(page);

		/*
		 * Lock the TPD page before starting critical section.  We might need
		 * to access it during page repair fragmentation.
		 */
		phdr = (PageHeader) page;
		if (ZHeapPageHasTPDSlot(phdr))
			TPDPageLock(relation, buffer);
	}

	/* Any error while applying the changes is critical */
	START_CRIT_SECTION();

	if (execute_pruning)
	{
		bool	has_pruned = false;

		/*
		 * Apply the planned item changes, then repair page fragmentation, and
		 * update the page's hint bit about whether it has free line pointers.
		 */
		zheap_page_prune_execute(buffer, target_offnum,
								 prstate.nowdeleted, prstate.ndeleted,
								 prstate.nowdead, prstate.ndead,
								 prstate.nowunused, prstate.nunused);

		/*
		 * Finally, repair any fragmentation, and update the page's hint bit about
		 * whether it has free pointers.
		 */
		ZPageRepairFragmentation(buffer, tmppage, target_offnum,
								 space_required, false, &has_pruned , false);

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
			XLogRecPtr	recptr;

			recptr = log_zheap_clean(relation, buffer, target_offnum,
									 space_required, prstate.nowdeleted,
									 prstate.ndeleted, prstate.nowdead,
									 prstate.ndead, prstate.nowunused,
									 prstate.nunused,
									 prstate.latestRemovedXid, has_pruned);

			PageSetLSN(BufferGetPage(buffer), recptr);
		}

		if (pruned)
			*pruned = has_pruned;
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
	if (report_stats && ndeleted > (prstate.ndead + prstate.ndeleted))
		pgstat_update_heap_dead_tuples(relation, ndeleted - (prstate.ndead + prstate.ndeleted));

	*latestRemovedXid = prstate.latestRemovedXid;

	/* be tidy. */
	if (tmppage)
		pfree(tmppage);
	UnlockReleaseTPDBuffers();

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
zheap_page_prune_execute(Buffer buffer, OffsetNumber target_offnum,
						 OffsetNumber *deleted, int ndeleted,
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
		ItemId		lp;

		/* The target offset must not be deleted. */
		Assert(target_offnum != off);

		lp = PageGetItemId(page, off);

		tup = (ZHeapTupleHeader) PageGetItem(page, lp);
		trans_slot = ZHeapTupleHeaderGetXactSlot(tup);

		/*
		 * The frozen slot indicates tuple is dead, so we must not see them in
		 * the array of tuples to be marked as deleted.
		 */
		Assert(trans_slot != ZHTUP_SLOT_FROZEN);

		if (ZHeapTupleDeleted(tup))
			vis_info = ITEMID_DELETED;
		if (ZHeapTupleHasInvalidXact(tup->t_infomask))
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
		ItemId		lp;

		/* The target offset must not be dead. */
		Assert(target_offnum != off);

		lp = PageGetItemId(page, off);

		ItemIdSetDead(lp);
	}

	/* Update all now-unused line pointers */
	offnum = nowunused;
	for (i = 0; i < nunused; i++)
	{
		OffsetNumber off = *offnum++;
		ItemId		lp;

		/* The target offset must not be unused. */
		Assert(target_offnum != off);

		lp = PageGetItemId(page, off);

		ItemIdSetUnused(lp);
	}
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
				 TransactionId OldestXmin, ZPruneState *prstate,
				 int *space_freed)
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

	switch (ZHeapTupleSatisfiesVacuum(&tup, OldestXmin, buffer, &xid))
	{
		case ZHEAPTUPLE_DEAD:
			tupdead = true;
			break;

		case ZHEAPTUPLE_RECENTLY_DEAD:
			recent_dead = true;
			break;

		case ZHEAPTUPLE_DELETE_IN_PROGRESS:

			/*
			 * This tuple may soon become DEAD.  Update the hint field so that
			 * the page is reconsidered for pruning in future.
			 */
			zheap_prune_record_prunable(prstate, xid);
			break;

		case ZHEAPTUPLE_LIVE:
		case ZHEAPTUPLE_INSERT_IN_PROGRESS:

			/*
			 * If we wanted to optimize for aborts, we might consider marking
			 * the page prunable when we see INSERT_IN_PROGRESS. But we don't.
			 * See related decisions about when to mark the page prunable in
			 * heapam.c.
			 */
			break;

		case ZHEAPTUPLE_ABORT_IN_PROGRESS:
			/*
			 * We can simply skip the tuple if it has inserted/operated by
			 * some aborted transaction and its rollback is still pending. It'll
			 * be taken care of by future prune calls.
			 */
			break;
		default:
			elog(ERROR, "unexpected ZHeapTupleSatisfiesVacuum result");
			break;
	}

	if (tupdead)
		ZHeapTupleHeaderAdvanceLatestRemovedXid(tup.t_data, xid, &prstate->latestRemovedXid);

	if (tupdead || recent_dead)
	{
		/*
		 * Count dead or recently dead tuple in result and update the space
		 * that can be freed.
		 */
		ndeleted++;

		/* short aligned */
		*space_freed += SHORTALIGN(tup.t_len);
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
	Assert(prstate->ndead < MaxZHeapTuplesPerPage);
	prstate->nowdead[prstate->ndead] = offnum;
	prstate->ndead++;
	Assert(!prstate->marked[offnum]);
	prstate->marked[offnum] = true;
}

/* Record item pointer to be deleted */
static void
zheap_prune_record_deleted(ZPruneState * prstate, OffsetNumber offnum)
{
	Assert(prstate->ndead < MaxZHeapTuplesPerPage);
	prstate->nowdeleted[prstate->ndeleted] = offnum;
	prstate->ndeleted++;
	Assert(!prstate->marked[offnum]);
	prstate->marked[offnum] = true;
}

/*
 * log_zheap_clean - Perform XLogInsert for a zheap-clean operation.
 *
 * Caller must already have modified the buffer and marked it dirty.
 *
 * We also include latestRemovedXid, which is the greatest XID present in
 * the removed tuples. That allows recovery processing to cancel or wait
 * for long standby queries that can still see these tuples.
 */
XLogRecPtr
log_zheap_clean(Relation reln, Buffer buffer, OffsetNumber target_offnum,
				Size space_required, OffsetNumber *nowdeleted, int ndeleted,
				OffsetNumber *nowdead, int ndead, OffsetNumber *nowunused,
				int nunused, TransactionId latestRemovedXid, bool pruned)
{
	XLogRecPtr      recptr;
	xl_zheap_clean	xl_rec;

	/* Caller should not call me on a non-WAL-logged relation */
	Assert(RelationNeedsWAL(reln));

	xl_rec.latestRemovedXid = latestRemovedXid;
	xl_rec.ndeleted = ndeleted;
	xl_rec.ndead = ndead;
	xl_rec.flags = 0;
	XLogBeginInsert();

	if (pruned)
		xl_rec.flags |= XLZ_CLEAN_ALLOW_PRUNING;
	XLogRegisterData((char *) &xl_rec, SizeOfZHeapClean);

	/* Register the offset information. */
	if (target_offnum != InvalidOffsetNumber)
	{
		xl_rec.flags |= XLZ_CLEAN_CONTAINS_OFFSET;
		XLogRegisterData((char *) &target_offnum, sizeof(OffsetNumber));
		XLogRegisterData((char *) &space_required, sizeof(space_required));
	}

	XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

	/*
	 * The OffsetNumber arrays are not actually in the buffer, but we pretend
	 * that they are.  When XLogInsert stores the whole buffer, the offset
	 * arrays need not be stored too.  Note that even if all three arrays are
	 * empty, we want to expose the buffer as a candidate for whole-page
	 * storage, since this record type implies a defragmentation operation
	 * even if no item pointers changed state.
	 */
	if (ndeleted > 0)
		XLogRegisterBufData(0, (char *) nowdeleted,
					ndeleted * sizeof(OffsetNumber) * 2);

	if (ndead > 0)
		XLogRegisterBufData(0, (char *) nowdead,
					ndead * sizeof(OffsetNumber));

	if (nunused > 0)
		XLogRegisterBufData(0, (char *) nowunused,
					nunused * sizeof(OffsetNumber));

	recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_CLEAN);

	return recptr;
}

/*
 * After removing or marking some line pointers unused, move the tuples to
 * remove the gaps caused by the removed items.  Here, we are rearranging
 * the page such that tuples will be placed in itemid order.  It will help
 * in the speedup of future sequential scans.
 *
 * Note that we use the temporary copy of the page to copy the tuples as
 * writing in itemid order will overwrite some tuples.
 */
void
compactify_ztuples(itemIdSort itemidbase, int nitems, Page page, Page tmppage)
{
	PageHeader	phdr = (PageHeader) page;
	Offset		upper;
	int			i;

	Assert(PageIsValid(tmppage));
	upper = phdr->pd_special;
	for (i = nitems - 1; i >= 0; i--)
	{
		itemIdSort	itemidptr = &itemidbase[i];
		ItemId		lp;

		lp = PageGetItemId(page, itemidptr->offsetindex + 1);
		upper -= itemidptr->alignedlen;
		memcpy((char *) page + upper,
			   (char *) tmppage + itemidptr->itemoff,
			   lp->lp_len);
		lp->lp_off = upper;
	}

	phdr->pd_upper = upper;
}

/*
 * ZPageRepairFragmentation
 *
 * Frees fragmented space on a page.
 *
 * The basic idea is same as PageRepairFragmentation, but here we additionally
 * deal with unused items that can't be immediately reclaimed.  We don't allow
 * page to be pruned, if there is an inplace update from an open transaction.
 * The reason is that we don't know the size of previous row in undo which
 * could be bigger in which case we might not be able to perform rollback once
 * the page is repaired.  Now, we can always traverse the undo chain to find
 * the size of largest tuple in the chain, but we don't do that for now as it
 * can take time especially if there are many such tuples on the page.
 *
 * The unused_set boolean argument is used to prevent re-evaluation of
 * itemId when it is already set with transaction slot information in the
 * caller function.
 */
void
ZPageRepairFragmentation(Buffer buffer, Page tmppage,
						 OffsetNumber target_offnum, Size space_required,
						 bool NoTPDBufLock, bool *pruned, bool unused_set)
{
	Page		page = BufferGetPage(buffer);
	Offset		pd_lower = ((PageHeader)page)->pd_lower;
	Offset		pd_upper = ((PageHeader)page)->pd_upper;
	Offset		pd_special = ((PageHeader)page)->pd_special;
	itemIdSortData itemidbase[MaxZHeapTuplesPerPage];
	itemIdSort	itemidptr;
	ItemId		lp;
	TransactionId	xid;
	uint32			epoch;
	UndoRecPtr		urec_ptr;
	int			nline,
				nstorage,
				nunused;
	int			i;
	Size		totallen;

	/*
	 * It's worth the trouble to be more paranoid here than in most places,
	 * because we are about to reshuffle data in (what is usually) a shared
	 * disk buffer.  If we aren't careful then corrupted pointers, lengths,
	 * etc could cause us to clobber adjacent disk buffers, spreading the data
	 * loss further.  So, check everything.
	 */
	if (pd_lower < SizeOfPageHeaderData ||
		pd_lower > pd_upper ||
		pd_upper > pd_special ||
		pd_special > BLCKSZ ||
		pd_special != MAXALIGN(pd_special))
		ereport(ERROR,
		(errcode(ERRCODE_DATA_CORRUPTED),
			errmsg("corrupted page pointers: lower = %u, upper = %u, special = %u",
				pd_lower, pd_upper, pd_special)));

	nline = PageGetMaxOffsetNumber(page);

	/*
	 * If there are any tuples which are inplace updated by any open
	 * transactions we shall not compactify the page contents, otherwise,
	 * rollback of those transactions will not be possible.  There could be
	 * a case, where within a transaction tuple is first inplace updated
	 * and then, either updated or deleted. So for now avoid compaction if
	 * there are any tuples which are marked inplace updated, updated or
	 * deleted by an open transaction.
	 */
	for (i = FirstOffsetNumber; i <= nline; i++)
	{
		lp = PageGetItemId(page, i);
		if (ItemIdIsUsed(lp) && ItemIdHasStorage(lp))
		{
			ZHeapTupleHeader tup;

			tup = (ZHeapTupleHeader) PageGetItem(page, lp);

			if (!(tup->t_infomask & (ZHEAP_INPLACE_UPDATED |
									 ZHEAP_UPDATED | ZHEAP_DELETED)))
				continue;

			if (!ZHeapTupleHasInvalidXact(tup->t_infomask))
			{
				int			trans_slot;

				trans_slot = ZHeapTupleHeaderGetXactSlot(tup);
				if (trans_slot == ZHTUP_SLOT_FROZEN)
					continue;

				/*
				 * XXX There is possibility that the updater's slot got reused by a
				 * locker in such a case the INVALID_XACT will be moved to lockers
				 * undo.  Now, we will find that the tuple has in-place update flag
				 * but it doesn't have INVALID_XACT flag and the slot transaction is
				 * also running, in such case we will not prune this page.  Ideally
				 * if the multi-locker is set we can get the actual transaction and
				 * check the status of the transaction.
				 */
				trans_slot = GetTransactionSlotInfo(buffer, i, trans_slot,
													&epoch, &xid, &urec_ptr,
													NoTPDBufLock, false);
				/*
				 * It is quite possible that the item is showing some
				 * valid transaction slot, but actual slot has been frozen.
				 * This can happen when the slot belongs to TPD entry and
				 * the corresponding TPD entry is pruned.
				 */
				if (trans_slot == ZHTUP_SLOT_FROZEN)
					continue;

				if (!TransactionIdDidCommit(xid))
					return;
			}
		}
	}

	/*
	 * Run through the line pointer array and collect data about live items.
	 */
	itemidptr = itemidbase;
	nunused = totallen = 0;
	for (i = FirstOffsetNumber; i <= nline; i++)
	{
		lp = PageGetItemId(page, i);
		if (ItemIdIsUsed(lp))
		{
			if (ItemIdHasStorage(lp))
			{
				itemidptr->offsetindex = i - 1;
				itemidptr->itemoff = ItemIdGetOffset(lp);
				if (unlikely(itemidptr->itemoff < (int)pd_upper ||
					itemidptr->itemoff >= (int)pd_special))
					ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
						errmsg("corrupted item pointer: %u",
							itemidptr->itemoff)));
				/*
				 * We need to save additional space for the target offset, so
				 * that we can save the space for new tuple.
				 */
				if (i == target_offnum)
					itemidptr->alignedlen = SHORTALIGN(ItemIdGetLength(lp) + space_required);
				else
					itemidptr->alignedlen = SHORTALIGN(ItemIdGetLength(lp));
				totallen += itemidptr->alignedlen;
				itemidptr++;
			}
		}
		else
		{
			nunused++;

			/*
			 * We allow Unused entries to be reused only if there is no
			 * transaction information for the entry or the transaction
			 * is committed.
			 */
			if (ItemIdHasPendingXact(lp))
			{
				int		trans_slot = ItemIdGetTransactionSlot(lp);

				/*
				 * Here, we are relying on the transaction information in
				 * slot as if the corresponding slot has been reused, then
				 * transaction information from the entry would have been
				 * cleared.  See PageFreezeTransSlots.
				 */
				if (trans_slot != ZHTUP_SLOT_FROZEN)
				{
					trans_slot = GetTransactionSlotInfo(buffer, i, trans_slot,
														&epoch, &xid,
														&urec_ptr, NoTPDBufLock,
														false);
					/*
					 * It is quite possible that the item is showing some
					 * valid transaction slot, but actual slot has been
					 * frozen. This can happen when the slot belongs to TPD
					 * entry and the corresponding TPD entry is pruned. If
					 * unused_set is true, it means that itemIds are already
					 * set unused with transaction slot information by the
					 * caller and we should not clear it.
					 */
					if ((trans_slot != ZHTUP_SLOT_FROZEN &&
						!TransactionIdDidCommit(xid)) || unused_set)
						continue;
				}
			}

			/* Unused entries should have lp_len = 0, but make sure */
			ItemIdSetUnused(lp);
		}
	}

	nstorage = itemidptr - itemidbase;
	if (nstorage == 0)
	{
		/* Page is completely empty, so just reset it quickly */
		((PageHeader)page)->pd_upper = pd_special;
	}
	else
	{
		/* Need to compact the page the hard way */
		if (totallen > (Size)(pd_special - pd_lower))
			ereport(ERROR,
			(errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("corrupted item lengths: total %u, available space %u",
				(unsigned int)totallen, pd_special - pd_lower)));

		compactify_ztuples(itemidbase, nstorage, page, tmppage);
	}

	/* Set hint bit for PageAddItem */
	if (nunused > 0)
		PageSetHasFreeLinePointers(page);
	else
		PageClearHasFreeLinePointers(page);

	/* indicate that the page has been pruned */
	if (pruned)
		*pruned = true;
}
