/*-------------------------------------------------------------------------
 *
 * zvacuumlazy.c
 *	  Concurrent ("lazy") vacuuming.
 *
 *
 * The lazy vacuum in zheap uses two-passes to clean up the dead tuples in
 * heap and index.  It reclaims all the dead items in heap in the first pass
 * and write undo record for such items, then clean the indexes in second
 * pass.  The undo is written, so that if there is any error while cleaning
 * indexes, we can rollback the operation and mark the entries in as dead.
 *
 * The other important aspect that is ensured in this system is that we don't
 * item ids that are marked as unused to be reused till the transaction that
 * has marked them unused is committed.
 *
 * The dead tuple tracking works in the same way as in heap.  See lazyvacuum.c.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/commands/zvacuumlazy.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <math.h>

#include "access/genam.h"
#include "access/xact.h"
#include "access/zhtup.h"
#include "access/zheapam_xlog.h"
#include "commands/dbcommands.h"
#include "commands/vacuum.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "portability/instr_time.h"
#include "postmaster/autovacuum.h"
#include "storage/bufmgr.h"
#include "storage/freespace.h"
#include "storage/lmgr.h"
#include "storage/procarray.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/pg_rusage.h"

/* A few variables that don't seem worth passing around as parameters */
static int	elevel = -1;
static TransactionId OldestXmin;
static BufferAccessStrategy vac_strategy;

/*
 * Guesstimation of number of dead tuples per page.  This is used to
 * provide an upper limit to memory allocated when vacuuming small
 * tables.
 */
#define LAZY_ALLOC_TUPLES		MaxZHeapTuplesPerPageAlign0

/* non-export function prototypes */
static int
lazy_vacuum_zpage(Relation onerel, BlockNumber blkno, Buffer buffer,
				  int tupindex, LVRelStats *vacrelstats);
static int
lazy_vacuum_zpage_with_undo(Relation onerel, BlockNumber blkno, Buffer buffer,
							int tupindex, LVRelStats *vacrelstats);
static void
lazy_space_zalloc(LVRelStats *vacrelstats, BlockNumber relblocks);

/*
 *	lazy_vacuum_zpage() -- free dead tuples on a page
 *					 and repair its fragmentation.
 *
 * Caller must hold pin and buffer exclusive lock on the buffer.
 *
 * tupindex is the index in vacrelstats->dead_tuples of the first dead
 * tuple for this page.  We assume the rest follow sequentially.
 * The return value is the first tupindex after the tuples of this page.
 */
static int
lazy_vacuum_zpage(Relation onerel, BlockNumber blkno, Buffer buffer,
				  int tupindex, LVRelStats *vacrelstats)
{
	Page		page = BufferGetPage(buffer);
	OffsetNumber unused[MaxOffsetNumber];
	int			uncnt = 0;

	START_CRIT_SECTION();

	for (; tupindex < vacrelstats->num_dead_tuples; tupindex++)
	{
		BlockNumber tblk;
		OffsetNumber toff;
		ItemId		itemid;

		tblk = ItemPointerGetBlockNumber(&vacrelstats->dead_tuples[tupindex]);
		if (tblk != blkno)
			break;				/* past end of tuples for this block */
		toff = ItemPointerGetOffsetNumber(&vacrelstats->dead_tuples[tupindex]);
		itemid = PageGetItemId(page, toff);
		ItemIdSetUnused(itemid);
		unused[uncnt++] = toff;
	}

	ZPageRepairFragmentation(page);

	/*
	 * Mark buffer dirty before we write WAL.
	 */
	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(onerel))
	{
		XLogRecPtr	recptr;

		recptr = log_zheap_clean(onerel, buffer,
								 NULL, 0, NULL, 0,
								 unused, uncnt,
								 vacrelstats->latestRemovedXid);
		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	return tupindex;
}

/*
 *	lazy_vacuum_zpage_with_undo() -- free dead tuples on a page
 *					 and repair its fragmentation.
 *
 * Caller must hold pin and buffer exclusive lock on the buffer.
 */
static int
lazy_vacuum_zpage_with_undo(Relation onerel, BlockNumber blkno, Buffer buffer,
							int tupindex, LVRelStats *vacrelstats)
{
	TransactionId xid = GetTopTransactionId();
	uint32	epoch = GetEpochForXid(xid);
	Page		page = BufferGetPage(buffer);
	UnpackedUndoRecord	undorecord;
	OffsetNumber unused[MaxOffsetNumber];
	UndoRecPtr	urecptr, prev_urecptr;
	int			i, uncnt = 0;
	int		trans_slot_id;

	for (; tupindex < vacrelstats->num_dead_tuples; tupindex++)
	{
		BlockNumber tblk;
		OffsetNumber toff;

		tblk = ItemPointerGetBlockNumber(&vacrelstats->dead_tuples[tupindex]);

		/*
		 * We should never pass the end of tuples for this block as we clean
		 * the tuples in the current block before moving to next block.
		 */
		Assert(tblk == blkno);

		toff = ItemPointerGetOffsetNumber(&vacrelstats->dead_tuples[tupindex]);
		unused[uncnt++] = toff;
	}

	if (uncnt <= 0)
		return tupindex;

reacquire_slot:
	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(onerel, buffer, epoch, xid);

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		goto reacquire_slot;
	}

	prev_urecptr = PageGetUNDO(page, trans_slot_id);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_ITEMID_UNUSED;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = onerel->rd_node.relNode;
	undorecord.uur_prevxid = xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = InvalidCommandId;
	undorecord.uur_tsid = onerel->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = 0;
	undorecord.uur_tuple.len = 0;
	undorecord.uur_payload.len = uncnt * sizeof(OffsetNumber);
	undorecord.uur_payload.data = (char *) palloc(uncnt * sizeof(OffsetNumber));

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT, InvalidTransactionId);

	START_CRIT_SECTION();

	memcpy(undorecord.uur_payload.data, unused, uncnt * sizeof(OffsetNumber));
	InsertPreparedUndo();
	PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);

	for (i = 0; i < uncnt; i++)
	{
		ItemId		itemid;

		itemid = PageGetItemId(page, unused[i]);
		ItemIdSetUnusedExtended(itemid, trans_slot_id);
	}
	ZPageRepairFragmentation(page);

	/*
	 * Mark buffer dirty before we write WAL.
	 */
	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(onerel))
	{
		xl_zheap_unused	xl_rec;
		xl_undo_header	xlundohdr;
		XLogRecPtr	recptr;

		/*
		 * Store the information required to generate undo record during
		 * replay.
		 */
		xlundohdr.relfilenode = undorecord.uur_relfilenode;
		xlundohdr.tsid = undorecord.uur_tsid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xl_rec.latestRemovedXid = vacrelstats->latestRemovedXid;
		xl_rec.nunused = uncnt;
		xl_rec.trans_slot_id = trans_slot_id;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xl_rec, SizeOfZHeapUnused);
		XLogRegisterData((char *) unused, uncnt * sizeof(OffsetNumber));
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		recptr = XLogInsert(RM_ZHEAP2_ID, XLOG_ZHEAP_UNUSED);
		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseUndoBuffers();

	return tupindex;
}

/*
 *	lazy_scan_zheap() -- scan an open heap relation
 *
 *		This routine prunes each page in the zheap, which will among other
 *		things truncate dead tuples to dead line pointers, truncate recently
 *		dead tuples to deleted line pointers and defragment the page
 *		(see zheap_page_prune).  It also builds lists of dead tuples and pages
 *		with free space, calculates statistics on the number of live tuples in
 *		the zheap.  It then reclaim all dead line pointers and write undo for
 *		each of them, so that if there is any error later, we can rollback the
 *		operation.  When done, or when we run low on space for dead-tuple
 *		TIDs, invoke vacuuming of indexes.
 *
 *		We also need to ensure that the heap-TIDs won't get reused till the
 *		transaction that has performed this vacuum is committed.  To achieve
 *		that, we need to store transaction slot information in the line
 *		pointers that are marked unused in the first-pass of heap.
 *
 *		If there are no indexes then we can reclaim line pointers without
 *		writting any undo;
 */
void
lazy_scan_zheap(Relation onerel, int options, LVRelStats *vacrelstats,
				Relation *Irel, int nindexes,
				BufferAccessStrategy vac_strategy, bool aggressive)
{
	BlockNumber nblocks,
				blkno;
	ZHeapTupleData tuple;
	char	   *relname;
	BlockNumber empty_pages,
				vacuumed_pages;
	double		num_tuples,
				tups_vacuumed,
				nkeep,
				nunused;
	IndexBulkDeleteResult **indstats;
	StringInfoData infobuf;
	int			i;
	int			tupindex = 0;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	relname = RelationGetRelationName(onerel);
	if (aggressive)
		ereport(elevel,
				(errmsg("aggressively vacuuming \"%s.%s\"",
						get_namespace_name(RelationGetNamespace(onerel)),
						relname)));
	else
		ereport(elevel,
				(errmsg("vacuuming \"%s.%s\"",
						get_namespace_name(RelationGetNamespace(onerel)),
						relname)));

	empty_pages = vacuumed_pages = 0;
	num_tuples = tups_vacuumed = nkeep = nunused = 0;

	indstats = (IndexBulkDeleteResult **)
		palloc0(nindexes * sizeof(IndexBulkDeleteResult *));

	nblocks = RelationGetNumberOfBlocks(onerel);
	vacrelstats->rel_pages = nblocks;
	vacrelstats->scanned_pages = 0;
	vacrelstats->tupcount_pages = 0;
	vacrelstats->nonempty_pages = 0;
	vacrelstats->latestRemovedXid = InvalidTransactionId;

	lazy_space_zalloc(vacrelstats, nblocks);

	for (blkno = 0; blkno < nblocks; blkno++)
	{
		Buffer		buf;
		Page		page;
		TransactionId	xid;
		OffsetNumber offnum,
					maxoff;
		Size		freespace;
		bool		tupgone,
					hastup;

		vacuum_delay_point();

		/*
		 * If we are close to overrunning the available space for dead-tuple
		 * TIDs, pause and do a cycle of vacuuming before we tackle this page.
		 */
		if ((vacrelstats->max_dead_tuples - vacrelstats->num_dead_tuples) < MaxZHeapTuplesPerPage &&
			vacrelstats->num_dead_tuples > 0)
		{
			/*
			 * Remove index entries.  Unlike, heap we don't need to log special
			 * cleanup info which includes latest latestRemovedXid for standby.
			 * This is because we have covered all the dead tuples in the first
			 * pass itself and we don't need another pass on heap after index.
			 */
			for (i = 0; i < nindexes; i++)
				lazy_vacuum_index(Irel[i],
								  &indstats[i],
								  vacrelstats);

			/*
			 * Forget the now-vacuumed tuples, and press on, but be careful
			 * not to reset latestRemovedXid since we want that value to be
			 * valid.
			 */
			vacrelstats->num_dead_tuples = 0;
			vacrelstats->num_index_scans++;
		}

		buf = ReadBufferExtended(onerel, MAIN_FORKNUM, blkno,
								 RBM_NORMAL, vac_strategy);
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		vacrelstats->scanned_pages++;
		vacrelstats->tupcount_pages++;

		page = BufferGetPage(buf);

		if (PageIsNew(page))
		{
			/*
			 * An all-zeroes page could be left over if a backend extends the
			 * relation but crashes before initializing the page. Reclaim such
			 * pages for use.  See the similar code in lazy_scan_heap to know
			 * why we have used relation extension lock.
			 */
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
			LockRelationForExtension(onerel, ExclusiveLock);
			UnlockRelationForExtension(onerel, ExclusiveLock);
			LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
			if (PageIsNew(page))
			{
				ereport(WARNING,
						(errmsg("relation \"%s\" page %u is uninitialized --- fixing",
								relname, blkno)));
				ZheapInitPage(page, BufferGetPageSize(buf));
				empty_pages++;
			}
			freespace = PageGetZHeapFreeSpace(page);
			MarkBufferDirty(buf);
			UnlockReleaseBuffer(buf);

			RecordPageWithFreeSpace(onerel, blkno, freespace);
			continue;
		}

		if (PageIsEmpty(page))
		{
			empty_pages++;
			freespace = PageGetZHeapFreeSpace(page);
			/*
			 * Fixme: If we need to support visibility map or visbile bit on
			 * page, then we need to handle that case in lazy_scan_heap.
			 */

			UnlockReleaseBuffer(buf);
			RecordPageWithFreeSpace(onerel, blkno, freespace);
			continue;
		}

		/*
		 * We count tuples removed by the pruning step as removed by VACUUM.
		 */
		tups_vacuumed += zheap_page_prune_guts(onerel, buf, OldestXmin, false,
											&vacrelstats->latestRemovedXid);

		/* Now scan the page to collect vacuumable items. */
		hastup = false;
		freespace = 0;
		maxoff = PageGetMaxOffsetNumber(page);

		for (offnum = FirstOffsetNumber;
			 offnum <= maxoff;
			 offnum = OffsetNumberNext(offnum))
		{
			ItemId		itemid;

			itemid = PageGetItemId(page, offnum);

			/* Unused items require no processing, but we count 'em */
			if (!ItemIdIsUsed(itemid))
			{
				nunused += 1;
				continue;
			}

			/* Deleted items mustn't be touched */
			if (ItemIdIsDeleted(itemid))
			{
				hastup = true;	/* this page won't be truncatable */
				continue;
			}

			ItemPointerSet(&(tuple.t_self), blkno, offnum);

			/*
			 * DEAD item pointers are to be vacuumed normally; but we don't
			 * count them in tups_vacuumed, else we'd be double-counting (at
			 * least in the common case where zheap_page_prune_guts() just
			 * freed up a tuple).
			 */
			if (ItemIdIsDead(itemid))
			{
				lazy_record_dead_tuple(vacrelstats, &(tuple.t_self));
				continue;
			}

			Assert(ItemIdIsNormal(itemid));

			tuple.t_data = (ZHeapTupleHeader) PageGetItem(page, itemid);
			tuple.t_len = ItemIdGetLength(itemid);
			tuple.t_tableOid = RelationGetRelid(onerel);

			tupgone = false;

			switch (ZHeapTupleSatisfiesOldestXmin(&tuple, OldestXmin, buf, &xid))
			{
				case HEAPTUPLE_DEAD:

					/*
					 * Ordinarily, DEAD tuples would have been removed by
					 * zheap_page_prune_guts(), but it's possible that the
					 * tuple state changed since heap_page_prune() looked.
					 * In particular an INSERT_IN_PROGRESS tuple could have
					 * changed to DEAD if the inserter aborted.  So this
					 * cannot be considered an error condition.
					 */
					tupgone = true; /* we can delete the tuple */
					break;
				case HEAPTUPLE_LIVE:
					/* Tuple is good --- but let's do some validity checks */
					if (onerel->rd_rel->relhasoids &&
						!OidIsValid(ZHeapTupleGetOid(&tuple)))
						elog(WARNING, "relation \"%s\" TID %u/%u: OID is invalid",
							 relname, blkno, offnum);
					break;
				case HEAPTUPLE_RECENTLY_DEAD:

					/*
					 * If tuple is recently deleted then we must not remove it
					 * from relation.
					 */
					nkeep += 1;
					break;
				case HEAPTUPLE_INSERT_IN_PROGRESS:
				case HEAPTUPLE_DELETE_IN_PROGRESS:
					/* This is an expected case during concurrent vacuum */
					break;
				default:
					elog(ERROR, "unexpected ZHeapTupleSatisfiesOldestXmin result");
					break;
			}

			if (tupgone)
			{
				lazy_record_dead_tuple(vacrelstats, &(tuple.t_self));
				ZHeapTupleHeaderAdvanceLatestRemovedXid(tuple.t_data, xid,
													   &vacrelstats->latestRemovedXid);
				tups_vacuumed += 1;
			}
			else
			{
				num_tuples += 1;
				hastup = true;
			}
		}						/* scan along page */

		/*
		 * If there are no indexes then we can vacuum the page right now
		 * instead of doing a second scan.
		 */
		if (vacrelstats->num_dead_tuples > 0)
		{
			if (nindexes == 0)
			{
				/* Remove tuples from zheap */
				tupindex = lazy_vacuum_zpage(onerel, blkno, buf, tupindex,
											 vacrelstats);

				/*
				 * Forget the now-vacuumed tuples, and press on, but be careful
				 * not to reset latestRemovedXid since we want that value to be
				 * valid.
				 */
				vacrelstats->num_dead_tuples = 0;
				vacuumed_pages++;
			}
			else
			{
				Assert(nindexes > 0);

				/* Remove tuples from zheap and write the undo for it. */
				tupindex = lazy_vacuum_zpage_with_undo(onerel, blkno, buf,
													   tupindex, vacrelstats);
			}

			/* Now that we've compacted the page, record its available space */
			freespace = PageGetZHeapFreeSpace(page);
		}

		UnlockReleaseBuffer(buf);

		/* Remember the location of the last page with nonremovable tuples */
		if (hastup)
			vacrelstats->nonempty_pages = blkno + 1;

		/* We're done with this page, so remember its free space as-is. */
		if (freespace)
			RecordPageWithFreeSpace(onerel, blkno, freespace);
	}

	/* save stats for use later */
	vacrelstats->tuples_deleted = tups_vacuumed;
	vacrelstats->new_dead_tuples = nkeep;

	/* now we can compute the new value for pg_class.reltuples */
	vacrelstats->new_rel_tuples = vac_estimate_reltuples(onerel,
														 nblocks,
														 vacrelstats->tupcount_pages,
														 num_tuples);

	if (vacrelstats->num_dead_tuples > 0)
	{
		/*
		 * Remove index entries.  Unlike, heap we don't need to log special
		 * cleanup info which includes latest latestRemovedXid for standby.
		 * This is because we have covered all the dead tuples in the first
		 * pass itself and we don't need another pass on heap after index.
		 */
		for (i = 0; i < nindexes; i++)
			lazy_vacuum_index(Irel[i],
							  &indstats[i],
							  vacrelstats);

		vacrelstats->num_index_scans++;
	}

	/* Do post-vacuum cleanup and statistics update for each index */
	for (i = 0; i < nindexes; i++)
		lazy_cleanup_index(Irel[i], indstats[i], vacrelstats);

	/*
	 * This is pretty messy, but we split it up so that we can skip emitting
	 * individual parts of the message when not applicable.
	 */
	initStringInfo(&infobuf);
	appendStringInfo(&infobuf,
					 _("%.0f dead row versions cannot be removed yet, oldest xmin: %u\n"),
					 nkeep, OldestXmin);
	appendStringInfo(&infobuf, _("There were %.0f unused item pointers.\n"),
					 nunused);
	appendStringInfo(&infobuf, ngettext("%u page is entirely empty.\n",
									"%u pages are entirely empty.\n",
									empty_pages),
					 empty_pages);
	appendStringInfo(&infobuf, _("%s."), pg_rusage_show(&ru0));

	ereport(elevel,
			(errmsg("\"%s\": found %.0f removable, %.0f nonremovable row versions in %u out of %u pages",
					RelationGetRelationName(onerel),
					tups_vacuumed, num_tuples,
					vacrelstats->scanned_pages, nblocks),
			 errdetail_internal("%s", infobuf.data)));
	pfree(infobuf.data);
}

/*
 *	lazy_vacuum_zheap_rel() -- perform LAZY VACUUM for one zheap relation
 */
void
lazy_vacuum_zheap_rel(Relation onerel, int options, VacuumParams *params,
					  BufferAccessStrategy bstrategy)
{
	LVRelStats *vacrelstats;
	Relation   *Irel;
	int			nindexes;
	PGRUsage	ru0;
	TimestampTz starttime = 0;
	long		secs;
	int			usecs;
	double		read_rate,
				write_rate;
	bool		aggressive;		/* should we scan all unfrozen pages? */
	BlockNumber new_rel_pages;
	double		new_rel_tuples;
	double		new_live_tuples;

	Assert(params != NULL);

	/* measure elapsed time iff autovacuum logging requires it */
	if (IsAutoVacuumWorkerProcess() && params->log_min_duration >= 0)
	{
		pg_rusage_init(&ru0);
		starttime = GetCurrentTimestamp();
	}

	if (options & VACOPT_VERBOSE)
		elevel = INFO;
	else
		elevel = DEBUG2;

	vac_strategy = bstrategy;

	/*
	 * We can always ignore processes running lazy vacuum.  This is because we
	 * use these values only for deciding which tuples we must keep in the
	 * tables.  Since lazy vacuum doesn't write its XID anywhere, it's safe to
	 * ignore it.  In theory it could be problematic to ignore lazy vacuums in
	 * a full vacuum, but keep in mind that only one vacuum process can be
	 * working on a particular table at any time, and that each vacuum is
	 * always an independent transaction.
	 */
	OldestXmin = GetOldestXmin(onerel, PROCARRAY_FLAGS_VACUUM);

	Assert(TransactionIdIsNormal(OldestXmin));

	/*
	 * We request an aggressive scan if DISABLE_PAGE_SKIPPING was specified.
	 */
	if (options & VACOPT_DISABLE_PAGE_SKIPPING)
		aggressive = true;

	vacrelstats = (LVRelStats *) palloc0(sizeof(LVRelStats));

	vacrelstats->old_rel_pages = onerel->rd_rel->relpages;
	vacrelstats->old_live_tuples = onerel->rd_rel->reltuples;
	vacrelstats->num_index_scans = 0;
	vacrelstats->pages_removed = 0;
	vacrelstats->lock_waiter_detected = false;

	/* Open all indexes of the relation */
	vac_open_indexes(onerel, RowExclusiveLock, &nindexes, &Irel);
	vacrelstats->hasindex = (nindexes > 0);

	/* Do the vacuuming */
	lazy_scan_zheap(onerel, options, vacrelstats, Irel, nindexes,
					vac_strategy, aggressive);

	/* Done with indexes */
	vac_close_indexes(nindexes, Irel, NoLock);

	/*
	 * Optionally truncate the relation.
	 */
	if (should_attempt_truncation(vacrelstats))
		lazy_truncate_heap(onerel, vacrelstats);

	/* Vacuum the Free Space Map */
	FreeSpaceMapVacuum(onerel);

	/*
	 * Update statistics in pg_class.
	 *
	 * A corner case here is that if we scanned no pages at all because every
	 * page is all-visible, we should not update relpages/reltuples, because
	 * we have no new information to contribute.  In particular this keeps us
	 * from replacing relpages=reltuples=0 (which means "unknown tuple
	 * density") with nonzero relpages and reltuples=0 (which means "zero
	 * tuple density") unless there's some actual evidence for the latter.
	 *
	 * We can use either tupcount_pages or scanned_pages for the check
	 * described above as both the valuse should be same.  However, we use
	 * earlier so as to be consistent with heap.
	 *
	 * Fixme: We do need to update relallvisible as in heap once we start
	 * using visibilitymap or something equivalent to it.
	 *
	 * relfrozenxid/relminmxid are invalid as we don't perform freeze
	 * operation in zheap.
	 */
	new_rel_pages = vacrelstats->rel_pages;
	new_rel_tuples = vacrelstats->new_rel_tuples;
	if (vacrelstats->tupcount_pages == 0 && new_rel_pages > 0)
	{
		new_rel_pages = vacrelstats->old_rel_pages;
		new_rel_tuples = vacrelstats->old_live_tuples;
	}

	vac_update_relstats(onerel,
						new_rel_pages,
						new_rel_tuples,
						new_rel_pages,
						vacrelstats->hasindex,
						InvalidTransactionId,
						InvalidMultiXactId,
						false);

	/* report results to the stats collector, too */
	new_live_tuples = new_rel_tuples - vacrelstats->new_dead_tuples;
	if (new_live_tuples < 0)
		new_live_tuples = 0;	/* just in case */

	pgstat_report_vacuum(RelationGetRelid(onerel),
						 onerel->rd_rel->relisshared,
						 new_live_tuples,
						 vacrelstats->new_dead_tuples);

	/* and log the action if appropriate */
	if (IsAutoVacuumWorkerProcess() && params->log_min_duration >= 0)
	{
		TimestampTz endtime = GetCurrentTimestamp();

		if (params->log_min_duration == 0 ||
			TimestampDifferenceExceeds(starttime, endtime,
									   params->log_min_duration))
		{
			StringInfoData buf;
			char	   *msgfmt;

			TimestampDifference(starttime, endtime, &secs, &usecs);

			read_rate = 0;
			write_rate = 0;
			if ((secs > 0) || (usecs > 0))
			{
				read_rate = (double) BLCKSZ * VacuumPageMiss / (1024 * 1024) /
					(secs + usecs / 1000000.0);
				write_rate = (double) BLCKSZ * VacuumPageDirty / (1024 * 1024) /
					(secs + usecs / 1000000.0);
			}

			/*
			 * This is pretty messy, but we split it up so that we can skip
			 * emitting individual parts of the message when not applicable.
			 */
			initStringInfo(&buf);
			if (aggressive)
				msgfmt = _("automatic aggressive vacuum of table \"%s.%s.%s\": index scans: %d\n");
			else
				msgfmt = _("automatic vacuum of table \"%s.%s.%s\": index scans: %d\n");
			appendStringInfo(&buf, msgfmt,
							 get_database_name(MyDatabaseId),
							 get_namespace_name(RelationGetNamespace(onerel)),
							 RelationGetRelationName(onerel),
							 vacrelstats->num_index_scans);
			appendStringInfo(&buf, _("pages: %u removed, %u remain, %u\n"),
							 vacrelstats->pages_removed,
							 vacrelstats->rel_pages);
			appendStringInfo(&buf,
							 _("tuples: %.0f removed, %.0f remain, %.0f are dead but not yet removable, oldest xmin: %u\n"),
							 vacrelstats->tuples_deleted,
							 vacrelstats->new_rel_tuples,
							 vacrelstats->new_dead_tuples,
							 OldestXmin);
			appendStringInfo(&buf,
							 _("buffer usage: %d hits, %d misses, %d dirtied\n"),
							 VacuumPageHit,
							 VacuumPageMiss,
							 VacuumPageDirty);
			appendStringInfo(&buf, _("avg read rate: %.3f MB/s, avg write rate: %.3f MB/s\n"),
							 read_rate, write_rate);
			appendStringInfo(&buf, _("system usage: %s"), pg_rusage_show(&ru0));

			ereport(LOG,
					(errmsg_internal("%s", buf.data)));
			pfree(buf.data);
		}
	}
}

/*
 * lazy_space_zalloc - space allocation decisions for lazy vacuum
 *
 * See the comments at the head of this file for rationale.
 */
static void
lazy_space_zalloc(LVRelStats *vacrelstats, BlockNumber relblocks)
{
	long		maxtuples;
	int			vac_work_mem = IsAutoVacuumWorkerProcess() &&
	autovacuum_work_mem != -1 ?
	autovacuum_work_mem : maintenance_work_mem;

	if (vacrelstats->hasindex)
	{
		maxtuples = (vac_work_mem * 1024L) / sizeof(ItemPointerData);
		maxtuples = Min(maxtuples, INT_MAX);
		maxtuples = Min(maxtuples, MaxAllocSize / sizeof(ItemPointerData));

		/* curious coding here to ensure the multiplication can't overflow */
		if ((BlockNumber) (maxtuples / LAZY_ALLOC_TUPLES) > relblocks)
			maxtuples = relblocks * LAZY_ALLOC_TUPLES;

		/* stay sane if small maintenance_work_mem */
		maxtuples = Max(maxtuples, MaxZHeapTuplesPerPageAlign0);
	}
	else
	{
		maxtuples = MaxZHeapTuplesPerPageAlign0;
	}

	vacrelstats->num_dead_tuples = 0;
	vacrelstats->max_dead_tuples = (int) maxtuples;
	vacrelstats->dead_tuples = (ItemPointer)
		palloc(maxtuples * sizeof(ItemPointerData));
}
