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
 * The vacuum progress checker also uses only two phases - the vacuuming heap
 * and the vacuuming index. The scanning heap phase is not used because it is
 * not a seperate pass in zheap but a part of the first pass.
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
#include "access/tpd.h"
#include "access/vacuumblk.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "access/zhtup.h"
#include "utils/ztqual.h"
#include "access/zheapam_xlog.h"
#include "commands/dbcommands.h"
#include "commands/progress.h"
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

/*
 * Before we consider skipping a page that's marked as clean in
 * visibility map, we must've seen at least this many clean pages.
 */
#define SKIP_PAGES_THRESHOLD	((BlockNumber) 32)

/* A few variables that don't seem worth passing around as parameters */
static int	elevel = -1;
static TransactionId OldestXmin;
static BufferAccessStrategy vac_strategy;

/*
 * Guesstimation of number of dead tuples per page.  This is used to
 * provide an upper limit to memory allocated when vacuuming small
 * tables.
 */
#define LAZY_ALLOC_TUPLES		MaxZHeapTuplesPerPage

/* non-export function prototypes */
static int
lazy_vacuum_zpage(Relation onerel, BlockNumber blkno, Buffer buffer,
				  int tupindex, LVRelStats *vacrelstats, Buffer *vmbuffer);
static int
lazy_vacuum_zpage_with_undo(Relation onerel, BlockNumber blkno, Buffer buffer,
							int tupindex, LVRelStats *vacrelstats,
							Buffer *vmbuffer,
							TransactionId *global_visibility_cutoff_xid);
static void
lazy_space_zalloc(LVRelStats *vacrelstats, BlockNumber relblocks);
static void
lazy_scan_zheap(Relation onerel, VacuumParams *params, LVRelStats *vacrelstats,
				Relation *Irel, int nindexes,
				BufferAccessStrategy vac_strategy, bool aggressive);
static bool
zheap_page_is_all_visible(Relation rel, Buffer buf,
						  TransactionId *visibility_cutoff_xid);

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
				  int tupindex, LVRelStats *vacrelstats, Buffer *vmbuffer)
{
	Page		page = BufferGetPage(buffer);
	Page		tmppage;
	OffsetNumber unused[MaxOffsetNumber];
	int			uncnt = 0;
	TransactionId visibility_cutoff_xid;
	bool		pruned = false;

	/*
	 * Lock the TPD page before starting critical section.  We might need
	 * to access it during page repair fragmentation.
	 */
	if (ZHeapPageHasTPDSlot((PageHeader) page))
		TPDPageLock(onerel, buffer);

	/*
	 * We prepare the temporary copy of the page so that during page
	 * repair fragmentation we can use it to copy the actual tuples.
	 * See comments atop zheap_page_prune_guts.
	 */
	tmppage = PageGetTempPageCopy(page);

	/* Report the number of blocks vacuumed. */
	pgstat_progress_update_param(PROGRESS_VACUUM_HEAP_BLKS_VACUUMED, blkno - 1);

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

	ZPageRepairFragmentation(buffer, tmppage, InvalidOffsetNumber, 0, false,
							 &pruned, false);

	/*
	 * Mark buffer dirty before we write WAL.
	 */
	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(onerel))
	{
		XLogRecPtr	recptr;

		recptr = log_zheap_clean(onerel, buffer, InvalidOffsetNumber, 0,
								 NULL, 0, NULL, 0,
								 unused, uncnt,
								 vacrelstats->latestRemovedXid, pruned);
		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	/* be tidy */
	pfree(tmppage);
	UnlockReleaseTPDBuffers();

	/*
	 * Now that we have removed the dead tuples from the page, once again
	 * check if the page has become all-visible.  The page is already marked
	 * dirty, exclusively locked.
	 */
	if (zheap_page_is_all_visible(onerel, buffer, &visibility_cutoff_xid))
	{
		uint8		vm_status = visibilitymap_get_status(onerel, blkno, vmbuffer);
		uint8		flags = 0;

		/* Set the VM all-visible bit to flag, if needed */
		if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) == 0)
			flags |= VISIBILITYMAP_ALL_VISIBLE;

		Assert(BufferIsValid(*vmbuffer));
		if (flags != 0)
			visibilitymap_set(onerel, blkno, buffer, InvalidXLogRecPtr,
							  *vmbuffer, visibility_cutoff_xid, flags);
	}

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
							int tupindex, LVRelStats *vacrelstats,
							Buffer *vmbuffer,
							TransactionId *global_visibility_cutoff_xid)
{
	TransactionId visibility_cutoff_xid;
	FullTransactionId fxid = GetTopFullTransactionId();
	TransactionId xid = XidFromFullTransactionId(fxid);
	uint32	epoch = EpochFromFullTransactionId(fxid);
	Page		page = BufferGetPage(buffer);
	Page		tmppage;
	UnpackedUndoRecord	undorecord;
	OffsetNumber unused[MaxOffsetNumber];
	UndoRecPtr	urecptr, prev_urecptr;
	int			i, uncnt = 0;
	int		trans_slot_id;
	xl_undolog_meta undometa;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;
	bool		lock_reacquired;
	bool		pruned = false;

	for (; tupindex < vacrelstats->num_dead_tuples; tupindex++)
	{
		BlockNumber tblk PG_USED_FOR_ASSERTS_ONLY;
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
	trans_slot_id = PageReserveTransactionSlot(onerel,
											   buffer,
											   PageGetMaxOffsetNumber(page),
											   epoch,
											   xid,
											   &prev_urecptr,
											   &lock_reacquired,
											   false,
											   true,
											   NULL);
	if (lock_reacquired)
		goto reacquire_slot;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		goto reacquire_slot;
	}

	/* prepare an undo record */
	undorecord.uur_rmid = RM_ZHEAP_ID;
	undorecord.uur_type = UNDO_ITEMID_UNUSED;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_reloid = onerel->rd_id;
	undorecord.uur_prevxid = xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = InvalidCommandId;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = 0;
	undorecord.uur_tuple.len = 0;
	undorecord.uur_payload.len = uncnt * sizeof(OffsetNumber);
	undorecord.uur_payload.data = (char *) palloc(uncnt * sizeof(OffsetNumber));

	/*
	 * XXX Unlike other undo records, we don't set the TPD slot number in undo
	 * record as this record is just skipped during processing of undo.
	 */

	urecptr = PrepareUndoInsert(&undorecord,
								InvalidFullTransactionId,
								UndoPersistenceForRelation(onerel),
								NULL,
								&undometa);

	/*
	 * Lock the TPD page before starting critical section.  We might need
	 * to access it during page repair fragmentation.  Note that if the
	 * transaction slot belongs to TPD entry, then the TPD page must be
	 * locked during slot reservation.
	 */
	if (trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
		ZHeapPageHasTPDSlot((PageHeader) page))
		TPDPageLock(onerel, buffer);

	/*
	 * We prepare the temporary copy of the page so that during page
	 * repair fragmentation we can use it to copy the actual tuples.
	 * See comments atop zheap_page_prune_guts.
	 */
	tmppage = PageGetTempPageCopy(page);


	/* Report the number of blocks vacuumed. */
	pgstat_progress_update_param(PROGRESS_VACUUM_HEAP_BLKS_VACUUMED, blkno - 1);

	START_CRIT_SECTION();

	memcpy(undorecord.uur_payload.data, unused, uncnt * sizeof(OffsetNumber));
	InsertPreparedUndo();
	/*
	 * We're sending the undo record for debugging purpose. So, just send
	 * the last one.
	 */
	if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		PageSetUNDO(undorecord,
					buffer,
					trans_slot_id,
					true,
					epoch,
					xid,
					urecptr,
					unused,
					uncnt);
	}
	else
	{
		PageSetUNDO(undorecord,
					buffer,
					trans_slot_id,
					true,
					epoch,
					xid,
					urecptr,
					NULL,
					0);
	}

	for (i = 0; i < uncnt; i++)
	{
		ItemId		itemid;

		itemid = PageGetItemId(page, unused[i]);
		ItemIdSetUnusedExtended(itemid, trans_slot_id);
	}

	ZPageRepairFragmentation(buffer, tmppage, InvalidOffsetNumber, 0, false,
							 &pruned, true);

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
		xlundohdr.reloid = undorecord.uur_reloid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xl_rec.latestRemovedXid = vacrelstats->latestRemovedXid;
		xl_rec.nunused = uncnt;
		xl_rec.trans_slot_id = trans_slot_id;
		xl_rec.flags = 0;
		if (pruned)
			xl_rec.flags |= XLZ_UNUSED_ALLOW_PRUNING;

prepare_xlog:
		/*
		 * WAL-LOG undolog meta data if this is the fisrt WAL after the
		 * checkpoint.
		 */
		LogUndoMetaData(&undometa);

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xl_rec, SizeOfZHeapUnused);

		XLogRegisterData((char *) unused, uncnt * sizeof(OffsetNumber));
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			(void) RegisterTPDBuffer(page, 1);

		RegisterUndoLogBuffers(2);

		recptr = XLogInsertExtended(RM_ZHEAP2_ID, XLOG_ZHEAP_UNUSED, RedoRecPtr,
									doPageWrites);
		if (recptr == InvalidXLogRecPtr)
		{
			ResetRegisteredTPDBuffers();
			goto prepare_xlog;
		}

		PageSetLSN(page, recptr);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			TPDPageSetLSN(page, recptr);
		UndoLogBuffersSetLSN(recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();

	/* be tidy */
	pfree(tmppage);

	/*
	 * Now that we have removed the dead tuples from the page, once again
	 * check if the page has become potentially all-visible.  The page is
	 * already marked dirty, exclusively locked.  We can't mark the page
	 * as all-visible here because we have yet to remove index entries
	 * corresponding dead tuples.  So, we mark them potentially all-visible
	 * and later after removing index entries, if still the bit is set, we
	 * mark them as all-visible.
	 */
	if (zheap_page_is_all_visible(onerel, buffer, &visibility_cutoff_xid))
	{
		uint8		vm_status = visibilitymap_get_status(onerel, blkno, vmbuffer);
		uint8		flags = 0;

		/* Set the VM to become potentially all-visible, if needed */
		if ((vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE) == 0)
			flags |= VISIBILITYMAP_POTENTIAL_ALL_VISIBLE;

		if (TransactionIdFollows(visibility_cutoff_xid,
								*global_visibility_cutoff_xid))
			*global_visibility_cutoff_xid = visibility_cutoff_xid;

		Assert(BufferIsValid(*vmbuffer));
		if (flags != 0)
			visibilitymap_set(onerel, blkno, buffer, InvalidXLogRecPtr,
							  *vmbuffer, InvalidTransactionId, flags);
	}

	return tupindex;
}

/*
 *	MarkPagesAsAllVisible() -- Mark all the pages corresponding to dead tuples
 *		as all-visible.
 *
 * We mark the page as all-visible, if it is already marked as potential
 * all-visible.
 */
static void
MarkPagesAsAllVisible(Relation rel, LVRelStats *vacrelstats,
					  TransactionId visibility_cutoff_xid)
{
	int		idx = 0;

	for (; idx < vacrelstats->num_dead_tuples; idx++)
	{
		BlockNumber tblk;
		BlockNumber prev_tblk = InvalidBlockNumber;
		Buffer		vmbuffer = InvalidBuffer;
		Buffer		buf = InvalidBuffer;
		uint8		vm_status;

		tblk = ItemPointerGetBlockNumber(&vacrelstats->dead_tuples[idx]);
		buf = ReadBufferExtended(rel, MAIN_FORKNUM, tblk,
								 RBM_NORMAL, NULL);

		/* Avoid processing same block again and again. */
		if (tblk == prev_tblk)
			continue;

		visibilitymap_pin(rel, tblk, &vmbuffer);
		vm_status = visibilitymap_get_status(rel, tblk, &vmbuffer);

		/* Set the VM all-visible bit, if needed */
		if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) == 0 &&
			(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
		{
			visibilitymap_clear(rel, tblk, vmbuffer,
								VISIBILITYMAP_VALID_BITS);

			Assert(BufferIsValid(buf));
			LockBuffer(buf, BUFFER_LOCK_SHARE);

			visibilitymap_set(rel, tblk, buf, InvalidXLogRecPtr, vmbuffer,
							  visibility_cutoff_xid, VISIBILITYMAP_ALL_VISIBLE);

			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		}

		if (BufferIsValid(vmbuffer))
		{
			ReleaseBuffer(vmbuffer);
			vmbuffer = InvalidBuffer;
		}

		if (BufferIsValid(buf))
		{
			ReleaseBuffer(buf);
			buf = InvalidBuffer;
		}

		prev_tblk = tblk;
	}
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
static void
lazy_scan_zheap(Relation onerel, VacuumParams *params,  LVRelStats *vacrelstats,
				Relation *Irel, int nindexes,
				BufferAccessStrategy vac_strategy, bool aggressive)
{
	BlockNumber nblocks,
				blkno;
	ZHeapTupleData tuple;
	char	   *relname;
	BlockNumber empty_pages,
				vacuumed_pages,
				next_fsm_block_to_vacuum;
	double		num_tuples,
				tups_vacuumed,
				nkeep,
				nunused;
	IndexBulkDeleteResult **indstats;
	StringInfoData infobuf;
	int			i;
	int			tupindex = 0;
	PGRUsage	ru0;
	BlockNumber next_unskippable_block;
	bool		skipping_blocks;
	Buffer		vmbuffer = InvalidBuffer;
	TransactionId visibility_cutoff_xid = InvalidTransactionId;
	const int	initprog_index[] = {
		PROGRESS_VACUUM_PHASE,
		PROGRESS_VACUUM_TOTAL_HEAP_BLKS,
		PROGRESS_VACUUM_MAX_DEAD_TUPLES
	};
	int64		initprog_val[3];


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
	next_fsm_block_to_vacuum = (BlockNumber) 0;
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

	/*
	 * Report that we are vacuuming heap and advertise the total number of
	 * blocks and max dead tuples. The metapage is also considered in nblocks,
	 * subtract by one to get total pages.
	 */
	initprog_val[0] = PROGRESS_VACUUM_PHASE_VACUUM_HEAP;
	initprog_val[1] = nblocks - 1;
	initprog_val[2] = vacrelstats->max_dead_tuples;
	pgstat_progress_update_multi_param(3, initprog_index, initprog_val);

	next_unskippable_block = ZHEAP_METAPAGE + 1;
	if (!aggressive)
	{

		Assert((params->options & VACOPT_DISABLE_PAGE_SKIPPING) == 0);
		while (next_unskippable_block < nblocks)
		{
			uint8       vmstatus;

			vmstatus = visibilitymap_get_status(onerel, next_unskippable_block,
												&vmbuffer);

			if ((vmstatus & VISIBILITYMAP_ALL_VISIBLE) == 0)
				break;

			vacuum_delay_point();
			next_unskippable_block++;
       }
   }

   if (next_unskippable_block >= SKIP_PAGES_THRESHOLD)
       skipping_blocks = true;
   else
       skipping_blocks = false;

	for (blkno = ZHEAP_METAPAGE + 1; blkno < nblocks; blkno++)
	{
		Buffer		buf;
		Page		page;
		TransactionId	xid;
		OffsetNumber offnum,
					maxoff;
		Size		freespace;
		bool		tupgone,
					hastup;
		bool		all_visible_according_to_vm = false;
		bool		all_visible;
		bool		has_dead_tuples;

		/* Report the number of blocks scanned. */
		pgstat_progress_update_param(PROGRESS_VACUUM_HEAP_BLKS_SCANNED, blkno - 1);

		if (blkno == next_unskippable_block)
		{
			/* Time to advance next_unskippable_block */
			next_unskippable_block++;
			if (!aggressive)
			{
				while (next_unskippable_block < nblocks)
				{
					uint8		vmskipflags;

					vmskipflags = visibilitymap_get_status(onerel,
														   next_unskippable_block,
														   &vmbuffer);
					if ((vmskipflags & VISIBILITYMAP_ALL_VISIBLE) == 0)
						break;

					vacuum_delay_point();
					next_unskippable_block++;
				}
			}

			/*
			 * We know we can't skip the current block.  But set up
			 * skipping_blocks to do the right thing at the following blocks.
			 */
			if (next_unskippable_block - blkno > SKIP_PAGES_THRESHOLD)
				skipping_blocks = true;
			else
				skipping_blocks = false;
		}
		else
		{
			/*
			 * The current block is potentially skippable; if we've seen a
			 * long enough run of skippable blocks to justify skipping it.
			 */
			if (skipping_blocks)
				continue;
			all_visible_according_to_vm = true;
		}

		vacuum_delay_point();

		/*
		 * If we are close to overrunning the available space for dead-tuple
		 * TIDs, pause and do a cycle of vacuuming before we tackle this page.
		 */
		if ((vacrelstats->max_dead_tuples - vacrelstats->num_dead_tuples) < MaxZHeapTuplesPerPage &&
			vacrelstats->num_dead_tuples > 0)
		{
			/*
			 * Before beginning index vacuuming, we release any pin we may
			 * hold on the visibility map page.  This isn't necessary for
			 * correctness, but we do it anyway to avoid holding the pin
			 * across a lengthy, unrelated operation.
			 */
			if (BufferIsValid(vmbuffer))
			{
				ReleaseBuffer(vmbuffer);
				vmbuffer = InvalidBuffer;
			}

			/* Report that we are now vacuuming indexes. */
			pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
										 PROGRESS_VACUUM_PHASE_VACUUM_INDEX);

			/*
			 * Remove index entries.  Unlike, heap we don't need to log special
			 * cleanup info which includes latest latestRemovedXid for standby.
			 * This is because we have covered all the dead tuples in the first
			 * pass itself and we don't need another pass on heap after index.
			 */
			for (i = 0; i < nindexes; i++)
				lazy_vacuum_index(Irel[i],
								  &indstats[i],
								  vacrelstats,
								  vac_strategy,
								  elevel);

			pgstat_progress_update_param(PROGRESS_VACUUM_NUM_INDEX_VACUUMS,
										 vacrelstats->num_index_scans + 1);

			/*
			 * XXX - The cutoff xid used here is the highest xmin of all the heap
			 * pages scanned.  This can lead to more query cancellations on
			 * standby.  However, alternative is that we track cutoff_xid for
			 * each page in first-pass of vacuum and then use it after removing
			 * index entries.  We didn't pursue the alternative because it would
			 * require more work memory which means it can lead to more index
			 * passes.
			 */
			MarkPagesAsAllVisible(onerel, vacrelstats, visibility_cutoff_xid);

			/*
			 * Forget the now-vacuumed tuples, and press on, but be careful
			 * not to reset latestRemovedXid since we want that value to be
			 * valid.
			 */
			tupindex = 0;
			vacrelstats->num_dead_tuples = 0;
			vacrelstats->num_index_scans++;

			/*
			 * Vacuum the Free Space Map to make newly-freed space visible on
			 * upper-level FSM pages.  Note we have not yet processed blkno.
			 */
			FreeSpaceMapVacuumRange(onerel, next_fsm_block_to_vacuum, blkno);
			next_fsm_block_to_vacuum = blkno;

			/* Report that we are once again vacuuming the heap. */
			pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
										 PROGRESS_VACUUM_PHASE_VACUUM_HEAP);
		}

		/*
		 * Pin the visibility map page in case we need to mark the page
		 * all-visible.  In most cases this will be very cheap, because we'll
		 * already have the correct page pinned anyway.  However, it's
		 * possible that (a) next_unskippable_block is covered by a different
		 * VM page than the current block or (b) we released our pin and did a
		 * cycle of index vacuuming.
		 *
		 */
		visibilitymap_pin(onerel, blkno, &vmbuffer);

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
			 * relation but crashes before initializing the page, or when
			 * bulk-extending the relation (which creates a number of empty
			 * pages at the tail end of the relation, but enters them into the
			 * FSM)Reclaim such pages for use.  See the similar code in
			 * lazy_scan_heap to know why we have used relation extension lock.
			 */
			Size		freespace = 0;

			empty_pages++;

			/*
			 * Perform checking of FSM after releasing lock, the fsm is
			 * approximate, after all.
			 */
			UnlockReleaseBuffer(buf);

			if (GetRecordedFreeSpace(onerel, blkno) == 0)
				freespace = BufferGetPageSize(buf) - SizeOfPageHeaderData;

			if (freespace > 0)
			{
				RecordPageWithFreeSpace(onerel, blkno, freespace, nblocks);
				elog(DEBUG1, "relation \"%s\" page %u is uninitialized and not in fsm, fixing",
					 relname, blkno);
			}
			continue;
		}

		/*
		 * Skip TPD pages.  This needs to be checked before PageIsEmpty as TPD
		 * pages can also be empty, but we don't want to deal with it like a
		 * heap page.
		 */
		/*
		 * Prune the TPD pages and if all the entries are removed, then record
		 * it in FSM, so that it can be reused as a zheap page.
		 */
		if (PageGetSpecialSize(page) == sizeof(TPDPageOpaqueData))
		{
			bool	should_free_page = true;

			/*
			 * The empty pages are not guaranteed to be removed from the TPD
			 * page list.  See TPDPagePrune.  So, ensure that we remove empty
			 * pages from the TPD page list if required.
			 */
			if (PageIsEmpty(page))
			{
				TPDPageOpaque   tpdopaque;

				tpdopaque = (TPDPageOpaque)PageGetSpecialPointer(BufferGetPage(buf));

				/*
				 * If TPD page still have valid previous or next block, then
				 * we are sure that this page is still not removed from meta
				 * list.  So we will remove now.
				 *
				 * If previous and next TPD blocks are invalid then also we
				 * are not sure that this TPD page is already removed from meta
				 * list because it is possible that this is first used TPD
				 * page.
				 */
				if (tpdopaque->tpd_prevblkno == InvalidBlockNumber &&
					tpdopaque->tpd_nextblkno == InvalidBlockNumber)
				{
					Buffer	metabuf;
					ZHeapMetaPage	metapage;

					/*
					 * Here, we will take lock on meta page and will check that
					 * this TPD page is first used TPD page or not.  If this is
					 * not first used TPD page, then we are sure that this page
					 * is already removed from list.
					 */
					metabuf = ReadBufferExtended(onerel, MAIN_FORKNUM,
												 ZHEAP_METAPAGE, RBM_NORMAL,
												 vac_strategy);
					LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);
					metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));
					Assert(metapage->zhm_magic == ZHEAP_MAGIC);
					if (metapage->zhm_first_used_tpd_page != blkno)
						should_free_page = false;
					UnlockReleaseBuffer(metabuf);
				}
			}

			/* If the page is already pruned, skip it. */
			if (should_free_page)
			{
				TPDPagePrune(onerel, buf, vac_strategy, InvalidOffsetNumber, 0,
							 true, NULL, NULL);
				/*
				 * Remember the location of the last page with nonremovable
				 * tuples.
				 */
				if (!PageIsEmpty(page))
					vacrelstats->nonempty_pages = blkno + 1;
			}

			UnlockReleaseBuffer(buf);
			continue;
		}

		if (PageIsEmpty(page))
		{
			uint8		vmstatus;
			empty_pages++;
			freespace = PageGetZHeapFreeSpace(page);

			vmstatus = visibilitymap_get_status(onerel,
												blkno,
												&vmbuffer);
			if ((vmstatus & VISIBILITYMAP_ALL_VISIBLE) == 0)
			{
				START_CRIT_SECTION();

				/* mark buffer dirty before writing a WAL record */
				MarkBufferDirty(buf);

				/*
				 * It's possible that another backend has extended the heap,
				 * initialized the page, and then failed to WAL-log the page
				 * due to an ERROR.  Since heap extension is not WAL-logged,
				 * recovery might try to replay our record setting the page
				 * all-visible and find that the page isn't initialized, which
				 * will cause a PANIC.  To prevent that, check whether the
				 * page has been previously WAL-logged, and if not, do that
				 * now.
				 */
				if (RelationNeedsWAL(onerel) &&
					PageGetLSN(page) == InvalidXLogRecPtr)
					log_newpage_buffer(buf, true);

				visibilitymap_set(onerel, blkno, buf, InvalidXLogRecPtr,
								  vmbuffer, InvalidTransactionId,
								  VISIBILITYMAP_ALL_VISIBLE);

				END_CRIT_SECTION();
			}

			UnlockReleaseBuffer(buf);
			RecordPageWithFreeSpace(onerel, blkno, freespace, nblocks);
			continue;
		}

		/*
		 * We count tuples removed by the pruning step as removed by VACUUM.
		 */
		tups_vacuumed += zheap_page_prune_guts(onerel, buf, OldestXmin,
											   InvalidOffsetNumber, 0, false,
											   false,
											   &vacrelstats->latestRemovedXid,
											   NULL);

		/* Now scan the page to collect vacuumable items. */
		hastup = false;
		freespace = 0;
		maxoff = PageGetMaxOffsetNumber(page);
		all_visible = true;
		has_dead_tuples = false;

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
				all_visible = false;
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
				all_visible = false;
				lazy_record_dead_tuple(vacrelstats, &(tuple.t_self));
				continue;
			}

			Assert(ItemIdIsNormal(itemid));

			tuple.t_data = (ZHeapTupleHeader) PageGetItem(page, itemid);
			tuple.t_len = ItemIdGetLength(itemid);
			tuple.t_tableOid = RelationGetRelid(onerel);

			tupgone = false;

			switch (ZHeapTupleSatisfiesVacuum(&tuple, OldestXmin, buf, &xid))
			{
				case ZHEAPTUPLE_DEAD:

					/*
					 * Ordinarily, DEAD tuples would have been removed by
					 * zheap_page_prune_guts(), but it's possible that the
					 * tuple state changed since heap_page_prune() looked.
					 * In particular an INSERT_IN_PROGRESS tuple could have
					 * changed to DEAD if the inserter aborted.  So this
					 * cannot be considered an error condition.
					 */
					tupgone = true; /* we can delete the tuple */
					all_visible = false;
					break;
				case ZHEAPTUPLE_LIVE:
					if (all_visible)
					{
						if (!TransactionIdPrecedes(xid, OldestXmin))
						{
							all_visible = false;
							break;
						}
					}

					/* Track newest xmin on page. */
					if (TransactionIdFollows(xid, visibility_cutoff_xid))
						visibility_cutoff_xid = xid;
					break;
				case ZHEAPTUPLE_RECENTLY_DEAD:

					/*
					 * If tuple is recently deleted then we must not remove it
					 * from relation.
					 */
					nkeep += 1;
					all_visible = false;
					break;
				case ZHEAPTUPLE_INSERT_IN_PROGRESS:
				case ZHEAPTUPLE_DELETE_IN_PROGRESS:
					/* This is an expected case during concurrent vacuum */
					all_visible = false;
					break;
				case ZHEAPTUPLE_ABORT_IN_PROGRESS:
					/*
					 * We can simply skip the tuple if it has inserted/operated by
					 * some aborted transaction and its rollback is still pending. It'll
					 * be taken care of by future vacuum calls.
					 */
					all_visible = false;
					break;
				default:
					elog(ERROR, "unexpected ZHeapTupleSatisfiesVacuum result");
					break;
			}

			if (tupgone)
			{
				lazy_record_dead_tuple(vacrelstats, &(tuple.t_self));
				ZHeapTupleHeaderAdvanceLatestRemovedXid(tuple.t_data, xid,
													   &vacrelstats->latestRemovedXid);
				tups_vacuumed += 1;
				has_dead_tuples = true;
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
											 vacrelstats, &vmbuffer);
				has_dead_tuples = false;

				/*
				 * Forget the now-vacuumed tuples, and press on, but be careful
				 * not to reset latestRemovedXid since we want that value to be
				 * valid.
				 */
				vacrelstats->num_dead_tuples = 0;
				vacuumed_pages++;
				/*
				 * Periodically do incremental FSM vacuuming to make newly-freed
				 * space visible on upper FSM pages.  Note: although we've cleaned
				 * the current block, we haven't yet updated its FSM entry (that
				 * happens further down), so passing end == blkno is correct.
				 */
				if (blkno - next_fsm_block_to_vacuum >= VACUUM_FSM_EVERY_PAGES)
				{
					FreeSpaceMapVacuumRange(onerel, next_fsm_block_to_vacuum,
											blkno);
					next_fsm_block_to_vacuum = blkno;
				}
			}
			else
			{
				Assert(nindexes > 0);

				/* Remove tuples from zheap and write the undo for it. */
				tupindex = lazy_vacuum_zpage_with_undo(onerel, blkno, buf,
													   tupindex, vacrelstats,
													   &vmbuffer,
													   &visibility_cutoff_xid);
			}
		}

		/* Now that we are done with the page, get its available space */
		freespace = PageGetZHeapFreeSpace(page);

		/* mark page all-visible, if appropriate */
		if (all_visible && !all_visible_according_to_vm)
		{
			uint8       flags = VISIBILITYMAP_ALL_VISIBLE;

			visibilitymap_set(onerel, blkno, buf, InvalidXLogRecPtr,
							  vmbuffer, visibility_cutoff_xid, flags);
		}
		else if (has_dead_tuples && all_visible_according_to_vm)
		{
    		visibilitymap_clear(onerel, blkno, vmbuffer,
								VISIBILITYMAP_VALID_BITS);
		}

		UnlockReleaseBuffer(buf);

		/* Remember the location of the last page with nonremovable tuples */
		if (hastup)
			vacrelstats->nonempty_pages = blkno + 1;

		/* We're done with this page, so remember its free space as-is. */
		if (freespace)
			RecordPageWithFreeSpace(onerel, blkno, freespace, nblocks);
	}

	/* Report that everything is scanned and vacuumed. */
	pgstat_progress_update_param(PROGRESS_VACUUM_HEAP_BLKS_SCANNED, blkno - 1);
	pgstat_progress_update_param(PROGRESS_VACUUM_HEAP_BLKS_VACUUMED, blkno - 1);

	/* save stats for use later */
	vacrelstats->tuples_deleted = tups_vacuumed;
	vacrelstats->new_dead_tuples = nkeep;

	/*
	 * Now we can compute the new value for pg_class.reltuples.  To compensate
	 * for metapage pass one less than the actual nblocks.
	 */
	vacrelstats->new_rel_tuples = vac_estimate_reltuples(onerel,
														 nblocks - 1,
														 vacrelstats->tupcount_pages,
														 num_tuples);

	/*
	 * Release any remaining pin on visibility map page.
	 */
	if (BufferIsValid(vmbuffer))
	{
		ReleaseBuffer(vmbuffer);
		vmbuffer = InvalidBuffer;
	}

	if (vacrelstats->num_dead_tuples > 0)
	{
		/* Report that we are now vacuuming indexes. */
		pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
									 PROGRESS_VACUUM_PHASE_VACUUM_INDEX);

		/*
		 * Remove index entries.  Unlike, heap we don't need to log special
		 * cleanup info which includes latest latestRemovedXid for standby.
		 * This is because we have covered all the dead tuples in the first
		 * pass itself and we don't need another pass on heap after index.
		 */
		for (i = 0; i < nindexes; i++)
			lazy_vacuum_index(Irel[i],
							  &indstats[i],
							  vacrelstats,
							  vac_strategy,
							  elevel);

		pgstat_progress_update_param(PROGRESS_VACUUM_NUM_INDEX_VACUUMS,
									 vacrelstats->num_index_scans + 1);

		/*
		 * XXX - The cutoff xid used here is the highest xmin of all the heap
		 * pages scanned.  This can lead to more query cancellations on
		 * standby.  However, alternative is that we track cutoff_xid for
		 * each page in first-pass of vacuum and then use it after removing
		 * index entries.  We didn't pursue the alternative because it would
		 * require more work memory which means it can lead to more index
		 * passes.
		 */
		MarkPagesAsAllVisible(onerel, vacrelstats, visibility_cutoff_xid);

		vacrelstats->num_index_scans++;

		/*
		 * Vacuum the Free Space Map to make newly-freed space visible on
		 * upper-level FSM pages.
		 */
		FreeSpaceMapVacuumRange(onerel, next_fsm_block_to_vacuum, blkno);
		next_fsm_block_to_vacuum = blkno;
	}

	/*
	 * Vacuum the remainder of the Free Space Map.  We must do this whether or
	 * not there were indexes.
	 */
	if (blkno > next_fsm_block_to_vacuum)
		FreeSpaceMapVacuumRange(onerel, next_fsm_block_to_vacuum, blkno);

	/* Report that we're cleaning up. */
	pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
								 PROGRESS_VACUUM_PHASE_INDEX_CLEANUP);

	/* Do post-vacuum cleanup and statistics update for each index */
	for (i = 0; i < nindexes; i++)
		lazy_cleanup_index(Irel[i], indstats[i], vacrelstats, vac_strategy,
						   elevel);

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
lazy_vacuum_zheap_rel(Relation onerel, VacuumParams *params,
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
	bool		aggressive = false;	/* should we scan all unfrozen pages? */
	BlockNumber new_rel_pages;
	double		new_rel_tuples;
	double		new_live_tuples;

	Assert(params != NULL);

	/*
	 * For zheap, since vacuum process also reserves transaction slot
	 * in page, other backend can't ignore this while calculating
	 * OldestXmin/RecentXmin.  See GetSnapshotData for details.
	 */
	LWLockAcquire(ProcArrayLock, LW_EXCLUSIVE);
	MyPgXact->vacuumFlags &= ~PROC_IN_VACUUM;
	LWLockRelease(ProcArrayLock);

	/* measure elapsed time iff autovacuum logging requires it */
	if (IsAutoVacuumWorkerProcess() && params->log_min_duration >= 0)
	{
		pg_rusage_init(&ru0);
		starttime = GetCurrentTimestamp();
	}

	if (params->options & VACOPT_VERBOSE)
		elevel = INFO;
	else
		elevel = DEBUG2;

	pgstat_progress_start_command(PROGRESS_COMMAND_VACUUM,
								  RelationGetRelid(onerel));

	vac_strategy = bstrategy;

	/*
	 * We can't ignore processes running lazy vacuum on zheap relations because
	 * like other backends operating on zheap, lazy vacuum also reserves a
	 * transaction slot in the page for pruning purpose.
	 */
	OldestXmin = GetOldestXmin(onerel, PROCARRAY_FLAGS_DEFAULT);

	Assert(TransactionIdIsNormal(OldestXmin));

	/*
	 * We request an aggressive scan if DISABLE_PAGE_SKIPPING was specified.
	 */
	if (params->options & VACOPT_DISABLE_PAGE_SKIPPING)
		aggressive = true;

	vacrelstats = (LVRelStats *) palloc0(sizeof(LVRelStats));

	vacrelstats->old_rel_pages = onerel->rd_rel->relpages;
	vacrelstats->old_live_tuples = onerel->rd_rel->reltuples;
	vacrelstats->num_index_scans = 0;
	vacrelstats->pages_removed = 0;
	vacrelstats->lock_waiter_detected = false;

	/* Open all indexes of the relation */
	vac_open_indexes(onerel, RowExclusiveLock, &nindexes, &Irel);
	vacrelstats->useindex = (nindexes > 0 &&
							 params->index_cleanup == VACOPT_TERNARY_ENABLED);

	/* Do the vacuuming */
	lazy_scan_zheap(onerel, params, vacrelstats, Irel, nindexes,
					vac_strategy, aggressive);

	/* Done with indexes */
	vac_close_indexes(nindexes, Irel, NoLock);

	/*
	 * Optionally truncate the relation.
	 */
	if (should_attempt_truncation(onerel, vacrelstats))
		lazy_truncate_heap(onerel, vacrelstats, vac_strategy, elevel);

	/* Report that we are now doing final cleanup. */
	pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
								 PROGRESS_VACUUM_PHASE_FINAL_CLEANUP);

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
						nindexes > 0,
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

	pgstat_progress_end_command();

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
			appendStringInfo(&buf, _("pages: %u removed, %u remain\n"),
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

	if (vacrelstats->useindex)
	{
		maxtuples = (vac_work_mem * 1024L) / sizeof(ItemPointerData);
		maxtuples = Min(maxtuples, INT_MAX);
		maxtuples = Min(maxtuples, MaxAllocSize / sizeof(ItemPointerData));

		/* curious coding here to ensure the multiplication can't overflow */
		if ((BlockNumber) (maxtuples / LAZY_ALLOC_TUPLES) > relblocks)
			maxtuples = relblocks * LAZY_ALLOC_TUPLES;

		/* stay sane if small maintenance_work_mem */
		maxtuples = Max(maxtuples, MaxZHeapTuplesPerPage);
	}
	else
	{
		maxtuples = MaxZHeapTuplesPerPage;
	}

	vacrelstats->num_dead_tuples = 0;
	vacrelstats->max_dead_tuples = (int) maxtuples;
	vacrelstats->dead_tuples = (ItemPointer)
		palloc(maxtuples * sizeof(ItemPointerData));
}

/*
 * Check if every tuple in the given page is visible to all current and future
 * transactions. Also return the visibility_cutoff_xid which is the highest
 * xmin amongst the visible tuples.
 */
static bool
zheap_page_is_all_visible(Relation rel, Buffer buf,
						  TransactionId *visibility_cutoff_xid)
{
	Page		page = BufferGetPage(buf);
	BlockNumber blockno = BufferGetBlockNumber(buf);
	OffsetNumber offnum,
				maxoff;
	bool		all_visible = true;

	*visibility_cutoff_xid = InvalidTransactionId;

	/*
	 * This is a stripped down version of the line pointer scan in
	 * lazy_scan_zheap(). So if you change anything here, also check that code.
	 */
	maxoff = PageGetMaxOffsetNumber(page);
	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff && all_visible;
		 offnum = OffsetNumberNext(offnum))
	{
		ItemId		itemid;
		TransactionId xid;
		ZHeapTupleData tuple;

		itemid = PageGetItemId(page, offnum);

		/* Unused or redirect line pointers are of no interest */
		if (!ItemIdIsUsed(itemid) || ItemIdIsRedirected(itemid))
			continue;

		ItemPointerSet(&(tuple.t_self), blockno, offnum);

		/*
		 * Dead line pointers can have index pointers pointing to them. So
		 * they can't be treated as visible
		 */
		if (ItemIdIsDead(itemid))
		{
			all_visible = false;
			break;
		}

		Assert(ItemIdIsNormal(itemid));

		tuple.t_data = (ZHeapTupleHeader) PageGetItem(page, itemid);
		tuple.t_len = ItemIdGetLength(itemid);
		tuple.t_tableOid = RelationGetRelid(rel);

		switch (ZHeapTupleSatisfiesVacuum(&tuple, OldestXmin, buf, &xid))
		{
			case ZHEAPTUPLE_LIVE:
				{
					/*
					 * The inserter definitely committed. But is it old enough
					 * that everyone sees it as committed?
					 */
					if (!TransactionIdPrecedes(xid, OldestXmin))
					{
						all_visible = false;
						break;
					}

					/* Track newest xmin on page. */
					if (TransactionIdFollows(xid, *visibility_cutoff_xid))
						*visibility_cutoff_xid = xid;
				}
				break;

			case ZHEAPTUPLE_DEAD:
			case ZHEAPTUPLE_RECENTLY_DEAD:
			case ZHEAPTUPLE_INSERT_IN_PROGRESS:
			case ZHEAPTUPLE_DELETE_IN_PROGRESS:
			case ZHEAPTUPLE_ABORT_IN_PROGRESS:
				{
					all_visible = false;
					break;
				}
			default:
				elog(ERROR, "unexpected ZHeapTupleSatisfiesVacuum result");
				break;
		}
	}							/* scan along page */

	return all_visible;
}
