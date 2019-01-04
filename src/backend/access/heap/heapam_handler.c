/*-------------------------------------------------------------------------
 *
 * heapam_handler.c
 *	  heap table access method code
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/heapam_handler.c
 *
 *
 * NOTES
 *	  This file contains the heap_ routines which implement
 *	  the POSTGRES heap table access method used for all POSTGRES
 *	  relations.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <math.h>

#include "miscadmin.h"

#include "access/heapam.h"
#include "access/multixact.h"
#include "access/relscan.h"
#include "access/rewriteheap.h"
#include "access/tableam.h"
#include "access/tsmapi.h"
#include "catalog/catalog.h"
#include "catalog/index.h"
#include "catalog/pg_am_d.h"
#include "catalog/storage.h"
#include "catalog/storage_xlog.h"
#include "executor/executor.h"
#include "optimizer/plancat.h"
#include "pgstat.h"
#include "storage/lmgr.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/tqual.h"
#include "storage/bufpage.h"
#include "storage/bufmgr.h"
#include "storage/predicate.h"
#include "storage/procarray.h"
#include "storage/smgr.h"
#include "access/xact.h"


/* ----------------------------------------------------------------
 *				storage AM support routines for heapam
 * ----------------------------------------------------------------
 */

static bool
heapam_fetch_row_version(Relation relation,
						 ItemPointer tid,
						 Snapshot snapshot,
						 TupleTableSlot *slot,
						 Relation stats_relation)
{
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	Buffer buffer;

	Assert(TTS_IS_BUFFERTUPLE(slot));

	if (heap_fetch(relation, tid, snapshot, &bslot->base.tupdata, &buffer, stats_relation))
	{
		ExecStoreBufferHeapTuple(&bslot->base.tupdata, slot, buffer);
		ReleaseBuffer(buffer);

		slot->tts_tableOid = RelationGetRelid(relation);

		return true;
	}

	slot->tts_tableOid = RelationGetRelid(relation);

	return false;
}

/*
 * Insert a heap tuple from a slot, which may contain an OID and speculative
 * insertion token.
 */
static void
heapam_heap_insert(Relation relation, TupleTableSlot *slot, CommandId cid,
				   int options, BulkInsertState bistate)
{
	bool		shouldFree = true;
	HeapTuple	tuple = ExecFetchSlotHeapTuple(slot, true, &shouldFree);

	/* Update the tuple with table oid */
	slot->tts_tableOid = RelationGetRelid(relation);
	if (slot->tts_tableOid != InvalidOid)
		tuple->t_tableOid = slot->tts_tableOid;

	/* Perform the insertion, and copy the resulting ItemPointer */
	heap_insert(relation, tuple, cid, options, bistate);
	ItemPointerCopy(&tuple->t_self, &slot->tts_tid);

	if (shouldFree)
		pfree(tuple);
}

static void
heapam_heap_insert_speculative(Relation relation, TupleTableSlot *slot, CommandId cid,
							   int options, BulkInsertState bistate, uint32 specToken)
{
	bool		shouldFree = true;
	HeapTuple	tuple = ExecFetchSlotHeapTuple(slot, true, &shouldFree);

	/* Update the tuple with table oid */
	slot->tts_tableOid = RelationGetRelid(relation);
	if (slot->tts_tableOid != InvalidOid)
		tuple->t_tableOid = slot->tts_tableOid;

	HeapTupleHeaderSetSpeculativeToken(tuple->t_data, specToken);

	/* Perform the insertion, and copy the resulting ItemPointer */
	heap_insert(relation, tuple, cid, options, bistate);
	ItemPointerCopy(&tuple->t_self, &slot->tts_tid);

	if (shouldFree)
		pfree(tuple);
}

static void
heapam_heap_complete_speculative(Relation relation, TupleTableSlot *slot, uint32 spekToken,
								 bool succeeded)
{
	bool		shouldFree = true;
	HeapTuple	tuple = ExecFetchSlotHeapTuple(slot, true, &shouldFree);

	/* adjust the tuple's state accordingly */
	if (!succeeded)
		heap_finish_speculative(relation, tuple);
	else
	{
		heap_abort_speculative(relation, tuple);
	}

	if (shouldFree)
		pfree(tuple);
}


static HTSU_Result
heapam_heap_delete(Relation relation, ItemPointer tid, CommandId cid,
				   Snapshot snapshot, Snapshot crosscheck, bool wait,
				   HeapUpdateFailureData *hufd, bool changingPart)
{
	/*
	 * Currently Deleting of index tuples are handled at vacuum, in case
	 * if the storage itself is cleaning the dead tuples by itself, it is
	 * the time to call the index tuple deletion also.
	 */
	return heap_delete(relation, tid, cid, crosscheck, wait, hufd, changingPart);
}


/*
 * Locks tuple and fetches its newest version and TID.
 *
 *	relation - table containing tuple
 *	tid - TID of tuple to lock
 *	snapshot - snapshot indentifying required version (used for assert check only)
 *	slot - tuple to be returned
 *	cid - current command ID (used for visibility test, and stored into
 *		  tuple's cmax if lock is successful)
 *	mode - indicates if shared or exclusive tuple lock is desired
 *	wait_policy - what to do if tuple lock is not available
 *	flags – indicating how do we handle updated tuples
 *	*hufd - filled in failure cases
 *
 * Function result may be:
 *	HeapTupleMayBeUpdated: lock was successfully acquired
 *	HeapTupleInvisible: lock failed because tuple was never visible to us
 *	HeapTupleSelfUpdated: lock failed because tuple updated by self
 *	HeapTupleUpdated: lock failed because tuple updated by other xact
 *	HeapTupleDeleted: lock failed because tuple deleted by other xact
 *	HeapTupleWouldBlock: lock couldn't be acquired and wait_policy is skip
 *
 * In the failure cases other than HeapTupleInvisible, the routine fills
 * *hufd with the tuple's t_ctid, t_xmax (resolving a possible MultiXact,
 * if necessary), and t_cmax (the last only for HeapTupleSelfUpdated,
 * since we cannot obtain cmax from a combocid generated by another
 * transaction).
 * See comments for struct HeapUpdateFailureData for additional info.
 */
static HTSU_Result
heapam_lock_tuple(Relation relation, ItemPointer tid, Snapshot snapshot,
				TupleTableSlot *slot, CommandId cid, LockTupleMode mode,
				LockWaitPolicy wait_policy, uint8 flags,
				HeapUpdateFailureData *hufd)
{
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	HTSU_Result		result;
	Buffer			buffer;
	HeapTuple		tuple = &bslot->base.tupdata;

	hufd->traversed = false;

	Assert(TTS_IS_BUFFERTUPLE(slot));

retry:
	result = heap_lock_tuple(relation, tid, cid, mode, wait_policy,
		(flags & TUPLE_LOCK_FLAG_LOCK_UPDATE_IN_PROGRESS) ? true : false,
							 tuple, &buffer, hufd);

	if (result == HeapTupleUpdated &&
		(flags & TUPLE_LOCK_FLAG_FIND_LAST_VERSION))
	{
		ReleaseBuffer(buffer);
		/* Should not encounter speculative tuple on recheck */
		Assert(!HeapTupleHeaderIsSpeculative(tuple->t_data));

		if (!ItemPointerEquals(&hufd->ctid, &tuple->t_self))
		{
			SnapshotData	SnapshotDirty;
			TransactionId	priorXmax;

			/* it was updated, so look at the updated version */
			*tid = hufd->ctid;
			/* updated row should have xmin matching this xmax */
			priorXmax = hufd->xmax;

			/*
			 * fetch target tuple
			 *
			 * Loop here to deal with updated or busy tuples
			 */
			InitDirtySnapshot(SnapshotDirty);
			for (;;)
			{
				if (ItemPointerIndicatesMovedPartitions(tid))
					ereport(ERROR,
							(errcode(ERRCODE_T_R_SERIALIZATION_FAILURE),
							 errmsg("tuple to be locked was already moved to another partition due to concurrent update")));


				if (heap_fetch(relation, tid, &SnapshotDirty, tuple, &buffer, NULL))
				{
					/*
					 * If xmin isn't what we're expecting, the slot must have been
					 * recycled and reused for an unrelated tuple.  This implies that
					 * the latest version of the row was deleted, so we need do
					 * nothing.  (Should be safe to examine xmin without getting
					 * buffer's content lock.  We assume reading a TransactionId to be
					 * atomic, and Xmin never changes in an existing tuple, except to
					 * invalid or frozen, and neither of those can match priorXmax.)
					 */
					if (!TransactionIdEquals(HeapTupleHeaderGetXmin(tuple->t_data),
											 priorXmax))
					{
						ReleaseBuffer(buffer);
						return HeapTupleDeleted;
					}

					/* otherwise xmin should not be dirty... */
					if (TransactionIdIsValid(SnapshotDirty.xmin))
						elog(ERROR, "t_xmin is uncommitted in tuple to be updated");

					/*
					 * If tuple is being updated by other transaction then we have to
					 * wait for its commit/abort, or die trying.
					 */
					if (TransactionIdIsValid(SnapshotDirty.xmax))
					{
						ReleaseBuffer(buffer);
						switch (wait_policy)
						{
							case LockWaitBlock:
								XactLockTableWait(SnapshotDirty.xmax,
												  relation, &tuple->t_self,
												  XLTW_FetchUpdated);
								break;
							case LockWaitSkip:
								if (!ConditionalXactLockTableWait(SnapshotDirty.xmax))
									return result;	/* skip instead of waiting */
								break;
							case LockWaitError:
								if (!ConditionalXactLockTableWait(SnapshotDirty.xmax))
									ereport(ERROR,
											(errcode(ERRCODE_LOCK_NOT_AVAILABLE),
											 errmsg("could not obtain lock on row in relation \"%s\"",
													RelationGetRelationName(relation))));
								break;
						}
						continue;		/* loop back to repeat heap_fetch */
					}

					/*
					 * If tuple was inserted by our own transaction, we have to check
					 * cmin against es_output_cid: cmin >= current CID means our
					 * command cannot see the tuple, so we should ignore it. Otherwise
					 * heap_lock_tuple() will throw an error, and so would any later
					 * attempt to update or delete the tuple.  (We need not check cmax
					 * because HeapTupleSatisfiesDirty will consider a tuple deleted
					 * by our transaction dead, regardless of cmax.) We just checked
					 * that priorXmax == xmin, so we can test that variable instead of
					 * doing HeapTupleHeaderGetXmin again.
					 */
					if (TransactionIdIsCurrentTransactionId(priorXmax) &&
						HeapTupleHeaderGetCmin(tuple->t_data) >= cid)
					{
						ReleaseBuffer(buffer);
						return result;
					}

					hufd->traversed = true;
					*tid = tuple->t_data->t_ctid;
					ReleaseBuffer(buffer);
					goto retry;
				}

				/*
				 * If the referenced slot was actually empty, the latest version of
				 * the row must have been deleted, so we need do nothing.
				 */
				if (tuple->t_data == NULL)
				{
					return HeapTupleDeleted;
				}

				/*
				 * As above, if xmin isn't what we're expecting, do nothing.
				 */
				if (!TransactionIdEquals(HeapTupleHeaderGetXmin(tuple->t_data),
										 priorXmax))
				{
					if (BufferIsValid(buffer))
						ReleaseBuffer(buffer);
					return HeapTupleDeleted;
				}

				/*
				 * If we get here, the tuple was found but failed SnapshotDirty.
				 * Assuming the xmin is either a committed xact or our own xact (as it
				 * certainly should be if we're trying to modify the tuple), this must
				 * mean that the row was updated or deleted by either a committed xact
				 * or our own xact.  If it was deleted, we can ignore it; if it was
				 * updated then chain up to the next version and repeat the whole
				 * process.
				 *
				 * As above, it should be safe to examine xmax and t_ctid without the
				 * buffer content lock, because they can't be changing.
				 */
				if (ItemPointerEquals(&tuple->t_self, &tuple->t_data->t_ctid))
				{
					/* deleted, so forget about it */
					if (BufferIsValid(buffer))
						ReleaseBuffer(buffer);
					return HeapTupleDeleted;
				}

				/* updated, so look at the updated row */
				*tid = tuple->t_data->t_ctid;
				/* updated row should have xmin matching this xmax */
				priorXmax = HeapTupleHeaderGetUpdateXid(tuple->t_data);
				if (BufferIsValid(buffer))
					ReleaseBuffer(buffer);
				/* loop back to fetch next in chain */
			}
		}
		else
		{
			/* tuple was deleted, so give up */
			return HeapTupleDeleted;
		}
	}

	slot->tts_tableOid = RelationGetRelid(relation);
	ExecStoreBufferHeapTuple(tuple, slot, buffer);
	ReleaseBuffer(buffer); // FIXME: invent option to just transfer pin?

	return result;
}


static HTSU_Result
heapam_heap_update(Relation relation, ItemPointer otid, TupleTableSlot *slot,
				   CommandId cid, Snapshot snapshot, Snapshot crosscheck,
				   bool wait, HeapUpdateFailureData *hufd,
				   LockTupleMode *lockmode, bool *update_indexes)
{
	bool		shouldFree = true;
	HeapTuple	tuple = ExecFetchSlotHeapTuple(slot, true, &shouldFree);
	HTSU_Result result;

	/* Update the tuple with table oid */
	if (slot->tts_tableOid != InvalidOid)
		tuple->t_tableOid = slot->tts_tableOid;

	result = heap_update(relation, otid, tuple, cid, crosscheck, wait,
						 hufd, lockmode);
	ItemPointerCopy(&tuple->t_self, &slot->tts_tid);

	slot->tts_tableOid = RelationGetRelid(relation);

	/*
	 * Note: instead of having to update the old index tuples associated with
	 * the heap tuple, all we do is form and insert new index tuples. This is
	 * because UPDATEs are actually DELETEs and INSERTs, and index tuple
	 * deletion is done later by VACUUM (see notes in ExecDelete). All we do
	 * here is insert new index tuples.  -cim 9/27/89
	 */

	/*
	 * insert index entries for tuple
	 *
	 * Note: heap_update returns the tid (location) of the new tuple in the
	 * t_self field.
	 *
	 * If it's a HOT update, we mustn't insert new index entries.
	 */
	*update_indexes = result == HeapTupleMayBeUpdated &&
		!HeapTupleIsHeapOnly(tuple);

	if (shouldFree)
		pfree(tuple);

	return result;
}

static void
heapam_finish_bulk_insert(Relation relation, int options)
{
	/*
	 * If we skipped writing WAL, then we need to sync the heap (but not
	 * indexes since those use WAL anyway)
	 */
	if (options & HEAP_INSERT_SKIP_WAL)
		heap_sync(relation);
}

static const TupleTableSlotOps *
heapam_slot_callbacks(Relation relation)
{
	return &TTSOpsBufferHeapTuple;
}

HeapTuple
heap_scan_getnext(TableScanDesc sscan, ScanDirection direction)
{
	if (unlikely(sscan->rs_rd->rd_rel->relam != HEAP_TABLE_AM_OID))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						errmsg("only heap AM is supported")));
	return heap_getnext(sscan, direction);
}

static bool
heapam_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot, Snapshot snapshot)
{
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	bool res;

	Assert(TTS_IS_BUFFERTUPLE(slot));
	Assert(BufferIsValid(bslot->buffer));

	/*
	 * We need buffer pin and lock to call HeapTupleSatisfiesVisibility.
	 * Caller should be holding pin, but not lock.
	 */
	LockBuffer(bslot->buffer, BUFFER_LOCK_SHARE);
	res = HeapTupleSatisfies(bslot->base.tuple, snapshot, bslot->buffer);
	LockBuffer(bslot->buffer, BUFFER_LOCK_UNLOCK);

	return res;
}

static IndexFetchTableData*
heapam_begin_index_fetch(Relation rel)
{
	IndexFetchHeapData *hscan = palloc0(sizeof(IndexFetchHeapData));

	hscan->xs_base.rel = rel;
	hscan->xs_cbuf = InvalidBuffer;
	//hscan->xs_continue_hot = false;

	return &hscan->xs_base;
}


static void
heapam_reset_index_fetch(IndexFetchTableData* scan)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;

	if (BufferIsValid(hscan->xs_cbuf))
	{
		ReleaseBuffer(hscan->xs_cbuf);
		hscan->xs_cbuf = InvalidBuffer;
	}

	//hscan->xs_continue_hot = false;
}

static void
heapam_end_index_fetch(IndexFetchTableData* scan)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;

	heapam_reset_index_fetch(scan);

	pfree(hscan);
}

static bool
heapam_fetch_follow(struct IndexFetchTableData *scan,
					ItemPointer tid,
					Snapshot snapshot,
					TupleTableSlot *slot,
					bool *call_again, bool *all_dead)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	bool got_heap_tuple;

	Assert(TTS_IS_BUFFERTUPLE(slot));

	/* We can skip the buffer-switching logic if we're in mid-HOT chain. */
	if (!*call_again)
	{
		/* Switch to correct buffer if we don't have it already */
		Buffer		prev_buf = hscan->xs_cbuf;

		hscan->xs_cbuf = ReleaseAndReadBuffer(hscan->xs_cbuf,
											  hscan->xs_base.rel,
											  ItemPointerGetBlockNumber(tid));

		/*
		 * Prune page, but only if we weren't already on this page
		 */
		if (prev_buf != hscan->xs_cbuf)
			heap_page_prune_opt(hscan->xs_base.rel, hscan->xs_cbuf);
	}

	/* Obtain share-lock on the buffer so we can examine visibility */
	LockBuffer(hscan->xs_cbuf, BUFFER_LOCK_SHARE);
	got_heap_tuple = heap_hot_search_buffer(tid,
											hscan->xs_base.rel,
											hscan->xs_cbuf,
											snapshot,
											&bslot->base.tupdata,
											all_dead,
											!*call_again);
	bslot->base.tupdata.t_self = *tid;
	LockBuffer(hscan->xs_cbuf, BUFFER_LOCK_UNLOCK);

	if (got_heap_tuple)
	{
		/*
		 * Only in a non-MVCC snapshot can more than one member of the HOT
		 * chain be visible.
		 */
		*call_again = !IsMVCCSnapshot(snapshot);
		// FIXME pgstat_count_heap_fetch(scan->indexRelation);

		slot->tts_tableOid = RelationGetRelid(scan->rel);
		ExecStoreBufferHeapTuple(&bslot->base.tupdata, slot, hscan->xs_cbuf);
	}
	else
	{
		/* We've reached the end of the HOT chain. */
		*call_again = false;
	}

	return got_heap_tuple;
}

/*
 * As above, except that instead of scanning the complete heap, only the given
 * number of blocks are scanned.  Scan to end-of-rel can be signalled by
 * passing InvalidBlockNumber as numblocks.  Note that restricting the range
 * to scan cannot be done when requesting syncscan.
 *
 * When "anyvisible" mode is requested, all tuples visible to any transaction
 * are indexed and counted as live, including those inserted or deleted by
 * transactions that are still in progress.
 */
static double
IndexBuildHeapRangeScan(Relation heapRelation,
						Relation indexRelation,
						IndexInfo *indexInfo,
						bool allow_sync,
						bool anyvisible,
						BlockNumber start_blockno,
						BlockNumber numblocks,
						IndexBuildCallback callback,
						void *callback_state,
						TableScanDesc sscan)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	bool		is_system_catalog;
	bool		checking_uniqueness;
	HeapTuple	heapTuple;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	double		reltuples;
	ExprState  *predicate;
	TupleTableSlot *slot;
	EState	   *estate;
	ExprContext *econtext;
	Snapshot	snapshot;
	bool		need_unregister_snapshot = false;
	TransactionId OldestXmin;
	BlockNumber root_blkno = InvalidBlockNumber;
	OffsetNumber root_offsets[MaxHeapTuplesPerPage];

	/*
	 * sanity checks
	 */
	Assert(OidIsValid(indexRelation->rd_rel->relam));

	/* Remember if it's a system catalog */
	is_system_catalog = IsSystemRelation(heapRelation);

	/* See whether we're verifying uniqueness/exclusion properties */
	checking_uniqueness = (indexInfo->ii_Unique ||
						   indexInfo->ii_ExclusionOps != NULL);

	/*
	 * "Any visible" mode is not compatible with uniqueness checks; make sure
	 * only one of those is requested.
	 */
	Assert(!(anyvisible && checking_uniqueness));

	/*
	 * Need an EState for evaluation of index expressions and partial-index
	 * predicates.  Also a slot to hold the current tuple.
	 */
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation),
									&TTSOpsHeapTuple);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/* Set up execution state for predicate, if any. */
	predicate = ExecPrepareQual(indexInfo->ii_Predicate, estate);

	/*
	 * Prepare for scan of the base relation.  In a normal index build, we use
	 * SnapshotAny because we must retrieve all tuples and do our own time
	 * qual checks (because we have to index RECENTLY_DEAD tuples). In a
	 * concurrent build, or during bootstrap, we take a regular MVCC snapshot
	 * and index whatever's live according to that.
	 */
	OldestXmin = InvalidTransactionId;

	/* okay to ignore lazy VACUUMs here */
	if (!IsBootstrapProcessingMode() && !indexInfo->ii_Concurrent)
		OldestXmin = GetOldestXmin(heapRelation, PROCARRAY_FLAGS_VACUUM);

	if (!scan)
	{
		/*
		 * Serial index build.
		 *
		 * Must begin our own heap scan in this case.  We may also need to
		 * register a snapshot whose lifetime is under our direct control.
		 */
		if (!TransactionIdIsValid(OldestXmin))
		{
			snapshot = RegisterSnapshot(GetTransactionSnapshot());
			need_unregister_snapshot = true;
		}
		else
			snapshot = SnapshotAny;

		sscan = table_beginscan_strat(heapRelation,	/* relation */
									  snapshot,	/* snapshot */
									  0,	/* number of keys */
									  NULL,	/* scan key */
									  true,	/* buffer access strategy OK */
									  allow_sync);	/* syncscan OK? */
		scan = (HeapScanDesc) sscan;
	}
	else
	{
		/*
		 * Parallel index build.
		 *
		 * Parallel case never registers/unregisters own snapshot.  Snapshot
		 * is taken from parallel heap scan, and is SnapshotAny or an MVCC
		 * snapshot, based on same criteria as serial case.
		 */
		Assert(!IsBootstrapProcessingMode());
		Assert(allow_sync);
		snapshot = scan->rs_scan.rs_snapshot;
	}

	/*
	 * Must call GetOldestXmin() with SnapshotAny.  Should never call
	 * GetOldestXmin() with MVCC snapshot. (It's especially worth checking
	 * this for parallel builds, since ambuild routines that support parallel
	 * builds must work these details out for themselves.)
	 */
	Assert(snapshot == SnapshotAny || IsMVCCSnapshot(snapshot));
	Assert(snapshot == SnapshotAny ? TransactionIdIsValid(OldestXmin) :
		   !TransactionIdIsValid(OldestXmin));
	Assert(snapshot == SnapshotAny || !anyvisible);

	/* set our scan endpoints */
	if (!allow_sync)
		table_setscanlimits(sscan, start_blockno, numblocks);
	else
	{
		/* syncscan can only be requested on whole relation */
		Assert(start_blockno == 0);
		Assert(numblocks == InvalidBlockNumber);
	}

	reltuples = 0;

	/*
	 * Scan all tuples in the base relation.
	 */
	while ((heapTuple = heap_scan_getnext(sscan, ForwardScanDirection)) != NULL)
	{
		bool		tupleIsAlive;

		CHECK_FOR_INTERRUPTS();

		/*
		 * When dealing with a HOT-chain of updated tuples, we want to index
		 * the values of the live tuple (if any), but index it under the TID
		 * of the chain's root tuple.  This approach is necessary to preserve
		 * the HOT-chain structure in the heap. So we need to be able to find
		 * the root item offset for every tuple that's in a HOT-chain.  When
		 * first reaching a new page of the relation, call
		 * heap_get_root_tuples() to build a map of root item offsets on the
		 * page.
		 *
		 * It might look unsafe to use this information across buffer
		 * lock/unlock.  However, we hold ShareLock on the table so no
		 * ordinary insert/update/delete should occur; and we hold pin on the
		 * buffer continuously while visiting the page, so no pruning
		 * operation can occur either.
		 *
		 * Also, although our opinions about tuple liveness could change while
		 * we scan the page (due to concurrent transaction commits/aborts),
		 * the chain root locations won't, so this info doesn't need to be
		 * rebuilt after waiting for another transaction.
		 *
		 * Note the implied assumption that there is no more than one live
		 * tuple per HOT-chain --- else we could create more than one index
		 * entry pointing to the same root tuple.
		 */
		if (scan->rs_cblock != root_blkno)
		{
			Page		page = BufferGetPage(scan->rs_cbuf);

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
			heap_get_root_tuples(page, root_offsets);
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			root_blkno = scan->rs_cblock;
		}

		if (snapshot == SnapshotAny)
		{
			/* do our own time qual check */
			bool		indexIt;
			TransactionId xwait;

	recheck:

			/*
			 * We could possibly get away with not locking the buffer here,
			 * since caller should hold ShareLock on the relation, but let's
			 * be conservative about it.  (This remark is still correct even
			 * with HOT-pruning: our pin on the buffer prevents pruning.)
			 */
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

			/*
			 * The criteria for counting a tuple as live in this block need to
			 * match what analyze.c's acquire_sample_rows() does, otherwise
			 * CREATE INDEX and ANALYZE may produce wildly different reltuples
			 * values, e.g. when there are many recently-dead tuples.
			 */
			switch (HeapTupleSatisfiesVacuum(heapTuple, OldestXmin, scan->rs_cbuf))
			{
				case HEAPTUPLE_DEAD:
					/* Definitely dead, we can ignore it */
					indexIt = false;
					tupleIsAlive = false;
					break;
				case HEAPTUPLE_LIVE:
					/* Normal case, index and unique-check it */
					indexIt = true;
					tupleIsAlive = true;
					/* Count it as live, too */
					reltuples += 1;
					break;
				case HEAPTUPLE_RECENTLY_DEAD:

					/*
					 * If tuple is recently deleted then we must index it
					 * anyway to preserve MVCC semantics.  (Pre-existing
					 * transactions could try to use the index after we finish
					 * building it, and may need to see such tuples.)
					 *
					 * However, if it was HOT-updated then we must only index
					 * the live tuple at the end of the HOT-chain.  Since this
					 * breaks semantics for pre-existing snapshots, mark the
					 * index as unusable for them.
					 *
					 * We don't count recently-dead tuples in reltuples, even
					 * if we index them; see acquire_sample_rows().
					 */
					if (HeapTupleIsHotUpdated(heapTuple))
					{
						indexIt = false;
						/* mark the index as unsafe for old snapshots */
						indexInfo->ii_BrokenHotChain = true;
					}
					else
						indexIt = true;
					/* In any case, exclude the tuple from unique-checking */
					tupleIsAlive = false;
					break;
				case HEAPTUPLE_INSERT_IN_PROGRESS:

					/*
					 * In "anyvisible" mode, this tuple is visible and we
					 * don't need any further checks.
					 */
					if (anyvisible)
					{
						indexIt = true;
						tupleIsAlive = true;
						reltuples += 1;
						break;
					}

					/*
					 * Since caller should hold ShareLock or better, normally
					 * the only way to see this is if it was inserted earlier
					 * in our own transaction.  However, it can happen in
					 * system catalogs, since we tend to release write lock
					 * before commit there.  Give a warning if neither case
					 * applies.
					 */
					xwait = HeapTupleHeaderGetXmin(heapTuple->t_data);
					if (!TransactionIdIsCurrentTransactionId(xwait))
					{
						if (!is_system_catalog)
							elog(WARNING, "concurrent insert in progress within table \"%s\"",
								 RelationGetRelationName(heapRelation));

						/*
						 * If we are performing uniqueness checks, indexing
						 * such a tuple could lead to a bogus uniqueness
						 * failure.  In that case we wait for the inserting
						 * transaction to finish and check again.
						 */
						if (checking_uniqueness)
						{
							/*
							 * Must drop the lock on the buffer before we wait
							 */
							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait, heapRelation,
											  &heapTuple->t_self,
											  XLTW_InsertIndexUnique);
							CHECK_FOR_INTERRUPTS();
							goto recheck;
						}
					}
					else
					{
						/*
						 * For consistency with acquire_sample_rows(), count
						 * HEAPTUPLE_INSERT_IN_PROGRESS tuples as live only
						 * when inserted by our own transaction.
						 */
						reltuples += 1;
					}

					/*
					 * We must index such tuples, since if the index build
					 * commits then they're good.
					 */
					indexIt = true;
					tupleIsAlive = true;
					break;
				case HEAPTUPLE_DELETE_IN_PROGRESS:

					/*
					 * As with INSERT_IN_PROGRESS case, this is unexpected
					 * unless it's our own deletion or a system catalog; but
					 * in anyvisible mode, this tuple is visible.
					 */
					if (anyvisible)
					{
						indexIt = true;
						tupleIsAlive = false;
						reltuples += 1;
						break;
					}

					xwait = HeapTupleHeaderGetUpdateXid(heapTuple->t_data);
					if (!TransactionIdIsCurrentTransactionId(xwait))
					{
						if (!is_system_catalog)
							elog(WARNING, "concurrent delete in progress within table \"%s\"",
								 RelationGetRelationName(heapRelation));

						/*
						 * If we are performing uniqueness checks, assuming
						 * the tuple is dead could lead to missing a
						 * uniqueness violation.  In that case we wait for the
						 * deleting transaction to finish and check again.
						 *
						 * Also, if it's a HOT-updated tuple, we should not
						 * index it but rather the live tuple at the end of
						 * the HOT-chain.  However, the deleting transaction
						 * could abort, possibly leaving this tuple as live
						 * after all, in which case it has to be indexed. The
						 * only way to know what to do is to wait for the
						 * deleting transaction to finish and check again.
						 */
						if (checking_uniqueness ||
							HeapTupleIsHotUpdated(heapTuple))
						{
							/*
							 * Must drop the lock on the buffer before we wait
							 */
							LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
							XactLockTableWait(xwait, heapRelation,
											  &heapTuple->t_self,
											  XLTW_InsertIndexUnique);
							CHECK_FOR_INTERRUPTS();
							goto recheck;
						}

						/*
						 * Otherwise index it but don't check for uniqueness,
						 * the same as a RECENTLY_DEAD tuple.
						 */
						indexIt = true;

						/*
						 * Count HEAPTUPLE_DELETE_IN_PROGRESS tuples as live,
						 * if they were not deleted by the current
						 * transaction.  That's what acquire_sample_rows()
						 * does, and we want the behavior to be consistent.
						 */
						reltuples += 1;
					}
					else if (HeapTupleIsHotUpdated(heapTuple))
					{
						/*
						 * It's a HOT-updated tuple deleted by our own xact.
						 * We can assume the deletion will commit (else the
						 * index contents don't matter), so treat the same as
						 * RECENTLY_DEAD HOT-updated tuples.
						 */
						indexIt = false;
						/* mark the index as unsafe for old snapshots */
						indexInfo->ii_BrokenHotChain = true;
					}
					else
					{
						/*
						 * It's a regular tuple deleted by our own xact. Index
						 * it, but don't check for uniqueness nor count in
						 * reltuples, the same as a RECENTLY_DEAD tuple.
						 */
						indexIt = true;
					}
					/* In any case, exclude the tuple from unique-checking */
					tupleIsAlive = false;
					break;
				default:
					elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
					indexIt = tupleIsAlive = false; /* keep compiler quiet */
					break;
			}

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			if (!indexIt)
				continue;
		}
		else
		{
			/* heap_getnext did the time qual check */
			tupleIsAlive = true;
			reltuples += 1;
		}

		MemoryContextReset(econtext->ecxt_per_tuple_memory);

		/* Set up for predicate or expression evaluation */
		ExecStoreHeapTuple(heapTuple, slot, false);

		/*
		 * In a partial index, discard tuples that don't satisfy the
		 * predicate.
		 */
		if (predicate != NULL)
		{
			if (!ExecQual(predicate, econtext))
				continue;
		}

		/*
		 * For the current heap tuple, extract all the attributes we use in
		 * this index, and note which are null.  This also performs evaluation
		 * of any expressions needed.
		 */
		FormIndexDatum(indexInfo,
					   slot,
					   estate,
					   values,
					   isnull);

		/*
		 * You'd think we should go ahead and build the index tuple here, but
		 * some index AMs want to do further processing on the data first.  So
		 * pass the values[] and isnull[] arrays, instead.
		 */

		if (HeapTupleIsHeapOnly(heapTuple))
		{
			/*
			 * For a heap-only tuple, pretend its TID is that of the root. See
			 * src/backend/access/heap/README.HOT for discussion.
			 */
			HeapTupleData rootTuple;
			OffsetNumber offnum;

			rootTuple = *heapTuple;
			offnum = ItemPointerGetOffsetNumber(&heapTuple->t_self);

			if (!OffsetNumberIsValid(root_offsets[offnum - 1]))
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg_internal("failed to find parent tuple for heap-only tuple at (%u,%u) in table \"%s\"",
										 ItemPointerGetBlockNumber(&heapTuple->t_self),
										 offnum,
										 RelationGetRelationName(heapRelation))));

			ItemPointerSetOffsetNumber(&rootTuple.t_self,
									   root_offsets[offnum - 1]);

			/* Call the AM's callback routine to process the tuple */
			callback(indexRelation, &rootTuple, values, isnull, tupleIsAlive,
					 callback_state);
		}
		else
		{
			/* Call the AM's callback routine to process the tuple */
			callback(indexRelation, heapTuple, values, isnull, tupleIsAlive,
					 callback_state);
		}
	}

	table_endscan(sscan);

	/* we can now forget our snapshot, if set and registered by us */
	if (need_unregister_snapshot)
		UnregisterSnapshot(snapshot);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	/* These may have been pointing to the now-gone estate */
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NULL;

	return reltuples;
}

/*
 * validate_index_heapscan - second table scan for concurrent index build
 *
 * This has much code in common with IndexBuildHeapScan, but it's enough
 * different that it seems cleaner to have two routines not one.
 */
static void
validate_index_heapscan(Relation heapRelation,
						Relation indexRelation,
						IndexInfo *indexInfo,
						Snapshot snapshot,
						ValidateIndexState *state)
{
	TableScanDesc sscan;
	HeapScanDesc scan;
	HeapTuple	heapTuple;
	Datum		values[INDEX_MAX_KEYS];
	bool		isnull[INDEX_MAX_KEYS];
	ExprState  *predicate;
	TupleTableSlot *slot;
	EState	   *estate;
	ExprContext *econtext;
	BlockNumber root_blkno = InvalidBlockNumber;
	OffsetNumber root_offsets[MaxHeapTuplesPerPage];
	bool		in_index[MaxHeapTuplesPerPage];

	/* state variables for the merge */
	ItemPointer indexcursor = NULL;
	ItemPointerData decoded;
	bool		tuplesort_empty = false;

	/*
	 * sanity checks
	 */
	Assert(OidIsValid(indexRelation->rd_rel->relam));

	/*
	 * Need an EState for evaluation of index expressions and partial-index
	 * predicates.  Also a slot to hold the current tuple.
	 */
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(heapRelation),
									&TTSOpsHeapTuple);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/* Set up execution state for predicate, if any. */
	predicate = ExecPrepareQual(indexInfo->ii_Predicate, estate);

	/*
	 * Prepare for scan of the base relation.  We need just those tuples
	 * satisfying the passed-in reference snapshot.  We must disable syncscan
	 * here, because it's critical that we read from block zero forward to
	 * match the sorted TIDs.
	 */
	sscan = table_beginscan_strat(heapRelation,	/* relation */
								   snapshot,	/* snapshot */
								   0,	/* number of keys */
								   NULL,	/* scan key */
								   true,	/* buffer access strategy OK */
								   false);	/* syncscan not OK */
	scan = (HeapScanDesc) sscan;

	/*
	 * Scan all tuples matching the snapshot.
	 *
	 * PBORKED: Slotify
	 */
	while ((heapTuple = heap_scan_getnext(sscan, ForwardScanDirection)) != NULL)
	{
		ItemPointer heapcursor = &heapTuple->t_self;
		ItemPointerData rootTuple;
		OffsetNumber root_offnum;

		CHECK_FOR_INTERRUPTS();

		state->htups += 1;

		/*
		 * As commented in IndexBuildHeapScan, we should index heap-only
		 * tuples under the TIDs of their root tuples; so when we advance onto
		 * a new heap page, build a map of root item offsets on the page.
		 *
		 * This complicates merging against the tuplesort output: we will
		 * visit the live tuples in order by their offsets, but the root
		 * offsets that we need to compare against the index contents might be
		 * ordered differently.  So we might have to "look back" within the
		 * tuplesort output, but only within the current page.  We handle that
		 * by keeping a bool array in_index[] showing all the
		 * already-passed-over tuplesort output TIDs of the current page. We
		 * clear that array here, when advancing onto a new heap page.
		 */
		if (scan->rs_cblock != root_blkno)
		{
			Page		page = BufferGetPage(scan->rs_cbuf);

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
			heap_get_root_tuples(page, root_offsets);
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			memset(in_index, 0, sizeof(in_index));

			root_blkno = scan->rs_cblock;
		}

		/* Convert actual tuple TID to root TID */
		rootTuple = *heapcursor;
		root_offnum = ItemPointerGetOffsetNumber(heapcursor);

		if (HeapTupleIsHeapOnly(heapTuple))
		{
			root_offnum = root_offsets[root_offnum - 1];
			if (!OffsetNumberIsValid(root_offnum))
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg_internal("failed to find parent tuple for heap-only tuple at (%u,%u) in table \"%s\"",
										 ItemPointerGetBlockNumber(heapcursor),
										 ItemPointerGetOffsetNumber(heapcursor),
										 RelationGetRelationName(heapRelation))));
			ItemPointerSetOffsetNumber(&rootTuple, root_offnum);
		}

		/*
		 * "merge" by skipping through the index tuples until we find or pass
		 * the current root tuple.
		 */
		while (!tuplesort_empty &&
			   (!indexcursor ||
				ItemPointerCompare(indexcursor, &rootTuple) < 0))
		{
			Datum		ts_val;
			bool		ts_isnull;

			if (indexcursor)
			{
				/*
				 * Remember index items seen earlier on the current heap page
				 */
				if (ItemPointerGetBlockNumber(indexcursor) == root_blkno)
					in_index[ItemPointerGetOffsetNumber(indexcursor) - 1] = true;
			}

			tuplesort_empty = !tuplesort_getdatum(state->tuplesort, true,
												  &ts_val, &ts_isnull, NULL);
			Assert(tuplesort_empty || !ts_isnull);
			if (!tuplesort_empty)
			{
				itemptr_decode(&decoded, DatumGetInt64(ts_val));
				indexcursor = &decoded;

				/* If int8 is pass-by-ref, free (encoded) TID Datum memory */
#ifndef USE_FLOAT8_BYVAL
				pfree(DatumGetPointer(ts_val));
#endif
			}
			else
			{
				/* Be tidy */
				indexcursor = NULL;
			}
		}

		/*
		 * If the tuplesort has overshot *and* we didn't see a match earlier,
		 * then this tuple is missing from the index, so insert it.
		 */
		if ((tuplesort_empty ||
			 ItemPointerCompare(indexcursor, &rootTuple) > 0) &&
			!in_index[root_offnum - 1])
		{
			MemoryContextReset(econtext->ecxt_per_tuple_memory);

			/* Set up for predicate or expression evaluation */
			ExecStoreHeapTuple(heapTuple, slot, false);

			/*
			 * In a partial index, discard tuples that don't satisfy the
			 * predicate.
			 */
			if (predicate != NULL)
			{
				if (!ExecQual(predicate, econtext))
					continue;
			}

			/*
			 * For the current heap tuple, extract all the attributes we use
			 * in this index, and note which are null.  This also performs
			 * evaluation of any expressions needed.
			 */
			FormIndexDatum(indexInfo,
						   slot,
						   estate,
						   values,
						   isnull);

			/*
			 * You'd think we should go ahead and build the index tuple here,
			 * but some index AMs want to do further processing on the data
			 * first. So pass the values[] and isnull[] arrays, instead.
			 */

			/*
			 * If the tuple is already committed dead, you might think we
			 * could suppress uniqueness checking, but this is no longer true
			 * in the presence of HOT, because the insert is actually a proxy
			 * for a uniqueness check on the whole HOT-chain.  That is, the
			 * tuple we have here could be dead because it was already
			 * HOT-updated, and if so the updating transaction will not have
			 * thought it should insert index entries.  The index AM will
			 * check the whole HOT-chain and correctly detect a conflict if
			 * there is one.
			 */

			index_insert(indexRelation,
						 values,
						 isnull,
						 &rootTuple,
						 heapRelation,
						 indexInfo->ii_Unique ?
						 UNIQUE_CHECK_YES : UNIQUE_CHECK_NO,
						 indexInfo);

			state->tups_inserted += 1;
		}
	}

	table_endscan(sscan);

	ExecDropSingleTupleTableSlot(slot);

	FreeExecutorState(estate);

	/* These may have been pointing to the now-gone estate */
	indexInfo->ii_ExpressionsState = NIL;
	indexInfo->ii_PredicateState = NULL;
}

static bool
heapam_scan_bitmap_pagescan(TableScanDesc sscan,
							TBMIterateResult *tbmres)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	BlockNumber page = tbmres->blockno;
	Buffer		buffer;
	Snapshot	snapshot;
	int			ntup;

	scan->rs_cindex = 0;
	scan->rs_ntuples = 0;

	/*
	 * Ignore any claimed entries past what we think is the end of the
	 * relation.  (This is probably not necessary given that we got at
	 * least AccessShareLock on the table before performing any of the
	 * indexscans, but let's be safe.)
	 */
	if (page >= scan->rs_scan.rs_nblocks)
		return false;

	scan->rs_cbuf = ReleaseAndReadBuffer(scan->rs_cbuf,
												 scan->rs_scan.rs_rd,
												 page);
	scan->rs_cblock = page;
	buffer = scan->rs_cbuf;
	snapshot = scan->rs_scan.rs_snapshot;

	ntup = 0;

	/*
	 * Prune and repair fragmentation for the whole page, if possible.
	 */
	heap_page_prune_opt(scan->rs_scan.rs_rd, buffer);

	/*
	 * We must hold share lock on the buffer content while examining tuple
	 * visibility.  Afterwards, however, the tuples we have found to be
	 * visible are guaranteed good as long as we hold the buffer pin.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	/*
	 * We need two separate strategies for lossy and non-lossy cases.
	 */
	if (tbmres->ntuples >= 0)
	{
		/*
		 * Bitmap is non-lossy, so we just look through the offsets listed in
		 * tbmres; but we have to follow any HOT chain starting at each such
		 * offset.
		 */
		int			curslot;

		for (curslot = 0; curslot < tbmres->ntuples; curslot++)
		{
			OffsetNumber offnum = tbmres->offsets[curslot];
			ItemPointerData tid;
			HeapTupleData heapTuple;

			ItemPointerSet(&tid, page, offnum);
			if (heap_hot_search_buffer(&tid, sscan->rs_rd, buffer, snapshot,
									   &heapTuple, NULL, true))
				scan->rs_vistuples[ntup++] = ItemPointerGetOffsetNumber(&tid);
		}
	}
	else
	{
		/*
		 * Bitmap is lossy, so we must examine each item pointer on the page.
		 * But we can ignore HOT chains, since we'll check each tuple anyway.
		 */
		Page		dp = (Page) BufferGetPage(buffer);
		OffsetNumber maxoff = PageGetMaxOffsetNumber(dp);
		OffsetNumber offnum;

		for (offnum = FirstOffsetNumber; offnum <= maxoff; offnum = OffsetNumberNext(offnum))
		{
			ItemId		lp;
			HeapTupleData loctup;
			bool		valid;

			lp = PageGetItemId(dp, offnum);
			if (!ItemIdIsNormal(lp))
				continue;
			loctup.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
			loctup.t_len = ItemIdGetLength(lp);
			loctup.t_tableOid = scan->rs_scan.rs_rd->rd_id;
			ItemPointerSet(&loctup.t_self, page, offnum);
			valid = HeapTupleSatisfies(&loctup, snapshot, buffer);
			if (valid)
			{
				scan->rs_vistuples[ntup++] = offnum;
				PredicateLockTid(scan->rs_scan.rs_rd, &loctup.t_self, snapshot,
								 HeapTupleHeaderGetXmin(loctup.t_data));
			}
			CheckForSerializableConflictOut(valid, scan->rs_scan.rs_rd, (void *) &loctup,
											buffer, snapshot);
		}
	}

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	Assert(ntup <= MaxHeapTuplesPerPage);
	scan->rs_ntuples = ntup;

	return ntup > 0;
}

static bool
heapam_scan_bitmap_pagescan_next(TableScanDesc sscan, TupleTableSlot *slot)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	OffsetNumber targoffset;
	Page		dp;
	ItemId		lp;

	if (scan->rs_cindex < 0 || scan->rs_cindex >= scan->rs_ntuples)
		return false;

	targoffset = scan->rs_vistuples[scan->rs_cindex];
	dp = (Page) BufferGetPage(scan->rs_cbuf);
	lp = PageGetItemId(dp, targoffset);
	Assert(ItemIdIsNormal(lp));

	scan->rs_ctup.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	scan->rs_ctup.t_len = ItemIdGetLength(lp);
	scan->rs_ctup.t_tableOid = scan->rs_scan.rs_rd->rd_id;
	ItemPointerSet(&scan->rs_ctup.t_self, scan->rs_cblock, targoffset);

	pgstat_count_heap_fetch(scan->rs_scan.rs_rd);

	/*
	 * Set up the result slot to point to this tuple.  Note that the
	 * slot acquires a pin on the buffer.
	 */
	ExecStoreBufferHeapTuple(&scan->rs_ctup,
							 slot,
							 scan->rs_cbuf);

	scan->rs_cindex++;

	return true;
}

/*
 * Check visibility of the tuple.
 */
static bool
SampleHeapTupleVisible(HeapScanDesc scan, Buffer buffer,
				   HeapTuple tuple,
				   OffsetNumber tupoffset)
{
	if (scan->rs_scan.rs_pageatatime)
	{
		/*
		 * In pageatatime mode, heapgetpage() already did visibility checks,
		 * so just look at the info it left in rs_vistuples[].
		 *
		 * We use a binary search over the known-sorted array.  Note: we could
		 * save some effort if we insisted that NextSampleTuple select tuples
		 * in increasing order, but it's not clear that there would be enough
		 * gain to justify the restriction.
		 */
		int			start = 0,
					end = scan->rs_ntuples - 1;

		while (start <= end)
		{
			int			mid = (start + end) / 2;
			OffsetNumber curoffset = scan->rs_vistuples[mid];

			if (tupoffset == curoffset)
				return true;
			else if (tupoffset < curoffset)
				end = mid - 1;
			else
				start = mid + 1;
		}

		return false;
	}
	else
	{
		/* Otherwise, we have to check the tuple individually. */
		return HeapTupleSatisfies(tuple, scan->rs_scan.rs_snapshot, buffer);
	}
}

static bool
heapam_scan_sample_next_block(TableScanDesc sscan, struct SampleScanState *scanstate)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	TsmRoutine *tsm = scanstate->tsmroutine;
	BlockNumber blockno;

	/* return false immediately if relation is empty */
	if (scan->rs_scan.rs_nblocks == 0)
		return false;

	if (tsm->NextSampleBlock)
	{
		blockno = tsm->NextSampleBlock(scanstate, scan->rs_scan.rs_nblocks);
		scan->rs_cblock = blockno;
	}
	else
	{
		/* scanning table sequentially */

		if (scan->rs_cblock == InvalidBlockNumber)
		{
			Assert(!scan->rs_inited);
			blockno = scan->rs_scan.rs_startblock;
		}
		else
		{
			Assert(scan->rs_inited);

			blockno = scan->rs_cblock + 1;

			if (blockno >= scan->rs_scan.rs_nblocks)
			{
				/* wrap to begining of rel, might not have started at 0 */
				blockno = 0;
			}

			/*
			 * Report our new scan position for synchronization purposes.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_scan.rs_syncscan)
				ss_report_location(scan->rs_scan.rs_rd, blockno);

			if (blockno == scan->rs_scan.rs_startblock)
			{
				blockno = InvalidBlockNumber;
			}
		}
	}

	if (!BlockNumberIsValid(blockno))
	{
		if (BufferIsValid(scan->rs_cbuf))
			ReleaseBuffer(scan->rs_cbuf);
		scan->rs_cbuf = InvalidBuffer;
		scan->rs_cblock = InvalidBlockNumber;
		scan->rs_inited = false;

		return false;
	}

	heapgetpage(sscan, blockno);
	scan->rs_inited = true;

	return true;
}

static bool
heapam_scan_sample_next_tuple(TableScanDesc sscan, struct SampleScanState *scanstate, TupleTableSlot *slot)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	TsmRoutine *tsm = scanstate->tsmroutine;
	BlockNumber blockno = scan->rs_cblock;
	bool		pagemode = scan->rs_scan.rs_pageatatime;

	Page		page;
	bool		all_visible;
	OffsetNumber maxoffset;

	ExecClearTuple(slot);

	/*
	 * When not using pagemode, we must lock the buffer during tuple
	 * visibility checks.
	 */
	if (!pagemode)
		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

	page = (Page) BufferGetPage(scan->rs_cbuf);
	all_visible = PageIsAllVisible(page) && !scan->rs_scan.rs_snapshot->takenDuringRecovery;
	maxoffset = PageGetMaxOffsetNumber(page);

	for (;;)
	{
		OffsetNumber tupoffset;

		CHECK_FOR_INTERRUPTS();

		/* Ask the tablesample method which tuples to check on this page. */
		tupoffset = tsm->NextSampleTuple(scanstate,
										 blockno,
										 maxoffset);

		if (OffsetNumberIsValid(tupoffset))
		{
			ItemId		itemid;
			bool		visible;
			HeapTuple	tuple = &(scan->rs_ctup);

			/* Skip invalid tuple pointers. */
			itemid = PageGetItemId(page, tupoffset);
			if (!ItemIdIsNormal(itemid))
				continue;

			tuple->t_data = (HeapTupleHeader) PageGetItem(page, itemid);
			tuple->t_len = ItemIdGetLength(itemid);
			ItemPointerSet(&(tuple->t_self), blockno, tupoffset);


			if (all_visible)
				visible = true;
			else
				visible = SampleHeapTupleVisible(scan, scan->rs_cbuf, tuple, tupoffset);

			/* in pagemode, heapgetpage did this for us */
			if (!pagemode)
				CheckForSerializableConflictOut(visible, scan->rs_scan.rs_rd, (void *) tuple,
												scan->rs_cbuf, scan->rs_scan.rs_snapshot);

			/* Try next tuple from same page. */
			if (!visible)
				continue;

			ExecStoreBufferHeapTuple(tuple, slot, scan->rs_cbuf);

			/* Found visible tuple, return it. */
			if (!pagemode)
				LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			/* Count successfully-fetched tuples as heap fetches */
			pgstat_count_heap_getnext(scan->rs_scan.rs_rd);

			return true;
		}
		else
		{
			/*
			 * If we get here, it means we've exhausted the items on this page and
			 * it's time to move to the next.
			 */
			if (!pagemode)
				LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

			break;
		}
	}

	return false;
}

static void
heapam_scan_analyze_next_block(TableScanDesc sscan, BlockNumber blockno, BufferAccessStrategy bstrategy)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;

	/*
	 * We must maintain a pin on the target page's buffer to ensure that
	 * the maxoffset value stays good (else concurrent VACUUM might delete
	 * tuples out from under us).  Hence, pin the page until we are done
	 * looking at it.  We also choose to hold sharelock on the buffer
	 * throughout --- we could release and re-acquire sharelock for each
	 * tuple, but since we aren't doing much work per tuple, the extra
	 * lock traffic is probably better avoided.
	 */
	scan->rs_cblock = blockno;
	scan->rs_cbuf = ReadBufferExtended(scan->rs_scan.rs_rd, MAIN_FORKNUM, blockno,
									   RBM_NORMAL, bstrategy);
	scan->rs_cindex = FirstOffsetNumber;
	LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
}

static bool
heapam_scan_analyze_next_tuple(TableScanDesc sscan, TransactionId OldestXmin, double *liverows, double *deadrows, TupleTableSlot *slot)
{
	HeapScanDesc scan = (HeapScanDesc) sscan;
	Page		targpage;
	OffsetNumber maxoffset;
	BufferHeapTupleTableSlot *hslot;

	Assert(TTS_IS_BUFFERTUPLE(slot));

	hslot = (BufferHeapTupleTableSlot *) slot;
	targpage = BufferGetPage(scan->rs_cbuf);
	maxoffset = PageGetMaxOffsetNumber(targpage);

	/* Inner loop over all tuples on the selected page */
	for (; scan->rs_cindex <= maxoffset; scan->rs_cindex++)
	{
		ItemId		itemid;
		HeapTuple	targtuple = &hslot->base.tupdata;
		bool		sample_it = false;

		itemid = PageGetItemId(targpage, scan->rs_cindex);

		/*
		 * We ignore unused and redirect line pointers.  DEAD line
		 * pointers should be counted as dead, because we need vacuum to
		 * run to get rid of them.  Note that this rule agrees with the
		 * way that heap_page_prune() counts things.
		 */
		if (!ItemIdIsNormal(itemid))
		{
			if (ItemIdIsDead(itemid))
				*deadrows += 1;
			continue;
		}

		ItemPointerSet(&targtuple->t_self, scan->rs_cblock, scan->rs_cindex);

		targtuple->t_tableOid = RelationGetRelid(scan->rs_scan.rs_rd);
		targtuple->t_data = (HeapTupleHeader) PageGetItem(targpage, itemid);
		targtuple->t_len = ItemIdGetLength(itemid);

		switch (HeapTupleSatisfiesVacuum(targtuple, OldestXmin, scan->rs_cbuf))
		{
			case HEAPTUPLE_LIVE:
				sample_it = true;
				*liverows += 1;
				break;

			case HEAPTUPLE_DEAD:
			case HEAPTUPLE_RECENTLY_DEAD:
				/* Count dead and recently-dead rows */
				*deadrows += 1;
				break;

			case HEAPTUPLE_INSERT_IN_PROGRESS:

				/*
				 * Insert-in-progress rows are not counted.  We assume
				 * that when the inserting transaction commits or aborts,
				 * it will send a stats message to increment the proper
				 * count.  This works right only if that transaction ends
				 * after we finish analyzing the table; if things happen
				 * in the other order, its stats update will be
				 * overwritten by ours.  However, the error will be large
				 * only if the other transaction runs long enough to
				 * insert many tuples, so assuming it will finish after us
				 * is the safer option.
				 *
				 * A special case is that the inserting transaction might
				 * be our own.  In this case we should count and sample
				 * the row, to accommodate users who load a table and
				 * analyze it in one transaction.  (pgstat_report_analyze
				 * has to adjust the numbers we send to the stats
				 * collector to make this come out right.)
				 */
				if (TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetXmin(targtuple->t_data)))
				{
					sample_it = true;
					*liverows += 1;
				}
				break;

			case HEAPTUPLE_DELETE_IN_PROGRESS:

				/*
				 * We count and sample delete-in-progress rows the same as
				 * live ones, so that the stats counters come out right if
				 * the deleting transaction commits after us, per the same
				 * reasoning given above.
				 *
				 * If the delete was done by our own transaction, however,
				 * we must count the row as dead to make
				 * pgstat_report_analyze's stats adjustments come out
				 * right.  (Note: this works out properly when the row was
				 * both inserted and deleted in our xact.)
				 *
				 * The net effect of these choices is that we act as
				 * though an IN_PROGRESS transaction hasn't happened yet,
				 * except if it is our own transaction, which we assume
				 * has happened.
				 *
				 * This approach ensures that we behave sanely if we see
				 * both the pre-image and post-image rows for a row being
				 * updated by a concurrent transaction: we will sample the
				 * pre-image but not the post-image.  We also get sane
				 * results if the concurrent transaction never commits.
				 */
				if (TransactionIdIsCurrentTransactionId(HeapTupleHeaderGetUpdateXid(targtuple->t_data)))
					deadrows += 1;
				else
				{
					sample_it = true;
					liverows += 1;
				}
				break;

			default:
				elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
				break;
		}

		if (sample_it)
		{
			ExecStoreBufferHeapTuple(targtuple, slot, scan->rs_cbuf);
			scan->rs_cindex++;

			/* note that we leave the buffer locked here! */
			return true;
		}
	}

	/* Now release the lock and pin on the page */
	UnlockReleaseBuffer(scan->rs_cbuf);
	scan->rs_cbuf = InvalidBuffer;

	return false;
}

/*
 * Reconstruct and rewrite the given tuple
 *
 * We cannot simply copy the tuple as-is, for several reasons:
 *
 * 1. We'd like to squeeze out the values of any dropped columns, both
 * to save space and to ensure we have no corner-case failures. (It's
 * possible for example that the new table hasn't got a TOAST table
 * and so is unable to store any large values of dropped cols.)
 *
 * 2. The tuple might not even be legal for the new table; this is
 * currently only known to happen as an after-effect of ALTER TABLE
 * SET WITHOUT OIDS.
 *
 * So, we must reconstruct the tuple from component Datums.
 */
static void
reform_and_rewrite_tuple(HeapTuple tuple,
						 Relation OldHeap, Relation NewHeap,
						 Datum *values, bool *isnull, RewriteState rwstate)
{
	TupleDesc oldTupDesc = RelationGetDescr(OldHeap);
	TupleDesc newTupDesc = RelationGetDescr(NewHeap);
	HeapTuple	copiedTuple;
	int			i;

	heap_deform_tuple(tuple, oldTupDesc, values, isnull);

	/* Be sure to null out any dropped columns */
	for (i = 0; i < newTupDesc->natts; i++)
	{
		if (TupleDescAttr(newTupDesc, i)->attisdropped)
			isnull[i] = true;
	}

	copiedTuple = heap_form_tuple(newTupDesc, values, isnull);

	/* The heap rewrite module does the rest */
	rewrite_heap_tuple(rwstate, tuple, copiedTuple);

	heap_freetuple(copiedTuple);
}

static void
heapam_relation_nontransactional_truncate(Relation rel)
{
	RelationTruncate(rel, 0);
}

static void
heap_copy_for_cluster(Relation OldHeap, Relation NewHeap, Relation OldIndex,
					 bool use_sort,
					 TransactionId OldestXmin, TransactionId FreezeXid, MultiXactId MultiXactCutoff,
					 double *num_tuples, double *tups_vacuumed, double *tups_recently_dead)
{
	RewriteState rwstate;
	IndexScanDesc indexScan;
	TableScanDesc heapScan;
	bool		use_wal;
	bool		is_system_catalog;
	Tuplesortstate *tuplesort;
	TupleDesc	oldTupDesc = RelationGetDescr(OldHeap);
	TupleDesc	newTupDesc = RelationGetDescr(NewHeap);
	TupleTableSlot *slot;
	int			natts;
	Datum	   *values;
	bool	   *isnull;
	BufferHeapTupleTableSlot *hslot;

	/* Remember if it's a system catalog */
	is_system_catalog = IsSystemRelation(OldHeap);

	/*
	 * We need to log the copied data in WAL iff WAL archiving/streaming is
	 * enabled AND it's a WAL-logged rel.
	 */
	use_wal = XLogIsNeeded() && RelationNeedsWAL(NewHeap);

	/* use_wal off requires smgr_targblock be initially invalid */
	Assert(RelationGetTargetBlock(NewHeap) == InvalidBlockNumber);

	/* Preallocate values/isnull arrays */
	natts = newTupDesc->natts;
	values = (Datum *) palloc(natts * sizeof(Datum));
	isnull = (bool *) palloc(natts * sizeof(bool));

	/* Initialize the rewrite operation */
	rwstate = begin_heap_rewrite(OldHeap, NewHeap, OldestXmin, FreezeXid,
								 MultiXactCutoff, use_wal);


	/* Set up sorting if wanted */
	if (use_sort)
		tuplesort = tuplesort_begin_cluster(oldTupDesc, OldIndex,
											maintenance_work_mem,
											NULL, false);
	else
		tuplesort = NULL;

	/*
	 * Prepare to scan the OldHeap.  To ensure we see recently-dead tuples
	 * that still need to be copied, we scan with SnapshotAny and use
	 * HeapTupleSatisfiesVacuum for the visibility test.
	 */
	if (OldIndex != NULL && !use_sort)
	{
		heapScan = NULL;
		indexScan = index_beginscan(OldHeap, OldIndex, SnapshotAny, 0, 0);
		index_rescan(indexScan, NULL, 0, NULL, 0);
	}
	else
	{
		heapScan = table_beginscan(OldHeap, SnapshotAny, 0, (ScanKey) NULL);
		indexScan = NULL;
	}

	slot = table_gimmegimmeslot(OldHeap, NULL);
	hslot = (BufferHeapTupleTableSlot *) slot;

	/*
	 * Scan through the OldHeap, either in OldIndex order or sequentially;
	 * copy each tuple into the NewHeap, or transiently to the tuplesort
	 * module.  Note that we don't bother sorting dead tuples (they won't get
	 * to the new table anyway).
	 */
	for (;;)
	{
		bool		isdead;
		TransactionId xid;

		CHECK_FOR_INTERRUPTS();

		if (indexScan != NULL)
		{
			if (!index_getnext_slot(indexScan, ForwardScanDirection, slot))
				break;

			/* Since we used no scan keys, should never need to recheck */
			if (indexScan->xs_recheck)
				elog(ERROR, "CLUSTER does not support lossy index conditions");
		}
		else
		{
			if (!table_scan_getnextslot(heapScan, ForwardScanDirection, slot))
				break;
		}

		LockBuffer(hslot->buffer, BUFFER_LOCK_SHARE);

		switch (HeapTupleSatisfiesVacuum(hslot->base.tuple, OldestXmin, hslot->buffer))
		{
			case HEAPTUPLE_DEAD:
				/* Definitely dead */
				isdead = true;
				break;
			case HEAPTUPLE_RECENTLY_DEAD:
				*tups_recently_dead += 1;
				/* fall through */
			case HEAPTUPLE_LIVE:
				/* Live or recently dead, must copy it */
				isdead = false;
				break;
			case HEAPTUPLE_INSERT_IN_PROGRESS:

				/*
				 * Since we hold exclusive lock on the relation, normally the
				 * only way to see this is if it was inserted earlier in our
				 * own transaction.  However, it can happen in system
				 * catalogs, since we tend to release write lock before commit
				 * there.  Give a warning if neither case applies; but in any
				 * case we had better copy it.
				 */
				xid = HeapTupleHeaderGetXmin(hslot->base.tuple->t_data);
				if (!is_system_catalog && !TransactionIdIsCurrentTransactionId(xid))
					elog(WARNING, "concurrent insert in progress within table \"%s\"",
						 RelationGetRelationName(OldHeap));
				/* treat as live */
				isdead = false;
				break;
			case HEAPTUPLE_DELETE_IN_PROGRESS:

				/*
				 * Similar situation to INSERT_IN_PROGRESS case.
				 */
				xid = HeapTupleHeaderGetUpdateXid(hslot->base.tuple->t_data);
				if (!is_system_catalog && !TransactionIdIsCurrentTransactionId(xid))
					elog(WARNING, "concurrent delete in progress within table \"%s\"",
						 RelationGetRelationName(OldHeap));
				/* treat as recently dead */
				*tups_recently_dead += 1;
				isdead = false;
				break;
			default:
				elog(ERROR, "unexpected HeapTupleSatisfiesVacuum result");
				isdead = false; /* keep compiler quiet */
				break;
		}

		LockBuffer(hslot->buffer, BUFFER_LOCK_UNLOCK);

		if (isdead)
		{
			*tups_vacuumed += 1;
			/* heap rewrite module still needs to see it... */
			if (rewrite_heap_dead_tuple(rwstate, ExecFetchSlotHeapTuple(slot, false, NULL)))
			{
				/* A previous recently-dead tuple is now known dead */
				*tups_vacuumed += 1;
				*tups_recently_dead -= 1;
			}
			continue;
		}

		*num_tuples += 1;
		if (tuplesort != NULL)
			tuplesort_puttupleslot(tuplesort, slot);
		else
			reform_and_rewrite_tuple(ExecFetchSlotHeapTuple(slot, false, NULL),
									 OldHeap, NewHeap,
									 values, isnull, rwstate);
	}

	if (indexScan != NULL)
		index_endscan(indexScan);
	if (heapScan != NULL)
		table_endscan(heapScan);

	ExecDropSingleTupleTableSlot(slot);

	/*
	 * In scan-and-sort mode, complete the sort, then read out all live tuples
	 * from the tuplestore and write them to the new relation.
	 */
	if (tuplesort != NULL)
	{
		tuplesort_performsort(tuplesort);

		for (;;)
		{
			HeapTuple	tuple;

			CHECK_FOR_INTERRUPTS();

			tuple = tuplesort_getheaptuple(tuplesort, true);
			if (tuple == NULL)
				break;

			reform_and_rewrite_tuple(tuple,
									 OldHeap, NewHeap,
									 values, isnull, rwstate);
		}

		tuplesort_end(tuplesort);
	}

	/* Write out any remaining tuples, and fsync if needed */
	end_heap_rewrite(rwstate);

	/* Clean up */
	pfree(values);
	pfree(isnull);
}

static void
heapam_set_new_filenode(Relation rel, char persistence,
						TransactionId *freezeXid, MultiXactId *minmulti)
{
	/*
	 * Initialize to the minimum XID that could put tuples in the table.
	 * We know that no xacts older than RecentXmin are still running, so
	 * that will do.
	 */
	*freezeXid = RecentXmin;

	/*
	 * Similarly, initialize the minimum Multixact to the first value that
	 * could possibly be stored in tuples in the table.  Running
	 * transactions could reuse values from their local cache, so we are
	 * careful to consider all currently running multis.
	 *
	 * XXX this could be refined further, but is it worth the hassle?
	 */
	*minmulti = GetOldestMultiXactId();

	RelationCreateStorage(rel->rd_node, persistence);

	/*
	 * If required, set up an init fork for an unlogged table so that it can
	 * be correctly reinitialized on restart.  An immediate sync is required
	 * even if the page has been logged, because the write did not go through
	 * shared_buffers and therefore a concurrent checkpoint may have moved the
	 * redo pointer past our xlog record.  Recovery may as well remove it
	 * while replaying, for example, XLOG_DBASE_CREATE or XLOG_TBLSPC_CREATE
	 * record. Therefore, logging is necessary even if wal_level=minimal.
	 */
	if (rel->rd_rel->relpersistence == RELPERSISTENCE_UNLOGGED)
	{
		Assert(rel->rd_rel->relkind == RELKIND_RELATION ||
			   rel->rd_rel->relkind == RELKIND_MATVIEW ||
			   rel->rd_rel->relkind == RELKIND_TOASTVALUE);
		RelationOpenSmgr(rel);
		smgrcreate(rel->rd_smgr, INIT_FORKNUM, false);
		log_smgrcreate(&rel->rd_smgr->smgr_rnode.node, INIT_FORKNUM);
		smgrimmedsync(rel->rd_smgr, INIT_FORKNUM);
	}
}

static void
heapam_relation_copy_data(Relation rel, RelFileNode newrnode)
{
	SMgrRelation dstrel;

	dstrel = smgropen(newrnode, rel->rd_backend);
	RelationOpenSmgr(rel);

	/*
	 * Create and copy all forks of the relation, and schedule unlinking of
	 * old physical files.
	 *
	 * NOTE: any conflict in relfilenode value will be caught in
	 * RelationCreateStorage().
	 */
	RelationCreateStorage(newrnode, rel->rd_rel->relpersistence);

	/* copy main fork */
	RelationCopyStorage(rel->rd_smgr, dstrel, MAIN_FORKNUM,
						rel->rd_rel->relpersistence);

	/* copy those extra forks that exist */
	for (ForkNumber forkNum = MAIN_FORKNUM + 1;
		 forkNum <= MAX_FORKNUM; forkNum++)
	{
		if (smgrexists(rel->rd_smgr, forkNum))
		{
			smgrcreate(dstrel, forkNum, false);

			/*
			 * WAL log creation if the relation is persistent, or this is the
			 * init fork of an unlogged relation.
			 */
			if (rel->rd_rel->relpersistence == RELPERSISTENCE_PERMANENT ||
				(rel->rd_rel->relpersistence == RELPERSISTENCE_UNLOGGED &&
				 forkNum == INIT_FORKNUM))
				log_smgrcreate(&newrnode, forkNum);
			RelationCopyStorage(rel->rd_smgr, dstrel, forkNum,
								rel->rd_rel->relpersistence);
		}
	}


	/* drop old relation, and close new one */
	RelationDropStorage(rel);
	smgrclose(dstrel);
}

static void
heapam_estimate_rel_size(Relation rel, int32 *attr_widths,
						 BlockNumber *pages, double *tuples,
						 double *allvisfrac)
{
	BlockNumber curpages;
	BlockNumber relpages;
	double		reltuples;
	BlockNumber relallvisible;
	double		density;

	/* it has storage, ok to call the smgr */
	curpages = RelationGetNumberOfBlocks(rel);

	/* coerce values in pg_class to more desirable types */
	relpages = (BlockNumber) rel->rd_rel->relpages;
	reltuples = (double) rel->rd_rel->reltuples;
	relallvisible = (BlockNumber) rel->rd_rel->relallvisible;

	/*
	 * HACK: if the relation has never yet been vacuumed, use a
	 * minimum size estimate of 10 pages.  The idea here is to avoid
	 * assuming a newly-created table is really small, even if it
	 * currently is, because that may not be true once some data gets
	 * loaded into it.  Once a vacuum or analyze cycle has been done
	 * on it, it's more reasonable to believe the size is somewhat
	 * stable.
	 *
	 * (Note that this is only an issue if the plan gets cached and
	 * used again after the table has been filled.  What we're trying
	 * to avoid is using a nestloop-type plan on a table that has
	 * grown substantially since the plan was made.  Normally,
	 * autovacuum/autoanalyze will occur once enough inserts have
	 * happened and cause cached-plan invalidation; but that doesn't
	 * happen instantaneously, and it won't happen at all for cases
	 * such as temporary tables.)
	 *
	 * We approximate "never vacuumed" by "has relpages = 0", which
	 * means this will also fire on genuinely empty relations.  Not
	 * great, but fortunately that's a seldom-seen case in the real
	 * world, and it shouldn't degrade the quality of the plan too
	 * much anyway to err in this direction.
	 *
	 * If the table has inheritance children, we don't apply this
	 * heuristic. Totally empty parent tables are quite common, so we should
	 * be willing to believe that they are empty.
	 */
	if (curpages < 10 &&
		relpages == 0 &&
		!rel->rd_rel->relhassubclass)
		curpages = 10;

	/* report estimated # pages */
	*pages = curpages;
	/* quick exit if rel is clearly empty */
	if (curpages == 0)
	{
		*tuples = 0;
		*allvisfrac = 0;
		return;
	}

	/* estimate number of tuples from previous tuple density */
	if (relpages > 0)
		density = reltuples / (double) relpages;
	else
	{
		/*
		 * When we have no data because the relation was truncated,
		 * estimate tuple width from attribute datatypes.  We assume
		 * here that the pages are completely full, which is OK for
		 * tables (since they've presumably not been VACUUMed yet) but
		 * is probably an overestimate for indexes.  Fortunately
		 * get_relation_info() can clamp the overestimate to the
		 * parent table's size.
		 *
		 * Note: this code intentionally disregards alignment
		 * considerations, because (a) that would be gilding the lily
		 * considering how crude the estimate is, and (b) it creates
		 * platform dependencies in the default plans which are kind
		 * of a headache for regression testing.
		 */
		int32		tuple_width;

		tuple_width = get_rel_data_width(rel, attr_widths);
		tuple_width += MAXALIGN(SizeofHeapTupleHeader);
		tuple_width += sizeof(ItemIdData);
		/* note: integer division is intentional here */
		density = (BLCKSZ - SizeOfPageHeaderData) / tuple_width;
	}
	*tuples = rint(density * (double) curpages);

	/*
	 * We use relallvisible as-is, rather than scaling it up like we
	 * do for the pages and tuples counts, on the theory that any
	 * pages added since the last VACUUM are most likely not marked
	 * all-visible.  But costsize.c wants it converted to a fraction.
	 */
	if (relallvisible == 0 || curpages <= 0)
		*allvisfrac = 0;
	else if ((double) relallvisible >= curpages)
		*allvisfrac = 1;
	else
		*allvisfrac = (double) relallvisible / curpages;
}

static const TableAmRoutine heapam_methods = {
	.type = T_TableAmRoutine,

	.slot_callbacks = heapam_slot_callbacks,

	.tuple_satisfies_snapshot = heapam_tuple_satisfies_snapshot,

	.scan_begin = heap_beginscan,
	.scansetlimits = heap_setscanlimits,
	.scan_getnextslot = heap_getnextslot,
	.scan_end = heap_endscan,
	.scan_rescan = heap_rescan,
	.scan_update_snapshot = heap_update_snapshot,

	.scan_bitmap_pagescan = heapam_scan_bitmap_pagescan,
	.scan_bitmap_pagescan_next = heapam_scan_bitmap_pagescan_next,

	.scan_sample_next_block = heapam_scan_sample_next_block,
	.scan_sample_next_tuple = heapam_scan_sample_next_tuple,

	.tuple_fetch_row_version = heapam_fetch_row_version,
	.tuple_fetch_follow = heapam_fetch_follow,
	.tuple_insert = heapam_heap_insert,
	.tuple_insert_speculative = heapam_heap_insert_speculative,
	.tuple_complete_speculative = heapam_heap_complete_speculative,
	.tuple_delete = heapam_heap_delete,
	.tuple_update = heapam_heap_update,
	.tuple_lock = heapam_lock_tuple,
	.multi_insert = heap_multi_insert,
	.finish_bulk_insert = heapam_finish_bulk_insert,

	.tuple_get_latest_tid = heap_get_latest_tid,

	.relation_vacuum = heap_vacuum_rel,
	.scan_analyze_next_block = heapam_scan_analyze_next_block,
	.scan_analyze_next_tuple = heapam_scan_analyze_next_tuple,
	.relation_nontransactional_truncate = heapam_relation_nontransactional_truncate,
	.relation_copy_for_cluster = heap_copy_for_cluster,
	.relation_set_new_filenode = heapam_set_new_filenode,
	.relation_copy_data = heapam_relation_copy_data,
	.relation_sync = heap_sync,
	.relation_estimate_size = heapam_estimate_rel_size,

	.begin_index_fetch = heapam_begin_index_fetch,
	.reset_index_fetch = heapam_reset_index_fetch,
	.end_index_fetch = heapam_end_index_fetch,

	.compute_xid_horizon_for_tuples = heap_compute_xid_horizon_for_tuples,

	.index_build_range_scan = IndexBuildHeapRangeScan,

	.index_validate_scan = validate_index_heapscan
};

const TableAmRoutine *
GetHeapamTableAmRoutine(void)
{
	return &heapam_methods;
}

Datum
heap_tableam_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&heapam_methods);
}
