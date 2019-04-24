/*-------------------------------------------------------------------------
 *
 * tableam.h
 *	  POSTGRES table access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/tableam.h
 *
 * NOTES
 *		See tableam.sgml for higher level documentation.
 *
 *-------------------------------------------------------------------------
 */
#ifndef TABLEAM_H
#define TABLEAM_H

#include "access/relscan.h"
#include "access/sdir.h"
#include "storage/bufmgr.h"
#include "utils/guc.h"
#include "utils/rel.h"
#include "utils/snapshot.h"


#define DEFAULT_TABLE_ACCESS_METHOD	"heap"

/* GUCs */
extern char *default_table_access_method;
extern bool synchronize_seqscans;


struct BulkInsertStateData;
struct IndexInfo;
struct IndexBuildCallback;
struct SampleScanState;
struct TBMIterateResult;
struct VacuumParams;
struct ValidateIndexState;


/*
 * Result codes for table_{update,delete,lock_tuple}, and for visibility
 * routines inside table AMs.
 */
typedef enum TM_Result
{
	/*
	 * Signals that the action succeeded (i.e. update/delete performed, lock
	 * was acquired)
	 */
	TM_Ok,

	/* The affected tuple wasn't visible to the relevant snapshot */
	TM_Invisible,

	/* The affected tuple was already modified by the calling backend */
	TM_SelfModified,

	/*
	 * The affected tuple was updated by another transaction. This includes
	 * the case where tuple was moved to another partition.
	 */
	TM_Updated,

	/* The affected tuple was deleted by another transaction */
	TM_Deleted,

	/*
	 * The affected tuple is currently being modified by another session. This
	 * will only be returned if table_(update/delete/lock_tuple) are
	 * instructed not to wait.
	 */
	TM_BeingModified,

	/* lock couldn't be acquired, action skipped. Only used by lock_tuple */
	TM_WouldBlock
} TM_Result;


/*
 * When table_update, table_delete, or table_lock_tuple fail because the target
 * tuple is already outdated, they fill in this struct to provide information
 * to the caller about what happened.
 *
 * ctid is the target's ctid link: it is the same as the target's TID if the
 * target was deleted, or the location of the replacement tuple if the target
 * was updated.
 *
 * xmax is the outdating transaction's XID.  If the caller wants to visit the
 * replacement tuple, it must check that this matches before believing the
 * replacement is really a match.
 *
 * cmax is the outdating command's CID, but only when the failure code is
 * TM_SelfModified (i.e., something in the current transaction outdated the
 * tuple); otherwise cmax is zero.  (We make this restriction because
 * HeapTupleHeaderGetCmax doesn't work for tuples outdated in other
 * transactions.)
 *
 * in_place_updated_or_locked indicates whether the tuple is updated or locked.
 * We need to re-verify the tuple even if it is just marked as locked, because
 * previously someone could have updated it in place.
 */
typedef struct TM_FailureData
{
	ItemPointerData ctid;
	TransactionId xmax;
	CommandId	cmax;
	bool		traversed;
	bool        in_place_updated_or_locked;
} TM_FailureData;

/* "options" flag bits for table_insert */
#define TABLE_INSERT_SKIP_WAL		0x0001
#define TABLE_INSERT_SKIP_FSM		0x0002
#define TABLE_INSERT_FROZEN			0x0004
#define TABLE_INSERT_NO_LOGICAL		0x0008

/* flag bits for table_lock_tuple */
/* Follow tuples whose update is in progress if lock modes don't conflict  */
#define TUPLE_LOCK_FLAG_LOCK_UPDATE_IN_PROGRESS	(1 << 0)
/* Follow update chain and lock latest version of tuple */
#define TUPLE_LOCK_FLAG_FIND_LAST_VERSION		(1 << 1)


/* Typedef for callback function for table_index_build_scan */
typedef void (*IndexBuildCallback) (Relation index,
									HeapTuple htup,
									Datum *values,
									bool *isnull,
									bool tupleIsAlive,
									void *state);

/*
 * API struct for a table AM.  Note this must be allocated in a
 * server-lifetime manner, typically as a static const struct, which then gets
 * returned by FormData_pg_am.amhandler.
 *
 * In most cases it's not appropriate to call the callbacks directly, use the
 * table_* wrapper functions instead.
 *
 * GetTableAmRoutine() asserts that required callbacks are filled in, remember
 * to update when adding a callback.
 */
typedef struct TableAmRoutine
{
	/* this must be set to T_TableAmRoutine */
	NodeTag		type;


	/* ------------------------------------------------------------------------
	 * Slot related callbacks.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Return slot implementation suitable for storing a tuple of this AM.
	 */
	const TupleTableSlotOps *(*slot_callbacks) (Relation rel);


	/* ------------------------------------------------------------------------
	 * Table scan callbacks.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Start a scan of `rel`.  The callback has to return a TableScanDesc,
	 * which will typically be embedded in a larger, AM specific, struct.
	 *
	 * If nkeys != 0, the results need to be filtered by those scan keys.
	 *
	 * pscan, if not NULL, will have already been initialized with
	 * parallelscan_initialize(), and has to be for the same relation. Will
	 * only be set coming from table_beginscan_parallel().
	 *
	 * allow_{strat, sync, pagemode} specify whether a scan strategy,
	 * synchronized scans, or page mode may be used (although not every AM
	 * will support those).
	 *
	 * is_{bitmapscan, samplescan} specify whether the scan is intended to
	 * support those types of scans.
	 *
	 * if temp_snap is true, the snapshot will need to be deallocated at
	 * scan_end.
	 */
	TableScanDesc (*scan_begin) (Relation rel,
								 Snapshot snapshot,
								 int nkeys, struct ScanKeyData *key,
								 ParallelTableScanDesc pscan,
								 bool allow_strat,
								 bool allow_sync,
								 bool allow_pagemode,
								 bool is_bitmapscan,
								 bool is_samplescan,
								 bool temp_snap);

	/*
	 * Release resources and deallocate scan. If TableScanDesc.temp_snap,
	 * TableScanDesc.rs_snapshot needs to be unregistered.
	 */
	void		(*scan_end) (TableScanDesc scan);

	/*
	 * Restart relation scan.  If set_params is set to true, allow_{strat,
	 * sync, pagemode} (see scan_begin) changes should be taken into account.
	 */
	void		(*scan_rescan) (TableScanDesc scan, struct ScanKeyData *key,
								bool set_params, bool allow_strat,
								bool allow_sync, bool allow_pagemode);

	/*
	 * Return next tuple from `scan`, store in slot.
	 */
	bool		(*scan_getnextslot) (TableScanDesc scan,
									 ScanDirection direction,
									 TupleTableSlot *slot);


	/* ------------------------------------------------------------------------
	 * Parallel table scan related functions.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Estimate the size of shared memory needed for a parallel scan of this
	 * relation. The snapshot does not need to be accounted for.
	 */
	Size		(*parallelscan_estimate) (Relation rel);

	/*
	 * Initialize ParallelTableScanDesc for a parallel scan of this relation.
	 * `pscan` will be sized according to parallelscan_estimate() for the same
	 * relation.
	 */
	Size		(*parallelscan_initialize) (Relation rel,
											ParallelTableScanDesc pscan);

	/*
	 * Reinitialize `pscan` for a new scan. `rel` will be the same relation as
	 * when `pscan` was initialized by parallelscan_initialize.
	 */
	void		(*parallelscan_reinitialize) (Relation rel,
											  ParallelTableScanDesc pscan);


	/* ------------------------------------------------------------------------
	 * Index Scan Callbacks
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Prepare to fetch tuples from the relation, as needed when fetching
	 * tuples for an index scan.  The callback has to return an
	 * IndexFetchTableData, which the AM will typically embed in a larger
	 * structure with additional information.
	 *
	 * Tuples for an index scan can then be fetched via index_fetch_tuple.
	 */
	struct IndexFetchTableData *(*index_fetch_begin) (Relation rel);

	/*
	 * Reset index fetch. Typically this will release cross index fetch
	 * resources held in IndexFetchTableData.
	 */
	void		(*index_fetch_reset) (struct IndexFetchTableData *data);

	/*
	 * Release resources and deallocate index fetch.
	 */
	void		(*index_fetch_end) (struct IndexFetchTableData *data);

	/*
	 * Fetch tuple at `tid` into `slot`, after doing a visibility test
	 * according to `snapshot`. If a tuple was found and passed the visibility
	 * test, return true, false otherwise.
	 *
	 * Note that AMs that do not necessarily update indexes when indexed
	 * columns do not change, need to return the current/correct version of
	 * the tuple that is visible to the snapshot, even if the tid points to an
	 * older version of the tuple.
	 *
	 * *call_again is false on the first call to index_fetch_tuple for a tid.
	 * If there potentially is another tuple matching the tid, *call_again
	 * needs be set to true by index_fetch_tuple, signalling to the caller
	 * that index_fetch_tuple should be called again for the same tid.
	 *
	 * *all_dead, if all_dead is not NULL, should be set to true by
	 * index_fetch_tuple iff it is guaranteed that no backend needs to see
	 * that tuple. Index AMs can use that do avoid returning that tid in
	 * future searches.
	 */
	bool		(*index_fetch_tuple) (struct IndexFetchTableData *scan,
									  ItemPointer tid,
									  Snapshot snapshot,
									  TupleTableSlot *slot,
									  bool *call_again, bool *all_dead);


	/* ------------------------------------------------------------------------
	 * Callbacks for non-modifying operations on individual tuples
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Fetch tuple at `tid` into `slot`, after doing a visibility test
	 * according to `snapshot`. If a tuple was found and passed the visibility
	 * test, returns true, false otherwise.
	 */
	bool		(*tuple_fetch_row_version) (Relation rel,
											ItemPointer tid,
											Snapshot snapshot,
											TupleTableSlot *slot);

	/*
	 * Return the latest version of the tuple at `tid`, by updating `tid` to
	 * point at the newest version.
	 */
	void		(*tuple_get_latest_tid) (Relation rel,
										 Snapshot snapshot,
										 ItemPointer tid);

	/*
	 * Does the tuple in `slot` satisfy `snapshot`?  The slot needs to be of
	 * the appropriate type for the AM.
	 */
	bool		(*tuple_satisfies_snapshot) (Relation rel,
											 TupleTableSlot *slot,
											 Snapshot snapshot);

	/* see table_compute_xid_horizon_for_tuples() */
	TransactionId (*compute_xid_horizon_for_tuples) (Relation rel,
													 ItemPointerData *items,
													 int nitems);


	/* ------------------------------------------------------------------------
	 * Manipulations of physical tuples.
	 * ------------------------------------------------------------------------
	 */

	/* see table_insert() for reference about parameters */
	void		(*tuple_insert) (Relation rel, TupleTableSlot *slot,
								 CommandId cid, int options,
								 struct BulkInsertStateData *bistate);

	/* see table_insert_speculative() for reference about parameters */
	void		(*tuple_insert_speculative) (Relation rel,
											 TupleTableSlot *slot,
											 CommandId cid,
											 int options,
											 struct BulkInsertStateData *bistate,
											 uint32 specToken);

	/* see table_complete_speculative() for reference about parameters */
	void		(*tuple_complete_speculative) (Relation rel,
											   TupleTableSlot *slot,
											   uint32 specToken,
											   bool succeeded);

	/* see table_multi_insert() for reference about parameters */
	void		(*multi_insert) (Relation rel, TupleTableSlot **slots, int nslots,
								 CommandId cid, int options, struct BulkInsertStateData *bistate);

	/* see table_delete() for reference about parameters */
	TM_Result	(*tuple_delete) (Relation rel,
								 ItemPointer tid,
								 CommandId cid,
								 Snapshot snapshot,
								 Snapshot crosscheck,
								 bool wait,
								 TM_FailureData *tmfd,
								 bool changingPart);

	/* see table_update() for reference about parameters */
	TM_Result	(*tuple_update) (Relation rel,
								 ItemPointer otid,
								 TupleTableSlot *slot,
								 CommandId cid,
								 Snapshot snapshot,
								 Snapshot crosscheck,
								 bool wait,
								 TM_FailureData *tmfd,
								 LockTupleMode *lockmode,
								 bool *update_indexes);

	/* see table_lock_tuple() for reference about parameters */
	TM_Result	(*tuple_lock) (Relation rel,
							   ItemPointer tid,
							   Snapshot snapshot,
							   TupleTableSlot *slot,
							   CommandId cid,
							   LockTupleMode mode,
							   LockWaitPolicy wait_policy,
							   uint8 flags,
							   TM_FailureData *tmfd);

	/*
	 * Perform operations necessary to complete insertions made via
	 * tuple_insert and multi_insert with a BulkInsertState specified. This
	 * may for example be used to flush the relation, when the
	 * TABLE_INSERT_SKIP_WAL option was used.
	 *
	 * Typically callers of tuple_insert and multi_insert will just pass all
	 * the flags that apply to them, and each AM has to decide which of them
	 * make sense for it, and then only take actions in finish_bulk_insert for
	 * those flags, and ignore others.
	 *
	 * Optional callback.
	 */
	void		(*finish_bulk_insert) (Relation rel, int options);


	/* ------------------------------------------------------------------------
	 * DDL related functionality.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * This callback needs to create a new relation filenode for `rel`, with
	 * appropriate durability behaviour for `persistence`.
	 *
	 * On output *freezeXid, *minmulti must be set to the values appropriate
	 * for pg_class.{relfrozenxid, relminmxid}. For AMs that don't need those
	 * fields to be filled they can be set to InvalidTransactionId and
	 * InvalidMultiXactId, respectively.
	 *
	 * See also table_relation_set_new_filenode().
	 */
	void		(*relation_set_new_filenode) (Relation rel,
											  char persistence,
											  TransactionId *freezeXid,
											  MultiXactId *minmulti);

	/*
	 * This callback needs to remove all contents from `rel`'s current
	 * relfilenode. No provisions for transactional behaviour need to be made.
	 * Often this can be implemented by truncating the underlying storage to
	 * its minimal size.
	 *
	 * See also table_relation_nontransactional_truncate().
	 */
	void		(*relation_nontransactional_truncate) (Relation rel);

	/*
	 * See table_relation_copy_data().
	 *
	 * This can typically be implemented by directly copying the underlying
	 * storage, unless it contains references to the tablespace internally.
	 */
	void		(*relation_copy_data) (Relation rel, RelFileNode newrnode);

	/* See table_relation_copy_for_cluster() */
	void		(*relation_copy_for_cluster) (Relation NewHeap,
											  Relation OldHeap,
											  Relation OldIndex,
											  bool use_sort,
											  TransactionId OldestXmin,
											  TransactionId FreezeXid,
											  MultiXactId MultiXactCutoff,
											  double *num_tuples,
											  double *tups_vacuumed,
											  double *tups_recently_dead);

	/*
	 * React to VACUUM command on the relation. The VACUUM might be user
	 * triggered or by autovacuum. The specific actions performed by the AM
	 * will depend heavily on the individual AM.
	 *
	 * On entry a transaction is already established, and the relation is
	 * locked with a ShareUpdateExclusive lock.
	 *
	 * Note that neither VACUUM FULL (and CLUSTER), nor ANALYZE go through
	 * this routine, even if (for ANALYZE) it is part of the same VACUUM
	 * command.
	 *
	 * There probably, in the future, needs to be a separate callback to
	 * integrate with autovacuum's scheduling.
	 */
	void		(*relation_vacuum) (Relation onerel,
									struct VacuumParams *params,
									BufferAccessStrategy bstrategy);

	/*
	 * Prepare to analyze block `blockno` of `scan`. The scan has been started
	 * with table_beginscan_analyze().  See also
	 * table_scan_analyze_next_block().
	 *
	 * The callback may acquire resources like locks that are held until
	 * table_scan_analyze_next_tuple() returns false. It e.g. can make sense
	 * to hold a lock until all tuples on a block have been analyzed by
	 * scan_analyze_next_tuple.
	 *
	 * The callback can return false if the block is not suitable for
	 * sampling, e.g. because it's a metapage that could never contain tuples.
	 *
	 * XXX: This obviously is primarily suited for block-based AMs. It's not
	 * clear what a good interface for non block based AMs would be, so there
	 * isn't one yet.
	 */
	bool		(*scan_analyze_next_block) (TableScanDesc scan,
											BlockNumber blockno,
											BufferAccessStrategy bstrategy);

	/*
	 * See table_scan_analyze_next_tuple().
	 *
	 * Not every AM might have a meaningful concept of dead rows, in which
	 * case it's OK to not increment *deadrows - but note that that may
	 * influence autovacuum scheduling (see comment for relation_vacuum
	 * callback).
	 */
	bool		(*scan_analyze_next_tuple) (TableScanDesc scan,
											TransactionId OldestXmin,
											double *liverows,
											double *deadrows,
											TupleTableSlot *slot);

	/* see table_index_build_range_scan for reference about parameters */
	double		(*index_build_range_scan) (Relation heap_rel,
										   Relation index_rel,
										   struct IndexInfo *index_nfo,
										   bool allow_sync,
										   bool anyvisible,
										   bool progress,
										   BlockNumber start_blockno,
										   BlockNumber end_blockno,
										   IndexBuildCallback callback,
										   void *callback_state,
										   TableScanDesc scan);

	/* see table_index_validate_scan for reference about parameters */
	void		(*index_validate_scan) (Relation heap_rel,
										Relation index_rel,
										struct IndexInfo *index_info,
										Snapshot snapshot,
										struct ValidateIndexState *state);


	/* ------------------------------------------------------------------------
	 * Planner related functions.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * See table_relation_estimate_size().
	 *
	 * While block oriented, it shouldn't be too hard for an AM that doesn't
	 * doesn't internally use blocks to convert into a usable representation.
	 */
	void		(*relation_estimate_size) (Relation rel, int32 *attr_widths,
										   BlockNumber *pages, double *tuples,
										   double *allvisfrac);


	/* ------------------------------------------------------------------------
	 * Executor related functions.
	 * ------------------------------------------------------------------------
	 */

	/*
	 * Prepare to fetch / check / return tuples from `tbmres->blockno` as part
	 * of a bitmap table scan. `scan` was started via table_beginscan_bm().
	 * Return false if there are no tuples to be found on the page, true
	 * otherwise.
	 *
	 * This will typically read and pin the target block, and do the necessary
	 * work to allow scan_bitmap_next_tuple() to return tuples (e.g. it might
	 * make sense to perform tuple visibility checks at this time). For some
	 * AMs it will make more sense to do all the work referencing `tbmres`
	 * contents here, for others it might be better to defer more work to
	 * scan_bitmap_next_tuple.
	 *
	 * If `tbmres->blockno` is -1, this is a lossy scan and all visible tuples
	 * on the page have to be returned, otherwise the tuples at offsets in
	 * `tbmres->offsets` need to be returned.
	 *
	 * XXX: Currently this may only be implemented if the AM uses md.c as its
	 * storage manager, and uses ItemPointer->ip_blkid in a manner that maps
	 * blockids directly to the underlying storage. nodeBitmapHeapscan.c
	 * performs prefetching directly using that interface.  This probably
	 * needs to be rectified at a later point.
	 *
	 * XXX: Currently this may only be implemented if the AM uses the
	 * visibilitymap, as nodeBitmapHeapscan.c unconditionally accesses it to
	 * perform prefetching.  This probably needs to be rectified at a later
	 * point.
	 *
	 * Optional callback, but either both scan_bitmap_next_block and
	 * scan_bitmap_next_tuple need to exist, or neither.
	 */
	bool		(*scan_bitmap_next_block) (TableScanDesc scan,
										   struct TBMIterateResult *tbmres);

	/*
	 * Fetch the next tuple of a bitmap table scan into `slot` and return true
	 * if a visible tuple was found, false otherwise.
	 *
	 * For some AMs it will make more sense to do all the work referencing
	 * `tbmres` contents in scan_bitmap_next_block, for others it might be
	 * better to defer more work to this callback.
	 *
	 * Optional callback, but either both scan_bitmap_next_block and
	 * scan_bitmap_next_tuple need to exist, or neither.
	 */
	bool		(*scan_bitmap_next_tuple) (TableScanDesc scan,
										   struct TBMIterateResult *tbmres,
										   TupleTableSlot *slot);

	/*
	 * Prepare to fetch tuples from the next block in a sample scan. Return
	 * false if the sample scan is finished, true otherwise. `scan` was
	 * started via table_beginscan_sampling().
	 *
	 * Typically this will first determine the target block by call the
	 * TsmRoutine's NextSampleBlock() callback if not NULL, or alternatively
	 * perform a sequential scan over all blocks.  The determined block is
	 * then typically read and pinned.
	 *
	 * As the TsmRoutine interface is block based, a block needs to be passed
	 * to NextSampleBlock(). If that's not appropriate for an AM, it
	 * internally needs to perform mapping between the internal and a block
	 * based representation.
	 *
	 * Note that it's not acceptable to hold deadlock prone resources such as
	 * lwlocks until scan_sample_next_tuple() has exhausted the tuples on the
	 * block - the tuple is likely to be returned to an upper query node, and
	 * the next call could be off a long while. Holding buffer pins and such
	 * is obviously OK.
	 *
	 * Currently it is required to implement this interface, as there's no
	 * alternative way (contrary e.g. to bitmap scans) to implement sample
	 * scans. If infeasible to implement the AM may raise an error.
	 */
	bool		(*scan_sample_next_block) (TableScanDesc scan,
										   struct SampleScanState *scanstate);

	/*
	 * This callback, only called after scan_sample_next_block has returned
	 * true, should determine the next tuple to be returned from the selected
	 * block using the TsmRoutine's NextSampleTuple() callback.
	 *
	 * The callback needs to perform visibility checks, and only return
	 * visible tuples. That obviously can mean calling NextSampletuple()
	 * multiple times.
	 *
	 * The TsmRoutine interface assumes that there's a maximum offset on a
	 * given page, so if that doesn't apply to an AM, it needs to emulate that
	 * assumption somehow.
	 */
	bool		(*scan_sample_next_tuple) (TableScanDesc scan,
										   struct SampleScanState *scanstate,
										   TupleTableSlot *slot);

} TableAmRoutine;


/* ----------------------------------------------------------------------------
 * Slot functions.
 * ----------------------------------------------------------------------------
 */

/*
 * Returns slot callbacks suitable for holding tuples of the appropriate type
 * for the relation.  Works for tables, views, foreign tables and partitioned
 * tables.
 */
extern const TupleTableSlotOps *table_slot_callbacks(Relation rel);

/*
 * Returns slot using the callbacks returned by table_slot_callbacks(), and
 * registers it on *reglist.
 */
extern TupleTableSlot *table_slot_create(Relation rel, List **reglist);


/* ----------------------------------------------------------------------------
 * Table scan functions.
 * ----------------------------------------------------------------------------
 */

/*
 * Start a scan of `rel`. Returned tuples pass a visibility test of
 * `snapshot`, and if nkeys != 0, the results are filtered by those scan keys.
 */
static inline TableScanDesc
table_beginscan(Relation rel, Snapshot snapshot,
				int nkeys, struct ScanKeyData *key)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   true, true, true, false, false, false);
}

/*
 * Like table_beginscan(), but for scanning catalog. It'll automatically use a
 * snapshot appropriate for scanning catalog relations.
 */
extern TableScanDesc table_beginscan_catalog(Relation rel, int nkeys,
						struct ScanKeyData *key);

/*
 * Like table_beginscan(), but table_beginscan_strat() offers an extended API
 * that lets the caller control whether a nondefault buffer access strategy
 * can be used, and whether syncscan can be chosen (possibly resulting in the
 * scan not starting from block zero).  Both of these default to true with
 * plain table_beginscan.
 */
static inline TableScanDesc
table_beginscan_strat(Relation rel, Snapshot snapshot,
					  int nkeys, struct ScanKeyData *key,
					  bool allow_strat, bool allow_sync)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   allow_strat, allow_sync, true,
									   false, false, false);
}

/*
 * table_beginscan_bm is an alternative entry point for setting up a
 * TableScanDesc for a bitmap heap scan.  Although that scan technology is
 * really quite unlike a standard seqscan, there is just enough commonality to
 * make it worth using the same data structure.
 */
static inline TableScanDesc
table_beginscan_bm(Relation rel, Snapshot snapshot,
				   int nkeys, struct ScanKeyData *key)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   false, false, true, true, false, false);
}

/*
 * table_beginscan_sampling is an alternative entry point for setting up a
 * TableScanDesc for a TABLESAMPLE scan.  As with bitmap scans, it's worth
 * using the same data structure although the behavior is rather different.
 * In addition to the options offered by table_beginscan_strat, this call
 * also allows control of whether page-mode visibility checking is used.
 */
static inline TableScanDesc
table_beginscan_sampling(Relation rel, Snapshot snapshot,
						 int nkeys, struct ScanKeyData *key,
						 bool allow_strat, bool allow_sync,
						 bool allow_pagemode)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   allow_strat, allow_sync, allow_pagemode,
									   false, true, false);
}

/*
 * table_beginscan_analyze is an alternative entry point for setting up a
 * TableScanDesc for an ANALYZE scan.  As with bitmap scans, it's worth using
 * the same data structure although the behavior is rather different.
 */
static inline TableScanDesc
table_beginscan_analyze(Relation rel)
{
	return rel->rd_tableam->scan_begin(rel, NULL, 0, NULL, NULL,
									   true, false, true,
									   false, true, false);
}

/*
 * End relation scan.
 */
static inline void
table_endscan(TableScanDesc scan)
{
	scan->rs_rd->rd_tableam->scan_end(scan);
}

/*
 * Restart a relation scan.
 */
static inline void
table_rescan(TableScanDesc scan,
			 struct ScanKeyData *key)
{
	scan->rs_rd->rd_tableam->scan_rescan(scan, key, false, false, false, false);
}

/*
 * Restart a relation scan after changing params.
 *
 * This call allows changing the buffer strategy, syncscan, and pagemode
 * options before starting a fresh scan.  Note that although the actual use of
 * syncscan might change (effectively, enabling or disabling reporting), the
 * previously selected startblock will be kept.
 */
static inline void
table_rescan_set_params(TableScanDesc scan, struct ScanKeyData *key,
						bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	scan->rs_rd->rd_tableam->scan_rescan(scan, key, true,
										 allow_strat, allow_sync,
										 allow_pagemode);
}

/*
 * Update snapshot used by the scan.
 */
extern void table_scan_update_snapshot(TableScanDesc scan, Snapshot snapshot);

/*
 * Return next tuple from `scan`, store in slot.
 */
static inline bool
table_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
	slot->tts_tableOid = RelationGetRelid(sscan->rs_rd);
	return sscan->rs_rd->rd_tableam->scan_getnextslot(sscan, direction, slot);
}


/* ----------------------------------------------------------------------------
 * Parallel table scan related functions.
 * ----------------------------------------------------------------------------
 */

/*
 * Estimate the size of shared memory needed for a parallel scan of this
 * relation.
 */
extern Size table_parallelscan_estimate(Relation rel, Snapshot snapshot);

/*
 * Initialize ParallelTableScanDesc for a parallel scan of this
 * relation. `pscan` needs to be sized according to parallelscan_estimate()
 * for the same relation.  Call this just once in the leader process; then,
 * individual workers attach via table_beginscan_parallel.
 */
extern void table_parallelscan_initialize(Relation rel,
							  ParallelTableScanDesc pscan,
							  Snapshot snapshot);

/*
 * Begin a parallel scan. `pscan` needs to have been initialized with
 * table_parallelscan_initialize(), for the same relation. The initialization
 * does not need to have happened in this backend.
 *
 * Caller must hold a suitable lock on the relation.
 */
extern TableScanDesc table_beginscan_parallel(Relation rel,
						 ParallelTableScanDesc pscan);

/*
 * Restart a parallel scan.  Call this in the leader process.  Caller is
 * responsible for making sure that all workers have finished the scan
 * beforehand.
 */
static inline void
table_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc pscan)
{
	rel->rd_tableam->parallelscan_reinitialize(rel, pscan);
}


/* ----------------------------------------------------------------------------
 *  Index scan related functions.
 * ----------------------------------------------------------------------------
 */

/*
 * Prepare to fetch tuples from the relation, as needed when fetching tuples
 * for an index scan.
 *
 * Tuples for an index scan can then be fetched via table_index_fetch_tuple().
 */
static inline IndexFetchTableData *
table_index_fetch_begin(Relation rel)
{
	return rel->rd_tableam->index_fetch_begin(rel);
}

/*
 * Reset index fetch. Typically this will release cross index fetch resources
 * held in IndexFetchTableData.
 */
static inline void
table_index_fetch_reset(struct IndexFetchTableData *scan)
{
	scan->rel->rd_tableam->index_fetch_reset(scan);
}

/*
 * Release resources and deallocate index fetch.
 */
static inline void
table_index_fetch_end(struct IndexFetchTableData *scan)
{
	scan->rel->rd_tableam->index_fetch_end(scan);
}

/*
 * Fetches, as part of an index scan, tuple at `tid` into `slot`, after doing
 * a visibility test according to `snapshot`. If a tuple was found and passed
 * the visibility test, returns true, false otherwise.
 *
 * *call_again needs to be false on the first call to table_index_fetch_tuple() for
 * a tid. If there potentially is another tuple matching the tid, *call_again
 * will be set to true, signalling that table_index_fetch_tuple() should be called
 * again for the same tid.
 *
 * *all_dead, if all_dead is not NULL, will be set to true by
 * table_index_fetch_tuple() iff it is guaranteed that no backend needs to see
 * that tuple. Index AMs can use that do avoid returning that tid in future
 * searches.
 *
 * The difference between this function and table_fetch_row_version is that
 * this function returns the currently visible version of a row if the AM
 * supports storing multiple row versions reachable via a single index entry
 * (like heap's HOT). Whereas table_fetch_row_version only evaluates the
 * tuple exactly at `tid`. Outside of index entry ->table tuple lookups,
 * table_fetch_row_version is what's usually needed.
 */
static inline bool
table_index_fetch_tuple(struct IndexFetchTableData *scan,
						ItemPointer tid,
						Snapshot snapshot,
						TupleTableSlot *slot,
						bool *call_again, bool *all_dead)
{

	return scan->rel->rd_tableam->index_fetch_tuple(scan, tid, snapshot,
													slot, call_again,
													all_dead);
}

/*
 * This is a convenience wrapper around table_index_fetch_tuple() which
 * returns whether there are table tuple items corresponding to an index
 * entry.  This likely is only useful to verify if there's a conflict in a
 * unique index.
 */
extern bool table_index_fetch_tuple_check(Relation rel,
							  ItemPointer tid,
							  Snapshot snapshot,
							  bool *all_dead);


/* ------------------------------------------------------------------------
 * Functions for non-modifying operations on individual tuples
 * ------------------------------------------------------------------------
 */


/*
 * Fetch tuple at `tid` into `slot`, after doing a visibility test according to
 * `snapshot`. If a tuple was found and passed the visibility test, returns
 * true, false otherwise.
 *
 * See table_index_fetch_tuple's comment about what the difference between
 * these functions is. This function is the correct to use outside of
 * index entry->table tuple lookups.
 */
static inline bool
table_fetch_row_version(Relation rel,
						ItemPointer tid,
						Snapshot snapshot,
						TupleTableSlot *slot)
{
	return rel->rd_tableam->tuple_fetch_row_version(rel, tid, snapshot, slot);
}

/*
 * Return the latest version of the tuple at `tid`, by updating `tid` to
 * point at the newest version.
 */
static inline void
table_get_latest_tid(Relation rel, Snapshot snapshot, ItemPointer tid)
{
	rel->rd_tableam->tuple_get_latest_tid(rel, snapshot, tid);
}

/*
 * Return true iff tuple in slot satisfies the snapshot.
 *
 * This assumes the slot's tuple is valid, and of the appropriate type for the
 * AM.
 *
 * Some AMs might modify the data underlying the tuple as a side-effect. If so
 * they ought to mark the relevant buffer dirty.
 */
static inline bool
table_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot,
							   Snapshot snapshot)
{
	return rel->rd_tableam->tuple_satisfies_snapshot(rel, slot, snapshot);
}

/*
 * Compute the newest xid among the tuples pointed to by items. This is used
 * to compute what snapshots to conflict with when replaying WAL records for
 * page-level index vacuums.
 */
static inline TransactionId
table_compute_xid_horizon_for_tuples(Relation rel,
									 ItemPointerData *items,
									 int nitems)
{
	return rel->rd_tableam->compute_xid_horizon_for_tuples(rel, items, nitems);
}


/* ----------------------------------------------------------------------------
 *  Functions for manipulations of physical tuples.
 * ----------------------------------------------------------------------------
 */

/*
 * Insert a tuple from a slot into table AM routine.
 *
 * The options bitmask allows to specify options that allow to change the
 * behaviour of the AM. Several options might be ignored by AMs not supporting
 * them.
 *
 * If the TABLE_INSERT_SKIP_WAL option is specified, the new tuple doesn't
 * need to be logged to WAL, even for a non-temp relation. It is the AMs
 * choice whether this optimization is supported.
 *
 * If the TABLE_INSERT_SKIP_FSM option is specified, AMs are free to not reuse
 * free space in the relation. This can save some cycles when we know the
 * relation is new and doesn't contain useful amounts of free space.  It's
 * commonly passed directly to RelationGetBufferForTuple, see for more info.
 *
 * TABLE_INSERT_FROZEN should only be specified for inserts into
 * relfilenodes created during the current subtransaction and when
 * there are no prior snapshots or pre-existing portals open.
 * This causes rows to be frozen, which is an MVCC violation and
 * requires explicit options chosen by user.
 *
 * TABLE_INSERT_NO_LOGICAL force-disables the emitting of logical decoding
 * information for the tuple. This should solely be used during table rewrites
 * where RelationIsLogicallyLogged(relation) is not yet accurate for the new
 * relation.
 *
 * Note that most of these options will be applied when inserting into the
 * heap's TOAST table, too, if the tuple requires any out-of-line data.
 *
 *
 * The BulkInsertState object (if any; bistate can be NULL for default
 * behavior) is also just passed through to RelationGetBufferForTuple. If
 * `bistate` is provided, table_finish_bulk_insert() needs to be called.
 *
 * On return the slot's tts_tid and tts_tableOid are updated to reflect the
 * insertion. But note that any toasting of fields within the slot is NOT
 * reflected in the slots contents.
 */
static inline void
table_insert(Relation rel, TupleTableSlot *slot, CommandId cid,
			 int options, struct BulkInsertStateData *bistate)
{
	rel->rd_tableam->tuple_insert(rel, slot, cid, options,
								  bistate);
}

/*
 * Perform a "speculative insertion". These can be backed out afterwards
 * without aborting the whole transaction.  Other sessions can wait for the
 * speculative insertion to be confirmed, turning it into a regular tuple, or
 * aborted, as if it never existed.  Speculatively inserted tuples behave as
 * "value locks" of short duration, used to implement INSERT .. ON CONFLICT.
 *
 * A transaction having performed a speculative insertion has to either abort,
 * or finish the speculative insertion with
 * table_complete_speculative(succeeded = ...).
 */
static inline void
table_insert_speculative(Relation rel, TupleTableSlot *slot, CommandId cid,
						 int options, struct BulkInsertStateData *bistate,
						 uint32 specToken)
{
	rel->rd_tableam->tuple_insert_speculative(rel, slot, cid, options,
											  bistate, specToken);
}

/*
 * Complete "speculative insertion" started in the same transaction. If
 * succeeded is true, the tuple is fully inserted, if false, it's removed.
 */
static inline void
table_complete_speculative(Relation rel, TupleTableSlot *slot,
						   uint32 specToken, bool succeeded)
{
	rel->rd_tableam->tuple_complete_speculative(rel, slot, specToken,
												succeeded);
}

/*
 * Insert multiple tuples into a table.
 *
 * This is like table_insert(), but inserts multiple tuples in one
 * operation. That's often faster than calling table_insert() in a loop,
 * because e.g. the AM can reduce WAL logging and page locking overhead.
 *
 * Except for taking `nslots` tuples as input, as an array of TupleTableSlots
 * in `slots`, the parameters for table_multi_insert() are the same as for
 * table_insert().
 *
 * Note: this leaks memory into the current memory context. You can create a
 * temporary context before calling this, if that's a problem.
 */
static inline void
table_multi_insert(Relation rel, TupleTableSlot **slots, int nslots,
				   CommandId cid, int options, struct BulkInsertStateData *bistate)
{
	rel->rd_tableam->multi_insert(rel, slots, nslots,
								  cid, options, bistate);
}

/*
 * Delete a tuple.
 *
 * NB: do not call this directly unless prepared to deal with
 * concurrent-update conditions.  Use simple_table_delete instead.
 *
 * Input parameters:
 *	relation - table to be modified (caller must hold suitable lock)
 *	tid - TID of tuple to be deleted
 *	cid - delete command ID (used for visibility test, and stored into
 *		cmax if successful)
 *	crosscheck - if not InvalidSnapshot, also check tuple against this
 *	wait - true if should wait for any conflicting update to commit/abort
 * Output parameters:
 *	tmfd - filled in failure cases (see below)
 *	changingPart - true iff the tuple is being moved to another partition
 *		table due to an update of the partition key. Otherwise, false.
 *
 * Normal, successful return value is TM_Ok, which means we did actually
 * delete it.  Failure return codes are TM_SelfModified, TM_Updated, and
 * TM_BeingModified (the last only possible if wait == false).
 *
 * In the failure cases, the routine fills *tmfd with the tuple's t_ctid,
 * t_xmax, and, if possible, and, if possible, t_cmax.  See comments for
 * struct TM_FailureData for additional info.
 */
static inline TM_Result
table_delete(Relation rel, ItemPointer tid, CommandId cid,
			 Snapshot snapshot, Snapshot crosscheck, bool wait,
			 TM_FailureData *tmfd, bool changingPart)
{
	return rel->rd_tableam->tuple_delete(rel, tid, cid,
										 snapshot, crosscheck,
										 wait, tmfd, changingPart);
}

/*
 * Update a tuple.
 *
 * NB: do not call this directly unless you are prepared to deal with
 * concurrent-update conditions.  Use simple_table_update instead.
 *
 * Input parameters:
 *	relation - table to be modified (caller must hold suitable lock)
 *	otid - TID of old tuple to be replaced
 *	slot - newly constructed tuple data to store
 *	cid - update command ID (used for visibility test, and stored into
 *		cmax/cmin if successful)
 *	crosscheck - if not InvalidSnapshot, also check old tuple against this
 *	wait - true if should wait for any conflicting update to commit/abort
 * Output parameters:
 *	tmfd - filled in failure cases (see below)
 *	lockmode - filled with lock mode acquired on tuple
 *  update_indexes - in success cases this is set to true if new index entries
 *		are required for this tuple
 *
 * Normal, successful return value is TM_Ok, which means we did actually
 * update it.  Failure return codes are TM_SelfModified, TM_Updated, and
 * TM_BeingModified (the last only possible if wait == false).
 *
 * On success, the slot's tts_tid and tts_tableOid are updated to match the new
 * stored tuple; in particular, slot->tts_tid is set to the TID where the
 * new tuple was inserted, and its HEAP_ONLY_TUPLE flag is set iff a HOT
 * update was done.  However, any TOAST changes in the new tuple's
 * data are not reflected into *newtup.
 *
 * In the failure cases, the routine fills *tmfd with the tuple's t_ctid,
 * t_xmax, and, if possible, t_cmax.  See comments for struct TM_FailureData
 * for additional info.
 */
static inline TM_Result
table_update(Relation rel, ItemPointer otid, TupleTableSlot *slot,
			 CommandId cid, Snapshot snapshot, Snapshot crosscheck, bool wait,
			 TM_FailureData *tmfd, LockTupleMode *lockmode,
			 bool *update_indexes)
{
	return rel->rd_tableam->tuple_update(rel, otid, slot,
										 cid, snapshot, crosscheck,
										 wait, tmfd,
										 lockmode, update_indexes);
}

/*
 * Lock a tuple in the specified mode.
 *
 * Input parameters:
 *	relation: relation containing tuple (caller must hold suitable lock)
 *	tid: TID of tuple to lock
 *	snapshot: snapshot to use for visibility determinations
 *	cid: current command ID (used for visibility test, and stored into
 *		tuple's cmax if lock is successful)
 *	mode: lock mode desired
 *	wait_policy: what to do if tuple lock is not available
 *	flags:
 *		If TUPLE_LOCK_FLAG_LOCK_UPDATE_IN_PROGRESS, follow the update chain to
 *		also lock descendant tuples if lock modes don't conflict.
 *		If TUPLE_LOCK_FLAG_FIND_LAST_VERSION, follow the update chain and lock
 *		latest version.
 *
 * Output parameters:
 *	*slot: contains the target tuple
 *	*tmfd: filled in failure cases (see below)
 *
 * Function result may be:
 *	TM_Ok: lock was successfully acquired
 *	TM_Invisible: lock failed because tuple was never visible to us
 *	TM_SelfModified: lock failed because tuple updated by self
 *	TM_Updated: lock failed because tuple updated by other xact
 *	TM_Deleted: lock failed because tuple deleted by other xact
 *	TM_WouldBlock: lock couldn't be acquired and wait_policy is skip
 *
 * In the failure cases other than TM_Invisible and TM_Deleted, the routine
 * fills *tmfd with the tuple's t_ctid, t_xmax, and, if possible, t_cmax.  See
 * comments for struct TM_FailureData for additional info.
 */
static inline TM_Result
table_lock_tuple(Relation rel, ItemPointer tid, Snapshot snapshot,
				 TupleTableSlot *slot, CommandId cid, LockTupleMode mode,
				 LockWaitPolicy wait_policy, uint8 flags,
				 TM_FailureData *tmfd)
{
	return rel->rd_tableam->tuple_lock(rel, tid, snapshot, slot,
									   cid, mode, wait_policy,
									   flags, tmfd);
}

/*
 * Perform operations necessary to complete insertions made via
 * tuple_insert and multi_insert with a BulkInsertState specified. This
 * e.g. may e.g. used to flush the relation when inserting with
 * TABLE_INSERT_SKIP_WAL specified.
 */
static inline void
table_finish_bulk_insert(Relation rel, int options)
{
	/* optional callback */
	if (rel->rd_tableam && rel->rd_tableam->finish_bulk_insert)
		rel->rd_tableam->finish_bulk_insert(rel, options);
}


/* ------------------------------------------------------------------------
 * DDL related functionality.
 * ------------------------------------------------------------------------
 */

/*
 * Create a new relation filenode for `rel`, with persistence set to
 * `persistence`.
 *
 * This is used both during relation creation and various DDL operations to
 * create a new relfilenode that can be filled from scratch.
 *
 * *freezeXid, *minmulti are set to the xid / multixact horizon for the table
 * that pg_class.{relfrozenxid, relminmxid} have to be set to.
 */
static inline void
table_relation_set_new_filenode(Relation rel, char persistence,
								TransactionId *freezeXid,
								MultiXactId *minmulti)
{
	rel->rd_tableam->relation_set_new_filenode(rel, persistence,
											   freezeXid, minmulti);
}

/*
 * Remove all table contents from `rel`, in a non-transactional manner.
 * Non-transactional meaning that there's no need to support rollbacks. This
 * commonly only is used to perform truncations for relfilenodes created in the
 * current transaction.
 */
static inline void
table_relation_nontransactional_truncate(Relation rel)
{
	rel->rd_tableam->relation_nontransactional_truncate(rel);
}

/*
 * Copy data from `rel` into the new relfilenode `newrnode`. The new
 * relfilenode may not have storage associated before this function is
 * called. This is only supposed to be used for low level operations like
 * changing a relation's tablespace.
 */
static inline void
table_relation_copy_data(Relation rel, RelFileNode newrnode)
{
	rel->rd_tableam->relation_copy_data(rel, newrnode);
}

/*
 * Copy data from `OldHeap` into `NewHeap`, as part of a CLUSTER or VACUUM
 * FULL.
 *
 * If `use_sort` is true, the table contents are sorted appropriate for
 * `OldIndex`; if use_sort is false and OldIndex is not InvalidOid, the data
 * is copied in that index's order; if use_sort is false and OidIndex is
 * InvalidOid, no sorting is performed.
 *
 * OldestXmin, FreezeXid, MultiXactCutoff must be currently valid values for
 * the table.
 *
 * *num_tuples, *tups_vacuumed, *tups_recently_dead will contain statistics
 * computed while copying for the relation. Not all might make sense for every
 * AM.
 */
static inline void
table_relation_copy_for_cluster(Relation OldHeap, Relation NewHeap,
								Relation OldIndex,
								bool use_sort,
								TransactionId OldestXmin,
								TransactionId FreezeXid,
								MultiXactId MultiXactCutoff,
								double *num_tuples,
								double *tups_vacuumed,
								double *tups_recently_dead)
{
	OldHeap->rd_tableam->relation_copy_for_cluster(OldHeap, NewHeap, OldIndex,
												   use_sort, OldestXmin,
												   FreezeXid, MultiXactCutoff,
												   num_tuples, tups_vacuumed,
												   tups_recently_dead);
}

/*
 * Perform VACUUM on the relation. The VACUUM can be user-triggered or by
 * autovacuum. The specific actions performed by the AM will depend heavily on
 * the individual AM.

 * On entry a transaction needs to already been established, and the
 * table is locked with a ShareUpdateExclusive lock.
 *
 * Note that neither VACUUM FULL (and CLUSTER), nor ANALYZE go through this
 * routine, even if (for ANALYZE) it is part of the same VACUUM command.
 */
static inline void
table_relation_vacuum(Relation rel, struct VacuumParams *params,
					  BufferAccessStrategy bstrategy)
{
	rel->rd_tableam->relation_vacuum(rel, params, bstrategy);
}

/*
 * Prepare to analyze block `blockno` of `scan`. The scan needs to have been
 * started with table_beginscan_analyze().  Note that this routine might
 * acquire resources like locks that are held until
 * table_scan_analyze_next_tuple() returns false.
 *
 * Returns false if block is unsuitable for sampling, true otherwise.
 */
static inline bool
table_scan_analyze_next_block(TableScanDesc scan, BlockNumber blockno,
							  BufferAccessStrategy bstrategy)
{
	return scan->rs_rd->rd_tableam->scan_analyze_next_block(scan, blockno,
															bstrategy);
}

/*
 * Iterate over tuples in the block selected with
 * table_scan_analyze_next_block() (which needs to have returned true, and
 * this routine may not have returned false for the same block before). If a
 * tuple that's suitable for sampling is found, true is returned and a tuple
 * is stored in `slot`.
 *
 * *liverows and *deadrows are incremented according to the encountered
 * tuples.
 */
static inline bool
table_scan_analyze_next_tuple(TableScanDesc scan, TransactionId OldestXmin,
							  double *liverows, double *deadrows,
							  TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableam->scan_analyze_next_tuple(scan, OldestXmin,
															liverows, deadrows,
															slot);
}

/*
 * table_index_build_scan - scan the table to find tuples to be indexed
 *
 * This is called back from an access-method-specific index build procedure
 * after the AM has done whatever setup it needs.  The parent heap relation
 * is scanned to find tuples that should be entered into the index.  Each
 * such tuple is passed to the AM's callback routine, which does the right
 * things to add it to the new index.  After we return, the AM's index
 * build procedure does whatever cleanup it needs.
 *
 * The total count of live tuples is returned.  This is for updating pg_class
 * statistics.  (It's annoying not to be able to do that here, but we want to
 * merge that update with others; see index_update_stats.)  Note that the
 * index AM itself must keep track of the number of index tuples; we don't do
 * so here because the AM might reject some of the tuples for its own reasons,
 * such as being unable to store NULLs.
 *
 * If 'progress', the PROGRESS_SCAN_BLOCKS_TOTAL counter is updated when
 * starting the scan, and PROGRESS_SCAN_BLOCKS_DONE is updated as we go along.
 *
 * A side effect is to set indexInfo->ii_BrokenHotChain to true if we detect
 * any potentially broken HOT chains.  Currently, we set this if there are any
 * RECENTLY_DEAD or DELETE_IN_PROGRESS entries in a HOT chain, without trying
 * very hard to detect whether they're really incompatible with the chain tip.
 * This only really makes sense for heap AM, it might need to be generalized
 * for other AMs later.
 */
static inline double
table_index_build_scan(Relation heap_rel,
					   Relation index_rel,
					   struct IndexInfo *index_nfo,
					   bool allow_sync,
					   bool progress,
					   IndexBuildCallback callback,
					   void *callback_state,
					   TableScanDesc scan)
{
	return heap_rel->rd_tableam->index_build_range_scan(heap_rel,
														index_rel,
														index_nfo,
														allow_sync,
														false,
														progress,
														0,
														InvalidBlockNumber,
														callback,
														callback_state,
														scan);
}

/*
 * As table_index_build_scan(), except that instead of scanning the complete
 * table, only the given number of blocks are scanned.  Scan to end-of-rel can
 * be signalled by passing InvalidBlockNumber as numblocks.  Note that
 * restricting the range to scan cannot be done when requesting syncscan.
 *
 * When "anyvisible" mode is requested, all tuples visible to any transaction
 * are indexed and counted as live, including those inserted or deleted by
 * transactions that are still in progress.
 */
static inline double
table_index_build_range_scan(Relation heap_rel,
							 Relation index_rel,
							 struct IndexInfo *index_nfo,
							 bool allow_sync,
							 bool anyvisible,
							 bool progress,
							 BlockNumber start_blockno,
							 BlockNumber numblocks,
							 IndexBuildCallback callback,
							 void *callback_state,
							 TableScanDesc scan)
{
	return heap_rel->rd_tableam->index_build_range_scan(heap_rel,
														index_rel,
														index_nfo,
														allow_sync,
														anyvisible,
														progress,
														start_blockno,
														numblocks,
														callback,
														callback_state,
														scan);
}

/*
 * table_index_validate_scan - second table scan for concurrent index build
 *
 * See validate_index() for an explanation.
 */
static inline void
table_index_validate_scan(Relation heap_rel,
						  Relation index_rel,
						  struct IndexInfo *index_info,
						  Snapshot snapshot,
						  struct ValidateIndexState *state)
{
	heap_rel->rd_tableam->index_validate_scan(heap_rel,
											  index_rel,
											  index_info,
											  snapshot,
											  state);
}


/* ----------------------------------------------------------------------------
 * Planner related functionality
 * ----------------------------------------------------------------------------
 */

/*
 * Estimate the current size of the relation, as an AM specific workhorse for
 * estimate_rel_size(). Look there for an explanation of the parameters.
 */
static inline void
table_relation_estimate_size(Relation rel, int32 *attr_widths,
							 BlockNumber *pages, double *tuples,
							 double *allvisfrac)
{
	rel->rd_tableam->relation_estimate_size(rel, attr_widths, pages, tuples,
											allvisfrac);
}


/* ----------------------------------------------------------------------------
 * Executor related functionality
 * ----------------------------------------------------------------------------
 */

/*
 * Prepare to fetch / check / return tuples from `tbmres->blockno` as part of
 * a bitmap table scan. `scan` needs to have been started via
 * table_beginscan_bm(). Returns false if there are no tuples to be found on
 * the page, true otherwise.
 *
 * Note, this is an optionally implemented function, therefore should only be
 * used after verifying the presence (at plan time or such).
 */
static inline bool
table_scan_bitmap_next_block(TableScanDesc scan,
							 struct TBMIterateResult *tbmres)
{
	return scan->rs_rd->rd_tableam->scan_bitmap_next_block(scan,
														   tbmres);
}

/*
 * Fetch the next tuple of a bitmap table scan into `slot` and return true if
 * a visible tuple was found, false otherwise.
 * table_scan_bitmap_next_block() needs to previously have selected a
 * block (i.e. returned true), and no previous
 * table_scan_bitmap_next_tuple() for the same block may have
 * returned false.
 */
static inline bool
table_scan_bitmap_next_tuple(TableScanDesc scan,
							 struct TBMIterateResult *tbmres,
							 TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableam->scan_bitmap_next_tuple(scan,
														   tbmres,
														   slot);
}

/*
 * Prepare to fetch tuples from the next block in a sample scan. Returns false
 * if the sample scan is finished, true otherwise. `scan` needs to have been
 * started via table_beginscan_sampling().
 *
 * This will call the TsmRoutine's NextSampleBlock() callback if necessary
 * (i.e. NextSampleBlock is not NULL), or perform a sequential scan over the
 * underlying relation.
 */
static inline bool
table_scan_sample_next_block(TableScanDesc scan,
							 struct SampleScanState *scanstate)
{
	return scan->rs_rd->rd_tableam->scan_sample_next_block(scan, scanstate);
}

/*
 * Fetch the next sample tuple into `slot` and return true if a visible tuple
 * was found, false otherwise. table_scan_sample_next_block() needs to
 * previously have selected a block (i.e. returned true), and no previous
 * table_scan_sample_next_tuple() for the same block may have returned false.
 *
 * This will call the TsmRoutine's NextSampleTuple() callback.
 */
static inline bool
table_scan_sample_next_tuple(TableScanDesc scan,
							 struct SampleScanState *scanstate,
							 TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableam->scan_sample_next_tuple(scan, scanstate,
														   slot);
}


/* ----------------------------------------------------------------------------
 * Functions to make modifications a bit simpler.
 * ----------------------------------------------------------------------------
 */

extern void simple_table_insert(Relation rel, TupleTableSlot *slot);
extern void simple_table_delete(Relation rel, ItemPointer tid,
					Snapshot snapshot);
extern void simple_table_update(Relation rel, ItemPointer otid,
					TupleTableSlot *slot, Snapshot snapshot,
					bool *update_indexes);


/* ----------------------------------------------------------------------------
 * Helper functions to implement parallel scans for block oriented AMs.
 * ----------------------------------------------------------------------------
 */

extern Size table_block_parallelscan_estimate(Relation rel);
extern Size table_block_parallelscan_initialize(Relation rel,
									ParallelTableScanDesc pscan);
extern void table_block_parallelscan_reinitialize(Relation rel,
									  ParallelTableScanDesc pscan);
extern BlockNumber table_block_parallelscan_nextpage(Relation rel,
								  ParallelBlockTableScanDesc pbscan);
extern void table_block_parallelscan_startblock_init(Relation rel,
										 ParallelBlockTableScanDesc pbscan);


/* ----------------------------------------------------------------------------
 * Functions in tableamapi.c
 * ----------------------------------------------------------------------------
 */

extern const TableAmRoutine *GetTableAmRoutine(Oid amhandler);
extern const TableAmRoutine *GetHeapamTableAmRoutine(void);
extern bool check_default_table_access_method(char **newval, void **extra,
								  GucSource source);

/* ----------------------------------------------------------------------------
 * Functions common to heap and zheap
 * ----------------------------------------------------------------------------
 */
typedef struct BulkInsertStateData *BulkInsertState;

extern bool heap_acquire_tuplock(Relation relation, ItemPointer tid,
				LockTupleMode mode, LockWaitPolicy wait_policy,
				bool *have_tuple_lock);
extern void GetVisibilityMapPins(Relation relation, Buffer buffer1,
				Buffer buffer2, BlockNumber block1, BlockNumber block2,
				Buffer *vmbuffer1, Buffer *vmbuffer2);
extern void RelationAddExtraBlocks(Relation relation, BulkInsertState bistate);
extern Buffer ReadBufferBI(Relation relation, BlockNumber targetBlock,
				ReadBufferMode mode, BulkInsertState bistate);

#endif							/* TABLEAM_H */
