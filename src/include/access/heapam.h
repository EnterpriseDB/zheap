/*-------------------------------------------------------------------------
 *
 * heapam.h
 *	  POSTGRES heap access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/heapam.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef HEAPAM_H
#define HEAPAM_H

#include "access/genham.h"
#include "nodes/lockoptions.h"
#include "nodes/primnodes.h"
#include "storage/bufpage.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"


/* "options" flag bits for heap_insert */
#define HEAP_INSERT_SKIP_WAL	0x0001
#define HEAP_INSERT_SKIP_FSM	0x0002
#define HEAP_INSERT_FROZEN		0x0004
#define HEAP_INSERT_SPECULATIVE 0x0008
#define HEAP_INSERT_NO_LOGICAL	0x0010

typedef struct BulkInsertStateData *BulkInsertState;

struct TupleTableSlot;

/* struct definition is private to rewriteheap.c */
typedef struct RewriteStateData *RewriteState;

/* ----------------
 *		function prototypes for heap access method
 *
 * heap_create, heap_create_with_catalog, and heap_drop_with_catalog
 * are declared in catalog/heap.h
 * ----------------
 */

/* in heap/heapam.c */
extern Relation relation_open(Oid relationId, LOCKMODE lockmode);
extern Relation try_relation_open(Oid relationId, LOCKMODE lockmode);
extern Relation relation_openrv(const RangeVar *relation, LOCKMODE lockmode);
extern Relation relation_openrv_extended(const RangeVar *relation,
						 LOCKMODE lockmode, bool missing_ok);
extern void relation_close(Relation relation, LOCKMODE lockmode);

extern Relation heap_open(Oid relationId, LOCKMODE lockmode);
extern Relation heap_openrv(const RangeVar *relation, LOCKMODE lockmode);
extern Relation heap_openrv_extended(const RangeVar *relation,
					 LOCKMODE lockmode, bool missing_ok);

#define heap_close(r,l)  relation_close(r,l)

/* struct definitions appear in relscan.h */
typedef struct TableScanDescData *TableScanDesc;
typedef struct HeapScanDescData *HeapScanDesc;
typedef struct ParallelTableScanDescData *ParallelTableScanDesc;

/*
 * HeapScanIsValid
 *		True iff the heap scan is valid.
 */
#define HeapScanIsValid(scan) PointerIsValid(scan)

extern TableScanDesc heap_beginscan(Relation relation, Snapshot snapshot,
			   int nkeys, ScanKey key,
			   ParallelTableScanDesc parallel_scan,
			   bool allow_strat,
			   bool allow_sync,
			   bool allow_pagemode,
			   bool is_bitmapscan,
			   bool is_samplescan,
			   bool temp_snap);
extern void heap_setscanlimits(TableScanDesc scan, BlockNumber startBlk,
				   BlockNumber endBlk);
extern void heapgetpage(TableScanDesc scan, BlockNumber page);
extern void heap_rescan(TableScanDesc scan, ScanKey key, bool set_params,
			bool allow_strat, bool allow_sync, bool allow_pagemode);
extern void heap_rescan_set_params(TableScanDesc scan, ScanKey key,
					   bool allow_strat, bool allow_sync, bool allow_pagemode);

extern void heap_endscan(TableScanDesc scan);
extern HeapTuple heap_getnext(TableScanDesc scan, ScanDirection direction);
extern struct TupleTableSlot *heap_getnextslot(TableScanDesc sscan, ScanDirection direction,
				 struct TupleTableSlot *slot);
extern HeapTuple heap_scan_getnext(TableScanDesc sscan, ScanDirection direction);

extern bool heap_fetch(Relation relation, ItemPointer tid, Snapshot snapshot,
		   HeapTuple tuple, Buffer *userbuf,
		   Relation stats_relation);
extern bool heap_hot_search_buffer(ItemPointer tid, Relation relation,
					   Buffer buffer, Snapshot snapshot, HeapTuple heapTuple,
					   bool *all_dead, bool first_call);
extern bool heap_hot_search(ItemPointer tid, Relation relation,
				Snapshot snapshot, bool *all_dead);
extern void heap_get_latest_tid(Relation relation, Snapshot snapshot,
					ItemPointer tid);
extern void setLastTid(const ItemPointer tid);

extern BulkInsertState GetBulkInsertState(void);
extern void FreeBulkInsertState(BulkInsertState bistate);
extern void ReleaseBulkInsertStatePin(BulkInsertState bistate);

extern void heap_insert(Relation relation, HeapTuple tup, CommandId cid,
			int options, BulkInsertState bistate);
extern void heap_multi_insert(Relation relation, struct TupleTableSlot **slots, int ntuples,
				  CommandId cid, int options, BulkInsertState bistate);
extern HTSU_Result heap_delete(Relation relation, ItemPointer tid,
			CommandId cid, Snapshot crosscheck, bool wait,
			HeapUpdateFailureData *hufd, bool changingPart);
extern void heap_finish_speculative(Relation relation, HeapTuple tuple);
extern void heap_abort_speculative(Relation relation, HeapTuple tuple);
extern HTSU_Result heap_update(Relation relation, ItemPointer otid,
			HeapTuple newtup,
			CommandId cid, Snapshot crosscheck, bool wait,
			HeapUpdateFailureData *hufd, LockTupleMode *lockmode);
extern HTSU_Result heap_lock_tuple(Relation relation, ItemPointer tid,
				CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
				bool follow_update, HeapTuple tuple,
				Buffer *buffer, HeapUpdateFailureData *hufd);

extern void heap_inplace_update(Relation relation, HeapTuple tuple);
extern bool heap_freeze_tuple(HeapTupleHeader tuple,
				  TransactionId relfrozenxid, TransactionId relminmxid,
				  TransactionId cutoff_xid, TransactionId cutoff_multi);
extern bool heap_tuple_needs_freeze(HeapTupleHeader tuple, TransactionId cutoff_xid,
						MultiXactId cutoff_multi, Buffer buf);
extern bool heap_tuple_needs_eventual_freeze(HeapTupleHeader tuple);

extern void simple_heap_insert(Relation relation, HeapTuple tup);
extern void simple_heap_delete(Relation relation, ItemPointer tid);
extern void simple_heap_update(Relation relation, ItemPointer otid,
				   HeapTuple tup);

extern void heap_sync(Relation relation);
extern void heap_update_snapshot(TableScanDesc scan, Snapshot snapshot);

extern TransactionId heap_compute_xid_horizon_for_tuples(Relation rel,
														 ItemPointerData *items,
														 int nitems);

/* in heap/pruneheap.c */
extern void heap_page_prune_opt(Relation relation, Buffer buffer);
extern int heap_page_prune(Relation relation, Buffer buffer,
				TransactionId OldestXmin,
				bool report_stats, TransactionId *latestRemovedXid);
extern void heap_page_prune_execute(Buffer buffer,
						OffsetNumber *redirected, int nredirected,
						OffsetNumber *nowdead, int ndead,
						OffsetNumber *nowunused, int nunused);
extern void heap_get_root_tuples(Page page, OffsetNumber *root_offsets);

/* in heap/syncscan.c */
extern void ss_report_location(Relation rel, BlockNumber location);
extern BlockNumber ss_get_location(Relation rel, BlockNumber relnblocks);
extern void SyncScanShmemInit(void);
extern Size SyncScanShmemSize(void);

/* in heap/vacuumlazy.c */
struct VacuumParams;
extern void heap_vacuum_rel(Relation onerel, int options,
				struct VacuumParams *params, BufferAccessStrategy bstrategy);

/* in heap/heapam_visibility.c */
extern bool HeapTupleSatisfies(HeapTuple stup, Snapshot snapshot, Buffer buffer);
extern HTSU_Result HeapTupleSatisfiesUpdate(HeapTuple stup, CommandId curcid,
						 Buffer buffer);
extern HTSV_Result HeapTupleSatisfiesVacuum(HeapTuple stup, TransactionId OldestXmin,
						 Buffer buffer);
extern void HeapTupleSetHintBits(HeapTupleHeader tuple, Buffer buffer,
					 uint16 infomask, TransactionId xid);
extern bool HeapTupleHeaderIsOnlyLocked(HeapTupleHeader tuple);
extern bool XidInMVCCSnapshot(TransactionId xid, Snapshot snapshot);
extern bool HeapTupleIsSurelyDead(HeapTuple htup, TransactionId OldestXmin);

/* in heap/rewriteheap.c */
extern RewriteState begin_heap_rewrite(Relation OldHeap, Relation NewHeap,
				   TransactionId OldestXmin, TransactionId FreezeXid,
				   MultiXactId MultiXactCutoff, bool use_wal);
extern void end_heap_rewrite(RewriteState state);
extern void rewrite_heap_tuple(RewriteState state, HeapTuple oldTuple,
				   HeapTuple newTuple);
extern bool rewrite_heap_dead_tuple(RewriteState state, HeapTuple oldTuple);

#endif							/* HEAPAM_H */
