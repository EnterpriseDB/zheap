/*-------------------------------------------------------------------------
 *
 * zheap.h
 *	  POSTGRES zheap header definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheap.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHEAP_H
#define ZHEAP_H

#include "postgres.h"

#include "access/genham.h"
#include "access/hio.h"
#include "access/undoinsert.h"
#include "access/zhtup.h"
#include "utils/rel.h"
#include "utils/snapshot.h"

/*
 * We need tansactionid and undo pointer to retrieve the undo information
 * for a particular transaction.  Xid's epoch is primarily required to check
 * if the xid is from current epoch.
 */
typedef struct TransInfo
{
	uint32		xid_epoch;
	TransactionId	xid;
	UndoRecPtr	urec_ptr;
} TransInfo;

typedef struct ZHeapPageOpaqueData
{
	TransInfo	transinfo[1];
} ZHeapPageOpaqueData;

typedef ZHeapPageOpaqueData *ZHeapPageOpaque;

#define SizeOfZHeapPageOpaqueData (ZHEAP_PAGE_TRANS_SLOTS \
										 * sizeof(TransInfo))

extern Oid zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate);
extern HTSU_Result zheap_delete(Relation relation, ItemPointer tid,
						CommandId cid, Snapshot crosscheck, Snapshot snapshot,
						bool wait, HeapUpdateFailureData *hufd);
extern HTSU_Result zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
					CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
					HeapUpdateFailureData *hufd, LockTupleMode *lockmode);
extern HTSU_Result zheap_lock_tuple(Relation relation, ZHeapTuple tuple,
					CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
					bool follow_updates, bool eval, Snapshot snapshot,
					Buffer *buffer, HeapUpdateFailureData *hufd);
extern void zheap_finish_speculative(Relation relation, ZHeapTuple tuple);
extern void zheap_abort_speculative(Relation relation, ZHeapTuple tuple);
extern void ZheapInitPage(Page page, Size pageSize);
extern void zheap_multi_insert(Relation relation, ZHeapTuple *tuples,
								int ntuples, CommandId cid, int options,
								BulkInsertState bistate);
extern void zheap_get_latest_tid(Relation relation,
					 Snapshot snapshot,
					 ItemPointer tid);
extern void PageSetUNDO(UnpackedUndoRecord undorecord, Page page, int trans_slot_id,
						uint32 epoch, TransactionId xid, UndoRecPtr urecptr);
extern void ZHeapTupleHeaderAdvanceLatestRemovedXid(ZHeapTupleHeader tuple,
						TransactionId xid, TransactionId *latestRemovedXid);
extern void zheap_page_prune_opt(Relation relation, Buffer buffer);
extern void zheap_page_prune_execute(Buffer buffer, OffsetNumber *deleted,
								int ndeleted, OffsetNumber *nowdead, int ndead,
								OffsetNumber *nowunused, int nunused);

/* Zheap scan related API's */
extern void zheapgetpage(HeapScanDesc scan, BlockNumber page);
extern void zheap_rescan(HeapScanDesc scan, ScanKey key);
extern void zheap_rescan_set_params(HeapScanDesc scan, ScanKey key,
					   bool allow_strat, bool allow_sync, bool allow_pagemode);
extern HeapScanDesc zheap_beginscan(Relation relation, Snapshot snapshot,
				int nkeys, ScanKey key);
extern HeapScanDesc zheap_beginscan_strat(Relation relation, Snapshot snapshot,
					int nkeys, ScanKey key,
					bool allow_strat, bool allow_sync);
extern HeapScanDesc zheap_beginscan_parallel(Relation, ParallelHeapScanDesc);
extern HeapScanDesc zheap_beginscan_sampling(Relation relation, Snapshot snapshot,
					int nkeys, ScanKey key,
					bool allow_strat, bool allow_sync, bool allow_pagemode);
extern ZHeapTuple zheap_getnext(HeapScanDesc scan, ScanDirection direction);
extern ZHeapTuple zheap_search_buffer(ItemPointer tid, Relation relation,
									  Buffer buffer, Snapshot snapshot,
									  bool *all_dead);
extern bool zheap_search(ItemPointer tid, Relation relation, Snapshot snapshot,
						 bool *all_dead);

extern bool zheap_fetch(Relation relation, Snapshot snapshot,
				ItemPointer tid, ZHeapTuple *tuple, Buffer *userbuf,
				bool keep_buf, Relation stats_relation);
extern bool zheap_fetch_undo(Relation relation, Snapshot snapshot,
				ItemPointer tid, ZHeapTuple *tuple, Buffer *userbuf,
				Relation stats_relation);
extern ZHeapTuple zheap_fetch_undo_guts(ZHeapTuple ztuple, Buffer buffer,
										ItemPointer tid);
extern void
ZHeapTupleHeaderAdvanceLatestRemovedXid(ZHeapTupleHeader tuple,
                                               TransactionId xid, TransactionId *latestRemovedXid);
extern void zheap_freeze_or_invalidate_tuples(Page page, int nSlots, int *slots,
											  bool isFrozen);

extern void GetCompletedSlotOffsets(Page page, int nCompletedXactSlots,
									int *completed_slots,
									OffsetNumber *offset_completed_slots,
									int	*numOffsets);

/* Zheap and undo record interaction related API's */
extern ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						bool free_zhtup);
extern bool
ZHeapSatisfyUndoRecord(UnpackedUndoRecord* uurec, BlockNumber blkno,
								OffsetNumber offset, TransactionId xid);
extern bool
ValidateTuplesXact(ZHeapTuple tuple, Snapshot snapshot, Buffer buf,
				   TransactionId priorXmax);
/*
 * Given a page, it stores contiguous ranges of free offsets that can be
 * used/reused in the same page. This is used in zheap_multi_insert to decide
 * the number of undo records needs to be prepared before entering into critical
 * section.
 */
typedef struct ZHeapFreeOffsetRanges
{
	OffsetNumber startOffset[MaxOffsetNumber];
	OffsetNumber endOffset[MaxOffsetNumber];
	int nranges;
} ZHeapFreeOffsetRanges;

#endif   /* ZHEAP_H */
