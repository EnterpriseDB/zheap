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

#define MAX_PAGE_TRANS_INFO_SLOTS	4

/*
 * We need tansactionid and undo pointer to retrieve the undo information
 * for a particular transaction.
 */
typedef struct TransInfo
{
	TransactionId	xid;
	UndoRecPtr	urec_ptr;
} TransInfo;

typedef struct ZHeapPageOpaqueData
{
	TransInfo	transinfo[MAX_PAGE_TRANS_INFO_SLOTS];
} ZHeapPageOpaqueData;

typedef ZHeapPageOpaqueData *ZHeapPageOpaque;

extern Oid zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options);
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
extern void ZheapInitPage(Page page, Size pageSize);
extern void zheap_multi_insert(Relation relation, ZHeapTuple *tuples,
								int ntuples, CommandId cid, int options,
								BulkInsertState bistate);
extern void PageSetUNDO(UnpackedUndoRecord undorecord, Page page, int trans_slot_id,
						TransactionId xid, UndoRecPtr urecptr);

/* Zheap scan related API's */
extern HeapScanDesc zheap_beginscan(Relation relation, Snapshot snapshot,
				int nkeys, ScanKey key);
extern HeapScanDesc zheap_beginscan_strat(Relation relation, Snapshot snapshot,
					int nkeys, ScanKey key,
					bool allow_strat, bool allow_sync);
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
extern void MarkTupleFrozen(Page page, int nFrozenSlots, int *frozen_slots);

extern void GetCompletedSlotOffsets(Page page, int nCompletedXactSlots,
									int *completed_slots,
									OffsetNumber *offset_completed_slots,
									int	*numOffsets);

/* Zheap and undo record interaction related API's */
extern ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						bool free_zhtup);

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
