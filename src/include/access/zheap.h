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
 * Additional bits used from page header for zheap specific pages.
 * See PageHeaderData.  We have considered to store these special flags
 * in zheap specific pages, but the pages have different structures for
 * special space which makes it inconvineint to store these flags.
 */
#define PD_PAGE_HAS_TPD_SLOT				0x0008

#define PD_ZHEAP_VALID_FLAG_BITS	0x000F	/* OR of all valid pd_flags bits */

#define ZHeapPageHasTPDSlot(phdr) \
( \
  ((phdr)->pd_flags & PD_PAGE_HAS_TPD_SLOT) != 0 \
)

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
typedef struct ZHeapMetaPageData
{
	uint32          zhm_magic;      /* magic no. for zheap tables */
	uint32          zhm_version;    /* version ID */
	uint32          zhm_first_used_tpd_page;
	uint32          zhm_last_used_tpd_page;
} ZHeapMetaPageData;

typedef ZHeapMetaPageData *ZHeapMetaPage;

#define ZHEAP_METAPAGE 0               /* metapage is always block 0 */
#define ZHEAP_MAGIC            0xA056
#define ZHEAP_VERSION  1

#define ZHeapPageGetMeta(page) \
		((ZHeapMetaPage) PageGetContents(page))

extern void zheap_init_meta_page(Buffer metabuf, BlockNumber first_blkno,
					BlockNumber last_blkno);
extern void ZheapInitMetaPage(Relation rel, ForkNumber forkNum);
extern bool zheap_exec_pending_rollback(Relation rel, Buffer buffer,
										int slot_no, TransactionId xwait);
extern Oid zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate);
extern void simple_zheap_delete(Relation relation, ItemPointer tid, Snapshot snapshot);
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
extern int PageReserveTransactionSlot(Relation relation, Buffer buf,
									  OffsetNumber offset, uint32 epoch,
									  TransactionId xid, UndoRecPtr *urec_ptr,
									  bool *lock_reacquired);
extern int PageGetTransactionSlotId(Relation rel, Buffer buf, uint32 epoch,
									TransactionId xid, UndoRecPtr *urec_ptr,
									bool keepTPDBufLock, bool locktpd);
extern void PageGetTransactionSlotInfo(Buffer buf, int slot_no,
									   uint32 *epoch, TransactionId *xid,
									   UndoRecPtr *urec_ptr,
									   bool keepTPDBufLock);

extern void ZheapInitPage(Page page, Size pageSize);
extern void zheap_multi_insert(Relation relation, ZHeapTuple *tuples,
								int ntuples, CommandId cid, int options,
								BulkInsertState bistate);
extern void zheap_get_latest_tid(Relation relation,
					 Snapshot snapshot,
					 ItemPointer tid);
extern XLogRecPtr log_zheap_visible(RelFileNode rnode, Buffer heap_buffer,
							Buffer vm_buf, TransactionId cutoff_xid, uint8 flags);
extern void PageSetTransactionSlotInfo(Buffer buf, int trans_slot_id,
					uint32 epoch, TransactionId xid, UndoRecPtr urec_ptr);
extern void PageSetUNDO(UnpackedUndoRecord undorecord, Buffer buffer,
				int trans_slot_id, bool set_tpd_map_slot, uint32 epoch,
				TransactionId xid, UndoRecPtr urecptr, OffsetNumber *usedoff,
				int ucnt);
extern UndoRecPtr PageGetUNDO(Page page, int trans_slot_id);

/* Pruning related API's (prunezheap.c) */
extern bool zheap_page_prune_opt(Relation relation, Buffer buffer,
								 OffsetNumber offnum, Size space_required);
extern int zheap_page_prune_guts(Relation relation, Buffer buffer,
								 TransactionId OldestXmin, OffsetNumber target_offnum,
								 Size space_required, bool report_stats, bool force_prune,
								 TransactionId *latestRemovedXid, bool *pruned);
extern void zheap_page_prune_execute(Buffer buffer, OffsetNumber target_offnum,
						OffsetNumber *deleted, int ndeleted,
						OffsetNumber *nowdead, int ndead,
						OffsetNumber *nowunused, int nunused);
extern XLogRecPtr log_zheap_clean(Relation reln, Buffer buffer,
								  OffsetNumber target_offnum, Size space_required,
								  OffsetNumber *nowdeleted, int ndeleted,
								  OffsetNumber *nowdead, int ndead,
								  OffsetNumber *nowunused, int nunused,
								  TransactionId latestRemovedXid, bool pruned);
extern void ZPageRepairFragmentation(Buffer buffer, Page tmppage, OffsetNumber target_offnum,
							Size space_required, bool *pruned);
extern void compactify_ztuples(itemIdSort itemidbase, int nitems, Page page,
							Page tmppage);

/* Zheap scan related API's */
extern bool zheapgetpage(HeapScanDesc scan, BlockNumber page);
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
extern void ZHeapTupleHeaderAdvanceLatestRemovedXid(ZHeapTupleHeader tuple,
						TransactionId xid, TransactionId *latestRemovedXid);
extern void zheap_freeze_or_invalidate_tuples(Buffer buf, int nSlots, int *slots,
											  bool isFrozen, bool TPDSlot);
extern bool PageFreezeTransSlots(Relation relation, Buffer buf,
								 bool *lock_reacquired, TransInfo *transinfo,
								 int num_slots);
extern void GetCompletedSlotOffsets(Page page, int nCompletedXactSlots,
									int *completed_slots,
									OffsetNumber *offset_completed_slots,
									int	*numOffsets);
extern TransactionId zheap_fetchinsertxid(ZHeapTuple zhtup, Buffer buffer);

/* Zheap and undo record interaction related API's */
extern ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						int *trans_slot_id, CommandId *cid, bool free_zhtup);
extern bool
ZHeapSatisfyUndoRecord(UnpackedUndoRecord* uurec, BlockNumber blkno,
								OffsetNumber offset, TransactionId xid);
extern bool
ValidateTuplesXact(ZHeapTuple tuple, Snapshot snapshot, Buffer buf,
					TransactionId priorXmax, bool nobuflock);
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
