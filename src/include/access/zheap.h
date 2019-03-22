/*-------------------------------------------------------------------------
 *
 * zheap.h
 *	  POSTGRES zheap header definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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
#include "access/tableam.h"
#include "access/undoinsert.h"
#include "access/zhtup.h"
#include "storage/smgr.h"
#include "utils/rel.h"
#include "utils/snapshot.h"

/*
 * Threshold for the number of blocks till which non-inplace updates due to
 * reuse of transaction slot or use of TPD slots are allowed.  The performance
 * testing on various sizes of tables indicate that threshold of 200 is good
 * enough to keep the contention on transaction slots under control.
 */
#define		NUM_BLOCKS_FOR_NON_INPLACE_UPDATES 200

/*
 * Additional bits used from page header for zheap specific pages.
 * See PageHeaderData.  We have considered to store these special flags
 * in zheap specific pages, but the pages have different structures for
 * special space which makes it inconvenient to store these flags.
 */
#define PD_PAGE_HAS_TPD_SLOT				0x0008

#define PD_ZHEAP_VALID_FLAG_BITS	0x000F	/* OR of all valid pd_flags bits */

#define ZHeapPageHasTPDSlot(phdr) \
( \
  ((phdr)->pd_flags & PD_PAGE_HAS_TPD_SLOT) != 0 \
)

/*
 * We need TransactionId and undo pointer to retrieve the undo information
 * for a particular transaction.  Xid's epoch is primarily required to check
 * if the xid is from current epoch.
 */
typedef struct TransInfo
{
	uint32		xid_epoch;
	TransactionId xid;
	UndoRecPtr	urec_ptr;
}			TransInfo;

typedef struct ZHeapPageOpaqueData
{
	TransInfo	transinfo[1];
}			ZHeapPageOpaqueData;

typedef ZHeapPageOpaqueData * ZHeapPageOpaque;

#define SizeOfZHeapPageOpaqueData (ZHEAP_PAGE_TRANS_SLOTS \
										 * sizeof(TransInfo))
typedef struct ZHeapMetaPageData
{
	uint32		zhm_magic;		/* magic number for zheap tables */
	uint32		zhm_version;	/* version ID */
	uint32		zhm_first_used_tpd_page;
	uint32		zhm_last_used_tpd_page;
}			ZHeapMetaPageData;

typedef ZHeapMetaPageData * ZHeapMetaPage;

#define ZHEAP_METAPAGE 0		/* metapage is always block 0 */
#define ZHEAP_MAGIC            0xA056
#define ZHEAP_VERSION  1

#define ZHeapPageGetMeta(page) \
		((ZHeapMetaPage) PageGetContents(page))

/* "options" flag bits for heap_insert */
#define ZHEAP_INSERT_SKIP_WAL	TABLE_INSERT_SKIP_WAL
#define ZHEAP_INSERT_SKIP_FSM	TABLE_INSERT_SKIP_FSM
#define ZHEAP_INSERT_FROZEN		TABLE_INSERT_FROZEN
#define ZHEAP_INSERT_NO_LOGICAL	TABLE_INSERT_NO_LOGICAL
#define ZHEAP_INSERT_SPECULATIVE 0x0010

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
	int			nranges;
}			ZHeapFreeOffsetRanges;

extern void zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate, uint32 specToken);
extern void simple_zheap_delete(Relation relation, ItemPointer tid, Snapshot snapshot);
extern TM_Result zheap_delete(Relation relation, ItemPointer tid,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot,
			 bool wait, TM_FailureData *tmfd, bool changingPart);
extern TM_Result zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
			 TM_FailureData *tmfd, LockTupleMode *lockmode);
extern TM_Result zheap_lock_tuple(Relation relation, ItemPointer tid,
				 CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
				 bool follow_updates, bool eval, Snapshot snapshot,
				 ZHeapTuple tuple, Buffer *buffer, TM_FailureData *tmfd);
extern void zheap_finish_speculative(Relation relation, ItemPointer tid);
extern void zheap_abort_speculative(Relation relation, ItemPointer tid);
extern int PageReserveTransactionSlot(Relation relation, Buffer buf,
						   OffsetNumber offset, uint32 epoch,
						   TransactionId xid, UndoRecPtr *ureptr,
						   bool *lock_reacquired,
						   bool extend_if_required,
						   bool use_aborted_slot,
						   bool *slot_reused_or_TPD_slot);
extern void MultiPageReserveTransSlot(Relation relation,
						  Buffer oldbuf, Buffer newbuf,
						  OffsetNumber oldbuf_offnum,
						  OffsetNumber newbuf_offnum,
						  uint32 epoch, TransactionId xid,
						  UndoRecPtr *oldbuf_prev_urecptr,
						  UndoRecPtr *newbuf_prev_urecptr,
						  int *oldbuf_trans_slot_id,
						  int *newbuf_trans_slot_id,
						  bool *lock_reacquired);
extern int PageGetTransactionSlotId(Relation rel, Buffer buf, uint32 epoch,
						 TransactionId xid, UndoRecPtr *urec_ptr,
						 bool keepTPDBufLock, bool locktpd,
						 bool *tpd_page_locked);
extern void PageGetTransactionSlotInfo(Buffer buf, int slot_no,
						   uint32 *epoch, TransactionId *xid,
						   UndoRecPtr *urec_ptr,
						   bool keepTPDBufLock);
extern TransInfo * GetTransactionsSlotsForPage(Relation rel, Buffer buf,
											   int *total_trans_slots,
											   BlockNumber *tpd_blkno);

struct TupleTableSlot;
extern void zheap_multi_insert(Relation relation, struct TupleTableSlot **slots,
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
extern void ZHeapTupleHeaderAdvanceLatestRemovedXid(ZHeapTupleHeader tuple,
										TransactionId xid, TransactionId *latestRemovedXid);
extern void zheap_freeze_or_invalidate_tuples(Buffer buf, int nSlots, int *slots,
								  bool isFrozen, bool TPDSlot);
extern bool PageFreezeTransSlots(Relation relation, Buffer buf,
					 bool *lock_reacquired, TransInfo * transinfo,
					 int num_slots, bool use_aborted_slot);
extern TransactionId zheap_fetchinsertxid(ZHeapTuple zhtup, Buffer buffer);
extern void copy_zrelation_data(Relation srcRel, SMgrRelation dst);
extern TransactionId zheap_compute_xid_horizon_for_tuples(Relation rel,
									 ItemPointerData *tids, int nitems);
extern UndoRecPtr zheap_prepare_undoinsert(Oid reloid, BlockNumber blkno,
						 OffsetNumber offnum, UndoRecPtr prev_urecptr,
						 FullTransactionId fxid, CommandId cid, uint32 specToken,
						 UndoPersistence undo_persistence, bool specIns,
						 UnpackedUndoRecord *undorecord,
						 XLogReaderState *xlog_record,
						 xl_undolog_meta * undometa);

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
						 Size space_required, bool NoTPDBufLock, bool *pruned,
						 bool unused_set);
extern void compactify_ztuples(itemIdSort itemidbase, int nitems, Page page,
				   Page tmppage);

/* Page related API's (zpage.c). */
#define ZPageAddItem(buffer, input_page, item, size, offsetNumber, overwrite, is_heap, NoTPDBufLock) \
	ZPageAddItemExtended(buffer, input_page, item, size, offsetNumber, \
						 ((overwrite) ? PAI_OVERWRITE : 0) | \
						 ((is_heap) ? PAI_IS_HEAP : 0), \
						 NoTPDBufLock)

extern OffsetNumber ZPageAddItemExtended(Buffer buffer, Page input_page,
					 Item item, Size size, OffsetNumber offsetNumber,
					 int flags, bool NoTPDBufLock);
extern Size PageGetZHeapFreeSpace(Page page);
extern void RelationPutZHeapTuple(Relation relation, Buffer buffer,
					  ZHeapTuple tuple);
extern ZHeapFreeOffsetRanges * ZHeapGetUsableOffsetRanges(Buffer buffer,
														  ZHeapTuple * tuples, int ntuples, Size saveFreeSpace);
extern void ZheapInitPage(Page page, Size pageSize);
extern void zheap_init_meta_page(Buffer metabuf, BlockNumber first_blkno,
					 BlockNumber last_blkno);
extern void ZheapInitMetaPage(Relation rel, ForkNumber forkNum, bool already_exists);

/* Zheap and undo record interaction related API's (zundo.c) */
extern bool ZHeapSatisfyUndoRecord(UnpackedUndoRecord *uurec, BlockNumber blkno,
					   OffsetNumber offset, TransactionId xid);
extern ZHeapTuple CopyTupleFromUndoRecord(UnpackedUndoRecord *urec,
										  ZHeapTuple zhtup, int *trans_slot_id,
										  CommandId *cid, bool free_zhtup,
										  Page page);
extern bool ValidateTuplesXact(ZHeapTuple tuple, Snapshot snapshot, Buffer buf,
				   TransactionId priorXmax, bool nobuflock);
extern bool zheap_exec_pending_rollback(Relation rel, Buffer buffer,
							int slot_no, TransactionId xwait);
extern void zbuffer_exec_pending_rollback(Relation rel, Buffer buf,
							  BlockNumber *tpd_blkno);

/* in zheap/zvacuumlazy.c */
struct VacuumParams;
extern void lazy_vacuum_zheap_rel(Relation onerel, struct VacuumParams *params,
					  BufferAccessStrategy bstrategy);

/* in zheap/zundo.c */
extern bool zheap_undo_actions(List *luinfo, UndoRecPtr urec_ptr, Oid reloid,
				   TransactionId xid, BlockNumber blkno,
				   bool blk_chain_complete, bool rellock);


#endif							/* ZHEAP_H */
