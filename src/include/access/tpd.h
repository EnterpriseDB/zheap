/*-------------------------------------------------------------------------
 *
 * tpd.h
 *	  POSTGRES TPD definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/tpd.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TPD_H
#define TPD_H

#include "postgres.h"

#include "access/xlogutils.h"
#include "access/zheap.h"
#include "storage/block.h"
#include "utils/rel.h"

/* TPD page information */
typedef struct TPDPageOpaqueData
{
	BlockNumber tpd_prevblkno;
	BlockNumber tpd_nextblkno;
	FullTransactionId tpd_latest_fxid;
} TPDPageOpaqueData;

typedef TPDPageOpaqueData *TPDPageOpaque;

#define SizeofTPDPageOpaque (offsetof(TPDPageOpaqueData, tpd_latest_fxid) + sizeof(FullTransactionId))

/*
 * IsTPDPage
 * 		returns true iff page is TPD page.
 */
#define IsTPDPage(page) \
	(PageGetSpecialSize(page) == MAXALIGN(sizeof(TPDPageOpaqueData)))

/* TPD entry information */
#define INITIAL_TRANS_SLOTS_IN_TPD_ENTRY	8
/*
 * Number of item to transaction slot mapping entries in addition to max
 * itemid's in heap page.  This is required to support newer inserts on the
 * page, otherwise, we might immediately need to allocate a new bigger TPD
 * entry.
 */
#define ADDITIONAL_MAP_ELEM_IN_TPD_ENTRY	8

typedef struct TPDEntryHeaderData
{
	BlockNumber blkno;			/* Heap block number to which this TPD entry
								 * belongs. */
	uint16		tpe_num_map_entries;
	uint16		tpe_num_slots;
	uint16		tpe_flags;
} TPDEntryHeaderData;

typedef TPDEntryHeaderData *TPDEntryHeader;

#define SizeofTPDEntryHeader (offsetof(TPDEntryHeaderData, tpe_flags) + sizeof(uint16))

#define	TPE_ONE_BYTE	0x0001
#define	TPE_FOUR_BYTE	0x0002
#define	TPE_DELETED		0x0004

#define	OFFSET_MASK	0x3FFFFF

#define TPDEntryIsDeleted(tpd_e_hdr) \
( \
	(tpd_e_hdr.tpe_flags & TPE_DELETED) != 0 \
)

/* Maximum size of one TPD entry. */
#define MaxTPDEntrySize \
	((int) (BLCKSZ - SizeOfPageHeaderData - SizeofTPDPageOpaque - sizeof(ItemIdData)))

/*
 * MaxTPDTuplesPerPage is an upper bound on the number of tuples that can
 * fit on one zheap page.
 */
#define MaxTPDTuplesPerPage	\
	((int) ((BLCKSZ - SizeOfPageHeaderData - SizeofTPDPageOpaque) / \
			(SizeofTPDEntryHeader  + sizeof(ItemIdData))))

extern OffsetNumber TPDPageAddEntry(Page tpdpage, char *tpd_entry, Size size,
									OffsetNumber offset);
extern void SetTPDLocation(Buffer heapbuffer, Buffer tpdbuffer, uint16 offset);
extern void ClearTPDLocation(Buffer heapbuf);
extern void TPDInitPage(Page page, Size pageSize);
extern bool TPDFreePage(Relation rel, Buffer buf, BufferAccessStrategy bstrategy);
extern void ReleaseLastTPDBufferByTPDBlock(BlockNumber tpdblk);
extern int	TPDAllocateAndReserveTransSlot(Relation relation, Buffer buf,
										   OffsetNumber offnum, UndoRecPtr *urec_ptr,
										   bool extend_if_required);
extern TransInfo *TPDPageGetTransactionSlots(Relation relation, Buffer heapbuf,
											 OffsetNumber offnum, bool keepTPDBufLock,
											 bool checkOffset, int *num_map_entries,
											 int *num_trans_slots, int *tpd_buf_id,
											 bool *tpd_e_pruned, bool *alloc_bigger_map,
											 bool clean_tpd_loc);
extern int	TPDPageReserveTransSlot(Relation relation, Buffer heapbuf,
									OffsetNumber offset, UndoRecPtr *urec_ptr,
									bool *lock_reacquired,
									bool always_extend, Buffer other_buf);
extern int	TPDPageGetSlotIfExists(Relation relation, Buffer heapbuf, OffsetNumber offnum,
								   FullTransactionId fxid, UndoRecPtr *urec_ptr,
								   bool keepTPDBufLock, bool checkOffset);
extern int	TPDPageGetTransactionSlotInfo(Buffer heapbuf, int trans_slot,
										  OffsetNumber offset, FullTransactionId *fxid,
										  UndoRecPtr *urec_ptr, bool NoTPDBufLock, bool keepTPDBufLock);
extern void TPDPageSetTransactionSlotInfo(Buffer heapbuf, int trans_slot_id,
										  FullTransactionId fxid, UndoRecPtr urec_ptr);
extern void TPDPageSetUndo(Buffer heapbuf, int trans_slot_id,
						   bool set_tpd_map_slot, FullTransactionId xid,
						   UndoRecPtr urec_ptr, OffsetNumber *usedoff, int ucnt);
extern void TPDPageSetOffsetMapSlot(Buffer heapbuf, int trans_slot_id,
									OffsetNumber offset);
extern void TPDPageGetOffsetMap(Buffer heapbuf, char *tpd_entry_data,
								int map_size);
extern int	TPDPageGetOffsetMapSize(Buffer heapbuf);
extern void TPDPageSetOffsetMap(Buffer heapbuf, char *tpd_offset_map);
extern bool TPDPageLock(Relation relation, Buffer heapbuf);
extern void GetTPDBlockAndOffset(Page heap_page, BlockNumber *tpd_blk,
								 OffsetNumber *tpd_item_off);
extern XLogRedoAction XLogReadTPDBuffer(XLogReaderState *record,
										uint8 block_id);
extern uint8 RegisterTPDBuffer(Page heappage, uint8 block_id);
extern void TPDPageSetLSN(Page heappage, XLogRecPtr recptr);
extern void UnlockReleaseTPDBuffers(void);
extern Size PageGetTPDFreeSpace(Page page);
extern void ResetRegisteredTPDBuffers(void);

/* interfaces exposed via prunetpd.c */
extern int	TPDPagePrune(Relation rel, Buffer tpdbuf, BufferAccessStrategy strategy,
						 OffsetNumber target_offnum, Size space_required, bool can_free,
						 bool *update_tpd_inplace, bool *tpd_e_pruned);
extern void TPDPagePruneExecute(Buffer tpdbuf, OffsetNumber *nowunused,
								int nunused);
extern void TPDPageRepairFragmentation(Page page, Page tmppage,
									   OffsetNumber target_offnum, Size space_required);

/* Reset globals related to TPD buffers. */
extern void ResetTPDBuffers(void);
#endif							/* TPD_H */
