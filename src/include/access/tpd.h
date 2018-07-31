/*-------------------------------------------------------------------------
 *
 * tpd.h
 *	  POSTGRES TPD definitions.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
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
	uint32		tpd_latest_xid_epoch;
	TransactionId	tpd_latest_xid;
} TPDPageOpaqueData;

typedef TPDPageOpaqueData *TPDPageOpaque;

#define SizeofTPDPageOpaque offsetof(TPDPageOpaqueData, tpd_latest_xid)

/* TPD entry information */
#define INITIAL_TRANS_SLOTS_IN_TPD_ENTRY	8
/*
 * Number of item to trasaction slot mapping entries in addition to max
 * itemid's in heap page.  This is required to support newer inserts on the
 * page, otherwise, we might immediately need to allocate a new bigger TPD
 * entry.
 */
#define ADDITIONAL_MAP_ELEM_IN_TPD_ENTRY	8

typedef struct TPDEntryHeaderData
{
	uint16		tpe_num_map_entries;
	uint16		tpe_num_slots;
	uint16		tpe_flags;
} TPDEntryHeaderData;

typedef TPDEntryHeaderData *TPDEntryHeader;

#define SizeofTPDEntryHeader (offsetof(TPDEntryHeaderData, tpe_flags) + sizeof(uint16))

#define	TPE_ONE_BYTE	0x0001
#define	TPE_FOUR_BYTE	0x0002

#define	OFFSET_MASK	0x3FFFFF

#define InvalidTPDOffset	0
#define MaxTPDOffset		(BLCKSZ - sizeof(TPDPageOpaqueData))

/*
 * MaxTPDTuplesPerPage is an upper bound on the number of tuples that can
 * fit on one zheap page.
 */
#define MaxTPDTuplesPerPage	\
	((int) ((BLCKSZ - SizeOfPageHeaderData - SizeofTPDPageOpaque) / \
			(SizeofTPDEntryHeader  + sizeof(ItemIdData))))

/*
 * TPDOffsetIsValid
 *		True iff the offset is valid.
 */
#define TPDOffsetIsValid(offset) \
	((bool) ((offset != InvalidTPDOffset) && \
			 (offset <= MaxTPDOffset)))

extern OffsetNumber TPDPageAddEntry(Page tpdpage, char *tpd_entry, Size size,
							OffsetNumber offset);
extern void SetTPDLocation(Buffer heapbuffer, Buffer tpdbuffer, uint16 offset);
extern void TPDInitPage(Page page, Size pageSize);
extern int TPDAllocateAndReserveTransSlot(Relation relation, Buffer buf,
								OffsetNumber offnum, UndoRecPtr *urec_ptr);
extern TransInfo *TPDPageGetTransactionSlots(Relation relation, Page heappage,
						   OffsetNumber offnum, int *num_trans_slots,
						   bool keepTPDBufLock, bool checkOffset, int *tpd_buf_idx);
extern int TPDPageReserveTransSlot(Relation relation, Page heappage,
						OffsetNumber offset, UndoRecPtr *urec_ptr);
extern int TPDPageGetSlotIfExists(Relation relation, Page heappage, OffsetNumber offnum,
					   uint32 epoch, TransactionId xid, UndoRecPtr *urec_ptr,
					   bool keepTPDBufLock, bool checkOffset);
extern int TPDPageGetTransactionSlotInfo(Buffer heapbuf, int trans_slot,
					OffsetNumber offset, uint32 *epoch, TransactionId *xid,
					UndoRecPtr *urec_ptr, bool NoTPDBufLock, bool keepTPDBufLock);
extern void TPDPageSetTransactionSlotInfo(Buffer heapbuf, int trans_slot_id,
					uint32 epoch, TransactionId xid, UndoRecPtr urec_ptr);
extern void TPDPageSetUndo(Page heappage, int trans_slot_id, uint32 epoch,
				TransactionId xid, UndoRecPtr urec_ptr, OffsetNumber *usedoff,
				int ucnt);
extern XLogRedoAction XLogReadTPDBuffer(XLogReaderState *record,
										uint8 block_id);
extern uint8 RegisterTPDBuffer(Page heappage, uint8 block_id);
extern void TPDPageSetLSN(Page heappage, XLogRecPtr recptr);
extern void UnlockReleaseTPDBuffers(void);

#endif   /* TPD_H */
