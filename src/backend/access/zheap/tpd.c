/*-------------------------------------------------------------------------
 *
 * tpd.c
 *	  zheap transaction overflow pages code
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * TPD is nothing but temporary data page consisting of extended transaction
 * slots from heap pages.  There are two primary reasons for having TPD (a) In
 * the heap page, we have fixed number of transaction slots which can lead to
 * deadlock, (b) To support cases where a large number of transactions acquire
 * SHARE or KEY SHARE locks on a single page.
 *
 * The TPD overflow pages will be stored in the zheap itself, interleaved with
 * regular pages.  We have a meta page in zheap from which all overflow pages
 * are tracked.
 *
 * TPD Entry acts like an extension of the transaction slot array in heap
 * page.  Tuple headers normally point to the transaction slot responsible for
 * the last modification, but since there aren't enough bits available to do
 * this in the case where a TPD is used, an offset -> slot mapping is stored
 * in the TPD entry itself.  This array can be used to get the slot for tuples
 * in heap page, but for undo tuples we can't use it because we can't track
 * multiple slots that have updated the same tuple.  So for undo records, we
 * record the TPD transaction slot number along with the undo record.
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/tpd.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/tpd_xlog.h"
#include "access/zheap.h"
#include "access/zheapam_xlog.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "storage/buf_internals.h"
#include "storage/lmgr.h"
#include "utils/lsyscache.h"
#include "utils/relfilenodemap.h"

/*
 * We never need more than two tpd buffers to hold TPD entries for a single
 * operation.
 */
#define MAX_TPD_BUFFERS	2

/* Undo block number to buffer mapping. */
typedef struct TPDBuffers
{
	BlockNumber		blk;			/* block number */
	Buffer			buf;			/* buffer allocated for the block */
} TPDBuffers;

/*
 * GetTPDBuffer operations
 *
 * TPD_BUF_FIND - Find the buffer in existing array of tpd buffers.
 * TPD_BUF_FIND_OR_ENTER - Like previous, but if not found then allocate a new
 * buffer and add it to tpd buffers array for future use.
 * TPD_BUF_FIND_OR_KNOWN_ENTER - Like TPD_BUF_FIND, but if not found, then add
 * the already known buffer to tpd buffers array for future use.
 * TPD_BUF_ENTER - Allocate a new TPD buffer and add it to tpd buffers array
 * for future use.
 */
typedef enum
{
	TPD_BUF_FIND,
	TPD_BUF_FIND_OR_ENTER,
	TPD_BUF_FIND_OR_KNOWN_ENTER,
	TPD_BUF_ENTER
} TPDACTION;

static	Buffer registered_tpd_buffers[MAX_TPD_BUFFERS];
static	TPDBuffers tpd_buffers[MAX_TPD_BUFFERS];
static	int tpd_buf_idx;
static	int registered_tpd_buf_idx;
static int GetTPDBuffer(Relation rel, BlockNumber blk, Buffer tpd_buf,
						TPDACTION tpd_action, bool *already_exists);
static bool TPDBufferAlreadyRegistered(Buffer tpd_buf);
static void ReleaseLastTPDBuffer(Buffer buf);

static Size PageGetTPDFreeSpace(Page page);

/*
 * GetTPDBuffer - Get the tpd buffer corresponding to give block number.
 *
 * Returns -1, if the tpd_action is TPD_BUF_FIND and buffer for the required
 * block is not present in tpd buffers array, otherwise returns the index of
 * buffer in the array.
 *
 * rel can be NULL, if user intends to just search for existing buffer.
 */
static int
GetTPDBuffer(Relation rel, BlockNumber blk, Buffer tpd_buf,
			 TPDACTION tpd_action, bool *already_exists)
{
	int		i;
	Buffer	buf;

	/* The number of active TPD buffers must be less than MAX_TPD_BUFFERS. */
	Assert(tpd_buf_idx <= MAX_TPD_BUFFERS);
	*already_exists = false;

	/*
	 * If new block needs to be allocated, then we don't need to search
	 * existing set of buffers.
	 */
	if (tpd_action != TPD_BUF_ENTER)
	{
		/*
		 * Don't do anything, if we already have a buffer pinned for the required
		 * block.
		 */
		for (i = 0; i < tpd_buf_idx; i++)
		{
			if (blk == tpd_buffers[i].blk)
			{
				*already_exists = true;
				return i;
			}
		}
	}
	else
		i = tpd_buf_idx;

	/*
	 * If the buffer doesn't exist and caller doesn't intend to allocate new
	 * buffer, then we are done.
	 */
	if (tpd_action == TPD_BUF_FIND && !(*already_exists))
		return -1;

	if (tpd_action == TPD_BUF_FIND_OR_KNOWN_ENTER)
	{
		Assert (i == tpd_buf_idx);
		Assert (BufferIsValid(tpd_buf));

		tpd_buffers[tpd_buf_idx].blk = BufferGetBlockNumber(tpd_buf);
		tpd_buffers[tpd_buf_idx].buf = tpd_buf;
		tpd_buf_idx++;

		return i;
	}

	/*
	 * Caller must have passed relation, if it intends to read a block that is
	 * not already read.
	 */
	Assert(rel != NULL);

	/*
	 * We don't have the required buffer, so read it and remember in the TPD
	 * buffer array.
	 */
	if (i == tpd_buf_idx)
	{
		buf = ReadBuffer(rel, blk);
		tpd_buffers[tpd_buf_idx].blk = BufferGetBlockNumber(buf);
		tpd_buffers[tpd_buf_idx].buf = buf;
		tpd_buf_idx++;
	}

	return i;
}

/*
 * TPDBufferAlreadyRegistered - Check whether the buffer is already registered.
 *
 * Returns true if the buffer is already registered, otherwise add it to the
 * registered buffer array and return false.
 */
static bool
TPDBufferAlreadyRegistered(Buffer tpd_buf)
{
	int i;

	for (i = 0; i < registered_tpd_buf_idx; i++)
	{
		if (tpd_buf == registered_tpd_buffers[i])
			return true;
	}

	registered_tpd_buffers[registered_tpd_buf_idx++] = tpd_buf;

	return false;
}

/*
 * ReleaseLastTPDBuffer - Release last tpd buffer
 */
static void
ReleaseLastTPDBuffer(Buffer buf)
{
	Buffer	last_tpd_buf PG_USED_FOR_ASSERTS_ONLY;

	last_tpd_buf = tpd_buffers[tpd_buf_idx - 1].buf;
	Assert(buf == last_tpd_buf);
	UnlockReleaseBuffer(buf);
	tpd_buffers[tpd_buf_idx - 1].buf = InvalidBuffer;
	tpd_buffers[tpd_buf_idx - 1].blk = InvalidBlockNumber;
	tpd_buf_idx--;
}

/*
 * AllocateAndFormTPDEntry - Allocate and form the new TPD entry.
 *
 * We initialize the TPD entry and also move the last transaction slot
 * information from heap page to first slot in TPD entry.
 *
 * reserved_slot - returns the first available slot.
 */
static char *
AllocateAndFormTPDEntry(Buffer buf, OffsetNumber offset,
						Size *size_tpd_entry, int *reserved_slot)
{
	Size		size_tpd_e_map;
	Size		size_tpd_e_slots;
	int		i;
	OffsetNumber offnum, max_required_offset;
	char	*tpd_entry;
	char	*tpd_entry_data;
	ZHeapPageOpaque	zopaque;
	TransInfo	last_trans_slot_info;
	TransInfo	*tpd_e_trans_slots;
	Page		page;
	TPDEntryHeaderData	tpe_header;
	uint16		num_map_entries;

	page = BufferGetPage(buf);
	if (OffsetNumberIsValid(offset))
		max_required_offset = offset;
	else
		max_required_offset = PageGetMaxOffsetNumber(page);

	num_map_entries = max_required_offset + ADDITIONAL_MAP_ELEM_IN_TPD_ENTRY;

	if (num_map_entries > 256)
		return NULL;

	/* form tpd entry header */
	tpe_header.tpe_num_map_entries = num_map_entries;
	tpe_header.tpe_num_slots = INITIAL_TRANS_SLOTS_IN_TPD_ENTRY;
	tpe_header.tpe_flags = TPE_ONE_BYTE;

	size_tpd_e_map = num_map_entries * sizeof(uint8);
	size_tpd_e_slots = INITIAL_TRANS_SLOTS_IN_TPD_ENTRY * sizeof(TransInfo);

	/* form transaction slots for tpd entry */
	tpd_e_trans_slots = (TransInfo *) palloc(size_tpd_e_slots);

	for (i = 0; i < INITIAL_TRANS_SLOTS_IN_TPD_ENTRY; i++)
	{
		tpd_e_trans_slots[i].xid_epoch = 0;
		tpd_e_trans_slots[i].xid = InvalidTransactionId;
		tpd_e_trans_slots[i].urec_ptr = InvalidUndoRecPtr;
	}

	/*
	 * Move the last transaction slot information from heap page to first
	 * transaction slot in TPD entry.
	 */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpd_e_trans_slots[0].xid_epoch = last_trans_slot_info.xid_epoch;
	tpd_e_trans_slots[0].xid = last_trans_slot_info.xid;
	tpd_e_trans_slots[0].urec_ptr = last_trans_slot_info.urec_ptr;

	/* form tpd entry */
	*size_tpd_entry = sizeof(TPDEntryHeaderData) + size_tpd_e_map +
										size_tpd_e_slots;

	tpd_entry = (char *) palloc0(*size_tpd_entry);

	memcpy(tpd_entry, (char *) &tpe_header, sizeof(TPDEntryHeaderData));

	tpd_entry_data = tpd_entry + sizeof(TPDEntryHeaderData);

	/*
	 * Update the itemid to slot map for all the itemid's that point to last
	 * transaction slot in the heap page.
	 */
	for (offnum = FirstOffsetNumber;
		 offnum <= max_required_offset;
		 offnum = OffsetNumberNext(offnum))
	{
		ZHeapTupleHeader	tup_hdr;
		ItemId		itemid;
		int		trans_slot;

		itemid = PageGetItemId(page, offnum);

		if (ItemIdIsDead(itemid))
			continue;

		if (!ItemIdIsUsed(itemid))
		{
			if (!ItemIdHasPendingXact(itemid))
				continue;
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else if (ItemIdIsDeleted(itemid))
		{
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else
		{
			tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
			trans_slot = ZHeapTupleHeaderGetXactSlot(tup_hdr);
		}

		/*
		 * Update the itemid to slot map in tpd entry such that all of the
		 * offsets corresponding to tuples that were pointing to last slot in
		 * heap page will now point to first slot in TPD entry.
		 */
		if (trans_slot == ZHEAP_PAGE_TRANS_SLOTS)
		{
			uint8	offset_tpd_e_loc;

			offset_tpd_e_loc = ZHEAP_PAGE_TRANS_SLOTS + 1;

			/*
			 * One byte access shouldn't cause unaligned access, but using memcpy
			 * for the sake of consistency.
			 */
			memcpy(tpd_entry_data + (offnum - 1), (char *) &offset_tpd_e_loc,
				   sizeof(uint8));
		}
	}

	memcpy(tpd_entry + sizeof(TPDEntryHeaderData) + size_tpd_e_map,
		   (char *) tpd_e_trans_slots, size_tpd_e_slots);

	/*
	 * The first slot location has been already assigned to last slot moved
	 * from heap page.  We can safely reserve the second slot location in new
	 * TPD entry.
	 */
	*reserved_slot = ZHEAP_PAGE_TRANS_SLOTS + 2;

	/* be tidy */
	pfree(tpd_e_trans_slots);

	return tpd_entry;
}

/*
 * TPDPageAddEntry - Add the given to TPD entry on the page and
 * move the upper to point to the next free location.
 *
 * This function returns the page offset location of the entry.
 */
uint16
TPDPageAddEntry(Page tpdpage, char *tpd_entry, Size size,
				uint16 offset)
{
	PageHeader	phdr = (PageHeader) tpdpage;
	uint16			upper;

	/*
	 * Be wary about corrupted page pointers
	 */
	if (phdr->pd_lower < SizeOfPageHeaderData ||
		phdr->pd_lower > phdr->pd_upper ||
		phdr->pd_upper > phdr->pd_special ||
		phdr->pd_special > BLCKSZ)
		ereport(PANIC,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("corrupted page pointers: lower = %u, upper = %u, special = %u",
						phdr->pd_lower, phdr->pd_upper, phdr->pd_special)));

	if (TPDOffsetIsValid(offset))
	{
		Assert(offset > SizeOfPageHeaderData && offset < BLCKSZ);
		upper = offset;
	}
	else
	{
		upper = (int) phdr->pd_upper - (int) size;
	}

	/* copy the item's data onto the page */
	memcpy((char *) tpdpage + upper, tpd_entry, size);
	phdr->pd_upper = (LocationIndex) upper;

	return upper;
}

/*
 * SetTPDLocation - Set TPD entry location in the last transaction slot of
 *		heap page and indicate the same in page.
 */
void
SetTPDLocation(Buffer heapbuffer, Buffer tpdbuffer, uint16 offset)
{
	Page	heappage;
	PageHeader	phdr;
	ZHeapPageOpaque	opaque;

	heappage = BufferGetPage(heapbuffer);
	phdr = (PageHeader) heappage;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);

	/* clear the last transaction slot info */
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid_epoch = 0;
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid =
											InvalidTransactionId;
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].urec_ptr =
											InvalidUndoRecPtr;
	/* set TPD location in last transaction slot */
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid_epoch =
											BufferGetBlockNumber(tpdbuffer);
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid =
			(opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid & ~OFFSET_MASK) | offset;

	phdr->pd_flags |= PD_PAGE_HAS_TPD_SLOT;
}

/*
 * TPDInitPage - Initialize the TPD page.
 */
void
TPDInitPage(Page page, Size pageSize)
{
	TPDPageOpaque	tpdopaque;

	PageInit(page, pageSize, sizeof(TPDPageOpaqueData));

	tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(page);
	tpdopaque->tpd_prevblkno = InvalidBlockNumber;
	tpdopaque->tpd_nextblkno = InvalidBlockNumber;
	tpdopaque->tpd_latest_xid_epoch = 0;
	tpdopaque->tpd_latest_xid = InvalidTransactionId;
}

/*
 * TPDAllocateAndReserveTransSlot - Allocates a new TPD entry and reserve a
 *		transaction slot in that entry.
 *
 * To allocate a new TPD entry, we first check if there is a space in any
 * existing TPD page starting from the last used TPD page and incase we
 * don't find any such page, then allocate a new TPD page and add it to the
 * existing list of TPD pages.
 *
 * We intentionally don't release the TPD buffer here as that will be
 * released once we have updated the transaction slot with required
 * information.  Caller must call UnlockReleaseTPDBuffers after doing
 * necessary updates.
 *
 * pagebuf - Caller must have an exclusive lock on this buffer.
 */
int
TPDAllocateAndReserveTransSlot(Relation relation, Buffer pagebuf,
							   OffsetNumber offnum, UndoRecPtr *urec_ptr)
{
	ZHeapMetaPage	metapage;
	TPDPageOpaque	tpdopaque, last_tpdopaque;
	Buffer	metabuf;
	Buffer	tpd_buf = InvalidBuffer;
	Buffer	last_used_tpd_buf = InvalidBuffer;
	Page	heappage;
	Page	tpdpage;
	BlockNumber	prevblk = InvalidBlockNumber;
	BlockNumber	nextblk = InvalidBlockNumber;
	uint32		first_used_tpd_page;
	uint32		last_used_tpd_page;
	char		*tpd_entry;
	Size		size_tpd_entry;
	int			reserved_slot = InvalidXactSlotId;
	int			buf_idx;
	uint16		offset;
	bool		allocate_new_tpd_page = false;
	bool		update_meta = false;
	bool		already_exists;

	metabuf = ReadBuffer(relation, ZHEAP_METAPAGE);
	LockBuffer(metabuf, BUFFER_LOCK_SHARE);
	metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));

	first_used_tpd_page = metapage->zhm_first_used_tpd_page;
	last_used_tpd_page = metapage->zhm_last_used_tpd_page;

	LockBuffer(metabuf, BUFFER_LOCK_UNLOCK);

	heappage = BufferGetPage(pagebuf);

	if (last_used_tpd_page != InvalidBlockNumber)
	{
		Size	tpdpageFreeSpace;
		Size	size_tpd_e_map, size_tpd_entry, size_tpd_e_slots;
		uint16	num_map_entries;
		OffsetNumber	max_required_offset;

		if (OffsetNumberIsValid(offnum))
			max_required_offset = offnum;
		else
			max_required_offset = PageGetMaxOffsetNumber(heappage);
		num_map_entries = max_required_offset +
							ADDITIONAL_MAP_ELEM_IN_TPD_ENTRY;
		if (num_map_entries > 256)
		{
			ReleaseBuffer(metabuf);
			return InvalidXactSlotId;
		}

		size_tpd_e_map = num_map_entries * sizeof(uint8);
		size_tpd_e_slots = INITIAL_TRANS_SLOTS_IN_TPD_ENTRY * sizeof(TransInfo);
		size_tpd_entry = sizeof(TPDEntryHeaderData) + size_tpd_e_map +
										size_tpd_e_slots;

		buf_idx = GetTPDBuffer(relation, last_used_tpd_page, InvalidBuffer,
							   TPD_BUF_FIND_OR_ENTER, &already_exists);
		tpd_buf = tpd_buffers[buf_idx].buf;
		/* We don't need to lock the buffer, if it is already locked */
		if (!already_exists)
			LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);
		tpdpageFreeSpace = PageGetTPDFreeSpace(BufferGetPage(tpd_buf));

		if (tpdpageFreeSpace < size_tpd_entry)
		{
			/*
			 * XXX Here, we can have an optimization such that instead of
			 * allocating a new page, we can search other TPD pages starting
			 * from the first_used_tpd_page till we reach last_used_tpd_page.
			 * However, I think that can help only when we have a mechanism
			 * to prune the TPD pages.
			 */
			if (!already_exists)
				ReleaseLastTPDBuffer(tpd_buf);
			allocate_new_tpd_page = true;
		}
	}

	if (allocate_new_tpd_page ||
		(last_used_tpd_page == InvalidBlockNumber &&
		first_used_tpd_page == InvalidBlockNumber))
	{
		bool	needLock;

		/* Must extend the file */
		needLock = !RELATION_IS_LOCAL(relation);
		if (needLock)
			LockRelationForExtension(relation, ExclusiveLock);

		/* Allocate a new TPD page */
		buf_idx = GetTPDBuffer(relation, P_NEW, InvalidBuffer, TPD_BUF_ENTER,
							   &already_exists);
		/* This must be a new buffer. */
		Assert(!already_exists);
		tpd_buf = tpd_buffers[buf_idx].buf;
		LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);
		LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);

		if (needLock)
			UnlockRelationForExtension(relation, ExclusiveLock);

		/*
		 * Lock the last tpd page in list, so that we can append new page to
		 * it.
		 */
		metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));
		if (metapage->zhm_first_used_tpd_page != InvalidBlockNumber)
		{
			last_used_tpd_buf = ReadBuffer(relation,
										   metapage->zhm_last_used_tpd_page);
			LockBuffer(last_used_tpd_buf, BUFFER_LOCK_EXCLUSIVE);
		}

		update_meta = true;
	}

	/* Allocate a new TPD entry */
	tpd_entry = AllocateAndFormTPDEntry(pagebuf, offnum, &size_tpd_entry,
										&reserved_slot);
	if (tpd_entry == NULL)
	{
		if (update_meta)
			UnlockReleaseBuffer(metabuf);
		else
			ReleaseBuffer(metabuf);
		
		if (!already_exists)
			ReleaseLastTPDBuffer(tpd_buf);
		
		if (BufferIsValid(last_used_tpd_buf))
			UnlockReleaseBuffer(last_used_tpd_buf);
			
		return InvalidXactSlotId;
	}

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	tpdpage = BufferGetPage(tpd_buf);

	/* Update metapage and add the new TPD page in the TPD page list. */
	if (update_meta)
	{
		BlockNumber tpdblkno;

		TPDInitPage(tpdpage, BufferGetPageSize(tpd_buf));
		tpdblkno = BufferGetBlockNumber(tpd_buf);
		tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);

		if (metapage->zhm_first_used_tpd_page == InvalidBlockNumber)
			metapage->zhm_first_used_tpd_page = tpdblkno;
		else
		{
			Assert(BufferIsValid(last_used_tpd_buf));

			/* Add the new TPD page at the end of the TPD page list. */
			last_tpdopaque = (TPDPageOpaque)
				PageGetSpecialPointer(BufferGetPage(last_used_tpd_buf));
			prevblk = tpdopaque->tpd_prevblkno = metapage->zhm_last_used_tpd_page;
			nextblk = last_tpdopaque->tpd_nextblkno = tpdblkno;

			MarkBufferDirty(last_used_tpd_buf);
		}

		metapage->zhm_last_used_tpd_page = tpdblkno;

		MarkBufferDirty(metabuf);
	}

	/* Add tpd entry to page */
	offset = TPDPageAddEntry(tpdpage, tpd_entry, size_tpd_entry,
							 InvalidTPDOffset);
	MarkBufferDirty(tpd_buf);

	/*
	 * Now that the last transaction slot from heap page has moved to TPD,
	 * we need to assign TPD location in the last transaction slot of heap.
	 */
	SetTPDLocation(pagebuf, tpd_buf, offset);
	MarkBufferDirty(pagebuf);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		XLogRecPtr	recptr;
		xl_tpd_allocate_entry	xlrec;
		xl_zheap_metadata	metadata;
		int		bufflags = 0;
		uint8	info = XLOG_ALLOCATE_TPD_ENTRY;

		xlrec.offset = offset;
		xlrec.prevblk = prevblk;
		xlrec.nextblk = nextblk;

		/*
		 * If we are adding TPD entry to a new page, we will reinit the page
		 * during replay.
		 */
		if (update_meta)
		{
			info |= XLOG_TPD_INIT_PAGE;
			bufflags |= REGBUF_WILL_INIT;
		}

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfTPDAllocateEntry);
		XLogRegisterBuffer(0, tpd_buf, REGBUF_STANDARD | bufflags);
		XLogRegisterBufData(0, (char *) tpd_entry, size_tpd_entry);
		XLogRegisterBuffer(1, pagebuf, REGBUF_STANDARD);
		if (update_meta)
		{
			XLogRegisterBuffer(2, metabuf, REGBUF_WILL_INIT | REGBUF_STANDARD);
			metadata.first_used_tpd_page = metapage->zhm_first_used_tpd_page;
			metadata.last_used_tpd_page = metapage->zhm_last_used_tpd_page;
			XLogRegisterBufData(2, (char *) &metadata, SizeOfMetaData);

			if (BufferIsValid(last_used_tpd_buf))
				XLogRegisterBuffer(3, last_used_tpd_buf, REGBUF_STANDARD);
		}

		recptr = XLogInsert(RM_TPD_ID, info);

		PageSetLSN(tpdpage, recptr);
		PageSetLSN(heappage, recptr);
		if (update_meta)
		{
			PageSetLSN(metapage, recptr);
			if (BufferIsValid(last_used_tpd_buf))
				PageSetLSN(BufferGetPage(last_used_tpd_buf), recptr);
		}
	}

	END_CRIT_SECTION();

	if (update_meta)
		UnlockReleaseBuffer(metabuf);
	else
		ReleaseBuffer(metabuf);
	if (update_meta && BufferIsValid(last_used_tpd_buf))
	{
		Assert (last_used_tpd_buf != tpd_buf);
		UnlockReleaseBuffer(last_used_tpd_buf);
	}

	/*
	 * Here, we don't release the tpdbuffer in which we have added the newly
	 * allocated TPD entry as that will be relased once we update the required
	 * trasaction slot info in it.  The caller will later call TPDPageSetUndo
	 * to update the required information.
	 */

	pfree(tpd_entry);

	/*
	 * As this is always a fresh transaction slot, so we can assume that
	 * there is no preexisting undo record pointer.
	 */
	*urec_ptr = InvalidUndoRecPtr;

	return reserved_slot;
}

/*
 * TPDPageGetTransactionSlots - Get the transaction slots array stored in TPD
 *			entry.  This is a helper routine for TPDPageReserveTransSlot and
 *			TPDPageGetSlotIfExists.
 *
 * The tpd entries are stored unaligned, so we need to be careful to read
 * them.  We use memcpy to avoid unaligned reads.
 *
 * This function returns a pointer to an array of transaction slots, it is the
 * responsibility of the caller to free it.
 */
TransInfo *
TPDPageGetTransactionSlots(Relation relation, Page heappage,
						   OffsetNumber offnum, int *num_trans_slots,
						   bool keepTPDBufLock, bool checkOffset,
						   int *tpd_buf_idx)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	*trans_slots;
	TransInfo	last_trans_slot_info;
	Buffer	tpd_buf;
	Page	tpdpage;
	BlockNumber	tpdblk;
	TPDEntryHeaderData	tpd_e_hdr;
	Size	size_tpd_e_map;
	Size	size_tpd_e_slots;
	int		loc_trans_slots;
	int		buf_idx;
	uint16	tpd_e_offset;
	bool	already_exists;

	phdr = (PageHeader) heappage;
	
	if (tpd_buf_idx)
		*tpd_buf_idx = -1;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	/* The last in page has the address of the required TPD entry. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpd_e_offset = last_trans_slot_info.xid & OFFSET_MASK;

	/*
	 * Fetch the required TPD entry.  We need to lock the buffer in exclusive
	 * mode as we later want to set the values in one of the transaction slot.
	 */
	buf_idx = GetTPDBuffer(relation, tpdblk, InvalidBuffer,
						   TPD_BUF_FIND_OR_ENTER, &already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;
	/* We don't need to lock the buffer, if it is already locked */
	if (!already_exists)
	{
		LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);
		if (tpd_buf_idx)
			*tpd_buf_idx = buf_idx;
	}

	tpdpage = BufferGetPage(tpd_buf);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset,
		   sizeof(TPDEntryHeaderData));

	/* Fixme: We should allocate a bigger TPD entry instead. */
	if (checkOffset && offnum > tpd_e_hdr.tpe_num_map_entries)
	{
		elog(LOG, "TPD entry does not have space for new offset");
		*num_trans_slots = 0;
		return NULL;
	}

	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint8);
	else
	{
		Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint32);
	}

	*num_trans_slots = tpd_e_hdr.tpe_num_slots;
	size_tpd_e_slots = tpd_e_hdr.tpe_num_slots * sizeof(TransInfo);
	loc_trans_slots = tpd_e_offset + sizeof(TPDEntryHeaderData) +
										size_tpd_e_map;

	trans_slots = (TransInfo *) palloc(size_tpd_e_slots);
	memcpy((char *) trans_slots, tpdpage + loc_trans_slots, size_tpd_e_slots);

	if (!keepTPDBufLock)
	{
		/*
		 * If we don't want to retain the buffer lock, it must have been taken
		 * now.  We can't release the already existing lock taken.
		 */
		Assert(!already_exists);
		ReleaseLastTPDBuffer(tpd_buf);

		if (tpd_buf_idx)
			*tpd_buf_idx = -1;
	}

	return trans_slots;
}

/*
 * TPDPageReserveTransSlot - Reserve the available transaction in current TPD
 *		entry if any, otherwise, return InvalidXactSlotId.
 *
 * We intentionally don't release the TPD buffer here as that will be
 * released once we have updated the transaction slot with required
 * information.  However, if no free slot is available, then we release the
 * buffer.  Caller must call UnlockReleaseTPDBuffers after doing necessary
 * updates if it is able to reserve a slot.
 */
int
TPDPageReserveTransSlot(Relation relation, Page heappage, OffsetNumber offnum,
						UndoRecPtr *urec_ptr)
{
	TransInfo	*trans_slots;
	int		slot_no;
	int		num_slots;
	int		result_slot_no = InvalidXactSlotId;
	int		buf_idx;

	trans_slots = TPDPageGetTransactionSlots(relation, heappage, offnum,
											 &num_slots, true, true, &buf_idx);

	for (slot_no = 0; slot_no < num_slots; slot_no++)
	{
		/* Check for an unreserved transaction slot in the TPD entry */
		if (trans_slots[slot_no].xid == InvalidTransactionId)
		{
			result_slot_no = slot_no;
			*urec_ptr = trans_slots[slot_no].urec_ptr;
			break;
		}
	}

	/*
	 * Fixme: If we didn't get a unreserved transaction slot, we should
	 * allocate a bigger TPD entry with more transaction slots.
	 */

	/* be tidy */
	if (trans_slots != NULL)
		pfree(trans_slots);

	/*
	 * The transaction slots in TPD entry are in addition to the maximum slots
	 * in the heap page.
	 */
	if (result_slot_no != InvalidXactSlotId)
		result_slot_no += (ZHEAP_PAGE_TRANS_SLOTS + 1);
	else if (buf_idx != -1)
		ReleaseLastTPDBuffer(tpd_buffers[buf_idx].buf);

	return result_slot_no;
}

/*
 * TPDPageGetSlotIfExists - Get the existing slot for the required transaction
 *		if exists, otherwise, return InvalidXactSlotId.
 *
 * This is similar to the TPDPageReserveTransSlot except that here we find the
 * exisiting transaction slot instead of reserving a new one.
 *
 * keepTPDBufLock - This indicates whether we need to retain the lock on TPD
 * buffer if we are able to reserve a transaction slot.
 */
int
TPDPageGetSlotIfExists(Relation relation, Page heappage, OffsetNumber offnum,
					   uint32 epoch, TransactionId xid, UndoRecPtr *urec_ptr,
					   bool keepTPDBufLock, bool checkOffset)
{
	TransInfo	*trans_slots;
	int		slot_no;
	int		num_slots;
	int		result_slot_no = InvalidXactSlotId;
	int		buf_idx;

	trans_slots = TPDPageGetTransactionSlots(relation,
											 heappage,
											 offnum,
											 &num_slots,
											 keepTPDBufLock,
											 checkOffset,
											 &buf_idx);

	for (slot_no = 0; slot_no < num_slots; slot_no++)
	{
		/* Check if already have a slot in the TPD entry */
		if (trans_slots[slot_no].xid_epoch == epoch &&
			trans_slots[slot_no].xid == xid)
		{
			result_slot_no = slot_no;
			*urec_ptr = trans_slots[slot_no].urec_ptr;
			break;
		}
	}

	/* be tidy */
	if (trans_slots)
		pfree(trans_slots);

	/*
	 * The transaction slots in TPD entry are in addition to the maximum slots
	 * in the heap page.
	 */
	if (result_slot_no != InvalidXactSlotId)
		result_slot_no += (ZHEAP_PAGE_TRANS_SLOTS + 1);
	else if (buf_idx != -1)
		ReleaseLastTPDBuffer(tpd_buffers[buf_idx].buf);

	return result_slot_no;
}

/*
 * TPDPageGetTransactionSlotInfo - Get the required transaction information from
 *		heap page's TPD entry.
 *
 * NoTPDBufLock - This indicates that caller doesn't have lock on required tpd
 * buffer in which case we need to read and lock the required buffer.
 */
int
TPDPageGetTransactionSlotInfo(Buffer heapbuf, int trans_slot,
							  OffsetNumber offset, uint32 *epoch,
							  TransactionId *xid, UndoRecPtr *urec_ptr,
							  bool NoTPDBufLock, bool keepTPDBufLock)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	trans_slot_info, last_trans_slot_info;
	RelFileNode	rnode;
	Buffer	tpdbuffer;
	Page	tpdpage;
	Page	heappage;
	BlockNumber	tpdblk, heapblk;
	ForkNumber forknum;
	TPDEntryHeaderData	tpd_e_hdr;
	Size		size_tpd_e_map;
	uint32	tpd_e_num_map_entries;
	int		trans_slot_loc;
	int		trans_slot_id = trans_slot;
	char	*tpd_entry_data;
	uint16	tpd_e_offset;
	char relpersistence;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/* Heap page must have a TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpd_e_offset = last_trans_slot_info.xid & OFFSET_MASK;

	if (NoTPDBufLock)
	{
		BufferGetTag(heapbuf, &rnode, &forknum, &heapblk);

		if (InRecovery)
			relpersistence = RELPERSISTENCE_PERMANENT;
		else
		{
			Oid		reloid;

			reloid = RelidByRelfilenode(rnode.spcNode, rnode.relNode);
			relpersistence = get_rel_persistence(reloid);
		}

		tpdbuffer = ReadBufferWithoutRelcache(rnode, forknum, tpdblk, RBM_NORMAL,
											  NULL, relpersistence);
		if (keepTPDBufLock)
			LockBuffer(tpdbuffer, BUFFER_LOCK_EXCLUSIVE);
		else
			LockBuffer(tpdbuffer, BUFFER_LOCK_SHARE);
	}
	else
	{
		int		buf_idx;
		bool	already_exists PG_USED_FOR_ASSERTS_ONLY;

		buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
							   &already_exists);
		/* We must get a valid buffer. */
		Assert(buf_idx != -1);
		Assert(already_exists);
		tpdbuffer = tpd_buffers[buf_idx].buf;
	}

	tpdpage = BufferGetPage(tpdbuffer);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset,
		   sizeof(TPDEntryHeaderData));

	tpd_e_num_map_entries = tpd_e_hdr.tpe_num_map_entries;
	tpd_entry_data = tpdpage + tpd_e_offset + sizeof(TPDEntryHeaderData);
	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint8);
	else
	{
		Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint32);
	}

	/*
	 * If the caller has passed transaction slot number that belongs to TPD
	 * entry, then we directly go and fetch the required info from the slot.
	 */
	if (offset != InvalidOffsetNumber)
	{
		/*
		 * The item for which we want to get the transaction slot information
		 * must be present in this TPD entry.
		 */
		Assert (offset <= tpd_e_num_map_entries);

		/* Get TPD entry map */
		if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		{
			uint8	offset_tpd_e_loc;

			/*
			 * One byte access shouldn't cause unaligned access, but using memcpy
			 * for the sake of consistency.
			 */
			memcpy((char *) &offset_tpd_e_loc, tpd_entry_data + (offset - 1),
				   sizeof(uint8));
			trans_slot_id = offset_tpd_e_loc;
		}
		else
		{
			uint32	offset_tpd_e_loc;

			memcpy((char *) &offset_tpd_e_loc, tpd_entry_data + (offset - 1),
				   sizeof(uint32));
			trans_slot_id = offset_tpd_e_loc;
		}
	}

	/* Transaction must belong to TPD entry. */
	Assert(trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS);

	/* Get the required transaction slot information. */
	trans_slot_loc = (trans_slot_id - ZHEAP_PAGE_TRANS_SLOTS - 1) *
										sizeof(TransInfo);
	memcpy((char *) &trans_slot_info,
			tpd_entry_data + size_tpd_e_map + trans_slot_loc,
			sizeof(TransInfo));

	/* Update the required output */
	if (epoch)
		*epoch = trans_slot_info.xid_epoch;
	if (xid)
		*xid = trans_slot_info.xid;
	if (urec_ptr)
		*urec_ptr = trans_slot_info.urec_ptr;

	if (NoTPDBufLock && !keepTPDBufLock)
		UnlockReleaseBuffer(tpdbuffer);

	return trans_slot_id;
}

/*
 * TPDPageSetTransactionSlotInfo - Set the transaction information for a given
 *		transaction slot in the TPD entry.
 *
 * Caller must ensure that it has required lock on tpd buffer which is going to
 * be updated here.  We can't lock the buffer here as this API is supposed to
 * be called from critical section and lock acquisition can fail.
 */
void
TPDPageSetTransactionSlotInfo(Buffer heapbuf, int trans_slot_id,
							  uint32 epoch, TransactionId xid,
							  UndoRecPtr urec_ptr)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	trans_slot_info, last_trans_slot_info;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	Buffer	tpd_buf;
	Page	tpdpage;
	Page	heappage;
	BlockNumber	tpdblk;
	TPDEntryHeaderData	tpd_e_hdr;
	TPDPageOpaque	tpdopaque;
	uint64		tpd_latest_xid_epoch, current_xid_epoch;
	Size		size_tpd_e_map;
	int		trans_slot_loc;
	int		buf_idx;
	char	*tpd_entry_data;
	uint16	tpd_e_offset;
	bool	already_exists PG_USED_FOR_ASSERTS_ONLY;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/* Heap page must have a TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpd_e_offset = last_trans_slot_info.xid & OFFSET_MASK;

	buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
						   &already_exists);
	/* We must get a valid buffer. */
	Assert(buf_idx != -1);
	Assert(already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;
	Assert(BufferIsValid(tpd_buf));
	tpdbufhdr = GetBufferDescriptor(tpd_buf - 1);
	Assert(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(tpdbufhdr),
								LW_EXCLUSIVE));
	Assert(BufferGetBlockNumber(tpd_buf) == tpdblk);

	tpdpage = BufferGetPage(tpd_buf);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset,
		   sizeof(TPDEntryHeaderData));

	tpd_entry_data = tpdpage + tpd_e_offset + sizeof(TPDEntryHeaderData);

	/* Get TPD entry map */
	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint8);
	else
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint32);

	/* Set the required transaction slot information. */
	trans_slot_loc = (trans_slot_id - ZHEAP_PAGE_TRANS_SLOTS - 1) *
										sizeof(TransInfo);
	trans_slot_info.xid_epoch = epoch;
	trans_slot_info.xid = xid;
	trans_slot_info.urec_ptr = urec_ptr;

	memcpy(tpd_entry_data + size_tpd_e_map + trans_slot_loc,
		   (char *) &trans_slot_info,
		   sizeof(TransInfo));

	/* Update latest transaction information on the page. */
	tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
	tpd_latest_xid_epoch = (uint64) tpdopaque->tpd_latest_xid_epoch;
	tpd_latest_xid_epoch = MakeEpochXid(tpd_latest_xid_epoch,
										tpdopaque->tpd_latest_xid);
	current_xid_epoch = (uint64) epoch;
	current_xid_epoch = MakeEpochXid(current_xid_epoch, xid);
	if (tpd_latest_xid_epoch < current_xid_epoch)
	{
		tpdopaque->tpd_latest_xid_epoch = epoch;
		tpdopaque->tpd_latest_xid = xid;
	}

	MarkBufferDirty(tpd_buf);
}

/*
 * TPDPageSetUndo - Set the transaction information for a given transaction
 *		slot in the TPD entry.  The difference between this function and
 *		TPDPageSetTransactionSlotInfo is that here along with transaction
 *		info, we update the offset to transaction slot map in the TPD entry as
 *		well.
 *
 * Caller is responsible for WAL logging this operation and release the TPD
 * buffers.  We have thought of WAL logging this as a separate operation, but
 * that won't work as the undorecord pointer can be bogus during WAL replay;
 * that is because we regenerate the undo during WAL replay and it is quite
 * possible that the system crashes after flushing this WAL record but before
 * flushing WAL of actual heap operation.  Similarly, doing it after heap
 * operation is not feasible as in that case the tuple's transaction
 * information can get lost.
 */
void
TPDPageSetUndo(Page heappage, int trans_slot_id, uint32 epoch,
			   TransactionId xid, UndoRecPtr urec_ptr, OffsetNumber *usedoff,
			   int ucnt)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	trans_slot_info, last_trans_slot_info;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	Buffer	tpd_buf;
	Page	tpdpage;
	BlockNumber	tpdblk;
	TPDEntryHeaderData	tpd_e_hdr;
	TPDPageOpaque	tpdopaque;
	uint64		tpd_latest_xid_epoch, current_xid_epoch;
	Size		size_tpd_e_map;
	uint32	tpd_e_num_map_entries;
	int		trans_slot_loc;
	int		buf_idx;
	int		i;
	char	*tpd_entry_data;
	uint16	tpd_e_offset;
	bool	already_exists;

	phdr = (PageHeader) heappage;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpd_e_offset = last_trans_slot_info.xid & OFFSET_MASK;

	buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
						   &already_exists);

	/* We must get a valid buffer. */
	Assert(buf_idx != -1);
	Assert(already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;

	/*
	 * Fetch the required TPD entry.  Ensure that we are operating on the
	 * right buffer.
	 */
	tpdbufhdr = GetBufferDescriptor(tpd_buf - 1);
	Assert(BufferIsValid(tpd_buf));
	Assert(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(tpdbufhdr),
								LW_EXCLUSIVE));
	Assert(BufferGetBlockNumber(tpd_buf) == tpdblk);

	tpdpage = BufferGetPage(tpd_buf);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset,
		   sizeof(TPDEntryHeaderData));

	tpd_e_num_map_entries = tpd_e_hdr.tpe_num_map_entries;
	tpd_entry_data = tpdpage + tpd_e_offset + sizeof(TPDEntryHeaderData);

	/* Update TPD entry map for all the modified offsets. */
	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
	{
		uint8	offset_tpd_e_loc;

		offset_tpd_e_loc = (uint8) trans_slot_id;

		for (i = 0; i < ucnt; i++)
		{
			/*
			 * The item for which we want to update the transaction slot information
			 * must be present in this TPD entry.
			 */
			Assert (usedoff[i] <= tpd_e_num_map_entries);
			/*
			 * One byte access shouldn't cause unaligned access, but using memcpy
			 * for the sake of consistency.
			 */
			memcpy(tpd_entry_data + (usedoff[i] - 1), (char *) &offset_tpd_e_loc,
				   sizeof(uint8));
		}
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint8);
	}
	else
	{
		uint32	offset_tpd_e_loc;

		Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);

		offset_tpd_e_loc = trans_slot_id;
		for (i = 0; i < ucnt; i++)
		{
			/*
			 * The item for which we want to update the transaction slot information
			 * must be present in this TPD entry.
			 */
			Assert (usedoff[i] <= tpd_e_num_map_entries);
			memcpy(tpd_entry_data + (usedoff[i] - 1), (char *) &offset_tpd_e_loc,
				   sizeof(uint32));
		}
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint32);
	}

	/* Update the required transaction slot information. */
	trans_slot_loc = (trans_slot_id - ZHEAP_PAGE_TRANS_SLOTS - 1) *
												sizeof(TransInfo);
	trans_slot_info.xid_epoch = epoch;
	trans_slot_info.xid = xid;
	trans_slot_info.urec_ptr = urec_ptr;
	memcpy(tpd_entry_data + size_tpd_e_map + trans_slot_loc,
		   (char *) &trans_slot_info,
		   sizeof(TransInfo));

	/* Update latest transaction information on the page. */
	tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
	tpd_latest_xid_epoch = (uint64) tpdopaque->tpd_latest_xid_epoch;
	tpd_latest_xid_epoch = MakeEpochXid(tpd_latest_xid_epoch,
										tpdopaque->tpd_latest_xid);
	current_xid_epoch = (uint64) epoch;
	current_xid_epoch = MakeEpochXid(current_xid_epoch, xid);
	if (tpd_latest_xid_epoch < current_xid_epoch)
	{
		tpdopaque->tpd_latest_xid_epoch = epoch;
		tpdopaque->tpd_latest_xid = xid;
	}

	MarkBufferDirty(tpd_buf);
}

/*
 * XLogReadTPDBuffer - Read the TPD buffer.
 */
XLogRedoAction
XLogReadTPDBuffer(XLogReaderState *record, uint8 block_id)
{
	Buffer	tpd_buf;
	XLogRedoAction action;
	bool	already_exists;

	action = XLogReadBufferForRedo(record, block_id, &tpd_buf);

	/*
	 * Remember the buffer, so that it can be release later via
	 * UnlockReleaseTPDBuffers.
	 */
	GetTPDBuffer(NULL, BufferGetBlockNumber(tpd_buf), tpd_buf,
				 TPD_BUF_FIND_OR_KNOWN_ENTER, &already_exists);

	return action;
}

/*
 * RegisterTPDBuffer - Register the TPD buffer
 *
 * returns the block_id that can be used to register additional buffers in the
 * caller.
 */
uint8
RegisterTPDBuffer(Page heappage, uint8 block_id)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	last_trans_slot_info;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	Buffer		tpd_buf;
	BlockNumber	tpdblk;
	int			buf_idx;
	bool		already_exists;

	phdr = (PageHeader) heappage;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	/* Get the tpd block number from last transaction slot in heap page. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];
	tpdblk = last_trans_slot_info.xid_epoch;

	buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
						   &already_exists);

	/* We must get a valid buffer. */
	Assert(buf_idx != -1);
	Assert(already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;

	/* Return same block id if this buffer is already registered. */
	if (TPDBufferAlreadyRegistered(tpd_buf))
		return block_id;

	/* We must be in critical section to perform this action. */
	Assert(CritSectionCount > 0);
	tpdbufhdr = GetBufferDescriptor(tpd_buf - 1);
	/* The TPD buffer must be valid and locked by me. */
	Assert(BufferIsValid(tpd_buf));
	Assert(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(tpdbufhdr),
								LW_EXCLUSIVE));

	XLogRegisterBuffer(block_id++, tpd_buf, REGBUF_STANDARD);

	return block_id;
}

/*
 * TPDPageSetLSN - Set LSN on TPD pages.
 */
void
TPDPageSetLSN(Page heappage, XLogRecPtr recptr)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	last_trans_slot_info;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	Buffer		tpd_buf;
	BlockNumber	tpdblk;
	int			buf_idx;
	bool		already_exists;

	phdr = (PageHeader) heappage;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	/* Get the tpd block number from last transaction slot in heap page. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];
	tpdblk = last_trans_slot_info.xid_epoch;

	buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
						   &already_exists);

	/* We must get a valid buffer. */
	Assert(buf_idx != -1);
	Assert(already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;

	/* Reset the registered buffer index. */
	registered_tpd_buf_idx = 0;

	/*
	 * Before recording the LSN, ensure that the TPD buffer must be valid and
	 * locked by me.
	 */
	tpdbufhdr = GetBufferDescriptor(tpd_buf - 1);
	Assert(BufferIsValid(tpd_buf));
	Assert(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(tpdbufhdr),
								LW_EXCLUSIVE));
	Assert(BufferGetBlockNumber(tpd_buf) == tpdblk);

	PageSetLSN(BufferGetPage(tpd_buf), recptr);
}

/*
 * UnlockReleaseTPDBuffers - Release all the TPD buffers locked by me.
 */
void
UnlockReleaseTPDBuffers(void)
{
	Buffer		tpd_buf;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	int			i;

	for (i = 0; i < tpd_buf_idx; i++)
	{
		tpd_buf = tpd_buffers[i].buf;
		Assert(BufferIsValid(tpd_buf));
		tpdbufhdr = GetBufferDescriptor(tpd_buf - 1);
		Assert(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(tpdbufhdr),
									LW_EXCLUSIVE));
		UnlockReleaseBuffer(tpd_buf);
		tpd_buffers[i].buf = InvalidBuffer;
		tpd_buffers[i].blk = InvalidBlockNumber;
	}

	tpd_buf_idx = 0;
}

/*
 * PageGetTPDFreeSpace
 *		Returns the size of the free (allocatable) space on a page.
 */
static Size
PageGetTPDFreeSpace(Page page)
{
	int			space;

	/*
	 * Use signed arithmetic here so that we behave sensibly if pd_lower >
	 * pd_upper.
	 */
	space = (int) ((PageHeader) page)->pd_upper -
		(int) ((PageHeader) page)->pd_lower;

	return (Size) space;
}
