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
#include "storage/proc.h"
#include "utils/lsyscache.h"
#include "utils/relfilenodemap.h"

/*
 * We never need more than two TPD buffers per zheap page, so the maximum
 * number of TPD buffers required will be four.  This can happen for
 * non-inplace updates that insert new record to a different zheap page.  In
 * general, we require one tpd page for zheap page, but for the cases when
 * we need to extend the tpd entry to a different page, we will operate on
 * two tpd buffers.
 */
#define MAX_TPD_BUFFERS	4

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
static void TPDEntryUpdate(Relation relation, Buffer tpd_buf,
			   uint16 tpd_e_offset, OffsetNumber tpd_item_off,
			   char *tpd_entry, Size size_tpd_entry);
static void TPDAllocatePageAndAddEntry(Relation relation, Buffer metabuf,
						Buffer pagebuf, Buffer old_tpd_buf,
						OffsetNumber old_off_num, char *tpd_entry,
						Size size_tpd_entry, bool add_new_tpd_page,
						bool delete_old_entry, bool always_extend);
static bool TPDBufferAlreadyRegistered(Buffer tpd_buf);
static void ReleaseLastTPDBuffer(Buffer buf, bool locked);
static void LogAndClearTPDLocation(Relation relation, Buffer heapbuf,
								   bool *tpd_e_pruned);
static bool TPDPageIsValid(Relation relation, Buffer heapbuf,
						   bool *tpd_e_pruned, Buffer tpd_buf,
						   OffsetNumber tpdItemOff,
						   TPDEntryHeaderData  *tpd_e_hdr,
						   bool clean_tpd_loc);

void
ResetRegisteredTPDBuffers()
{
	registered_tpd_buf_idx = 0;
}

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
ReleaseLastTPDBuffer(Buffer buf, bool locked)
{
	Buffer	last_tpd_buf PG_USED_FOR_ASSERTS_ONLY;

	last_tpd_buf = tpd_buffers[tpd_buf_idx - 1].buf;
	Assert(buf == last_tpd_buf);
	if (locked)
		UnlockReleaseBuffer(buf);
	else
		ReleaseBuffer(buf);
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

	/* form tpd entry header */
	tpe_header.blkno = BufferGetBlockNumber(buf);
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
	*size_tpd_entry = SizeofTPDEntryHeader + size_tpd_e_map +
										size_tpd_e_slots;

	tpd_entry = (char *) palloc0(*size_tpd_entry);

	memcpy(tpd_entry, (char *) &tpe_header, SizeofTPDEntryHeader);

	tpd_entry_data = tpd_entry + SizeofTPDEntryHeader;

	/*
	 * Update the itemid to slot map for all the itemid's that point to last
	 * transaction slot in the heap page.
	 */
	for (offnum = FirstOffsetNumber;
		 offnum <= PageGetMaxOffsetNumber(page);
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

	memcpy(tpd_entry + SizeofTPDEntryHeader + size_tpd_e_map,
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
 * ExtendTPDEntry - Allocate bigger TPD entry and copy the contents of old TPD
 *  entry to new TPD entry.
 *
 * We are quite conservative in extending the TPD entry because the bigger the
 * entry more is the chance of space wastage.  OTOH, it might have some
 * performance impact because smaller the entry more is the chance of getting
 * a request for extension.  However, we feel that as we have a mechanism to
 * reuse the transaction slots, we shouldn't get the frequent requests for
 * extending the entry, at the very least not in performance critical paths.
 */
static void
ExtendTPDEntry(Relation relation, Buffer heapbuf, TransInfo *trans_slots,
			   OffsetNumber offnum, int buf_idx, int old_num_map_entries,
			   int old_num_slots, int *reserved_slot_no, UndoRecPtr *urecptr,
			   bool *tpd_e_pruned, bool always_extend)
{
	TPDEntryHeaderData	old_tpd_e_header, tpd_e_header;
	ZHeapPageOpaque		zopaque;
	TransInfo	last_trans_slot_info;
	Page		old_tpd_page;
	Page		heappage;
	Buffer		old_tpd_buf;
	Buffer		metabuf = InvalidBuffer;
	BlockNumber	tpdblk;
	OffsetNumber	max_page_offnum;
	Size		tpdpageFreeSpace;
	Size		new_size_tpd_entry,
				old_size_tpd_entry,
				new_size_tpd_e_map,
				new_size_tpd_e_slots,
				old_size_tpd_e_map,
				old_size_tpd_e_slots;
	ItemId		itemId;
	OffsetNumber	tpdItemOff;
	int			old_loc_tpd_e_map,
				old_loc_trans_slots;
	int			max_reqd_map_entries;
	int			max_reqd_slots = 0;
	int			num_free_slots = 0;
	int			slot_no;
	int			entries_removed;
	uint16		tpd_e_offset;
	char		*tpd_entry;
	bool		already_exists;
	bool		allocate_new_tpd_page = false;
	bool		update_tpd_inplace,
				tpd_pruned;

	heappage = BufferGetPage(heapbuf);
	max_page_offnum = PageGetMaxOffsetNumber(heappage);

	/*
	 * Select the maximum among required offset num, current map
	 * entries, and highest page offset as the number of offset-map
	 * entries for a new TPD entry.  We do allocate few additional map
	 * entries so that we don't need to allocate new TPD entry soon.
	 * Also, we ensure that we don't try to allocate more than
	 * MaxZHeapTuplesPerPage offset-map entries.
	 */
	max_reqd_map_entries = Max(offnum,
							   Max(old_num_map_entries, max_page_offnum));
	max_reqd_map_entries += ADDITIONAL_MAP_ELEM_IN_TPD_ENTRY;
	max_reqd_map_entries = Min(max_reqd_map_entries,
							   MaxZHeapTuplesPerPage);

	/*
	 * If there are more than fifty percent of empty slots available,
	 * then we don't extend the number of transaction slots in new TPD
	 * entry.  Otherwise also, we extend the slots quite conservately
	 * to avoid space wastage.
	 */
	if (*reserved_slot_no != InvalidXactSlotId)
	{
		for (slot_no = 0; slot_no < old_num_slots; slot_no++)
		{
			/*
			 * Check for the number of unreserved transaction slots in
			 * the TPD entry.
			 */
			if (trans_slots[slot_no].xid == InvalidTransactionId)
				num_free_slots++;
		}

		if (num_free_slots >= old_num_slots / 2)
			max_reqd_slots = old_num_slots;
	}

	if (max_reqd_slots <= 0)
		max_reqd_slots = old_num_slots + INITIAL_TRANS_SLOTS_IN_TPD_ENTRY;

	/*
	 * The transaction slots in TPD entry are in addition to the
	 * maximum slots in the heap page. The one-byte offset-map can
	 * store maximum upto 255 transaction slot number.
	 */
	if (max_reqd_slots + ZHEAP_PAGE_TRANS_SLOTS < 256)
		new_size_tpd_e_map = max_reqd_map_entries * sizeof(uint8);
	else
		new_size_tpd_e_map = max_reqd_map_entries * sizeof(uint32);
	new_size_tpd_e_slots = max_reqd_slots * sizeof(TransInfo);
	new_size_tpd_entry = SizeofTPDEntryHeader + new_size_tpd_e_map +
									new_size_tpd_e_slots;

	/* TPD entries can't span in multiple blocks. */
	if (new_size_tpd_entry > MaxTPDEntrySize)
	{
		/*
		 * FIXME:  what we should do if TPD entry can not fit in one page?
		 * currently we are giving error.
		 */
		elog(ERROR, "TPD entry size (%lu) cannot be greater than \
			 MaxTPDEntrySize (%u)", new_size_tpd_entry, MaxTPDEntrySize);

		*reserved_slot_no = InvalidXactSlotId;
		return;
	}

	if (buf_idx != -1)
		old_tpd_buf = tpd_buffers[buf_idx].buf;
	else
	{
		/*
		 * The last slot in page has the address of the required TPD
		 * entry.
		 */
		zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
		last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

		tpdblk = last_trans_slot_info.xid_epoch;
		buf_idx = GetTPDBuffer(relation, tpdblk, InvalidBuffer,
							   TPD_BUF_FIND_OR_ENTER, &already_exists);
		old_tpd_buf = tpd_buffers[buf_idx].buf;

		/*
		 * The tpd buffer must already exists as before reaching here
		 * we must have called TPDPageGetTransactionSlots which would
		 * have read the required buffer.
		 */
		Assert(already_exists);
	}

	/* The last slot in page has the address of the required TPD entry. */
	old_tpd_page = BufferGetPage(old_tpd_buf);
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(heapbuf));
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;
	itemId = PageGetItemId(old_tpd_page, tpdItemOff);
	old_size_tpd_entry = ItemIdGetLength(itemId);

	/* We have a lock on tpd page, so nobody can prune our tpd entry. */
	Assert(ItemIdIsUsed(itemId));

	tpdpageFreeSpace = PageGetTPDFreeSpace(old_tpd_page);

	/*
	 * Call TPDPagePrune to ensure that it will create a space adjacent to
	 * current offset for the new (bigger) TPD entry, if possible.  Note that,
	 * we set can_free as false. When we free a TPD page, we've to take lock
	 * on previous block. It's possible that we already have a lock on the same
	 * (non-inplace update on other buffer). In that case, we'll wait on ourselves.
	 */
	entries_removed = TPDPagePrune(relation, old_tpd_buf, NULL, tpdItemOff,
								   (new_size_tpd_entry - old_size_tpd_entry),
								   false, &update_tpd_inplace, &tpd_pruned);
	/*
	 * If the item got pruned, then clear the TPD slot from the page and
	 * return.  The entry can be pruned by ourselves or by anyone else
	 * as we release the lock during pruning if the page is empty.
	 */
	if (PageIsEmpty(old_tpd_page) ||
		!ItemIdIsUsed(itemId) ||
		tpd_pruned)
	{
		LogAndClearTPDLocation(relation, heapbuf, tpd_e_pruned);
		*reserved_slot_no = InvalidXactSlotId;
		*tpd_e_pruned = true;
		if (metabuf != InvalidBuffer)
			ReleaseBuffer(metabuf);
		return;
	}

	if (!update_tpd_inplace)
	{
		if (entries_removed > 0)
			tpdpageFreeSpace = PageGetTPDFreeSpace(old_tpd_page);

		if (tpdpageFreeSpace < new_size_tpd_entry)
		{
			/*
			 * XXX Here, we can have an optimization such that instead of
			 * allocating a new page, we can search other TPD pages starting
			 * from the first_used_tpd_page till we reach last_used_tpd_page.
			 * It is not clear whether such an optimization can help because
			 * checking all the TPD pages isn't free either.
			 */
			metabuf = ReadBuffer(relation, ZHEAP_METAPAGE);
			allocate_new_tpd_page = true;
		}
		else
		{
			/*
			 * We must not reach here because if the new tpd entry can fit on the same
			 * page, then update_tpd_inplace would have been set by TPDPagePrune.
			 */
			Assert(false);
		}
	}

	/* form tpd entry header */
	tpd_e_header.blkno = BufferGetBlockNumber(heapbuf);
	tpd_e_header.tpe_num_map_entries = max_reqd_map_entries;
	tpd_e_header.tpe_num_slots = max_reqd_slots;

	/*
	 * The transaction slots in TPD entry are in addition to the
	 * maximum slots in the heap page. The one-byte offset-map can
	 * store maximum upto 255 transaction slot number.
	 */
	if (max_reqd_slots + ZHEAP_PAGE_TRANS_SLOTS < 256)
		tpd_e_header.tpe_flags = TPE_ONE_BYTE;
	else
		tpd_e_header.tpe_flags = TPE_FOUR_BYTE;

	/*
	 * If we reach here, then the page must be a TPD page.
	 */
	Assert(PageGetSpecialSize(old_tpd_page) == MAXALIGN(sizeof(TPDPageOpaqueData)));

	/* TPD entry isn't pruned */
	tpd_e_offset = ItemIdGetOffset(itemId);

	memcpy((char *) &old_tpd_e_header, old_tpd_page + tpd_e_offset, SizeofTPDEntryHeader);

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(old_tpd_e_header));

	/* This TPD entry can't be for some other block. */
	Assert(old_tpd_e_header.blkno == BufferGetBlockNumber(heapbuf));

	if (old_tpd_e_header.tpe_flags & TPE_ONE_BYTE)
		old_size_tpd_e_map = old_tpd_e_header.tpe_num_map_entries * sizeof(uint8);
	else
	{
		Assert(old_tpd_e_header.tpe_flags & TPE_FOUR_BYTE);
		old_size_tpd_e_map = old_tpd_e_header.tpe_num_map_entries * sizeof(uint32);
	}

	old_size_tpd_e_slots = old_tpd_e_header.tpe_num_slots * sizeof(TransInfo);
	old_loc_tpd_e_map = tpd_e_offset + SizeofTPDEntryHeader;
	old_loc_trans_slots = tpd_e_offset + SizeofTPDEntryHeader + old_size_tpd_e_map;

	/* Form new TPD entry.  Whatever be the case, header will remain same. */
	tpd_entry = (char *) palloc0(new_size_tpd_entry);
	memcpy(tpd_entry, (char *) &tpd_e_header, SizeofTPDEntryHeader);

	if (tpd_e_header.tpe_flags & TPE_ONE_BYTE ||
		(tpd_e_header.tpe_flags & TPE_FOUR_BYTE &&
		 old_tpd_e_header.tpe_flags & TPE_FOUR_BYTE))
	{
		/*
		 * Caller must try to extend the TPD entry iff either there is a
		 * need of more offset-map entries or transaction slots.
		 */
		Assert(tpd_e_header.tpe_num_map_entries >= old_num_map_entries);
		Assert(tpd_e_header.tpe_num_slots >= old_num_slots);

		/*
		 * In this case we can copy the contents of old offset-map and
		 * old transaction slots as it is.
		 */
		memcpy(tpd_entry + SizeofTPDEntryHeader,
			   old_tpd_page + old_loc_tpd_e_map,
			   old_size_tpd_e_map);
		memcpy(tpd_entry + SizeofTPDEntryHeader + new_size_tpd_e_map,
			   old_tpd_page + old_loc_trans_slots,
			   old_size_tpd_e_slots);
	}
	else if (tpd_e_header.tpe_flags & TPE_FOUR_BYTE &&
			 old_tpd_e_header.tpe_flags & TPE_ONE_BYTE)
	{
		int		i;
		char	*new_start_loc,
				*old_start_loc;

		/*
		 * Here, we can't directly copy the offset-map because we are
		 * expanding it from one byte to four-bytes.  We need to perform
		 * byte-by-byte copy for the offset-map.  However, transaction
		 * slots can be directly copied as the size for each slot still
		 * remains same.
		 */
		Assert(old_tpd_e_header.tpe_num_map_entries == old_num_map_entries);

		new_start_loc = tpd_entry + SizeofTPDEntryHeader;
		old_start_loc = old_tpd_page + old_loc_tpd_e_map;

		for (i = 0; i < old_num_map_entries; i++)
		{
			memcpy(new_start_loc, old_start_loc, sizeof(uint8));
			old_start_loc += sizeof(uint8);
			new_start_loc += sizeof(uint32);
		}

		memcpy(tpd_entry + SizeofTPDEntryHeader + new_size_tpd_e_map,
			   old_tpd_page + old_loc_trans_slots,
			   old_size_tpd_e_slots);
	}
	else
	{
		/* All the valid cases should have been dealt above. */
		Assert(false);
	}
	
	if (update_tpd_inplace)
	{
		TPDEntryUpdate(relation, old_tpd_buf, tpd_e_offset, tpdItemOff,
					   tpd_entry, new_size_tpd_entry);
	}
	else
	{
		/*
		 * Note that if we have to allocate a new page, we must delete the
		 * old tpd entry in old tpd buffer.
		 */
		TPDAllocatePageAndAddEntry(relation, metabuf, heapbuf, old_tpd_buf,
								   tpdItemOff, tpd_entry, new_size_tpd_entry,
								   allocate_new_tpd_page,
								   allocate_new_tpd_page, always_extend);
	}

	/* Release the meta buffer. */
	if (metabuf != InvalidBuffer)
		ReleaseBuffer(metabuf);

	if (*reserved_slot_no == InvalidXactSlotId)
	{
		int		slot_no;

		trans_slots = (TransInfo *) (tpd_entry + SizeofTPDEntryHeader + new_size_tpd_e_map);

		for (slot_no = 0; slot_no < tpd_e_header.tpe_num_slots; slot_no++)
		{
			/* Check for an unreserved transaction slot in the TPD entry */
			if (trans_slots[slot_no].xid == InvalidTransactionId)
			{
				*reserved_slot_no = slot_no;
				break;
			}
		}
	}
	
	if (*reserved_slot_no != InvalidXactSlotId)
		*urecptr = trans_slots[*reserved_slot_no].urec_ptr;

	pfree(tpd_entry);

	return;
}

/*
 * TPDPageAddEntry - Add the given to TPD entry on the page and
 * move the upper to point to the next free location.
 *
 * Return value is the offset at which it was inserted, or InvalidOffsetNumber
 * if the item is not inserted for any reason.  A WARNING is issued indicating
 * the reason for the refusal.
 *
 * This function is same as PageAddItemExtended, but has different
 * alignment requirements.  We might want to deal with that by passing
 * additional argument to PageAddItemExtended, but for now we have kept
 * it as a separate function.
 */
OffsetNumber
TPDPageAddEntry(Page tpdpage, char *tpd_entry, Size size,
				OffsetNumber offnum)
{
	PageHeader	phdr = (PageHeader) tpdpage;
	OffsetNumber	limit;
	ItemId		itemId;
	uint16		lower;
	uint16		upper;

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

	/*
	 * Select offsetNumber to place the new item at
	 */
	limit = OffsetNumberNext(PageGetMaxOffsetNumber(tpdpage));

	lower = phdr->pd_lower + sizeof(ItemIdData);

	if (OffsetNumberIsValid(offnum))
	{
		/*
		 * In TPD, we send valid offset number only during recovery. Hence,
		 * we don't need to shuffle the offsets as well.
		 */
		Assert(InRecovery);
		if (offnum < limit)
		{
			itemId = PageGetItemId(phdr, offnum);
			if (ItemIdIsUsed(itemId) || ItemIdHasStorage(itemId))
			{
				elog(WARNING, "will not overwrite a used ItemId");
				return InvalidOffsetNumber;
			}
		}
	}
	else
	{
		/* offsetNumber was not passed in, so find a free slot */
		/* if no free slot, we'll put it at limit (1st open slot) */
		if (PageHasFreeLinePointers(phdr))
		{
			/*
			 * Look for "recyclable" (unused) ItemId.  We check for no storage
			 * as well, just to be paranoid --- unused items should never have
			 * storage.
			 */
			for (offnum = 1; offnum < limit; offnum++)
			{
				itemId = PageGetItemId(phdr, offnum);
				if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
					break;
			}
			if (offnum >= limit)
			{
				/* the hint is wrong, so reset it */
				PageClearHasFreeLinePointers(phdr);
			}
		}
		else
		{
			offnum = limit;
		}
	}

	/* Reject placing items beyond the first unused line pointer */
	if (offnum > limit)
	{
		elog(WARNING, "specified item offset is too large");
		return InvalidOffsetNumber;
	}

	/* Reject placing items beyond tpd boundary */
	if (offnum > MaxTPDTuplesPerPage)
	{
		elog(WARNING, "can't put more than MaxTPDTuplesPerPage items in a tpd page");
		return InvalidOffsetNumber;
	}

	/*
	 * Compute new lower and upper pointers for page, see if it'll fit.
	 *
	 * Note: do arithmetic as signed ints, to avoid mistakes if, say,
	 * alignedSize > pd_upper.
	 */
	if (offnum == limit)
		lower = phdr->pd_lower + sizeof(ItemIdData);
	else
		lower = phdr->pd_lower;

	upper = (int) phdr->pd_upper - (int) size;

	if (lower > upper)
		return InvalidOffsetNumber;

	/* OK to insert the item. */
	itemId = PageGetItemId(phdr, offnum);

	/* set the item pointer */
	ItemIdSetNormal(itemId, upper, size);

	/* copy the item's data onto the page */
	memcpy((char *) tpdpage + upper, tpd_entry, size);

	phdr->pd_lower = (LocationIndex) lower;
	phdr->pd_upper = (LocationIndex) upper;

	return offnum;
}

/*
 * SetTPDLocation - Set TPD entry location in the last transaction slot of
 *		heap page and indicate the same in page.
 */
void
SetTPDLocation(Buffer heapbuffer, Buffer tpdbuffer, OffsetNumber offset)
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
 * ClearTPDLocation - Clear TPD entry location in the last transaction slot of
 *		heap page and indicate the same in page.
 */
void
ClearTPDLocation(Buffer heapbuf)
{
	PageHeader	phdr;
	ZHeapPageOpaque	opaque;
	Page		heappage;
	int frozen_slots = ZHEAP_PAGE_TRANS_SLOTS - 1;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/*
	 * Before clearing the TPD slot, mark all the tuples pointing to TPD slot
	 * as frozen.
	 */
	zheap_freeze_or_invalidate_tuples(heapbuf, 1, &frozen_slots,
									  true, false);

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);

	/* clear the last transaction slot info */
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid_epoch = 0;
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid =
											InvalidTransactionId;
	opaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].urec_ptr =
											InvalidUndoRecPtr;

	phdr->pd_flags &= ~PD_PAGE_HAS_TPD_SLOT;
}

/*
 * LogClearTPDLocation - Write a WAL record for clearing TPD location.
 */
static void
LogClearTPDLocation(Buffer buffer)
{
	XLogRecPtr	recptr;

	XLogBeginInsert();
	XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

	recptr = XLogInsert(RM_TPD_ID, XLOG_TPD_CLEAR_LOCATION);

	PageSetLSN(BufferGetPage(buffer), recptr);
}

/*
 * LogAndClearTPDLocation - Clear the TPD location from heap page and WAL log
 *			it.
 */
static void
LogAndClearTPDLocation(Relation relation, Buffer heapbuf, bool *tpd_e_pruned)
{
	START_CRIT_SECTION();

	ClearTPDLocation(heapbuf);
	MarkBufferDirty(heapbuf);
	if (RelationNeedsWAL(relation))
		LogClearTPDLocation(heapbuf);

	END_CRIT_SECTION();

	if (tpd_e_pruned)
		*tpd_e_pruned = true;
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
 * TPDFreePage - Remove the TPD page from the chain.
 *
 * Initialize the empty page and remove it from the chain.  This function
 * ensures that the buffers are locked such that the block that exists prior
 * in chain gets locked first and meta page is locked at end after which no
 * existing page is locked.  This is to avoid deadlocks, see comments atop
 * function TPDAllocatePageAndAddEntry.
 *
 * We expect that the caller must have acquired EXCLUSIVE lock on the current
 * buffer (buf) and will be responsible for releasing the same.
 *
 * Returns true, if we are able to successfully remove the page from chain,
 * false, otherwise.
 */
bool
TPDFreePage(Relation rel, Buffer buf, BufferAccessStrategy bstrategy)
{
	TPDPageOpaque	tpdopaque,
					prevtpdopaque,
					nexttpdopaque;
	ZHeapMetaPage	metapage;
	Page			page = NULL,
					prevpage = NULL,
					nextpage = NULL;
	BlockNumber		curblkno PG_USED_FOR_ASSERTS_ONLY = InvalidBlockNumber;
	BlockNumber		prevblkno = InvalidBlockNumber;
	BlockNumber		nextblkno = InvalidBlockNumber;
	Buffer			prevbuf = InvalidBuffer;
	Buffer			nextbuf = InvalidBuffer;
	Buffer			metabuf = InvalidBuffer;
	bool			update_meta = false;

	/*
	 * We must acquire the cleanup lock here to wait for backends that have
	 * already read this buffer and might be in the process of deciding
	 * whether this is a valid TPD page (aka it contain valid TPD entries).
	 * All of them must reach a conclution, that there is no valid TPD entry
	 * in this page as we have already pruned all TPD entries from this page
	 * by this time.  If we don't wait here for other backends who have
	 * already read this page, then it is possible that by the time they try
	 * to acquire lock on this page, we would have freed this page and some
	 * other backend could have reused it as heap page and had a lock on it.
	 * In such a situation, the system can deadlock because the backend-1
	 * which tries to acquire a lock on this page thinking it is a TPD page
	 * would wait on backend-2 which has reused it as a heap page and
	 * backend-2 can wait start waiting on some page on which backend-1 has
	 * a lock (this can usually happen when multiple heap buffers are involved
	 * in a single operation like in case of non-in-place updates).
	 *
	 * For new backends that come to access this as a TPD page after we
	 * acquire cleanup lock here would definetely see this as a invalid
	 * TPD page (no valid TPD entries).
	 *
	 * One can imagine that after we release the lock, vacuum or some other
	 * process can record this page in FSM, but that is not possible as we
	 * haven't cleared the special space which will make it appear as a TPD
	 * page and it will just ignore this page.  See lazy_scan_zheap.
	 */
	LockBuffer(buf, BUFFER_LOCK_UNLOCK);
	LockBufferForCleanup(buf);

	/*
	 * After reaquiring the lock, check whether page is still empty, if
	 * not, then we don't need to do anything.  As of now, there is no
	 * possiblity that the empty page in the chain can be reused, however,
	 * in future, we can use it.
	 */
	page = BufferGetPage(buf);
	if (!PageIsEmpty(page))
		return false;

	curblkno = BufferGetBlockNumber(buf);
	tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(page);
	prevblkno = tpdopaque->tpd_prevblkno;

	/* Fetch and lock the previous block, if exists. */
	if (BlockNumberIsValid(prevblkno))
	{
		/*
		 * Before taking the lock on previous block, we need to release the
		 * lock on the current buffer.  This is to ensure that we always lock
		 * the buffers in the order in which they are present in list.  This
		 * avoids the deadlock risks.  See atop TPDAllocatePageAndAddEntry.
		 */
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		prevbuf = ReadBufferExtended(rel, MAIN_FORKNUM, prevblkno, RBM_NORMAL,
									 bstrategy);
		LockBuffer(prevbuf, BUFFER_LOCK_EXCLUSIVE);
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * After reaquiring the lock, check whether page is still empty, if
		 * not, then we don't need to do anything.  As of now, there is no
		 * possiblity that the empty page in the chain can be reused, however,
		 * in future, we can use it.
		 */
		page = BufferGetPage(buf);
		if (!PageIsEmpty(page))
		{
			UnlockReleaseBuffer(prevbuf);
			return false;
		}
		tpdopaque = (TPDPageOpaque)PageGetSpecialPointer(page);
	}

	nextblkno = tpdopaque->tpd_nextblkno;

	/* Fetch and lock the next buffer. */
	if (BlockNumberIsValid(nextblkno))
	{
		nextbuf = ReadBufferExtended(rel, MAIN_FORKNUM, nextblkno, RBM_NORMAL,
									 bstrategy);
		LockBuffer(nextbuf, BUFFER_LOCK_EXCLUSIVE);
	}

	metabuf = ReadBufferExtended(rel, MAIN_FORKNUM, ZHEAP_METAPAGE,
								 RBM_NORMAL, bstrategy);
	LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);

	metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));
	Assert(metapage->zhm_magic == ZHEAP_MAGIC);

	START_CRIT_SECTION();

	/* Update the current page. */
	tpdopaque->tpd_prevblkno = InvalidBlockNumber;
	tpdopaque->tpd_nextblkno = InvalidBlockNumber;
	tpdopaque->tpd_latest_xid_epoch = 0;
	tpdopaque->tpd_latest_xid = InvalidTransactionId;

	MarkBufferDirty(buf);

	/* Update the previous page. */
	if (BufferIsValid(prevbuf))
	{
		prevpage = BufferGetPage(prevbuf);
		prevtpdopaque = (TPDPageOpaque) PageGetSpecialPointer(prevpage);

		prevtpdopaque->tpd_nextblkno = nextblkno;
		MarkBufferDirty(prevbuf);
	}
	/* Update the next page. */
	if (BufferIsValid(nextbuf))
	{
		nextpage = BufferGetPage(nextbuf);
		nexttpdopaque = (TPDPageOpaque) PageGetSpecialPointer(nextpage);

		nexttpdopaque->tpd_prevblkno = prevblkno;
		MarkBufferDirty(nextbuf);
	}

	/*
	 * Update the metapage.  If the previous or next block is invalid, the
	 * page to be removed could be first or last page in the chain in which
	 * case we need to update the metapage accordingly.
	 */
	if (!BlockNumberIsValid(prevblkno) ||
		!BlockNumberIsValid(nextblkno))
	{
		if (!BlockNumberIsValid(prevblkno) && !BlockNumberIsValid(nextblkno))
		{
			/*
			 * If there is no prevblock and nextblock, then the current page
			 * must be the first and the last page.
			 */
			Assert(metapage->zhm_first_used_tpd_page == curblkno);
			Assert(metapage->zhm_last_used_tpd_page == curblkno);
			metapage->zhm_first_used_tpd_page = InvalidBlockNumber;
			metapage->zhm_last_used_tpd_page = InvalidBlockNumber;
		}
		else if (!BlockNumberIsValid(prevblkno))
		{
			/*
			 * If there is no prevblock, then the current block must be first
			 * used page.
			 */
			Assert(BlockNumberIsValid(nextblkno));
			metapage->zhm_first_used_tpd_page = nextblkno;
		}
		else if (!BlockNumberIsValid(nextblkno))
		{
			/*
			 * If next block is invalid, then the current block must be last
			 * used page.
			 */
			Assert(metapage->zhm_last_used_tpd_page == curblkno);
			metapage->zhm_last_used_tpd_page = prevblkno;
		}
		else
		{
			/* one of the above two conditions must be satisfied. */
			Assert(false);
		}

		MarkBufferDirty(metabuf);
		update_meta = true;
	}
	else
	{
		/*
		 * If next block is a valid block then the last used page can't be the
		 * current page being removed.
		 */
		Assert(metapage->zhm_last_used_tpd_page != curblkno);
	}

	if (RelationNeedsWAL(rel))
	{
		XLogRecPtr	recptr;
		xl_tpd_free_page	xlrec;
		uint8 	info =  XLOG_TPD_FREE_PAGE;

		xlrec.prevblkno = prevblkno;
		xlrec.nextblkno = nextblkno;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfTPDFreePage);
		if (BufferIsValid(prevbuf))
			XLogRegisterBuffer(0, prevbuf, REGBUF_STANDARD);
		XLogRegisterBuffer(1, buf, REGBUF_STANDARD);
		if (BufferIsValid(nextbuf))
			XLogRegisterBuffer(2, nextbuf, REGBUF_STANDARD);
		if (update_meta)
		{
			xl_zheap_metadata		xl_meta;

			info |= XLOG_TPD_INIT_PAGE;
			xl_meta.first_used_tpd_page = metapage->zhm_first_used_tpd_page;
			xl_meta.last_used_tpd_page = metapage->zhm_last_used_tpd_page;
			XLogRegisterBuffer(3, metabuf, REGBUF_STANDARD | REGBUF_WILL_INIT);
			XLogRegisterBufData(3, (char *) &xl_meta, SizeOfMetaData);
		}

		recptr = XLogInsert(RM_TPD_ID, info);

		if (BufferIsValid(prevbuf))
			PageSetLSN(prevpage, recptr);
		PageSetLSN(page, recptr);
		if (BufferIsValid(nextbuf))
			PageSetLSN(nextpage, recptr);
		if (update_meta)
			PageSetLSN(BufferGetPage(metabuf), recptr);
	}

	END_CRIT_SECTION();

	if (BufferIsValid(prevbuf))
		UnlockReleaseBuffer(prevbuf);
	if (BufferIsValid(nextbuf))
		UnlockReleaseBuffer(nextbuf);
	UnlockReleaseBuffer(metabuf);

	return true;
}

/*
 * TPDEntryUpdate - Update the TPD entry inplace and write a WAL record for
 *					the same.
 */
static void
TPDEntryUpdate(Relation relation, Buffer tpd_buf, uint16 tpd_e_offset,
			   OffsetNumber tpd_item_off, char *tpd_entry,
			   Size size_tpd_entry)
{
	Page	tpd_page = BufferGetPage(tpd_buf);
	ItemId	itemId = PageGetItemId(tpd_page, tpd_item_off);

	START_CRIT_SECTION();

	memcpy((char *) (tpd_page + tpd_e_offset),
		   tpd_entry,
		   size_tpd_entry);
	ItemIdChangeLen(itemId, size_tpd_entry);

	MarkBufferDirty(tpd_buf);

	if (RelationNeedsWAL(relation))
	{
		XLogRecPtr	recptr;

		XLogBeginInsert();
		XLogRegisterBuffer(0, tpd_buf, REGBUF_STANDARD);
		XLogRegisterBufData(0, (char *) &tpd_item_off, sizeof(OffsetNumber));
		XLogRegisterBufData(0, (char *) tpd_entry, size_tpd_entry);

		recptr = XLogInsert(RM_TPD_ID, XLOG_INPLACE_UPDATE_TPD_ENTRY);

		PageSetLSN(tpd_page, recptr);
	}

	END_CRIT_SECTION();
}

/*
 * TPDAllocatePageAndAddEntry - Allocates a new tpd page if required and adds
 *								tpd entry.
 *
 * This function takes care of inserting the new tpd entry to a page and
 * allows to mark old entry as deleted when requested.  The typical actions
 * performed in this function are (a) add a TPD entry in the newly allocated
 * or an existing TPD page, (b) update the metapage to indicate the addion of
 * a new page (if allocated) and for updating zhm_last_used_tpd_page, (c) mark
 * the old TPD entry as prunable, (c) update the new offset number of TPD
 * entry in heap page. Finally write a WAL entry and corresponding replay
 * routine to cover all these operations and release all the buffers.
 *
 * The other aspect this function needs to ensure is the buffer locking order
 * to avoid deadlocks.  We operate on four buffers: metapage buffer, old tpd
 * page buffer, last used tpd page buffer and new tpd page buffer.  The old
 * buffer is always locked by the caller and we ensure that this function first
 * locks the last used tpd page buffer, then locks the metapage buffer and then
 * the newly allocated page buffer.  This locking can never lead to deadlock as
 * old buffer block will always be lesser (or equal) than last buffer block.
 * However, if anytime, we change our startegy such that after acquiring
 * metapage lock, we try to acquire lock on any existing page, then we might
 * need to reconsider our locking order.
 *
 * always_extend, this parameter indicates whether we can use FSM to get the
 * new TPD page or not.  This is required to avoid some deadlock hazards by
 * the callers, basically they don't want to lock any tpd page with lower
 * number, when they already have lock on some other tpd page.
 */
static void
TPDAllocatePageAndAddEntry(Relation relation, Buffer metabuf, Buffer pagebuf,
						   Buffer old_tpd_buf, OffsetNumber old_off_num,
						   char *tpd_entry, Size size_tpd_entry,
						   bool add_new_tpd_page, bool delete_old_entry,
						   bool always_extend)
{
	ZHeapMetaPage	metapage = NULL;
	TPDPageOpaque	tpdopaque, last_tpdopaque;
	TPDEntryHeader	old_tpd_entry;
	Buffer	last_used_tpd_buf = InvalidBuffer;
	Buffer	tpd_buf;
	Page	tpdpage;
	BlockNumber	prevblk = InvalidBlockNumber;
	BlockNumber	nextblk = InvalidBlockNumber;
	BlockNumber last_used_tpd_page;
	OffsetNumber	offset_num;
	bool			free_last_used_tpd_buf = false;

	if (add_new_tpd_page)
	{
		BlockNumber		targetBlock = InvalidBlockNumber;
		Size	len = MaxTPDEntrySize;
		int		buf_idx;
		bool	needLock;
		bool	already_exists;

		/*
		 * While adding a new page, if we've to delete the old entry,
		 * the old buffer must be valid. Else, it should be invalid.
		 */
		Assert(!delete_old_entry || BufferIsValid(old_tpd_buf));
		Assert(delete_old_entry || !BufferIsValid(old_tpd_buf));

		/* Always extend when asked to do so. */
		if (!always_extend)
		{
			/* Before extending the relation, check the FSM for free page. */
			targetBlock = GetPageWithFreeSpace(relation, len, false);

			while (targetBlock != InvalidBlockNumber)
			{
				Page page;
				Size pageFreeSpace;

				tpd_buf = ReadBuffer(relation, targetBlock);

				/*
				 * We need to take the lock on meta page before new page to
				 * avoid deadlocks.  See comments atop of function.
				 */
				LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);

				/* It's possible that FSM returns a zheap page on which the
				 * current backend already holds a lock in exclusive mode.
				 * Hence, try using conditional lock. If it can't get the lock
				 * immediately, extend the relation and allocate a new TPD
				 * block.
				 */
				if (ConditionalLockBuffer(tpd_buf))
				{
					page = BufferGetPage(tpd_buf);

					if (PageIsEmpty(page))
					{
						GetTPDBuffer(relation, targetBlock, tpd_buf,
									 TPD_BUF_FIND_OR_KNOWN_ENTER,
									 &already_exists);
						break;
					}

					LockBuffer(metabuf, BUFFER_LOCK_UNLOCK);

					if (PageGetSpecialSize(page) == MAXALIGN(sizeof(TPDPageOpaqueData)))
						pageFreeSpace = PageGetTPDFreeSpace(page);
					else
						pageFreeSpace = PageGetZHeapFreeSpace(page);

					/*
					 * Update FSM as to condition of this page, and ask for
					 * another page to try.
					 */
					targetBlock = RecordAndGetPageWithFreeSpace(relation,
																targetBlock,
																pageFreeSpace,
																len);
					UnlockReleaseBuffer(tpd_buf);
				}
				else
				{
					LockBuffer(metabuf, BUFFER_LOCK_UNLOCK);
					ReleaseBuffer(tpd_buf);
					targetBlock = InvalidBlockNumber;
				}
			}
		}

		/* Extend the relation, if required? */
		if (targetBlock == InvalidBlockNumber)
		{
			/* Acquire the extension lock, if extension is required. */
			needLock = !RELATION_IS_LOCAL(relation);
			if (needLock)
				LockRelationForExtension(relation, ExclusiveLock);

			buf_idx = GetTPDBuffer(relation, P_NEW, InvalidBuffer,
									TPD_BUF_ENTER, &already_exists);
			/* This must be a new buffer. */
			Assert(!already_exists);
			tpd_buf = tpd_buffers[buf_idx].buf;
			LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);
			LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);
			targetBlock = BufferGetBlockNumber(tpd_buf);

			if (needLock)
				UnlockRelationForExtension(relation, ExclusiveLock);
		}

		/*
		 * Once we've allocated a TPD page, we should update the FSM with the
		 * available freespace which is zero in this case. This restricts other
		 * backends from getting the same page from FSM.
		 */
		RecordPageWithFreeSpace(relation, targetBlock, 0, InvalidBlockNumber);

		/*
		 * Lock the last tpd page in list, so that we can append new page to
		 * it.
		 */
		metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));
		Assert(metapage->zhm_magic == ZHEAP_MAGIC);

recheck_meta:
		last_used_tpd_page = metapage->zhm_last_used_tpd_page;
		if (metapage->zhm_last_used_tpd_page != InvalidBlockNumber)
		{
			last_used_tpd_page	= metapage->zhm_last_used_tpd_page;
			buf_idx = GetTPDBuffer(relation, last_used_tpd_page, InvalidBuffer,
								   TPD_BUF_FIND, &already_exists);

			if (buf_idx == -1)
			{
				last_used_tpd_buf = ReadBuffer(relation,
											   metapage->zhm_last_used_tpd_page);
				/*
				 * To avoid deadlock, ensure that we never acquire lock on any existing
				 * block after acquiring meta page lock.  See comments atop function.
				 */
				LockBuffer(metabuf, BUFFER_LOCK_UNLOCK);
				LockBuffer(last_used_tpd_buf, BUFFER_LOCK_EXCLUSIVE);
				LockBuffer(metabuf, BUFFER_LOCK_EXCLUSIVE);
				
				if (metapage->zhm_last_used_tpd_page != last_used_tpd_page)
				{
					UnlockReleaseBuffer(last_used_tpd_buf);
					goto recheck_meta;
				}

				free_last_used_tpd_buf = true;
			}
			else
			{
				/* We don't need to lock the buffer, if it is already locked */
				last_used_tpd_buf = tpd_buffers[buf_idx].buf;
			}
		}
	}
	else
	{
		/* old buffer must be valid */
		Assert(BufferIsValid(old_tpd_buf));
		tpd_buf = old_tpd_buf;
	}

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	tpdpage = BufferGetPage(tpd_buf);

	/* Update metapage and add the new TPD page in the TPD page list. */
	if (add_new_tpd_page)
	{
		BlockNumber tpdblkno;

		/* Page must be new or empty. */
		Assert(PageIsEmpty(tpdpage) || PageIsNew(tpdpage));

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
	else
	{
		/*
		 * TPD chain should remain unchanged.
		 */
		tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
		prevblk = tpdopaque->tpd_prevblkno;
		nextblk = tpdopaque->tpd_nextblkno;
	}

	/* Mark the old tpd entry as dead before adding new entry. */
	if (delete_old_entry)
	{
		Page	otpdpage;
		ItemId	old_item_id;

		/* We must be adding new TPD entry into a new page. */
		Assert(add_new_tpd_page);
		Assert(old_tpd_buf != tpd_buf);

		otpdpage = BufferGetPage(old_tpd_buf);
		old_item_id = PageGetItemId(otpdpage, old_off_num);
		old_tpd_entry = (TPDEntryHeader) PageGetItem(otpdpage, old_item_id);
		old_tpd_entry->tpe_flags |= TPE_DELETED;
		MarkBufferDirty(old_tpd_buf);
	}

	/* Add tpd entry to page */
	offset_num = TPDPageAddEntry(tpdpage, tpd_entry, size_tpd_entry,
								 InvalidOffsetNumber);
	if (offset_num == InvalidOffsetNumber)
		elog(PANIC, "failed to add TPD entry");

	MarkBufferDirty(tpd_buf);

	/*
	 * Now that the last transaction slot from heap page has moved to TPD,
	 * we need to assign TPD location in the last transaction slot of heap.
	 */
	SetTPDLocation(pagebuf, tpd_buf, offset_num);
	MarkBufferDirty(pagebuf);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		XLogRecPtr	recptr;
		xl_tpd_allocate_entry	xlrec;
		xl_zheap_metadata	metadata;
		int		bufflags = 0;
		uint8	info = XLOG_ALLOCATE_TPD_ENTRY;

		xlrec.offnum = offset_num;
		xlrec.prevblk = prevblk;
		xlrec.nextblk = nextblk;
		xlrec.flags = 0;

		/*
		 * If we are adding TPD entry to a new page, we will reinit the page
		 * during replay.
		 */
		if (add_new_tpd_page)
		{
			info |= XLOG_TPD_INIT_PAGE;
			bufflags |= REGBUF_WILL_INIT;
		}

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfTPDAllocateEntry);
		XLogRegisterBuffer(0, tpd_buf, REGBUF_STANDARD | bufflags);
		XLogRegisterBufData(0, (char *) tpd_entry, size_tpd_entry);
		XLogRegisterBuffer(1, pagebuf, REGBUF_STANDARD);
		if (add_new_tpd_page)
		{
			XLogRegisterBuffer(2, metabuf, REGBUF_WILL_INIT | REGBUF_STANDARD);
			metadata.first_used_tpd_page = metapage->zhm_first_used_tpd_page;
			metadata.last_used_tpd_page = metapage->zhm_last_used_tpd_page;
			XLogRegisterBufData(2, (char *) &metadata, SizeOfMetaData);

			if (BufferIsValid(last_used_tpd_buf))
				XLogRegisterBuffer(3, last_used_tpd_buf, REGBUF_STANDARD);

			/* The old entry is deleted only when new page is allocated. */
			if (delete_old_entry)
			{
				/*
				 * If the last tpd buffer and the old tpd buffer are same, we
				 * don't need to register old_tpd_buf.
				 */
				if (last_used_tpd_buf == old_tpd_buf)
				{
					xlrec.flags = XLOG_OLD_TPD_BUF_EQ_LAST_TPD_BUF;
					XLogRegisterBufData(3, (char *) &old_off_num, sizeof(OffsetNumber));
				}
				else
				{
					XLogRegisterBuffer(4, old_tpd_buf, REGBUF_STANDARD);
					XLogRegisterBufData(4, (char *) &old_off_num, sizeof(OffsetNumber));
				}
			}
		}

		recptr = XLogInsert(RM_TPD_ID, info);

		PageSetLSN(tpdpage, recptr);
		PageSetLSN(BufferGetPage(pagebuf), recptr);
		if (add_new_tpd_page)
		{
			PageSetLSN(BufferGetPage(metabuf), recptr);
			if (BufferIsValid(last_used_tpd_buf))
				PageSetLSN(BufferGetPage(last_used_tpd_buf), recptr);
			if (delete_old_entry)
				PageSetLSN(BufferGetPage(old_tpd_buf), recptr);
		}
	}

	END_CRIT_SECTION();

	if (add_new_tpd_page)
		LockBuffer(metabuf, BUFFER_LOCK_UNLOCK);
	if (free_last_used_tpd_buf)
	{
		Assert (last_used_tpd_buf != tpd_buf);
		UnlockReleaseBuffer(last_used_tpd_buf);
	}
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
							   OffsetNumber offnum, UndoRecPtr *urec_ptr,
							   bool always_extend)
{
	ZHeapMetaPage	metapage;
	Buffer	metabuf;
	Buffer	tpd_buf = InvalidBuffer;
	Page	heappage;
	uint32		first_used_tpd_page;
	uint32		last_used_tpd_page;
	char		*tpd_entry;
	Size		size_tpd_entry;
	int			reserved_slot = InvalidXactSlotId;
	int			buf_idx;
	bool		allocate_new_tpd_page = false;
	bool		update_meta = false;
	bool		already_exists;

	metabuf = ReadBuffer(relation, ZHEAP_METAPAGE);
	LockBuffer(metabuf, BUFFER_LOCK_SHARE);
	metapage = ZHeapPageGetMeta(BufferGetPage(metabuf));
	Assert(metapage->zhm_magic == ZHEAP_MAGIC);

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

		size_tpd_e_map = num_map_entries * sizeof(uint8);
		size_tpd_e_slots = INITIAL_TRANS_SLOTS_IN_TPD_ENTRY * sizeof(TransInfo);
		size_tpd_entry = SizeofTPDEntryHeader + size_tpd_e_map +
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
			int		entries_removed;

			/*
			 * Prune the TPD page to make space for new TPD entries.  After
			 * pruning, check again to see if the TPD entry can be accomodated
			 * on the page. We can't afford to free the page while pruning as
			 * we need to use it to insert the TPD entry.
			 */
			entries_removed = TPDPagePrune(relation, tpd_buf, NULL,
										   InvalidOffsetNumber, 0, false, NULL,
										   NULL);

			if (entries_removed > 0)
				tpdpageFreeSpace = PageGetTPDFreeSpace(BufferGetPage(tpd_buf));

			if (tpdpageFreeSpace < size_tpd_entry)
			{
				/*
				 * XXX Here, we can have an optimization such that instead of
				 * allocating a new page, we can search other TPD pages starting
				 * from the first_used_tpd_page till we reach last_used_tpd_page.
				 * It is not clear whether such an optimization can help because
				 * checking all the TPD pages isn't free either.
				 */
				if (!already_exists)
					ReleaseLastTPDBuffer(tpd_buf, true);
				allocate_new_tpd_page = true;
			}
		}
	}

	if (allocate_new_tpd_page ||
		(last_used_tpd_page == InvalidBlockNumber &&
		first_used_tpd_page == InvalidBlockNumber))
	{
		tpd_buf = InvalidBuffer;
		update_meta = true;
	}

	/* Allocate a new TPD entry */
	tpd_entry = AllocateAndFormTPDEntry(pagebuf, offnum, &size_tpd_entry,
										&reserved_slot);
	Assert (tpd_entry != NULL);

	TPDAllocatePageAndAddEntry(relation, metabuf, pagebuf, tpd_buf,
							   InvalidOffsetNumber, tpd_entry, size_tpd_entry,
							   update_meta, false, always_extend);

	ReleaseBuffer(metabuf);

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
 * It is quite possible that the TPD entry containing required transaction slot
 * information got pruned away (as all the transaction entries are all-visible)
 * by the time caller tries to enquire about it.  See atop
 * TPDPageGetTransactionSlotInfo for more details on how we deal with pruned
 * TPD entries.
 *
 * clean_tpd_loc indicates whether we can clear the TPD location from the page
 * zheap page if the corresponding TPD entry got pruned away.  To clear the TPD
 * location from the zheap page, the zheap buffer must be locked in exclusive
 * mode.
 *
 * This function returns a pointer to an array of transaction slots, it is the
 * responsibility of the caller to free it.
 */
TransInfo *
TPDPageGetTransactionSlots(Relation relation, Buffer heapbuf,
						   OffsetNumber offnum, bool keepTPDBufLock,
						   bool checkOffset, int *num_map_entries,
						   int *num_trans_slots, int *tpd_buf_id,
						   bool *tpd_e_pruned, bool *alloc_bigger_map,
						   bool clean_tpd_loc)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	Page		heappage = BufferGetPage(heapbuf);
	ZHeapPageOpaque	zopaque;
	TransInfo	*trans_slots = NULL;
	TransInfo	last_trans_slot_info;
	Buffer	tpd_buf;
	Page	tpdpage;
	BlockNumber	tpdblk;
	BlockNumber lastblock;
	TPDEntryHeaderData	tpd_e_hdr;
	Size	size_tpd_e_map;
	Size	size_tpd_e_slots;
	int		loc_trans_slots;
	int		buf_idx;
	OffsetNumber	tpdItemOff;
	ItemId	itemId;
	uint16	tpd_e_offset;
	bool	already_exists;
	bool	valid;

	phdr = (PageHeader) heappage;
	
	if (tpd_buf_id)
		*tpd_buf_id = -1;
	if (num_map_entries)
		*num_map_entries = 0;
	if (num_trans_slots)
		*num_trans_slots = 0;
	if (tpd_e_pruned)
		*tpd_e_pruned = false;
	if (alloc_bigger_map)
		*alloc_bigger_map = false;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	/*
	 * Heap page should be locked in exclusive mode in case the TPD location
	 * from the can be cleaned.
	 */
	Assert(!clean_tpd_loc ||
		   LWLockHeldByMeInMode(BufferDescriptorGetContentLock(GetBufferDescriptor(heapbuf - 1)),
								LW_EXCLUSIVE));

	/* The last slot in page has the address of the required TPD entry. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

	if (!InRecovery)
	{
		lastblock = RelationGetNumberOfBlocks(relation);

		if (lastblock <= tpdblk)
		{
			/*
			 * The required TPD block has been pruned and then truncated away
			 * which means all transaction slots on that page are older than
			 * oldestXidHavingUndo.  So, we can assume the transaction slot is
			 * frozen aka transaction is all-visible and can clear the slot from
			 * heap tuples.
			 */
			if (clean_tpd_loc)
				LogAndClearTPDLocation(relation, heapbuf, tpd_e_pruned);
			goto failed_and_buf_not_locked;
		}
	}

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
		/*
		 * Before acquiring the lock on this page, we need to check whether TPD
		 * entry can exist on page.  This is mainly to ensure that this page
		 * hasn't already been reused as a heap page in which case we might
		 * either start waiting on our own backend or some other backend which
		 * can lead to dead lock.  See TPDFreePage to know more about how we
		 * prevent such deadlocks.
		 *
		 * There is a race condition (it can become a non-TPD page immediately
		 * after this check) here as we are checking validity of TPD entry
		 * without acquiring the lock on page, but we do this check again after
		 * acquiring the lock, so we are safe here.
		 */
		valid = TPDPageIsValid(relation, heapbuf, tpd_e_pruned, tpd_buf,
							   tpdItemOff, &tpd_e_hdr, clean_tpd_loc);
		if (!valid)
		{
			ReleaseLastTPDBuffer(tpd_buf, false);
			goto failed_and_buf_not_locked;
		}

		/* We have to lock the TPD buffer. */
		LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);
		if (tpd_buf_id)
			*tpd_buf_id = buf_idx;
	}

	/* Check whether TPD entry can exist on page? */
	valid = TPDPageIsValid(relation, heapbuf, tpd_e_pruned, tpd_buf,
						   tpdItemOff, &tpd_e_hdr, clean_tpd_loc);
	if (!valid)
		goto failed;

	tpdpage = BufferGetPage(tpd_buf);
	itemId = PageGetItemId(tpdpage, tpdItemOff);
	tpd_e_offset = ItemIdGetOffset(itemId);

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(tpd_e_hdr));

	/* Allow caller to allocate a bigger TPD entry instead. */
	if (checkOffset && offnum > tpd_e_hdr.tpe_num_map_entries)
	{
		/*
		 * If the caller has requested to check offset, it must be prepared to
		 * allocate a TPD entry.
		 */
		Assert(alloc_bigger_map);
		*alloc_bigger_map = true;
	}

	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint8);
	else
	{
		Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint32);
	}

	if (num_map_entries)
		*num_map_entries = tpd_e_hdr.tpe_num_map_entries;
	if (num_trans_slots)
		*num_trans_slots = tpd_e_hdr.tpe_num_slots;
	size_tpd_e_slots = tpd_e_hdr.tpe_num_slots * sizeof(TransInfo);
	loc_trans_slots = tpd_e_offset + SizeofTPDEntryHeader + size_tpd_e_map;

	trans_slots = (TransInfo *) palloc(size_tpd_e_slots);
	memcpy((char *) trans_slots, tpdpage + loc_trans_slots, size_tpd_e_slots);

failed:
	if (!keepTPDBufLock)
	{
		/*
		 * If we don't want to retain the buffer lock, it must have been taken
		 * now.  We can't release the already existing lock taken.
		 */
		Assert(!already_exists);
		ReleaseLastTPDBuffer(tpd_buf, true);

		if (tpd_buf_id)
			*tpd_buf_id = -1;
	}

failed_and_buf_not_locked:
	return trans_slots;
}

/*
 * TPDPageIsValid - To verify TPD page is pruned or not.
 *
 * If TPD buffer is pruned and clean_tpd_loc is true then this will clear TPD
 * location from haep page.
 *
 * Returns false, if the page is pruned, otherwise return true.
 */
static bool
TPDPageIsValid(Relation relation, Buffer heapbuf, bool *tpd_e_pruned,
			   Buffer tpd_buf, OffsetNumber tpdItemOff,
			   TPDEntryHeaderData  *tpd_e_hdr, bool clean_tpd_loc)
{
	Page	tpdpage;
	ItemId	itemId;
	uint16	tpd_e_offset;

	tpdpage = BufferGetPage(tpd_buf);

	/* Check whether TPD entry can exist on page? */
	if (PageIsEmpty(tpdpage))
		goto failed;

	if (PageGetSpecialSize(tpdpage) != MAXALIGN(sizeof(TPDPageOpaqueData)))
		goto failed;

	if (tpdItemOff > PageGetMaxOffsetNumber(tpdpage))
		goto failed;

	itemId = PageGetItemId(tpdpage, tpdItemOff);
	/* TPD entry has been pruned */
	if (!ItemIdIsUsed(itemId))
		goto failed;

	tpd_e_offset = ItemIdGetOffset(itemId);
	memcpy((char *) tpd_e_hdr, tpdpage + tpd_e_offset, SizeofTPDEntryHeader);

	/*
	 * This TPD entry is for some other block, so we can't continue.  This
	 * indicates that the TPD entry corresponding to heap block has been
	 * pruned and some other TPD entry has been moved at its location.
	 */
	if (tpd_e_hdr->blkno != BufferGetBlockNumber(heapbuf))
		goto failed;

	/* This TPD buffer is not pruned, so return true. */
	return true;

failed:
	/* Clear the TPD location from heap page. */
	if (clean_tpd_loc)
		LogAndClearTPDLocation(relation, heapbuf, tpd_e_pruned);

	/* This TPD buffer is pruned, so return true. */
	return false;
}

/*
 * ReleaseLastTPDBufferByTPDBlock - Release last TPD buffer.
 *
 * tpdblk - block number of TPD buffer.
 */
void ReleaseLastTPDBufferByTPDBlock(BlockNumber tpdblk)
{
	bool	already_exists = true;
	int		buf_idx;
	Buffer	tpd_buf;

	/* Get the corresponding TPD buffer corresponding to tpd block. */
	buf_idx = GetTPDBuffer(NULL, tpdblk, InvalidBuffer, TPD_BUF_FIND,
						   &already_exists);

	/* We should have TPD buffer lock. */
	Assert(already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;

	/* Release the last TPD buffer. */
	ReleaseLastTPDBuffer(tpd_buf, true);
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
TPDPageReserveTransSlot(Relation relation, Buffer buf, OffsetNumber offnum,
						UndoRecPtr *urec_ptr, bool *lock_reacquired,
						bool always_extend, bool use_aborted_slot)
{
	TransInfo	*trans_slots;
	int		slot_no;
	int		num_map_entries;
	int		num_slots;
	int		result_slot_no = InvalidXactSlotId;
	int		buf_idx;
	bool	tpd_e_pruned;
	bool	alloc_bigger_map;

	/*
	 * Since the zheap buffer is locked in exclusive mode, we can clear the
	 * TPD location from the page if necessary.
	 */
	trans_slots = TPDPageGetTransactionSlots(relation, buf, offnum,
											 true, true, &num_map_entries,
											 &num_slots, &buf_idx,
											 &tpd_e_pruned, &alloc_bigger_map,
											 true);
	if (tpd_e_pruned)
	{
		Assert(trans_slots == NULL);
		Assert(num_slots == 0);
	}

	for (slot_no = 0; slot_no < num_slots; slot_no++)
	{
		/* Check for an unreserved transaction slot in the TPD entry */
		if (trans_slots[slot_no].xid == InvalidTransactionId)
		{
			result_slot_no = slot_no;
			*urec_ptr = trans_slots[slot_no].urec_ptr;
			goto extend_entry_if_required;
		}
	}

	/* no transaction slot available, try to reuse some existing slot */
	if (num_slots > 0 &&
		PageFreezeTransSlots(relation, buf, lock_reacquired, trans_slots, num_slots, use_aborted_slot))
	{
		pfree(trans_slots);

		/*
		 * If the lock is re-acquired inside, then the callers must recheck
		 * that whether they can still perform the required operation.
		 */
		if (*lock_reacquired)
			return InvalidXactSlotId;

		/*
		 * Since the zheap buffer is locked in exclusive mode, we can clear the
		 * TPD location from the page if necessary.
		 */
		trans_slots = TPDPageGetTransactionSlots(relation, buf, offnum, true,
												 true, &num_map_entries,
												 &num_slots, &buf_idx,
												 &tpd_e_pruned, &alloc_bigger_map,
												 true);
		/*
		 * We are already holding TPD buffer lock so the TPD entry can not be
		 * pruned away.
		 */
		Assert(!tpd_e_pruned);

		for (slot_no = 0; slot_no < num_slots; slot_no++)
		{
			if (trans_slots[slot_no].xid == InvalidTransactionId)
			{
				*urec_ptr = trans_slots[slot_no].urec_ptr;
				result_slot_no = slot_no;
				goto extend_entry_if_required;
			}
		}

		/*
		 * After freezing transaction slots, we should get at least one free
		 * slot.
		 */
		Assert(result_slot_no != InvalidXactSlotId);
	}

extend_entry_if_required:

	/*
	 * Allocate a bigger TPD entry if either we need a bigger offset-map
	 * or there is no unreserved slot available provided TPD entry is not
	 * pruned in which case we can use last slot on the heap page.
	 */
	if (!tpd_e_pruned &&
		(alloc_bigger_map || result_slot_no == InvalidXactSlotId))
	{
		ExtendTPDEntry(relation, buf, trans_slots, offnum, buf_idx,
					   num_map_entries, num_slots, &result_slot_no, urec_ptr,
					   &tpd_e_pruned, always_extend);
	}

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
		ReleaseLastTPDBuffer(tpd_buffers[buf_idx].buf, true);

	/*
	 * As TPD entry is pruned, so last transaction slot must be free on the
	 * heap page.
	 */
	if (tpd_e_pruned)
	{
		Assert(result_slot_no == InvalidXactSlotId);
		result_slot_no = ZHEAP_PAGE_TRANS_SLOTS;
		*urec_ptr = InvalidUndoRecPtr;
	}

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
TPDPageGetSlotIfExists(Relation relation, Buffer heapbuf, OffsetNumber offnum,
					   uint32 epoch, TransactionId xid, UndoRecPtr *urec_ptr,
					   bool keepTPDBufLock, bool checkOffset)
{
	TransInfo	*trans_slots;
	int		slot_no;
	int		num_map_entries;
	int		num_slots;
	int		result_slot_no = InvalidXactSlotId;
	int		buf_idx;
	bool	tpd_e_pruned;
	bool	alloc_bigger_map;

	/*
	 * Since the zheap buffer is locked in exclusive mode, we can clear the
	 * TPD location from the page if necessary.
	 */
	trans_slots = TPDPageGetTransactionSlots(relation,
											 heapbuf,
											 offnum,
											 keepTPDBufLock,
											 checkOffset,
											 &num_map_entries,
											 &num_slots,
											 &buf_idx,
											 &tpd_e_pruned,
											 &alloc_bigger_map,
											 true);
	if (tpd_e_pruned)
	{
		Assert(trans_slots == NULL);
		Assert(num_slots == 0);
	}

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

	/*
	 * Allocate a bigger TPD entry if we get the required slot in TPD entry,
	 * but it requires a bigger offset-map.
	 */
	if (result_slot_no != InvalidXactSlotId && alloc_bigger_map)
	{
		ExtendTPDEntry(relation, heapbuf, trans_slots, offnum, buf_idx,
					   num_map_entries, num_slots, &result_slot_no, urec_ptr,
					   &tpd_e_pruned, false);
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
		ReleaseLastTPDBuffer(tpd_buffers[buf_idx].buf, true);

	return result_slot_no;
}

/*
 * TPDPageGetTransactionSlotInfo - Get the required transaction information from
 *		heap page's TPD entry.
 *
 * It is quite possible that the TPD entry containing required transaction slot
 * information got pruned away (as all the transaction entries are all-visible)
 * by the time caller tries to enquire about it.  One might expect that if the
 * TPD entry is pruned, the corresponding affected tuples should be updated to
 * reflect the same, however, we don't do that due to multiple reasons (a) we
 * don't access heap pages from TPD layer, it can lead to deadlock, (b) it
 * might lead to dirtying a lot of pages and random I/O.  However, the first
 * time we detect it and we have exclusive lock on page, we update the
 * corresponding heap page.
 *
 * We can consider TPD entry to be pruned under following conditions: (a) the
 * tpd block doesn't exist (pruned and truncated by vacuum), (b) the tpd block
 * is empty which means all the entries in it are pruned, (c) the tpd block
 * has been reused as a heap page, (d) the corresponding TPD entry has been
 * pruned away and either the itemid is unused or is reused for some other
 * block's TPD entry.
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
	OffsetNumber	tpdItemOff;
	ItemId	itemId;
	uint16	tpd_e_offset;
	char relpersistence;
	bool	valid;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/* Heap page must have a TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

	if (NoTPDBufLock)
	{
		SMgrRelation	smgr;
		BlockNumber		lastblock;

		BufferGetTag(heapbuf, &rnode, &forknum, &heapblk);

		if (InRecovery)
			relpersistence = RELPERSISTENCE_PERMANENT;
		else
		{
			Oid		reloid;

			reloid = RelidByRelfilenode(rnode.spcNode, rnode.relNode);
			relpersistence = get_rel_persistence(reloid);
		}

		smgr = smgropen(rnode,
						relpersistence == RELPERSISTENCE_TEMP ?
						MyBackendId : InvalidBackendId);

		lastblock = smgrnblocks(smgr, forknum);

		/* required block exists? */
		if (tpdblk < lastblock)
		{
			tpdbuffer = ReadBufferWithoutRelcache(rnode, forknum, tpdblk, RBM_NORMAL,
												  NULL, relpersistence);

			/* Check whether TPD entry can exist on page? */
			valid = TPDPageIsValid(NULL, heapbuf, NULL, tpdbuffer, tpdItemOff,
								   &tpd_e_hdr, false);
			if (!valid)
			{
				ReleaseBuffer(tpdbuffer);
				goto slot_is_frozen_and_buf_not_locked;
			}

			if (keepTPDBufLock)
				LockBuffer(tpdbuffer, BUFFER_LOCK_EXCLUSIVE);
			else
				LockBuffer(tpdbuffer, BUFFER_LOCK_SHARE);
		}
		else
		{
			/*
			 * The required TPD block has been pruned and then truncated away
			 * which means all transaction slots on that page are older than
			 * oldestXidHavingUndo.  So, we can assume the transaction slot is
			 * frozen aka transaction is all-visible.
			 */
			goto slot_is_frozen_and_buf_not_locked;
		}
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

	/*
	 * Check whether TPD entry can exist on page?
	 *
	 * Ideally, we can clear the TPD location from the heap page (aka pass
	 * claen_tpd_loc as true), but for that, we need to have an exclusive lock
	 * on the heap page.  As this API can be called with a shared lock on a
	 * heap page, we can't perform that action.
	 *
	 * XXX If it ever turns out to be a performance problem, we can release the
	 * current lock and acuire the exclusive lock on heap page.  Also we need
	 * to ensure that the lock on TPD page also needs to be released and
	 * reacquired as we always follow the protocol of acquiring the lock on
	 * heap page first and then on TPD page, doing it otherway can lead to
	 * undetected deadlock.
	 */
	valid = TPDPageIsValid(NULL, heapbuf, NULL, tpdbuffer, tpdItemOff,
						   &tpd_e_hdr, false);
	if (!valid)
		goto slot_is_frozen;

	tpdpage = BufferGetPage(tpdbuffer);
	itemId = PageGetItemId(tpdpage, tpdItemOff);
	tpd_e_offset = ItemIdGetOffset(itemId);

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(tpd_e_hdr));

	tpd_e_num_map_entries = tpd_e_hdr.tpe_num_map_entries;
	tpd_entry_data = tpdpage + tpd_e_offset + SizeofTPDEntryHeader;
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

			memcpy((char *) &offset_tpd_e_loc,
				   tpd_entry_data + (sizeof(uint32) * (offset - 1)),
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

slot_is_frozen:
	if (NoTPDBufLock && !keepTPDBufLock)
		UnlockReleaseBuffer(tpdbuffer);

slot_is_frozen_and_buf_not_locked:
	trans_slot_id = ZHTUP_SLOT_FROZEN;
	if (epoch)
		*epoch = 0;
	if (xid)
		*xid = InvalidTransactionId;
	if (urec_ptr)
		*urec_ptr = InvalidUndoRecPtr;

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
	OffsetNumber	tpdItemOff;
	ItemId	itemId;
	uint16	tpd_e_offset;
	bool	already_exists PG_USED_FOR_ASSERTS_ONLY;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/* Heap page must have a TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

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
	itemId = PageGetItemId(tpdpage, tpdItemOff);

	/*
	 * TPD entry can't go away as we acquire the lock while reserving the slot
	 * from TPD entry and keep it till we set the required transaction
	 * information in the slot.
	 */
	Assert(ItemIdIsUsed(itemId));

	tpd_e_offset = ItemIdGetOffset(itemId);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset, SizeofTPDEntryHeader);

	/* TPD entry can't be pruned. */
	Assert(tpd_e_hdr.blkno == BufferGetBlockNumber(heapbuf));

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(tpd_e_hdr));

	tpd_entry_data = tpdpage + tpd_e_offset + SizeofTPDEntryHeader;

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
 * GetTPDEntryData - Helper function for TPDPageGetOffsetMap and
 *					 TPDPageSetOffsetMap.
 *
 * Caller must ensure that it has acquired lock on the TPD buffer.
 */
static char *
GetTPDEntryData(Buffer heapbuf, int *num_entries, int *entry_size,
				Buffer *tpd_buffer)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	ZHeapPageOpaque	zopaque;
	TransInfo	last_trans_slot_info;
	BufferDesc *tpdbufhdr PG_USED_FOR_ASSERTS_ONLY;
	Buffer	tpd_buf;
	Page	tpdpage;
	Page	heappage;
	BlockNumber	tpdblk;
	TPDEntryHeaderData	tpd_e_hdr;
	int		buf_idx;
	char	*tpd_entry_data;
	OffsetNumber	tpdItemOff;
	ItemId	itemId;
	uint16	tpd_e_offset;
	bool	already_exists PG_USED_FOR_ASSERTS_ONLY;
	bool	valid;

	heappage = BufferGetPage(heapbuf);
	phdr = (PageHeader) heappage;

	/* Heap page must have a TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

	/*
	 * Here we don't need to check if the tpd block is pruned and truncated
	 * away because the tpd buffer must be locked before.
	 */

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

	/* Check whether TPD entry can exist on page? */
	valid = TPDPageIsValid(NULL, heapbuf, NULL, tpd_buf, tpdItemOff,
						   &tpd_e_hdr, false);
	if (!valid)
		return NULL;

	tpdpage = BufferGetPage(tpd_buf);
	itemId = PageGetItemId(tpdpage, tpdItemOff);
	tpd_e_offset = ItemIdGetOffset(itemId);

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(tpd_e_hdr));

	tpd_entry_data = tpdpage + tpd_e_offset + SizeofTPDEntryHeader;
	*num_entries = tpd_e_hdr.tpe_num_map_entries;

	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		*entry_size = sizeof(uint8);
	else
		*entry_size = sizeof(uint32);

	if (tpd_buffer)
		*tpd_buffer = tpd_buf;

	return tpd_entry_data;
}

/*
 * TPDPageSetOffsetMapSlot - Set the transaction slot for given offset in TPD
 *							 offset map.
 *
 * Caller must ensure that it has required lock on tpd buffer which is going to
 * be updated here.  We can't lock the buffer here as this API is supposed to
 * be called from critical section and lock acquisition can fail.
 */
void
TPDPageSetOffsetMapSlot(Buffer heapbuf, int trans_slot_id,
						OffsetNumber offset)
{
	char   *tpd_entry_data;
	int		num_entries = 0,
			entry_size = 0;
	Buffer	tpd_buf = InvalidBuffer;

	tpd_entry_data = GetTPDEntryData(heapbuf, &num_entries, &entry_size,
									 &tpd_buf);

	/*
	 * Caller would have checked that the entry is not pruned after taking
	 * lock on the tpd page.
	 */
	Assert(tpd_entry_data);

	Assert (offset <= num_entries);

	if (entry_size == sizeof(uint8))
	{
		uint8 offset_tpd_e_loc = trans_slot_id;

		/*
		 * One byte access shouldn't cause unaligned access, but using memcpy
		 * for the sake of consistency.
		 */
		memcpy(tpd_entry_data + (offset - 1),
			   (char *) &offset_tpd_e_loc,
			   sizeof(uint8));
	}
	else
	{
		uint32	offset_tpd_e_loc;

		offset_tpd_e_loc = trans_slot_id;
		memcpy(tpd_entry_data + (sizeof(uint32) * (offset - 1)),
			   (char *) &offset_tpd_e_loc,
			   sizeof(uint32));
	}

	MarkBufferDirty(tpd_buf);
}

/*
 * TPDPageGetOffsetMap - Get the Offset map array of the TPD entry.
 *
 * This function copy the offset map into tpd_offset_map array allocated by the
 * caller.
 */
void
TPDPageGetOffsetMap(Buffer heapbuf, char *tpd_offset_map, int map_size)
{
	char	*tpd_entry_data;
	int		 num_entries, entry_size;

	tpd_entry_data = GetTPDEntryData(heapbuf, &num_entries, &entry_size, NULL);

	/*
	 * Caller would have checked that the entry is not pruned after taking
	 * lock on the tpd page.
	 */
	Assert(tpd_entry_data);

	Assert(map_size == num_entries * entry_size);

	memcpy(tpd_offset_map, tpd_entry_data, map_size);
}

/*
 * TPDPageGetOffsetMapSize - Get the Offset map size of the TPD entry.
 *
 * Caller must ensure that it has acquired lock on tpd buffer corresponding to
 * passed heap buffer.
 *
 * Returns 0, if the tpd entry gets pruned away, otherwise, return the size of
 * TPD offset-map.
 */
int
TPDPageGetOffsetMapSize(Buffer heapbuf)
{
	int		 num_entries, entry_size;

	if (GetTPDEntryData(heapbuf, &num_entries, &entry_size, NULL) == NULL)
		return 0;

	return (num_entries * entry_size);
}

/*
 * TPDPageSetOffsetMap - Overwrite TPD offset map array with input offset map
 *						 array.
 *
 * This function returns a pointer to an array of offset map, it is the
 * responsibility of the caller to free it.
 *
 * Caller must ensure that it has acquired lock on the TPD buffer which is
 * going to be updated here.
 */
void
TPDPageSetOffsetMap(Buffer heapbuf, char *tpd_offset_map)
{
	char	*tpd_entry_data;
	int		 num_entries = 0,
			 entry_size = 0;
	Buffer	 tpd_buf = InvalidBuffer;

	/* This function should only be called during recovery. */
	Assert(InRecovery);

	tpd_entry_data = GetTPDEntryData(heapbuf, &num_entries, &entry_size,
									 &tpd_buf);

	/* Entry can't be pruned during recovery. */
	Assert(tpd_entry_data);

	memcpy(tpd_entry_data, tpd_offset_map, num_entries * entry_size);

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
TPDPageSetUndo(Buffer heapbuf, int trans_slot_id, bool set_tpd_map_slot,
			   uint32 epoch, TransactionId xid, UndoRecPtr urec_ptr,
			   OffsetNumber *usedoff, int ucnt)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	Page	heappage = BufferGetPage(heapbuf);
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
	OffsetNumber	tpdItemOff;
	ItemId	itemId;
	uint16	tpd_e_offset;
	bool	already_exists;

	phdr = (PageHeader) heappage;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

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
	itemId = PageGetItemId(tpdpage, tpdItemOff);

	/*
	 * TPD entry can't go away as we acquire the lock while reserving the slot
	 * from TPD entry and keep it till we set the required transaction
	 * information in the slot.
	 */
	Assert(ItemIdIsUsed(itemId));

	tpd_e_offset = ItemIdGetOffset(itemId);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset, SizeofTPDEntryHeader);

	/* TPD entry can't be pruned. */
	Assert(tpd_e_hdr.blkno == BufferGetBlockNumber(heapbuf));

	/* We should never access deleted entry. */
	Assert(!TPDEntryIsDeleted(tpd_e_hdr));

	tpd_e_num_map_entries = tpd_e_hdr.tpe_num_map_entries;
	tpd_entry_data = tpdpage + tpd_e_offset + SizeofTPDEntryHeader;

	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint8);
	else
		size_tpd_e_map = tpd_e_num_map_entries * sizeof(uint32);

	/*
	 * Update TPD entry map for all the modified offsets if we
	 * have asked to do so.
	 */
	if (set_tpd_map_slot)
	{
		/*  */
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
				memcpy(tpd_entry_data + (usedoff[i] - 1),
					   (char *) &offset_tpd_e_loc,
					   sizeof(uint8));
			}
		}
		else
		{
			uint32	offset_tpd_e_loc;

			Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);

			offset_tpd_e_loc = trans_slot_id;
			for (i = 0; i < ucnt; i++)
			{
				/*
				 * The item for which we want to update the transaction slot
				 * information must be present in this TPD entry.
				 */
				Assert (usedoff[i] <= tpd_e_num_map_entries);
				memcpy(tpd_entry_data + (sizeof(uint32) * (usedoff[i] - 1)),
					   (char *) &offset_tpd_e_loc,
					   sizeof(uint32));
			}
		}
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
 * TPDPageLock - Routine to lock the TPD page corresponding to heap page
 *
 * Caller should not already hold the lock.
 *
 * Returns false, if couldn't acquire lock because the page is pruned,
 * otherwise, true.
 */
bool
TPDPageLock(Relation relation, Buffer heapbuf)
{
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	Page		heappage = BufferGetPage(heapbuf);
	ZHeapPageOpaque	zopaque;
	TransInfo	last_trans_slot_info;
	Buffer	tpd_buf;
	BlockNumber	tpdblk,
				lastblock;
	int		buf_idx;
	bool	already_exists;
	OffsetNumber	tpdItemOff;
	bool			valid;
	TPDEntryHeaderData	tpd_e_hdr;

	phdr = (PageHeader) heappage;

	/* Heap page must have TPD entry. */
	Assert(phdr->pd_flags & PD_PAGE_HAS_TPD_SLOT);

	/* The last in page has the address of the required TPD entry. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(heappage);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	tpdblk = last_trans_slot_info.xid_epoch;
	tpdItemOff = last_trans_slot_info.xid & OFFSET_MASK;

	lastblock = RelationGetNumberOfBlocks(relation);

	if (lastblock <= tpdblk)
	{
		/*
		 * The required TPD block has been pruned and then truncated away
		 * which means all transaction slots on that page are older than
		 * oldestXidHavingUndo.  So, we can't lock the page.
		 *
		 * The required TPD block has been pruned which means all transaction
		 * slots on that page are older than oldestXidHavingUndo.  So, we can
		 * assume the TPD transaction slots are frozen aka transactions are
		 * all-visible and can clear the TPD slots from heap tuples.
		 */
		LogAndClearTPDLocation(relation, heapbuf, NULL);
		return false;
	}

	/*
	 * Fetch the required TPD entry.  We need to lock the buffer in exclusive
	 * mode as we later want to set the values in one of the transaction slot.
	 */
	buf_idx = GetTPDBuffer(relation, tpdblk, InvalidBuffer,
						   TPD_BUF_FIND_OR_ENTER, &already_exists);
	tpd_buf = tpd_buffers[buf_idx].buf;
	Assert(!already_exists);

	/*
	 * We need to check whether TPD page can contain valid TPD entry before
	 * acquiring lock to avoid deadlock.  See in TPDPageGetTransactionSlots
	 * where we have used TPDPageIsValid for similar reason.
	 */
	valid = TPDPageIsValid(relation, heapbuf, NULL, tpd_buf, tpdItemOff,
						   &tpd_e_hdr, true);
	if (!valid)
	{
		ReleaseLastTPDBuffer(tpd_buf, false);
		return false;
	}

	LockBuffer(tpd_buf, BUFFER_LOCK_EXCLUSIVE);

	/* Check whether TPD entry can exist on page? */
	valid = TPDPageIsValid(relation, heapbuf, NULL, tpd_buf, tpdItemOff,
						   &tpd_e_hdr, true);
	if (!valid)
	{
		ReleaseLastTPDBuffer(tpd_buf, true);
		return false;
	}

	return true;
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
	if (action != BLK_NOTFOUND)
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
 * ResetTPDBuffers  - Reset TPD buffer index. Required at the time of
 * transaction abort or release TPD buffers.
 */
void
ResetTPDBuffers(void)
{
	int i;

	for (i = 0; i < tpd_buf_idx; i++)
	{
		tpd_buffers[i].buf = InvalidBuffer;
		tpd_buffers[i].blk = InvalidBlockNumber;
	}

	tpd_buf_idx = 0;
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
	}

	ResetTPDBuffers();
}

/*
 * PageGetTPDFreeSpace
 *		Returns the size of the free (allocatable) space on a page.
 *
 * As of now, this is just a wrapper over PageGetFreeSpace, however in future,
 * the space management in TPD pages could be different.
 */
Size
PageGetTPDFreeSpace(Page page)
{
	int			space;

	/*
	 * Use signed arithmetic here so that we behave sensibly if pd_lower >
	 * pd_upper.
	 */
	space = PageGetFreeSpace(page);

	return (Size) space;
}
