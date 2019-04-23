/*-------------------------------------------------------------------------
 *
 * prunetpd.c
 *	  TPD page pruning
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/prunetpd.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/tpd_xlog.h"
#include "miscadmin.h"
#include "storage/bufpage.h"
#include "storage/freespace.h"
#include "storage/proc.h"

typedef struct TPDPruneState
{
	int			nunused;
	OffsetNumber nowunused[MaxTPDTuplesPerPage];
} TPDPruneState;

static void TPDEntryPrune(Buffer buf, OffsetNumber offnum, TPDPruneState *prstate,
			  Size *space_freed);
static XLogRecPtr LogTPDClean(Relation rel, Buffer tpdbuf,
			OffsetNumber *nowunused, int nunused,
			OffsetNumber target_offnum, Size space_required);
static int	TPDPruneEntirePage(Relation rel, Buffer tpdbuf);

/*
 * TPDPagePrune - Prune the TPD page.
 *
 * Process all the TPD entries in the page and remove the old entries which
 * are all-visible.  We first collect all such entries and then process them
 * in one-shot.
 *
 * We expect caller must have an exclusive lock on the page.
 *
 * Returns the number of entries pruned.
 */
int
TPDPagePrune(Relation rel, Buffer tpdbuf, BufferAccessStrategy strategy,
			 OffsetNumber target_offnum, Size space_required, bool can_free,
			 bool *update_tpd_inplace, bool *tpd_e_pruned)
{
	Page		tpdpage,
				tmppage = NULL;
	TPDPageOpaque tpdopaque;
	TPDPruneState prstate;
	OffsetNumber offnum,
				maxoff;
	ItemId		itemId;
	uint64		epoch_xid;
	uint32		epoch;
	Size		space_freed;

	prstate.nunused = 0;
	tpdpage = BufferGetPage(tpdbuf);

	/* Initialize the out variables. */
	if (update_tpd_inplace)
		*update_tpd_inplace = false;
	if (tpd_e_pruned)
		*tpd_e_pruned = false;

	/* Can we prune the entire page? */
	tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
	epoch = tpdopaque->tpd_latest_xid_epoch;
	epoch_xid = U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch,
																		  tpdopaque->tpd_latest_xid));
	if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		prstate.nunused = TPDPruneEntirePage(rel, tpdbuf);
		goto free_tpd_page;
	}

	/* initialize the space_free with already existing free space in page */
	space_freed = PageGetExactFreeSpace(tpdpage);

	/* Scan the page */
	maxoff = PageGetMaxOffsetNumber(tpdpage);
	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
	{
		itemId = PageGetItemId(tpdpage, offnum);

		/* Nothing to do if slot is empty. */
		if (!ItemIdIsUsed(itemId))
			continue;

		TPDEntryPrune(tpdbuf, offnum, &prstate, &space_freed);
	}

	/*
	 * There is not much advantage in continuing, if we can't free the space
	 * required by the caller or we are not asked to forcefully prune the
	 * page.
	 *
	 * XXX - In theory, we can still continue and perform pruning in the hope
	 * that some future update in this page will be able to use that space.
	 * However, it will lead to additional writes without any guaranteed
	 * benefit, so we skip the pruning for now.
	 */
	if (space_freed < space_required)
		return 0;

	/*
	 * We prepare the temporary copy of the page so that during page repair
	 * fragmentation we can use it to copy the actual tuples.
	 */
	if (prstate.nunused > 0 || OffsetNumberIsValid(target_offnum))
		tmppage = PageGetTempPageCopy(tpdpage);

	/* Any error while applying the changes is critical */
	START_CRIT_SECTION();

	/*
	 * Have we found any prunable items or caller has asked us to make space
	 * next to target_offnum?
	 */
	if (prstate.nunused > 0 || OffsetNumberIsValid(target_offnum))
	{
		/*
		 * Apply the planned item changes, then repair page fragmentation, and
		 * update the page's hint bit about whether it has free line pointers.
		 */
		TPDPagePruneExecute(tpdbuf, prstate.nowunused, prstate.nunused);

		/*
		 * Finally, repair any fragmentation, and update the page's hint bit
		 * about whether it has free pointers.  It is quite possible that
		 * there are no prunable items on the page in which case it will
		 * rearrange the page to make the space at the required offset.
		 */
		TPDPageRepairFragmentation(tpdpage, tmppage, target_offnum,
								   space_required);

		MarkBufferDirty(tpdbuf);

		/*
		 * Emit a WAL TPD_CLEAN record showing what we did.
		 *
		 * XXX Unlike heap pruning, we don't need to remember latestRemovedXid
		 * for the purpose of generating conflicts on standby.  We use
		 * oldestXidHavingUndo as the horizon to prune the TPD entries which
		 * means all the prior undo must have discarded and during undo
		 * discard we already generate such xid (see undolog_xlog_discard)
		 * which should serve our purpose as this WAL must reach after that.
		 */
		if (RelationNeedsWAL(rel))
		{
			XLogRecPtr	recptr;

			recptr = LogTPDClean(rel, tpdbuf, prstate.nowunused,
								 prstate.nunused, target_offnum,
								 space_required);

			PageSetLSN(tpdpage, recptr);
		}

		if (update_tpd_inplace)
			*update_tpd_inplace = true;
	}

	END_CRIT_SECTION();

	/* be tidy. */
	if (tmppage)
		pfree(tmppage);

free_tpd_page:
	if (can_free && PageIsEmpty(tpdpage))
	{
		Size		freespace;

		/* If the page is empty, we have certainly pruned all the tpd entries. */
		if (tpd_e_pruned)
			*tpd_e_pruned = true;

		/*
		 * We can reuse empty page as either a heap page or a TPD page, so no
		 * need to consider opaque space.
		 */
		freespace = BLCKSZ - SizeOfPageHeaderData;

		/*
		 * TPD page is empty, remove it from TPD used page list and record it
		 * in FSM.
		 */
		if (TPDFreePage(rel, tpdbuf, strategy))
			RecordPageWithFreeSpace(rel, BufferGetBlockNumber(tpdbuf),
									freespace, InvalidBlockNumber);
	}

	return prstate.nunused;
}

/*
 * TPDEntryPrune - Check whether the TPD entry is prunable.
 *
 * Process all the transaction slots of a TPD entry present at a given offset.
 * TPD entry will be considered prunable, if all the transaction slots either
 * contains transaction that is older than oldestXidHavingUndo or
 * doesn't have a valid transaction.
 */
static void
TPDEntryPrune(Buffer tpdbuf, OffsetNumber offnum, TPDPruneState *prstate,
			  Size *space_freed)
{
	Page		tpdpage;
	TPDEntryHeaderData tpd_e_hdr;
	TransInfo  *trans_slots;
	ItemId		itemId;
	Size		size_tpd_e_slots,
				size_tpd_e_map;
	Size		size_tpd_entry;
	int			num_trans_slots,
				slot_no;
	int			loc_trans_slots;
	uint16		tpd_e_offset;
	bool		prune_entry = true;
	FullTransactionId oldestXidWithEpochHavingUndo;

	tpdpage = BufferGetPage(tpdbuf);
	itemId = PageGetItemId(tpdpage, offnum);
	tpd_e_offset = ItemIdGetOffset(itemId);
	size_tpd_entry = ItemIdGetLength(itemId);

	memcpy((char *) &tpd_e_hdr, tpdpage + tpd_e_offset, SizeofTPDEntryHeader);

	/*
	 * We can prune the deleted entries as no one will be referring to such
	 * entries.
	 */
	if (TPDEntryIsDeleted(tpd_e_hdr))
		goto prune_tpd_entry;

	if (tpd_e_hdr.tpe_flags & TPE_ONE_BYTE)
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint8);
	else
	{
		Assert(tpd_e_hdr.tpe_flags & TPE_FOUR_BYTE);
		size_tpd_e_map = tpd_e_hdr.tpe_num_map_entries * sizeof(uint32);
	}

	num_trans_slots = tpd_e_hdr.tpe_num_slots;
	size_tpd_e_slots = num_trans_slots * sizeof(TransInfo);
	loc_trans_slots = tpd_e_offset + SizeofTPDEntryHeader + size_tpd_e_map;

	trans_slots = (TransInfo *) palloc(size_tpd_e_slots);
	memcpy((char *) trans_slots, tpdpage + loc_trans_slots, size_tpd_e_slots);

	oldestXidWithEpochHavingUndo = FullTransactionIdFromU64(
		pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	for (slot_no = 0; slot_no < num_trans_slots; slot_no++)
	{
		FullTransactionId slot_fxid;
		UndoRecPtr	urec_ptr = trans_slots[slot_no].urec_ptr;

		slot_fxid = trans_slots[slot_no].fxid;

		/*
		 * Check whether transaction slot can be considered frozen? If both
		 * transaction id and undo record pointer are invalid or xid is
		 * invalid and its undo has been discarded or xid is older than the
		 * oldest xid with undo.
		 */
		if ((!FullTransactionIdIsValid(slot_fxid) &&
			 (!UndoRecPtrIsValid(urec_ptr) || UndoLogIsDiscarded(urec_ptr))) ||
			(FullTransactionIdIsValid(slot_fxid) &&
			 FullTransactionIdPrecedes(slot_fxid, oldestXidWithEpochHavingUndo)))
			continue;
		else
		{
			prune_entry = false;
			break;
		}
	}

	pfree(trans_slots);

prune_tpd_entry:
	if (prune_entry)
	{
		Assert(prstate->nunused < MaxTPDTuplesPerPage);
		prstate->nowunused[prstate->nunused] = offnum;
		prstate->nunused++;

		*space_freed += size_tpd_entry;
	}
}

/*
 * TPDPagePruneExecute - Guts of the TPD page pruning.
 *
 * Here, we mark all the entries that can be pruned as unused and then call page
 * repair fragmentation to compact the page.
 */
void
TPDPagePruneExecute(Buffer tpdbuf, OffsetNumber *nowunused, int nunused)
{
	Page		tpdpage;
	OffsetNumber *offnum;
	int			i;

	tpdpage = BufferGetPage(tpdbuf);

	/* Update all now-unused line pointers */
	offnum = nowunused;
	for (i = 0; i < nunused; i++)
	{
		OffsetNumber off = *offnum++;
		ItemId		lp = PageGetItemId(tpdpage, off);

		ItemIdSetUnused(lp);
	}
}

/*
 * TPDPageRepairFragmentation - Frees fragmented space on a tpd page.
 *
 * It doesn't remove unused line pointers because some heap page might
 * still point to the line pointer.  If we remove the line pointer, then
 * the same space could be occupied by actual TPD entry in which case somebody
 * trying to access that line pointer will get unpredictable behavior.
 */
void
TPDPageRepairFragmentation(Page page, Page tmppage, OffsetNumber target_offnum,
						   Size space_required)
{
	Offset		pd_lower = ((PageHeader) page)->pd_lower;
	Offset		pd_upper = ((PageHeader) page)->pd_upper;
	Offset		pd_special = ((PageHeader) page)->pd_special;
	itemIdSortData itemidbase[MaxTPDTuplesPerPage];
	itemIdSort	itemidptr;
	ItemId		lp;
	int			nline,
				nstorage,
				nunused;
	int			i;
	Size		totallen;

	/*
	 * It's worth the trouble to be more paranoid here than in most places,
	 * because we are about to reshuffle data in (what is usually) a shared
	 * disk buffer.  If we aren't careful then corrupted pointers, lengths,
	 * etc. could cause us to clobber adjacent disk buffers, spreading the
	 * data loss further.  So, check everything.
	 */
	if (pd_lower < SizeOfPageHeaderData ||
		pd_lower > pd_upper ||
		pd_upper > pd_special ||
		pd_special > BLCKSZ)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("corrupted page pointers: lower = %u, upper = %u, special = %u",
						pd_lower, pd_upper, pd_special)));

	/*
	 * Run through the line pointer array and collect data about live items.
	 */
	nline = PageGetMaxOffsetNumber(page);
	itemidptr = itemidbase;
	nunused = totallen = 0;
	for (i = FirstOffsetNumber; i <= nline; i++)
	{
		lp = PageGetItemId(page, i);
		if (ItemIdIsUsed(lp))
		{
			if (ItemIdHasStorage(lp))
			{
				itemidptr->offsetindex = i - 1;
				itemidptr->itemoff = ItemIdGetOffset(lp);
				if (unlikely(itemidptr->itemoff < (int) pd_upper ||
							 itemidptr->itemoff >= (int) pd_special))
					ereport(ERROR,
							(errcode(ERRCODE_DATA_CORRUPTED),
							 errmsg("corrupted item pointer: %u",
									itemidptr->itemoff)));
				if (i == target_offnum)
					itemidptr->alignedlen = ItemIdGetLength(lp) +
						space_required;
				else
					itemidptr->alignedlen = ItemIdGetLength(lp);
				totallen += itemidptr->alignedlen;
				itemidptr++;
			}
		}
		else
		{
			/* Unused entries should have lp_len = 0, but make sure */
			ItemIdSetUnused(lp);
			nunused++;
		}
	}

	nstorage = itemidptr - itemidbase;
	if (nstorage == 0)
	{
		/* Page is completely empty, so just reset it quickly */
		((PageHeader) page)->pd_lower = SizeOfPageHeaderData;
		((PageHeader) page)->pd_upper = pd_special;
	}
	else
	{
		/* Need to compact the page the hard way */
		if (totallen > (Size) (pd_special - pd_lower))
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("corrupted item lengths: total %u, available space %u",
							(unsigned int) totallen, pd_special - pd_lower)));

		compactify_ztuples(itemidbase, nstorage, page, tmppage);
	}

	/* Set hint bit for TPDPageAddEntry */
	if (nunused > 0)
		PageSetHasFreeLinePointers(page);
	else
		PageClearHasFreeLinePointers(page);
}

/*
 * LogTPDClean - Write WAL for TPD entries that can be pruned.
 */
XLogRecPtr
LogTPDClean(Relation rel, Buffer tpdbuf,
			OffsetNumber *nowunused, int nunused,
			OffsetNumber target_offnum, Size space_required)
{
	XLogRecPtr	recptr;
	xl_tpd_clean xl_rec;

	/* Caller should not call me on a non-WAL-logged relation */
	Assert(RelationNeedsWAL(rel));

	xl_rec.flags = 0;
	XLogBeginInsert();

	if (target_offnum != InvalidOffsetNumber)
		xl_rec.flags |= XL_TPD_CONTAINS_OFFSET;
	XLogRegisterData((char *) &xl_rec, SizeOfTPDClean);

	/* Register the offset information. */
	if (target_offnum != InvalidOffsetNumber)
	{
		XLogRegisterData((char *) &target_offnum, sizeof(OffsetNumber));
		XLogRegisterData((char *) &space_required, sizeof(space_required));
	}

	XLogRegisterBuffer(0, tpdbuf, REGBUF_STANDARD);

	/*
	 * The OffsetNumber array is not actually in the buffer, but we pretend it
	 * is.  When XLogInsert stores the whole buffer, the offset array need not
	 * be stored too.  Note that even if the array is empty, we want to expose
	 * the buffer as a candidate for whole-page storage, since this record
	 * type implies a defragmentation operation even if no item pointers
	 * changed state.
	 */
	if (nunused > 0)
		XLogRegisterBufData(0, (char *) nowunused,
							nunused * sizeof(OffsetNumber));

	recptr = XLogInsert(RM_TPD_ID, XLOG_TPD_CLEAN);

	return recptr;
}

/*
 * TPDPruneEntirePage
 */
static int
TPDPruneEntirePage(Relation rel, Buffer tpdbuf)
{
	Page		page = BufferGetPage(tpdbuf);
	int			entries_removed = PageGetMaxOffsetNumber(page);

	START_CRIT_SECTION();

	/* Page is completely empty, so just reset it quickly */
	((PageHeader) page)->pd_lower = SizeOfPageHeaderData;
	((PageHeader) page)->pd_upper = ((PageHeader) page)->pd_special;

	MarkBufferDirty(tpdbuf);

	if (RelationNeedsWAL(rel))
	{
		XLogRecPtr	recptr;

		XLogBeginInsert();

		XLogRegisterBuffer(0, tpdbuf, REGBUF_STANDARD);

		recptr = XLogInsert(RM_TPD_ID, XLOG_TPD_CLEAN_ALL_ENTRIES);

		PageSetLSN(BufferGetPage(tpdbuf), recptr);
	}

	END_CRIT_SECTION();

	return entries_removed;
}
