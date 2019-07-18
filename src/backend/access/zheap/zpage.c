/*-------------------------------------------------------------------------
 *
 * zpage.c
 *	  Routines to operate on a zheap page.
 *
 * The zheap page consists of the page header, line pointer array, tuples and
 * transaction slots.  The line pointer array grows from top to down and
 * tuples grow from bottom to up.  There is a fixed transaction slot array
 * in the special space.  In the future, we want this array to be of variable
 * length.
 *
 * zheap tuples are not MAXALIGN'd as PageAddItemExtended would do, but are
 * instead aligned only on 2-byte boundaries.  This is sufficient to access
 * the tuple header without copying the data, since there's nothing in the
 * tuple header wider than a uint16.  The tuple data is always copied
 * before we access it (since otherwise in-place updates would be difficut
 * to implement).
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zpage.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/tpd.h"
#include "miscadmin.h"
#include "utils/memdebug.h"
#include "utils/ztqual.h"

/*
 * ZPageAddItemExtended - Add an item to a zheap page.
 *
 * This is similar to PageAddItemExtended except for max tuples that can be
 * accommodated on a page and alignment for each item (Ideally, we don't need
 * to align space between tuples as we always make the copy of tuple to
 * support in-place updates.  However, there are places in zheap code where
 * we access tuple header directly from page (e.g. zheap_delete, zheap_update,
 * etc.) for which we them to be aligned at two-byte boundary). It
 * additionally handles the itemids that are marked as unused, but still
 * can't be reused.
 *
 * Callers passed a valid input_page only in case there are constructing the
 * in-memory copy of tuples and then directly sync the page.
 */
OffsetNumber
ZPageAddItemExtended(Buffer buffer,
					 Page input_page,
					 Item item,
					 Size size,
					 OffsetNumber offsetNumber,
					 int flags,
					 bool NoTPDBufLock)
{
	Page		page;
	Size		alignedSize;
	PageHeader	phdr;
	int			lower;
	int			upper;
	ItemId		itemId;
	OffsetNumber limit;
	bool		needshuffle = false;

	/* Either one of buffer or page could be valid. */
	if (BufferIsValid(buffer))
	{
		Assert(!PageIsValid(input_page));
		page = BufferGetPage(buffer);
	}
	else
	{
		Assert(PageIsValid(input_page));
		page = input_page;
	}

	phdr = (PageHeader) page;

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
	limit = OffsetNumberNext(PageGetMaxOffsetNumber(page));

	/* was offsetNumber passed in? */
	if (OffsetNumberIsValid(offsetNumber))
	{
		/* yes, check it */
		if ((flags & PAI_OVERWRITE) != 0)
		{
			if (offsetNumber < limit)
			{
				itemId = PageGetItemId(phdr, offsetNumber);
				if (ItemIdIsUsed(itemId) || ItemIdHasStorage(itemId))
				{
					elog(WARNING, "will not overwrite a used ItemId");
					return InvalidOffsetNumber;
				}
			}
		}
		else
		{
			if (offsetNumber < limit)
				needshuffle = true; /* need to move existing linp's */
		}
	}
	else
	{
		/* offsetNumber was not passed in, so find a free slot */
		/* if no free slot, we'll put it at limit (1st open slot) */
		if (PageHasFreeLinePointers(phdr))
		{
			bool		hasPendingXact = false;

			/*
			 * Look for "recyclable" (unused) ItemId.  We check for no storage
			 * as well, just to be paranoid --- unused items should never have
			 * storage.
			 */
			for (offsetNumber = 1; offsetNumber < limit; offsetNumber++)
			{
				itemId = PageGetItemId(phdr, offsetNumber);
				if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
				{
					/*
					 * We allow Unused entries to be reused only if there is
					 * no transaction information for the entry or the
					 * transaction is committed.
					 */
					if (ItemIdHasPendingXact(itemId))
					{
						ZHeapTupleTransInfo zinfo;

						zinfo.trans_slot = ItemIdGetTransactionSlot(itemId);

						/*
						 * We can't reach here for a valid input page as the
						 * callers passed it for the pages that wouldn't have
						 * been pruned.
						 */
						Assert(!PageIsValid(input_page));

						/*
						 * Here, we are relying on the transaction information
						 * in slot as if the corresponding slot has been
						 * reused, then transaction information from the entry
						 * would have been cleared.  See PageFreezeTransSlots.
						 */
						if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
							break;
						GetTransactionSlotInfo(buffer, offsetNumber,
											   zinfo.trans_slot, NoTPDBufLock,
											   false, &zinfo);

						/*
						 * It is quite possible that the item is showing some
						 * valid transaction slot, but actual slot has been
						 * frozen. This can happen when the slot belongs to
						 * TPD entry and the corresponding TPD entry is
						 * pruned.
						 */
						if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
							break;
						if (TransactionIdIsValid(zinfo.xid) &&
							!TransactionIdDidCommit(zinfo.xid))
						{
							hasPendingXact = true;
							continue;
						}
					}
					break;
				}
			}
			if (offsetNumber >= limit && !hasPendingXact)
			{
				/* the hint is wrong, so reset it */
				PageClearHasFreeLinePointers(phdr);
			}
		}
		else
		{
			/* don't bother searching if hint says there's no free slot */
			offsetNumber = limit;
		}
	}

	/* Reject placing items beyond the first unused line pointer */
	if (offsetNumber > limit)
	{
		elog(WARNING, "specified item offset is too large");
		return InvalidOffsetNumber;
	}

	/* Reject placing items beyond heap boundary, if heap */
	if ((flags & PAI_IS_HEAP) != 0 && offsetNumber > MaxZHeapTuplesPerPage)
	{
		elog(WARNING, "can't put more than MaxZHeapTuplesPerPage items in a heap page");
		return InvalidOffsetNumber;
	}

	/*
	 * Compute new lower and upper pointers for page, see if it'll fit.
	 *
	 * Note: do arithmetic as signed ints, to avoid mistakes if, say, size >
	 * pd_upper.
	 */
	if (offsetNumber == limit || needshuffle)
		lower = phdr->pd_lower + sizeof(ItemIdData);
	else
		lower = phdr->pd_lower;

	alignedSize = SHORTALIGN(size);

	upper = (int) phdr->pd_upper - (int) alignedSize;

	if (lower > upper)
		return InvalidOffsetNumber;

	/*
	 * OK to insert the item.  First, shuffle the existing pointers if needed.
	 */
	itemId = PageGetItemId(phdr, offsetNumber);

	if (needshuffle)
		memmove(itemId + 1, itemId,
				(limit - offsetNumber) * sizeof(ItemIdData));

	/* set the item pointer */
	ItemIdSetNormal(itemId, upper, size);

	/*
	 * Items normally contain no uninitialized bytes.  Core bufpage consumers
	 * conform, but this is not a necessary coding rule; a new index AM could
	 * opt to depart from it.  However, data type input functions and other
	 * C-language functions that synthesize datums should initialize all
	 * bytes; datumIsEqual() relies on this.  Testing here, along with the
	 * similar check in printtup(), helps to catch such mistakes.
	 *
	 * Values of the "name" type retrieved via index-only scans may contain
	 * uninitialized bytes; see comment in btrescan().  Valgrind will report
	 * this as an error, but it is safe to ignore.
	 */
	VALGRIND_CHECK_MEM_IS_DEFINED(item, size);

	/* copy the item's data onto the page */
	memcpy((char *) page + upper, item, size);

	/* adjust page header */
	phdr->pd_lower = (LocationIndex) lower;
	phdr->pd_upper = (LocationIndex) upper;

	return offsetNumber;
}

/*
 * PageGetZHeapFreeSpace
 *		Returns the size of the free (allocatable) space on a zheap page,
 *		reduced by the space needed for a new line pointer.
 *
 * This is same as PageGetHeapFreeSpace except for max tuples that can
 * be accommodated on a page or the way unused items are dealt.
 */
Size
PageGetZHeapFreeSpace(Page page)
{
	Size		space;

	space = PageGetFreeSpace(page);
	if (space > 0)
	{
		OffsetNumber offnum,
					nline;

		nline = PageGetMaxOffsetNumber(page);
		if (nline >= MaxZHeapTuplesPerPage)
		{
			if (PageHasFreeLinePointers((PageHeader) page))
			{
				/*
				 * Since this is just a hint, we must confirm that there is
				 * indeed a free line pointer
				 */
				for (offnum = FirstOffsetNumber; offnum <= nline; offnum = OffsetNumberNext(offnum))
				{
					ItemId		lp = PageGetItemId(page, offnum);

					/*
					 * The unused items that have pending xact information
					 * can't be reused.
					 */
					if (!ItemIdIsUsed(lp) && !ItemIdHasPendingXact(lp))
						break;
				}

				if (offnum > nline)
				{
					/*
					 * The hint is wrong, but we can't clear it here since we
					 * don't have the ability to mark the page dirty.
					 */
					space = 0;
				}
			}
			else
			{
				/*
				 * Although the hint might be wrong, PageAddItem will believe
				 * it anyway, so we must believe it too.
				 */
				space = 0;
			}
		}
	}
	return space;
}

/*
 * RelationPutZHeapTuple - Same as RelationPutHeapTuple, but for ZHeapTuple.
 */
void
RelationPutZHeapTuple(Relation relation,
					  Buffer buffer,
					  ZHeapTuple tuple)
{
	OffsetNumber offnum;

	/* Add the tuple to the page.  Caller must ensure to have a TPD page lock. */
	offnum = ZPageAddItem(buffer, NULL, (Item) tuple->t_data, tuple->t_len,
						  InvalidOffsetNumber, false, true, false);

	if (offnum == InvalidOffsetNumber)
		elog(PANIC, "failed to add tuple to page");

	/* Update tuple->t_self to the actual position where it was stored */
	ItemPointerSet(&(tuple->t_self), BufferGetBlockNumber(buffer), offnum);
}

/*
 * ZHeapGetUsableOffsetRanges
 *
 * Given a page and a set of tuples, it calculates how many tuples can fit in
 * the page and the contiguous ranges of free offsets that can be used/reused
 * in the same page to store those tuples.
 */
ZHeapFreeOffsetRanges *
ZHeapGetUsableOffsetRanges(Buffer buffer,
						   ZHeapTuple *tuples,
						   int ntuples,
						   Size saveFreeSpace)
{
	Page		page;
	PageHeader	phdr;
	int			nthispage;
	Size		used_space;
	Size		avail_space;
	OffsetNumber limit,
				offsetNumber;
	ZHeapFreeOffsetRanges *zfree_offset_ranges;

	page = BufferGetPage(buffer);
	phdr = (PageHeader) page;

	zfree_offset_ranges = (ZHeapFreeOffsetRanges *)
		palloc0(sizeof(ZHeapFreeOffsetRanges));

	zfree_offset_ranges->nranges = 0;
	limit = OffsetNumberNext(PageGetMaxOffsetNumber(page));
	avail_space = PageGetExactFreeSpace(page);
	nthispage = 0;
	used_space = 0;

	if (PageHasFreeLinePointers(phdr))
	{
		bool		in_range = false;

		/*
		 * Look for "recyclable" (unused) ItemId.  We check for no storage as
		 * well, just to be paranoid --- unused items should never have
		 * storage.
		 */
		for (offsetNumber = 1; offsetNumber < limit; offsetNumber++)
		{
			ItemId		itemId = PageGetItemId(phdr, offsetNumber);

			if (nthispage >= ntuples)
			{
				/* No more tuples to insert */
				break;
			}
			if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
			{
				ZHeapTuple	zheaptup = tuples[nthispage];
				Size		needed_space = used_space + zheaptup->t_len + saveFreeSpace;

				/* Check if we can fit this tuple in the page */
				if (avail_space < needed_space)
				{
					/* No more space to insert tuples in this page */
					break;
				}

				used_space += zheaptup->t_len;
				nthispage++;

				if (!in_range)
				{
					/* Start of a new range */
					zfree_offset_ranges->nranges++;
					zfree_offset_ranges->startOffset[zfree_offset_ranges->nranges - 1] = offsetNumber;
					in_range = true;
				}
				zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1] = offsetNumber;
			}
			else
			{
				in_range = false;
			}
		}
	}

	/*
	 * Now, there are no free line pointers. Check whether we can insert
	 * another tuple in the page, then we'll insert another range starting
	 * from limit to max required offset number. We can decide the actual end
	 * offset for this range while inserting tuples in the buffer.
	 */
	if ((limit <= MaxZHeapTuplesPerPage) && (nthispage < ntuples))
	{
		ZHeapTuple	zheaptup = tuples[nthispage];
		Size		needed_space = used_space + sizeof(ItemIdData) +
		zheaptup->t_len + saveFreeSpace;

		/* Check if we can fit this tuple + a new offset in the page */
		if (avail_space >= needed_space)
		{
			OffsetNumber max_required_offset;
			int			required_tuples = ntuples - nthispage;

			/*
			 * Choose minimum among MaxOffsetNumber and the maximum offsets
			 * required for tuples.
			 */
			max_required_offset = Min(MaxOffsetNumber, (limit + required_tuples));

			zfree_offset_ranges->nranges++;
			zfree_offset_ranges->startOffset[zfree_offset_ranges->nranges - 1] = limit;
			zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1] = max_required_offset;
		}
	}

	return zfree_offset_ranges;
}

/*
 * Initialize zheap page.
 */
void
ZheapInitPage(Page page, Size pageSize)
{
	ZHeapPageOpaque opaque;
	TransInfo  *thistrans;
	int			i;

	/*
	 * The size of the opaque space depends on the number of transaction slots
	 * in a page. We set it to default here.
	 */
	PageInit(page, pageSize, ZHEAP_PAGE_TRANS_SLOTS * sizeof(TransInfo));

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	for (i = 0; i < ZHEAP_PAGE_TRANS_SLOTS; i++)
	{
		thistrans = &opaque->transinfo[i];
		thistrans->fxid = InvalidFullTransactionId;
		thistrans->urec_ptr = InvalidUndoRecPtr;
	}
}

/*
 * ZheapInitMetaPage - Allocate and initialize the zheap metapage.
 *
 * If already_exists is true, we allocate a new zheap metapage else we
 * re-initialize the existing metapage.
 */
void
ZheapInitMetaPage(RelFileNode rnode, ForkNumber forkNum,
				  char persistence, bool already_exists)
{
	Buffer		buf;
	bool		use_wal;

	buf = ReadBufferWithoutRelcache(SMGR_MD, rnode, forkNum,
									already_exists ? ZHEAP_METAPAGE : P_NEW,
									RBM_NORMAL, NULL, persistence);
	if (BufferGetBlockNumber(buf) != ZHEAP_METAPAGE)
		elog(ERROR, "unexpected zheap metapage block number: %u, should be %u",
			 BufferGetBlockNumber(buf), ZHEAP_METAPAGE);

	LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

	START_CRIT_SECTION();

	zheap_init_meta_page(buf, InvalidBlockNumber, InvalidBlockNumber);
	MarkBufferDirty(buf);

	/*
	 * WAL log creation of metapage if the relation is persistent, or this is
	 * the init fork.  Init forks for unlogged relations always need to be WAL
	 * logged.
	 */
	use_wal = persistence == RELPERSISTENCE_PERMANENT ||
		forkNum == INIT_FORKNUM;

	if (use_wal)
		log_newpage_buffer(buf, true);

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buf);
}

/*
 * zheap_init_meta_page - Initialize the metapage.
 */
void
zheap_init_meta_page(Buffer metabuf, BlockNumber first_blkno,
					 BlockNumber last_blkno)
{
	ZHeapMetaPage metap;
	Page		page;

	page = BufferGetPage(metabuf);
	PageInit(page, BufferGetPageSize(metabuf), 0);

	metap = ZHeapPageGetMeta(page);
	metap->zhm_magic = ZHEAP_MAGIC;
	metap->zhm_version = ZHEAP_VERSION;
	metap->zhm_first_used_tpd_page = first_blkno;
	metap->zhm_last_used_tpd_page = last_blkno;

	/*
	 * Set pd_lower just past the end of the metadata.  This is essential,
	 * because without doing so, metadata will be lost if xlog.c compresses
	 * the page.
	 */
	((PageHeader) page)->pd_lower =
		((char *) metap + sizeof(ZHeapMetaPageData)) - (char *) page;
}

/*
 * zheap_gettuple
 *
 * Copy a raw tuple from a zheap page, forming a ZHeapTuple.
 */
ZHeapTuple
zheap_gettuple(Relation relation, Buffer buffer, OffsetNumber offnum)
{
	Page		dp;
	ItemId		lp;
	Size		tuple_len;
	ZHeapTupleHeader item;
	ZHeapTuple	tuple;

	dp = BufferGetPage(buffer);
	lp = PageGetItemId(dp, offnum);

	Assert(offnum >= FirstOffsetNumber && offnum <= PageGetMaxOffsetNumber(dp));
	Assert(ItemIdIsNormal(lp));

	tuple_len = ItemIdIsDeleted(lp) ? 0 : ItemIdGetLength(lp);
	tuple = palloc(ZHEAPTUPLESIZE + tuple_len);
	tuple->t_tableOid = RelationGetRelid(relation);
	tuple->t_len = tuple_len;
	ItemPointerSet(&tuple->t_self, BufferGetBlockNumber(buffer), offnum);
	item = (ZHeapTupleHeader) PageGetItem(dp, lp);
	tuple->t_data = (ZHeapTupleHeader) ((char *) tuple + ZHEAPTUPLESIZE);
	memcpy(tuple->t_data, item, tuple_len);

	return tuple;
}
