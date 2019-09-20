/*-------------------------------------------------------------------------
 *
 * tpdxlog.c
 *	  WAL replay logic for tpd.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/tpdxlog.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/tpd_xlog.h"
#include "access/xlogutils.h"
#include "access/zheapam_xlog.h"

/*
 * replay of tpd entry allocation
 */
static void
tpd_xlog_allocate_entry(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_tpd_allocate_entry *xlrec;
	Buffer		tpdbuffer;
	Buffer		heap_page_buffer;
	Buffer		metabuf = InvalidBuffer;
	Buffer		last_used_buf = InvalidBuffer;
	Buffer		old_tpd_buf = InvalidBuffer;
	Page		tpdpage;
	TPDPageOpaque tpdopaque;
	XLogRedoAction action;

	xlrec = (xl_tpd_allocate_entry *) XLogRecGetData(record);

	/*
	 * If we inserted the first and only tpd entry on the page, re-initialize
	 * the page from scratch.
	 */
	if (XLogRecGetInfo(record) & XLOG_TPD_INIT_PAGE)
	{
		tpdbuffer = XLogInitBufferForRedo(record, 0);
		tpdpage = BufferGetPage(tpdbuffer);
		TPDInitPage(tpdpage, BufferGetPageSize(tpdbuffer));
		action = BLK_NEEDS_REDO;
	}
	else
		action = XLogReadBufferForRedo(record, 0, &tpdbuffer);
	if (action == BLK_NEEDS_REDO)
	{
		char	   *tpd_entry;
		Size		size_tpd_entry;
		OffsetNumber offnum;

		tpd_entry = XLogRecGetBlockData(record, 0, &size_tpd_entry);
		tpdpage = BufferGetPage(tpdbuffer);
		offnum = TPDPageAddEntry(tpdpage, tpd_entry, size_tpd_entry,
								 xlrec->offnum);
		if (offnum == InvalidOffsetNumber)
			elog(PANIC, "failed to add TPD entry");
		MarkBufferDirty(tpdbuffer);
		PageSetLSN(tpdpage, lsn);

		/* The TPD entry must be added at the provided offset. */
		Assert(offnum == xlrec->offnum);

		tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
		tpdopaque->tpd_prevblkno = xlrec->prevblk;

		MarkBufferDirty(tpdbuffer);
		PageSetLSN(tpdpage, lsn);
	}
	else if (action == BLK_RESTORED)
	{
		/*
		 * Note that we still update the page even if it was restored from a
		 * full page image, because the special space is not included in the
		 * image.
		 */
		tpdpage = BufferGetPage(tpdbuffer);

		tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(tpdpage);
		tpdopaque->tpd_prevblkno = xlrec->prevblk;

		MarkBufferDirty(tpdbuffer);
		PageSetLSN(tpdpage, lsn);
	}

	if (XLogReadBufferForRedo(record, 1, &heap_page_buffer) == BLK_NEEDS_REDO)
	{
		/* Set the TPD location in last transaction slot of heap page. */
		SetTPDLocation(heap_page_buffer, tpdbuffer, xlrec->offnum);
		MarkBufferDirty(heap_page_buffer);

		PageSetLSN(BufferGetPage(heap_page_buffer), lsn);
	}

	/* replay the record for meta page */
	if (XLogRecHasBlockRef(record, 2))
	{
		xl_zheap_metadata *xlrecmeta;
		char	   *ptr;
		Size		len;

		metabuf = XLogInitBufferForRedo(record, 2);
		ptr = XLogRecGetBlockData(record, 2, &len);

		Assert(len == SizeOfMetaData);
		Assert(BufferGetBlockNumber(metabuf) == ZHEAP_METAPAGE);
		xlrecmeta = (xl_zheap_metadata *) ptr;

		zheap_init_meta_page(metabuf, xlrecmeta->first_used_tpd_page,
							 xlrecmeta->last_used_tpd_page);
		MarkBufferDirty(metabuf);
		PageSetLSN(BufferGetPage(metabuf), lsn);

		/*
		 * We can have reference of block 3, iff we have reference for block
		 * 2.
		 */
		if (XLogRecHasBlockRef(record, 3))
		{
			action = XLogReadBufferForRedo(record, 3, &last_used_buf);

			/*
			 * Note that we still update the page even if it was restored from
			 * a full page image, because the special space is not included in
			 * the image.
			 */
			if (action == BLK_NEEDS_REDO || action == BLK_RESTORED)
			{
				Page		last_used_page;
				TPDPageOpaque last_tpdopaque;

				last_used_page = BufferGetPage(last_used_buf);
				last_tpdopaque = (TPDPageOpaque) PageGetSpecialPointer(last_used_page);
				last_tpdopaque->tpd_nextblkno = xlrec->nextblk;

				/* old and last tpd buffer are same. */
				if (xlrec->flags & XLOG_OLD_TPD_BUF_EQ_LAST_TPD_BUF)
				{
					TPDEntryHeader old_tpd_entry;
					Page		otpdpage;
					char	   *data;
					OffsetNumber *off_num;
					Size		datalen PG_USED_FOR_ASSERTS_ONLY;
					ItemId		old_item_id;

					if (action == BLK_NEEDS_REDO)
					{
						data = XLogRecGetBlockData(record, 3, &datalen);

						off_num = (OffsetNumber *) data;
						Assert(datalen == sizeof(OffsetNumber));

						otpdpage = BufferGetPage(last_used_buf);
						old_item_id = PageGetItemId(otpdpage, *off_num);
						old_tpd_entry = (TPDEntryHeader) PageGetItem(otpdpage, old_item_id);
						old_tpd_entry->tpe_flags |= TPE_DELETED;
					}

					/* We can't have a separate reference for old tpd buffer. */
					Assert(!XLogRecHasBlockRef(record, 4));
				}

				MarkBufferDirty(last_used_buf);
				PageSetLSN(last_used_page, lsn);
			}
		}

		/*
		 * We can have reference of block 4, iff we have reference for block
		 * 2.
		 */
		if (XLogRecHasBlockRef(record, 4))
		{
			TPDEntryHeader old_tpd_entry;
			Page		otpdpage;
			char	   *data;
			OffsetNumber *off_num;
			Size		datalen PG_USED_FOR_ASSERTS_ONLY;
			ItemId		old_item_id;

			action = XLogReadBufferForRedo(record, 4, &old_tpd_buf);

			if (action == BLK_NEEDS_REDO)
			{
				data = XLogRecGetBlockData(record, 4, &datalen);

				off_num = (OffsetNumber *) data;
				Assert(datalen == sizeof(OffsetNumber));

				otpdpage = BufferGetPage(old_tpd_buf);
				old_item_id = PageGetItemId(otpdpage, *off_num);
				old_tpd_entry = (TPDEntryHeader) PageGetItem(otpdpage, old_item_id);
				old_tpd_entry->tpe_flags |= TPE_DELETED;

				MarkBufferDirty(old_tpd_buf);
				PageSetLSN(BufferGetPage(old_tpd_buf), lsn);
			}
		}
	}

	if (BufferIsValid(tpdbuffer))
		UnlockReleaseBuffer(tpdbuffer);
	if (BufferIsValid(heap_page_buffer))
		UnlockReleaseBuffer(heap_page_buffer);
	if (BufferIsValid(metabuf))
		UnlockReleaseBuffer(metabuf);
	if (BufferIsValid(last_used_buf))
		UnlockReleaseBuffer(last_used_buf);
	if (BufferIsValid(old_tpd_buf))
		UnlockReleaseBuffer(old_tpd_buf);
}

/*
 * replay inplace update of TPD entry
 */
static void
tpd_xlog_inplace_update_entry(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer		tpdbuf;
	XLogRedoAction action;

	/*
	 * If we have a full-page image, restore it (using a cleanup lock) and
	 * we're done.
	 */
	action = XLogReadBufferForRedoExtended(record, 0, RBM_NORMAL, true,
										   &tpdbuf);
	if (action == BLK_NEEDS_REDO)
	{
		Page		tpdpage = (Page) BufferGetPage(tpdbuf);
		ItemId		item_id;
		OffsetNumber *off_num;
		char	   *data;
		char	   *new_tpd_entry;
		Size		datalen,
					size_new_tpd_entry;
		uint16		tpd_e_offset;

		data = XLogRecGetBlockData(record, 0, &datalen);
		off_num = (OffsetNumber *) data;
		new_tpd_entry = (char *) ((char *) data + sizeof(OffsetNumber));
		size_new_tpd_entry = datalen - sizeof(OffsetNumber);

		item_id = PageGetItemId(tpdpage, *off_num);
		tpd_e_offset = ItemIdGetOffset(item_id);
		memcpy((char *) (tpdpage + tpd_e_offset),
			   new_tpd_entry,
			   size_new_tpd_entry);
		ItemIdChangeLen(item_id, size_new_tpd_entry);

		MarkBufferDirty(tpdbuf);
		PageSetLSN(tpdpage, lsn);
	}
	if (BufferIsValid(tpdbuf))
		UnlockReleaseBuffer(tpdbuf);
}

/*
 * replay of pruning tpd page
 */
static void
tpd_xlog_clean(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_tpd_clean *xlrec = (xl_tpd_clean *) XLogRecGetData(record);
	Buffer		tpdbuf;
	XLogRedoAction action;

	/*
	 * If we have a full-page image, restore it (using a cleanup lock) and
	 * we're done.
	 */
	action = XLogReadBufferForRedoExtended(record, 0, RBM_NORMAL, true,
										   &tpdbuf);
	if (action == BLK_NEEDS_REDO)
	{
		Page		tpdpage = (Page) BufferGetPage(tpdbuf);
		Page		tmppage;
		OffsetNumber *end;
		OffsetNumber *nowunused;
		OffsetNumber *target_offnum;
		OffsetNumber tmp_target_off;
		Size	   *space_required;
		Size		tmp_spc_rqd;
		Size		datalen;
		int			nunused;

		if (xlrec->flags & XLZ_CLEAN_CONTAINS_OFFSET)
		{
			target_offnum = (OffsetNumber *) ((char *) xlrec + SizeOfTPDClean);
			space_required = (Size *) ((char *) target_offnum + sizeof(OffsetNumber));
		}
		else
		{
			target_offnum = &tmp_target_off;
			*target_offnum = InvalidOffsetNumber;
			space_required = &tmp_spc_rqd;
			*space_required = 0;
		}

		nowunused = (OffsetNumber *) XLogRecGetBlockData(record, 0, &datalen);
		end = (OffsetNumber *) ((char *) nowunused + datalen);
		nunused = (end - nowunused);

		if (nunused >= 0)
		{
			/*
			 * Update all item pointers per the record, and repair
			 * fragmentation.
			 */
			TPDPagePruneExecute(tpdbuf, nowunused, nunused);
		}

		tmppage = PageGetTempPageCopy(tpdpage);
		TPDPageRepairFragmentation(tpdpage, tmppage, *target_offnum,
								   *space_required);

		/*
		 * Note: we don't worry about updating the page's prunability hints.
		 * At worst this will cause an extra prune cycle to occur soon.
		 */

		MarkBufferDirty(tpdbuf);
		PageSetLSN(tpdpage, lsn);

		pfree(tmppage);
	}
	if (BufferIsValid(tpdbuf))
		UnlockReleaseBuffer(tpdbuf);
}

/*
 * replay for clearing tpd location from heap page.
 */
static void
tpd_xlog_clear_location(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer		buffer;

	if (XLogReadBufferForRedo(record, 0, &buffer) == BLK_NEEDS_REDO)
	{
		Page		page = (Page) BufferGetPage(buffer);

		ClearTPDLocation(buffer);
		MarkBufferDirty(buffer);
		PageSetLSN(page, lsn);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
}

/*
 * replay for freeing tpd page.
 */
static void
tpd_xlog_free_page(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	RelFileNode rnode;
	xl_tpd_free_page *xlrec = (xl_tpd_free_page *) XLogRecGetData(record);
	Buffer		buffer = InvalidBuffer,
				prevbuf = InvalidBuffer,
				nextbuf = InvalidBuffer,
				metabuf = InvalidBuffer;
	BlockNumber blkno;
	Page		page;
	XLogRedoAction action;
	Size		freespace;

	if (XLogRecHasBlockRef(record, 0))
	{
		action = XLogReadBufferForRedo(record, 0, &prevbuf);

		/*
		 * Note that we still update the page even if it was restored from a
		 * full page image, because the special space is not included in the
		 * image.
		 */
		if (action == BLK_NEEDS_REDO || action == BLK_RESTORED)
		{
			TPDPageOpaque prevtpdopaque;
			Page		prevpage = (Page) BufferGetPage(prevbuf);

			prevtpdopaque = (TPDPageOpaque) PageGetSpecialPointer(prevpage);
			prevtpdopaque->tpd_nextblkno = xlrec->nextblkno;

			MarkBufferDirty(prevbuf);
			PageSetLSN(prevpage, lsn);
		}
	}

	XLogRecGetBlockTag(record, 1, &rnode, NULL, &blkno);
	action = XLogReadBufferForRedo(record, 1, &buffer);

	/*
	 * It is quite possible that this buffer is already flushed by checkpoint
	 * so in that case, we will can't read that buffer because at do time, we
	 * are making buffer as new to free it.  So, if here action is BLK_NOTFOUND,
	 * then we will skip memset.
	 */
	if (action != BLK_NOTFOUND)
	{
		page = (Page) BufferGetPage(buffer);

		/*
		 * Note that we still update the page even if it was restored from a
		 * full page image, because the special space is not included in the
		 * image.
		 */
		if (action == BLK_NEEDS_REDO || action == BLK_RESTORED)
		{
			MemSet((PageHeader) page, 0, BufferGetPageSize(buffer));
			MarkBufferDirty(buffer);
		}

		/* Page should be marked as NEW. */
		Assert(PageIsNew(page));
		Assert(blkno == BufferGetBlockNumber(buffer));
	}

	if (XLogRecHasBlockRef(record, 2))
	{
		action = XLogReadBufferForRedo(record, 2, &nextbuf);

		if (action == BLK_NEEDS_REDO || action == BLK_RESTORED)
		{
			TPDPageOpaque nexttpdopaque;
			Page		nextpage = (Page) BufferGetPage(nextbuf);

			nexttpdopaque = (TPDPageOpaque) PageGetSpecialPointer(nextpage);
			nexttpdopaque->tpd_prevblkno = xlrec->prevblkno;

			MarkBufferDirty(nextbuf);
			PageSetLSN(nextpage, lsn);
		}
	}

	if (XLogRecHasBlockRef(record, 3))
	{
		xl_zheap_metadata *xlrecmeta;
		char	   *ptr;
		Size		len;

		metabuf = XLogInitBufferForRedo(record, 3);
		ptr = XLogRecGetBlockData(record, 3, &len);

		Assert(len == SizeOfMetaData);
		Assert(BufferGetBlockNumber(metabuf) == ZHEAP_METAPAGE);
		xlrecmeta = (xl_zheap_metadata *) ptr;

		zheap_init_meta_page(metabuf, xlrecmeta->first_used_tpd_page,
							 xlrecmeta->last_used_tpd_page);
		MarkBufferDirty(metabuf);
		PageSetLSN(BufferGetPage(metabuf), lsn);
	}

	if (BufferIsValid(prevbuf))
		UnlockReleaseBuffer(prevbuf);
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	if (BufferIsValid(nextbuf))
		UnlockReleaseBuffer(nextbuf);
	if (BufferIsValid(metabuf))
		UnlockReleaseBuffer(metabuf);

	freespace = BLCKSZ - SizeOfPageHeaderData;

	/* Record the empty page in FSM. */
	XLogRecordPageWithFreeSpace(rnode, blkno, freespace);
}

/*
 * replay of pruning all the entries in tpd page.
 */
static void
tpd_xlog_clean_all_entries(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer		buffer;

	if (XLogReadBufferForRedo(record, 0, &buffer) == BLK_NEEDS_REDO)
	{
		Page		page = (Page) BufferGetPage(buffer);

		((PageHeader) page)->pd_lower = SizeOfPageHeaderData;
		((PageHeader) page)->pd_upper = ((PageHeader) page)->pd_special;

		MarkBufferDirty(buffer);
		PageSetLSN(page, lsn);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
}

void
tpd_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info & XLOG_TPD_OPMASK)
	{
		case XLOG_ALLOCATE_TPD_ENTRY:
			tpd_xlog_allocate_entry(record);
			break;
		case XLOG_INPLACE_UPDATE_TPD_ENTRY:
			tpd_xlog_inplace_update_entry(record);
			break;
		case XLOG_TPD_CLEAN:
			tpd_xlog_clean(record);
			break;
		case XLOG_TPD_CLEAR_LOCATION:
			tpd_xlog_clear_location(record);
			break;
		case XLOG_TPD_FREE_PAGE:
			tpd_xlog_free_page(record);
			break;
		case XLOG_TPD_CLEAN_ALL_ENTRIES:
			tpd_xlog_clean_all_entries(record);
			break;
		default:
			elog(PANIC, "tpd_redo: unknown op code %u", info);
	}
}
