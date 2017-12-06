/*-------------------------------------------------------------------------
 *
 * zheapamxlog.c
 *	  WAL replay logic for zheap.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zheapamxlog.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/visibilitymap.h"
#include "access/xlog.h"
#include "access/xlogutils.h"
#include "access/zheap.h"
#include "access/zheapam_xlog.h"
#include "storage/standby.h"
#include "storage/freespace.h"

static void
zheap_xlog_insert(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xl_zheap_insert *xlrec;
	Buffer		buffer;
	Page		page;
	union
	{
		ZHeapTupleHeaderData hdr;
		char		data[MaxZHeapTupleSize];
	}			tbuf;
	ZHeapTupleHeader zhtup;
	UnpackedUndoRecord	undorecord;
	UndoRecPtr	urecptr;
	xl_zheap_header xlhdr;
	uint32		newlen;
	RelFileNode target_node;
	BlockNumber blkno;
	ItemPointerData target_tid;
	XLogRedoAction action;

	xlrec = (xl_zheap_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

	XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
	ItemPointerSetBlockNumber(&target_tid, blkno);
	ItemPointerSetOffsetNumber(&target_tid, xlrec->offnum);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
	 *
	 * Fixme - This is just for future support of visibility maps with zheap.
	 * Once that is supported, we can test if this code works and remove this
	 * comment after it works.
	 */
	if (xlrec->flags & XLZ_INSERT_ALL_VISIBLE_CLEARED)
	{
		Relation	reln = CreateFakeRelcacheEntry(target_node);
		Buffer		vmbuffer = InvalidBuffer;

		visibilitymap_pin(reln, blkno, &vmbuffer);
		visibilitymap_clear(reln, blkno, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
		FreeFakeRelcacheEntry(reln);
	}

	/* prepare an undo record */
	undorecord.uur_type = UNDO_INSERT;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = XLogRecGetXid(record);
	undorecord.uur_xid = XLogRecGetXid(record);
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);
	undorecord.uur_payload.len = 0;
	undorecord.uur_tuple.len = 0;

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT, XLogRecGetXid(record));
	InsertPreparedUndo();
	SetUndoPageLSNs(lsn);

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	/*
	 * If we inserted the first and only tuple on the page, re-initialize the
	 * page from scratch.
	 */
	if (XLogRecGetInfo(record) & XLOG_ZHEAP_INIT_PAGE)
	{
		buffer = XLogInitBufferForRedo(record, 0);
		page = BufferGetPage(buffer);
		ZheapInitPage(page, BufferGetPageSize(buffer));
		action = BLK_NEEDS_REDO;
	}
	else
		action = XLogReadBufferForRedo(record, 0, &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		Size		datalen;
		char	   *data;
		int			trans_slot_id;

		page = BufferGetPage(buffer);

		if (PageGetMaxOffsetNumber(page) + 1 < xlrec->offnum)
			elog(PANIC, "invalid max offset number");

		data = XLogRecGetBlockData(record, 0, &datalen);

		newlen = datalen - SizeOfZHeapHeader;
		Assert(datalen > SizeOfZHeapHeader && newlen <= MaxZHeapTupleSize);
		memcpy((char *) &xlhdr, data, SizeOfZHeapHeader);
		data += SizeOfZHeapHeader;

		zhtup = &tbuf.hdr;
		MemSet((char *) zhtup, 0, SizeofZHeapTupleHeader);
		/* PG73FORMAT: get bitmap [+ padding] [+ oid] + data */
		memcpy((char *) zhtup + SizeofZHeapTupleHeader,
			   data,
			   newlen);
		newlen += SizeofZHeapTupleHeader;
		zhtup->t_infomask2 = xlhdr.t_infomask2;
		zhtup->t_infomask = xlhdr.t_infomask;
		zhtup->t_hoff = xlhdr.t_hoff;

		if (ZPageAddItem(page, (Item) zhtup, newlen, xlrec->offnum,
						 true, true) == InvalidOffsetNumber)
			elog(PANIC, "failed to add tuple");

		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup);
		
		PageSetUNDO(undorecord, page, trans_slot_id, XLogRecGetXid(record), urecptr);
		PageSetLSN(page, lsn);

		if (xlrec->flags & XLZ_INSERT_ALL_VISIBLE_CLEARED)
			PageClearAllVisible(page);

		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();
}

static void
zheap_xlog_delete(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	Size	recordlen = XLogRecGetDataLen(record);
	xl_zheap_delete *xlrec;
	Buffer		buffer;
	Page		page;
	ZHeapTupleData	zheaptup;
	UnpackedUndoRecord	undorecord;
	UndoRecPtr	urecptr;
	RelFileNode target_node;
	BlockNumber blkno;
	ItemPointerData target_tid;
	XLogRedoAction action;
	Relation	reln;
	ItemId	lp = NULL;

	xlrec = (xl_zheap_delete *) ((char *) xlundohdr + SizeOfUndoHeader);

	XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
	ItemPointerSetBlockNumber(&target_tid, blkno);
	ItemPointerSetOffsetNumber(&target_tid, xlrec->offnum);

	reln = CreateFakeRelcacheEntry(target_node);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
	 *
	 * Fixme - This is just for future support of visibility maps with zheap.
	 * Once that is supported, we can test if this code works and remove this
	 * comment after it works.
	 */
	if (xlrec->flags & XLZ_DELETE_ALL_VISIBLE_CLEARED)
	{
		Buffer		vmbuffer = InvalidBuffer;

		visibilitymap_pin(reln, blkno, &vmbuffer);
		visibilitymap_clear(reln, blkno, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
	}

	action = XLogReadBufferForRedo(record, 0, &buffer);

	page = BufferGetPage(buffer);

	if (PageGetMaxOffsetNumber(page) >= xlrec->offnum)
		lp = PageGetItemId(page, xlrec->offnum);

	if (PageGetMaxOffsetNumber(page) < xlrec->offnum || !ItemIdIsNormal(lp))
		elog(PANIC, "invalid lp");

	zheaptup.t_tableOid = RelationGetRelid(reln);
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);
	zheaptup.t_self = target_tid;

	/*
	 * If the WAL stream contains undo tuple, then replace it with the
	 * explicitly stored tuple.
	 */
	if (xlrec->flags & XLZ_HAS_DELETE_UNDOTUPLE)
	{
		char	   *data;
		xl_zheap_header xlhdr;
		union
		{
			ZHeapTupleHeaderData hdr;
			char		data[MaxZHeapTupleSize];
		} tbuf;
		ZHeapTupleHeader zhtup;
		Size	datalen;

		data = (char *) xlrec + SizeOfZHeapDelete;
		memcpy((char *) &xlhdr, data, SizeOfZHeapHeader);
		data += SizeOfZHeapHeader;

		datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapDelete - SizeOfZHeapHeader;

		zhtup = &tbuf.hdr;
		MemSet((char *) zhtup, 0, SizeofZHeapTupleHeader);
		/* PG73FORMAT: get bitmap [+ padding] [+ oid] + data */
		memcpy((char *) zhtup + SizeofZHeapTupleHeader,
			   data,
			   datalen);
		datalen += SizeofZHeapTupleHeader;
		zhtup->t_infomask2 = xlhdr.t_infomask2;
		zhtup->t_infomask = xlhdr.t_infomask;
		zhtup->t_hoff = xlhdr.t_hoff;

		zheaptup.t_data = zhtup;
		zheaptup.t_len = datalen;
	}

	/* prepare an undo record */
	undorecord.uur_type = UNDO_DELETE;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = xlrec->prevxid;
	undorecord.uur_xid = XLogRecGetXid(record);
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_len,
						   sizeof(uint32));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_self,
						   sizeof(ItemPointerData));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_tableOid,
						   sizeof(Oid));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) zheaptup.t_data,
						   zheaptup.t_len);

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT, XLogRecGetXid(record));
	InsertPreparedUndo();
	SetUndoPageLSNs(lsn);

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	if (action == BLK_NEEDS_REDO)
	{
		zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zheaptup.t_len = ItemIdGetLength(lp);
		ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, xlrec->trans_slot_id);
		zheaptup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		zheaptup.t_data->t_infomask |= ZHEAP_DELETED;

		PageSetUNDO(undorecord, page, xlrec->trans_slot_id, XLogRecGetXid(record), urecptr);

		/* Mark the page as a candidate for pruning */
		/* Fixme : need to uncomment once we have done this in zheap_delete operation */
		/* PageSetPrunable(page, XLogRecGetXid(record)); */

		if (xlrec->flags & XLZ_DELETE_ALL_VISIBLE_CLEARED)
			PageClearAllVisible(page);

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();
	FreeFakeRelcacheEntry(reln);
}

static void
zheap_xlog_update(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr;
	xl_undo_header	*xlnewundohdr = NULL;
	xl_zheap_header xlhdr;
	Size	recordlen;
	Size		freespace = 0;
	xl_zheap_update *xlrec;
	Buffer		oldbuffer, newbuffer;
	Page		oldpage, newpage;
	ZHeapTupleData	oldtup;
	ZHeapTupleHeader newtup;
	union
	{
		ZHeapTupleHeaderData hdr;
		char		data[MaxZHeapTupleSize];
	} tbuf;
	UnpackedUndoRecord	undorecord, newundorecord;
	UndoRecPtr	urecptr = InvalidUndoRecPtr;
	UndoRecPtr	newurecptr = InvalidUndoRecPtr;
	RelFileNode rnode;
	BlockNumber oldblk, newblk;
	ItemPointerData oldtid, newtid;
	XLogRedoAction oldaction, newaction;
	Relation	reln;
	ItemId	lp = NULL;
	int			trans_slot_id;
	bool	inplace_update;

	xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xlrec = (xl_zheap_update *) ((char *) xlundohdr + SizeOfUndoHeader);
	recordlen = XLogRecGetDataLen(record);

	if (xlrec->flags & XLZ_NON_INPLACE_UPDATE)
	{
		inplace_update = false;
		xlnewundohdr = (xl_undo_header *) ((char *) xlrec + SizeOfZHeapUpdate);
	}
	else
	{
		inplace_update = true;
	}

	XLogRecGetBlockTag(record, 0, &rnode, NULL, &newblk);
	if (XLogRecGetBlockTag(record, 1, NULL, NULL, &oldblk))
	{
		/* inplace updates are never done across pages */
		Assert(!inplace_update);
	}
	else
		oldblk = newblk;

	ItemPointerSet(&oldtid, oldblk, xlrec->old_offnum);
	ItemPointerSet(&newtid, newblk, xlrec->new_offnum);

	reln = CreateFakeRelcacheEntry(rnode);

	/*
	 * The visibility map may need to be fixed even if the zheap page is
	 * already up-to-date.
	 *
	 * Fixme - This is just for future support of visibility maps with zheap.
	 * Once that is supported, we can test if this code works and remove this
	 * comment after it works.
	 */
	if (xlrec->flags & XLZ_UPDATE_OLD_ALL_VISIBLE_CLEARED)
	{
		Buffer		vmbuffer = InvalidBuffer;

		visibilitymap_pin(reln, oldblk, &vmbuffer);
		visibilitymap_clear(reln, oldblk, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
	}

	oldaction = XLogReadBufferForRedo(record, (oldblk == newblk) ? 0 : 1, &oldbuffer);

	oldpage = BufferGetPage(oldbuffer);

	if (PageGetMaxOffsetNumber(oldpage) >= xlrec->old_offnum)
		lp = PageGetItemId(oldpage, xlrec->old_offnum);

	if (PageGetMaxOffsetNumber(oldpage) < xlrec->old_offnum || !ItemIdIsNormal(lp))
		elog(PANIC, "invalid lp");

	oldtup.t_tableOid = RelationGetRelid(reln);
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(oldpage, lp);
	oldtup.t_len = ItemIdGetLength(lp);
	oldtup.t_self = oldtid;

	/*
	 * If the WAL stream contains undo tuple, then replace it with the
	 * explicitly stored tuple.
	 */
	if (xlrec->flags & XLZ_HAS_UPDATE_UNDOTUPLE)
	{
		ZHeapTupleHeader zhtup;
		Size	datalen;
		char	*data;

		data = (char *) xlrec + SizeOfZHeapUpdate;
		memcpy((char *) &xlhdr, data, SizeOfZHeapHeader);
		data += SizeOfZHeapHeader;

		/* There is an additional undo header for non-inplace-update. */
		if (inplace_update)
			datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapUpdate - SizeOfZHeapHeader;
		else
			datalen = recordlen - (2 * SizeOfUndoHeader) - SizeOfZHeapUpdate - SizeOfZHeapHeader;

		zhtup = &tbuf.hdr;
		MemSet((char *) zhtup, 0, SizeofZHeapTupleHeader);
		/* PG73FORMAT: get bitmap [+ padding] [+ oid] + data */
		memcpy((char *) zhtup + SizeofZHeapTupleHeader,
			   data,
			   datalen);
		datalen += SizeofZHeapTupleHeader;
		zhtup->t_infomask2 = xlhdr.t_infomask2;
		zhtup->t_infomask = xlhdr.t_infomask;
		zhtup->t_hoff = xlhdr.t_hoff;

		oldtup.t_data = zhtup;
		oldtup.t_len = datalen;
	}

	/* prepare an undo record */
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = xlrec->prevxid;
	undorecord.uur_xid = XLogRecGetXid(record);
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&oldtid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&oldtid);
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_len,
						   sizeof(uint32));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_self,
						   sizeof(ItemPointerData));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_tableOid,
						   sizeof(Oid));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) oldtup.t_data,
						   oldtup.t_len);

	if (inplace_update)
	{
		undorecord.uur_type =  UNDO_INPLACE_UPDATE;
		urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT, XLogRecGetXid(record));
	}
	else
	{
		undorecord.uur_type = UNDO_UPDATE;
		undorecord.uur_payload.len = sizeof(ItemPointerData);
		initStringInfo(&undorecord.uur_payload);
		/* update new tuple location in undo record */
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &newtid,
							   sizeof(ItemPointerData));
		urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT, XLogRecGetXid(record));

		/* prepare an undo record for new tuple */
		newundorecord.uur_type = UNDO_INSERT;
		newundorecord.uur_info = 0;
		newundorecord.uur_prevlen = 0;
		newundorecord.uur_relfilenode = xlnewundohdr->relfilenode;
		newundorecord.uur_prevxid = XLogRecGetXid(record);
		newundorecord.uur_xid = XLogRecGetXid(record);
		newundorecord.uur_cid = FirstCommandId;
		newundorecord.uur_tsid = xlnewundohdr->tsid;
		newundorecord.uur_fork = MAIN_FORKNUM;
		newundorecord.uur_blkprev = xlnewundohdr->blkprev;
		newundorecord.uur_block = ItemPointerGetBlockNumber(&newtid);
		newundorecord.uur_offset = ItemPointerGetOffsetNumber(&newtid);
		newundorecord.uur_payload.len = 0;
		newundorecord.uur_tuple.len = 0;

		newurecptr = PrepareUndoInsert(&newundorecord, UNDO_PERSISTENT, XLogRecGetXid(record));

		Assert (newurecptr == xlnewundohdr->urec_ptr);
	}

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	InsertPreparedUndo();
	SetUndoPageLSNs(lsn);

	/* Ensure old tuple points to the tuple in page. */
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(oldpage, lp);
	oldtup.t_len = ItemIdGetLength(lp);

	/* First deal with old tuple */
	if (oldaction == BLK_NEEDS_REDO)
	{
		oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		if (inplace_update)
			oldtup.t_data->t_infomask |= ZHEAP_INPLACE_UPDATED;
		else
			oldtup.t_data->t_infomask |= ZHEAP_UPDATED;
		ZHeapTupleHeaderSetXactSlot(oldtup.t_data, xlrec->old_trans_slot_id);

		if (oldblk != newblk)
			PageSetUNDO(undorecord, oldpage, xlrec->old_trans_slot_id,
						XLogRecGetXid(record), urecptr);

		if (xlrec->flags & XLZ_UPDATE_OLD_ALL_VISIBLE_CLEARED)
			PageClearAllVisible(oldpage);

		PageSetLSN(oldpage, lsn);
		MarkBufferDirty(oldbuffer);
	}

	/*
	 * Read the page the new tuple goes into, if different from old.
	 */
	if (oldblk == newblk)
	{
		newbuffer = oldbuffer;
		newaction = oldaction;
	}
	else if (XLogRecGetInfo(record) & XLOG_ZHEAP_INIT_PAGE)
	{
		newbuffer = XLogInitBufferForRedo(record, 0);
		newpage = (Page) BufferGetPage(newbuffer);
		PageInit(newpage, BufferGetPageSize(newbuffer), 0);
		newaction = BLK_NEEDS_REDO;
	}
	else
		newaction = XLogReadBufferForRedo(record, 0, &newbuffer);

	/*
	 * The visibility map may need to be fixed even if the zheap page is
	 * already up-to-date.
	 */
	if (xlrec->flags & XLZ_UPDATE_NEW_ALL_VISIBLE_CLEARED)
	{
		Buffer		vmbuffer = InvalidBuffer;

		visibilitymap_pin(reln, newblk, &vmbuffer);
		visibilitymap_clear(reln, newblk, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
	}

	if (newaction == BLK_NEEDS_REDO)
	{
		uint16		prefixlen = 0,
					suffixlen = 0;
		char	   *newp;
		char	   *recdata;
		char	   *recdata_end;
		Size		datalen;
		Size		tuplen;
		uint32		newlen;

		newpage = BufferGetPage(newbuffer);

		if (PageGetMaxOffsetNumber(newpage) + 1 < xlrec->new_offnum)
			elog(PANIC, "invalid max offset number");

		recdata = XLogRecGetBlockData(record, 0, &datalen);
		recdata_end = recdata + datalen;

		if (xlrec->flags & XLZ_UPDATE_PREFIX_FROM_OLD)
		{
			Assert(newblk == oldblk);
			memcpy(&prefixlen, recdata, sizeof(uint16));
			recdata += sizeof(uint16);
		}
		if (xlrec->flags & XLZ_UPDATE_SUFFIX_FROM_OLD)
		{
			Assert(newblk == oldblk);
			memcpy(&suffixlen, recdata, sizeof(uint16));
			recdata += sizeof(uint16);
		}

		memcpy((char *) &xlhdr, recdata, SizeOfZHeapHeader);
		recdata += SizeOfZHeapHeader;

		tuplen = recdata_end - recdata;
		Assert(tuplen <= MaxZHeapTupleSize);

		newtup = &tbuf.hdr;
		MemSet((char *) newtup, 0, SizeofZHeapTupleHeader);

		/*
		 * Reconstruct the new tuple using the prefix and/or suffix from the
		 * old tuple, and the data stored in the WAL record.
		 */
		newp = (char *) newtup + SizeofZHeapTupleHeader;
		if (prefixlen > 0)
		{
			int			len;

			/* copy bitmap [+ padding] [+ oid] from WAL record */
			len = xlhdr.t_hoff - SizeofZHeapTupleHeader;
			memcpy(newp, recdata, len);
			recdata += len;
			newp += len;

			/* copy prefix from old tuple */
			memcpy(newp, (char *) oldtup.t_data + oldtup.t_data->t_hoff, prefixlen);
			newp += prefixlen;

			/* copy new tuple data from WAL record */
			len = tuplen - (xlhdr.t_hoff - SizeofZHeapTupleHeader);
			memcpy(newp, recdata, len);
			recdata += len;
			newp += len;
		}
		else
		{
			/*
			 * copy bitmap [+ padding] [+ oid] + data from record, all in one
			 * go
			 */
			memcpy(newp, recdata, tuplen);
			recdata += tuplen;
			newp += tuplen;
		}
		Assert(recdata == recdata_end);

		/* copy suffix from old tuple */
		if (suffixlen > 0)
			memcpy(newp, (char *) oldtup.t_data + oldtup.t_len - suffixlen, suffixlen);

		newlen = SizeofZHeapTupleHeader + tuplen + prefixlen + suffixlen;
		newtup->t_infomask2 = xlhdr.t_infomask2;
		newtup->t_infomask = xlhdr.t_infomask;
		newtup->t_hoff = xlhdr.t_hoff;
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(newtup);

		if (inplace_update)
		{
			/*
			 * For inplace updates, we copy the entire data portion including null
			 * bitmap of new tuple.
			 */
			ItemIdChangeLen(lp, newlen);
			memcpy((char *) oldtup.t_data + SizeofZHeapTupleHeader,
				   (char *) newtup + SizeofZHeapTupleHeader,
				   newlen - SizeofZHeapTupleHeader);
			PageSetUNDO(undorecord, newpage, trans_slot_id, XLogRecGetXid(record), urecptr);
		}
		else
		{
			if (ZPageAddItem(newpage, (Item) newtup, newlen, xlrec->new_offnum,
						 true, true) == InvalidOffsetNumber)
				elog(PANIC, "failed to add tuple");
			PageSetUNDO(undorecord, newpage, trans_slot_id, XLogRecGetXid(record), newurecptr);
		}

		if (xlrec->flags & XLZ_UPDATE_NEW_ALL_VISIBLE_CLEARED)
			PageClearAllVisible(newpage);

		freespace = PageGetHeapFreeSpace(newpage); /* needed to update FSM below */

		PageSetLSN(newpage, lsn);
		MarkBufferDirty(newbuffer);
	}

	if (BufferIsValid(newbuffer) && newbuffer != oldbuffer)
		UnlockReleaseBuffer(newbuffer);
	if (BufferIsValid(oldbuffer))
		UnlockReleaseBuffer(oldbuffer);
	UnlockReleaseUndoBuffers();
	FreeFakeRelcacheEntry(reln);

	/*
	 * Update the freespace.  We don't need to update it for inplace updates as
	 * they won't freeup any space or consume any extra space assuming the new
	 * tuple is about the same size as the old one.  See heap_xlog_update.
	 */
	if (newaction == BLK_NEEDS_REDO && !inplace_update && freespace < BLCKSZ / 5)
		XLogRecordPageWithFreeSpace(rnode, newblk, freespace);
}

static void
zheap_xlog_freeze_xact_slot(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer		buffer;
	xl_zheap_freeze_xact_slot *xlrec =
			(xl_zheap_freeze_xact_slot *) XLogRecGetData(record);
	XLogRedoAction action;

	/* There must be some frozen slots.*/
	Assert(xlrec->nFrozen > 0);

	/*
	 * In Hot Standby mode, ensure that no running query conflicts with the
	 * frozen xids.
	 */
	if (InHotStandby)
	{
		RelFileNode rnode;

		/*
		 * FIXME: We need some handling for transaction wraparound.
		 */
		TransactionId lastestFrozenXid = xlrec->lastestFrozenXid;

		XLogRecGetBlockTag(record, 0, &rnode, NULL, NULL);
		ResolveRecoveryConflictWithSnapshot(lastestFrozenXid, rnode);
	}

	action = XLogReadBufferForRedo(record, 0, &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		Page	page;
		ZHeapPageOpaque	opaque;
		int		slot_no;
		int	   *frozen;
		int		i;

		frozen = (int *) XLogRecGetBlockData(record, 0, NULL);

		page = BufferGetPage(buffer);
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

		/* clear the transaction slot info on tuples */
		MarkTupleFrozen(page, xlrec->nFrozen, frozen);

		/* Initialize the frozen slots. */
		for (i = 0; i < xlrec->nFrozen; i++)
		{
			slot_no = frozen[i];
			opaque->transinfo[slot_no].xid = InvalidTransactionId;
			opaque->transinfo[slot_no].urec_ptr = InvalidUndoRecPtr;
		}

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
}

static void
zheap_xlog_invalid_xact_slot(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr;
	xl_zheap_invalid_xact_slot *xlrec;
	xl_zheap_completed_slot	*completed_slots = NULL;
	xl_zheap_completed_slot all_slots[MAX_PAGE_TRANS_INFO_SLOTS];
	xl_zheap_tuple_info *tuples = NULL;
	XLogRedoAction action;
	UnpackedUndoRecord	*undorecord;
	UnpackedUndoRecord	*slot_urec[MAX_PAGE_TRANS_INFO_SLOTS];
	Buffer	buffer;
	int	   *completed_xact_slots = NULL;
	char   *data;
	int		slot_no;
	Page	page;
	int		i;
	int		noffsets;
	int 	nCompletedXactSlots;
	ZHeapPageOpaque	 opaque;
	OffsetNumber	*offsets = NULL;

	data = XLogRecGetData(record);
	xlundohdr = (xl_undo_header *) data;
	data += SizeOfUndoHeader;

	xlrec = (xl_zheap_invalid_xact_slot *) data;
	data += SizeOfZHeapInvalidXactSlot;

	action = XLogReadBufferForRedo(record, 0, &buffer);
	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	if (xlrec->flags & XLZ_HAS_TUPLE_INFO)
	{
		completed_slots = (xl_zheap_completed_slot *) data;
		data += xlrec->nCompletedSlots * sizeof(xl_zheap_completed_slot);
		tuples = (xl_zheap_tuple_info *) data;

		/*
		 * Initialize the all_slots array this will avoid searching in the
		 * completed_slot array and we can directly index by slotno.
		 */
		for (i = 0; i < xlrec->nCompletedSlots; i++)
		{
			slot_no = completed_slots[i].slotno;
			all_slots[slot_no] = completed_slots[i];
		}

		noffsets = xlrec->nOffsets;
	}
	else
	{
		nCompletedXactSlots = xlrec->nCompletedSlots;
		completed_xact_slots = (int *) data;

		if (xlrec->nOffsets)
		{
			offsets = palloc(sizeof(OffsetNumber) * xlrec->nOffsets);

			/*
			 * find all the tuples pointing to the transaction slots for
			 * committed transactions.
			 */
			GetCompletedSlotOffsets(page, nCompletedXactSlots,
									completed_xact_slots, offsets,
									&noffsets);

			Assert(noffsets == xlrec->nOffsets);
		}

		for (i = 0; i < xlrec->nCompletedSlots; i++)
		{
			slot_no = completed_xact_slots[i];
			all_slots[slot_no].urp = opaque->transinfo[slot_no].urec_ptr;
			all_slots[slot_no].xid = opaque->transinfo[slot_no].xid;
		}
	}

	/* Set the prepared undo size */
	if (noffsets > 0)
	{
		UndoSetPrepareSize(noffsets);
		undorecord = (UnpackedUndoRecord *) palloc(noffsets *
											sizeof(UnpackedUndoRecord));
	}

	/*
	 * Write separate undo record for each of the tuple in page that points
	 * to transaction slot which we are going to mark for reuse.
	 */
	for (i = 0; i < noffsets; i++)
	{
		UndoRecPtr	urecptr, prev_urecptr;
		OffsetNumber	offnum;


		if (xlrec->flags & XLZ_HAS_TUPLE_INFO)
		{
			offnum = tuples[i].offnum;
			slot_no = tuples[i].slotno;
		}
		else
		{
			ZHeapTupleHeader	tup_hdr;
			ItemId		itemid;

			offnum = offsets[i];

			itemid = PageGetItemId(page, offnum);
			tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
			slot_no = ZHeapTupleHeaderGetXactSlot(tup_hdr);
		}

		prev_urecptr = all_slots[slot_no].urp;

		/* prepare an undo record */
		undorecord[i].uur_type = UNDO_INVALID_XACT_SLOT;
		undorecord[i].uur_info = 0;
		undorecord[i].uur_prevlen = 0;
		undorecord[i].uur_relfilenode = xlundohdr->relfilenode;
		undorecord[i].uur_prevxid = all_slots[slot_no].xid;
		undorecord[i].uur_xid = XLogRecGetXid(record);
		undorecord[i].uur_cid = FirstCommandId;
		undorecord[i].uur_tsid = xlundohdr->tsid;
		undorecord[i].uur_fork = MAIN_FORKNUM;
		undorecord[i].uur_blkprev = prev_urecptr;
		undorecord[i].uur_block = BufferGetBlockNumber(buffer);
		undorecord[i].uur_offset = offnum;
		undorecord[i].uur_payload.len = 0;
		undorecord[i].uur_tuple.len = 0;

		urecptr = PrepareUndoInsert(&undorecord[i], UNDO_PERSISTENT,
									XLogRecGetXid(record));
		all_slots[slot_no].urp = urecptr;

		/* Stores latest undorec for slot for debug log */
		slot_urec[slot_no] = &undorecord[i];
	}

	if (noffsets > 0)
	{
		InsertPreparedUndo();
		SetUndoPageLSNs(lsn);
	}

	if (action == BLK_NEEDS_REDO)
	{
		ZHeapTupleData	tup;
		ItemId		itemid;
		OffsetNumber offnum;

		/* mark all the tuple that their slot is reused */
		for (i = 0; i < noffsets; i++)
		{
			if (xlrec->flags & XLZ_HAS_TUPLE_INFO)
				offnum = tuples[i].offnum;
			else
				offnum = offsets[i];

			itemid = PageGetItemId(page, offnum);
			Assert(ItemIdIsUsed(itemid));

			page = BufferGetPage(buffer);
			tup.t_data = (ZHeapTupleHeader) PageGetItem(page, itemid);
			tup.t_data->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
		}

		/* Initialize the completed slots. */
		for (i = 0; i < xlrec->nCompletedSlots; i++)
		{
			UnpackedUndoRecord	undorec;

			if (xlrec->flags & XLZ_HAS_TUPLE_INFO)
				slot_no = completed_slots[i].slotno;
			else
				slot_no = completed_xact_slots[i];

			if (slot_urec[slot_no] != NULL)
				undorec = *(slot_urec[slot_no]);

			PageSetUNDO(undorec, page, slot_no, InvalidTransactionId,
						all_slots[slot_no].urp);
		}

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}

	/* perform cleanup */
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	UnlockReleaseUndoBuffers();
}

static void
zheap_xlog_lock(XLogReaderState *record)
{
	XLogRecPtr  lsn = record->EndRecPtr;
	xl_undo_header  *xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xl_zheap_lock *xlrec;
	Buffer      buffer;
	Page        page;
	ZHeapTupleData  zheaptup;
	char		*tup_hdr;
	UnpackedUndoRecord  undorecord;
	UndoRecPtr  urecptr;
	RelFileNode target_node;
	BlockNumber blkno;
	ItemPointerData target_tid;
	XLogRedoAction action;
	Relation    reln;
	ItemId  lp = NULL;

	xlrec = (xl_zheap_lock *) ((char *) xlundohdr + SizeOfUndoHeader);

	XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
	ItemPointerSet(&target_tid, blkno, xlrec->offnum);

	reln = CreateFakeRelcacheEntry(target_node);
	action = XLogReadBufferForRedo(record, 0, &buffer);
	page = BufferGetPage(buffer);

	if (PageGetMaxOffsetNumber(page) >= xlrec->offnum)
		lp = PageGetItemId(page, xlrec->offnum);

	if (PageGetMaxOffsetNumber(page) < xlrec->offnum || !ItemIdIsNormal(lp))
		elog(PANIC, "invalid lp");

	zheaptup.t_tableOid = RelationGetRelid(reln);
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);
	zheaptup.t_self = target_tid;

	/*
	 * WAL stream contains undo tuple header, replace it with the explicitly
	 * stored tuple header.
	 */
	tup_hdr = (char *) xlrec + SizeOfZHeapLock;

	/* prepare an undo record */
	undorecord.uur_type = UNDO_XID_LOCK_ONLY;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = xlrec->prev_xid;
	undorecord.uur_xid = XLogRecGetXid(record);
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   tup_hdr,
						   SizeofZHeapTupleHeader);

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT,
								XLogRecGetXid(record));
	InsertPreparedUndo();
	SetUndoPageLSNs(lsn);

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	if (action == BLK_NEEDS_REDO)
	{
		zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zheaptup.t_len = ItemIdGetLength(lp);
		ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, xlrec->trans_slot_id);
		zheaptup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		zheaptup.t_data->t_infomask |= ZHEAP_XID_LOCK_ONLY;

		PageSetUNDO(undorecord, page, xlrec->trans_slot_id, XLogRecGetXid(record), urecptr);

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	UnlockReleaseUndoBuffers();
	FreeFakeRelcacheEntry(reln);
}

static void
zheap_xlog_multi_insert(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr;
	xl_zheap_multi_insert *xlrec;
	RelFileNode rnode;
	BlockNumber blkno;
	Buffer		buffer;
	Page		page;
	union
	{
		ZHeapTupleHeaderData hdr;
		char		data[MaxZHeapTupleSize];
	}			tbuf;
	ZHeapTupleHeader zhtup;
	uint32		newlen;
	UnpackedUndoRecord	*undorecord;
	UndoRecPtr	urecptr,
						prev_urecptr;
	int			i;
	int			nranges;
	bool		isinit = (XLogRecGetInfo(record) & XLOG_ZHEAP_INIT_PAGE) != 0;
	XLogRedoAction action;
	char	   *data;

	xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xlrec = (xl_zheap_multi_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

	XLogRecGetBlockTag(record, 0, &rnode, NULL, &blkno);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
	 *
	 * Fixme - This is just for future support of visibility maps with zheap.
	 * Once that is supported, we can test if this code works and remove this
	 * comment after it works.
	 */
	if (xlrec->flags & XLZ_INSERT_ALL_VISIBLE_CLEARED)
	{
		Relation	reln = CreateFakeRelcacheEntry(rnode);
		Buffer		vmbuffer = InvalidBuffer;

		visibilitymap_pin(reln, blkno, &vmbuffer);
		visibilitymap_clear(reln, blkno, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
		FreeFakeRelcacheEntry(reln);
	}

	if (isinit)
	{
		buffer = XLogInitBufferForRedo(record, 0);
		page = BufferGetPage(buffer);
		ZheapInitPage(page, BufferGetPageSize(buffer));
		action = BLK_NEEDS_REDO;
	}
	else
		action = XLogReadBufferForRedo(record, 0, &buffer);

	/* allocate the information related to offset ranges */
	data = (char *)xlrec + SizeOfZHeapMultiInsert;

	/* fetch number of distinct ranges */
	nranges = *(int *) data;
	data += sizeof(int);

	Assert(nranges > 0);
	undorecord = (UnpackedUndoRecord *) palloc(nranges * sizeof(UnpackedUndoRecord));

	/* Start UNDO prepare Stuff */
	prev_urecptr = xlundohdr->blkprev;
	urecptr = prev_urecptr;

	UndoSetPrepareSize(nranges);

	for (i = 0; i < nranges; i++)
	{
		/* prepare an undo record */
		undorecord[i].uur_type = UNDO_MULTI_INSERT;
		undorecord[i].uur_info = 0;
		undorecord[i].uur_prevlen = 0;
		undorecord[i].uur_relfilenode = xlundohdr->relfilenode;
		undorecord[i].uur_prevxid = XLogRecGetXid(record);
		undorecord[i].uur_xid = XLogRecGetXid(record);
		undorecord[i].uur_cid = FirstCommandId;
		undorecord[i].uur_tsid = xlundohdr->tsid;
		undorecord[i].uur_fork = MAIN_FORKNUM;
		undorecord[i].uur_blkprev = urecptr;
		undorecord[i].uur_block = blkno;
		undorecord[i].uur_offset = 0;
		undorecord[i].uur_tuple.len = 0;
		undorecord[i].uur_payload.len = 2 * sizeof(OffsetNumber);
		undorecord[i].uur_payload.data = (char *)palloc(2 * sizeof(OffsetNumber));
		urecptr = PrepareUndoInsert(&undorecord[i], UNDO_PERSISTENT, XLogRecGetXid(record));

		memcpy(undorecord[i].uur_payload.data,
			   (char *) data,
			   undorecord[i].uur_payload.len);
		data += undorecord[i].uur_payload.len;

	}
	elog(DEBUG1, "Undo record prepared: %d for Block Number: %d",
		 nranges, blkno);

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	InsertPreparedUndo();
	SetUndoPageLSNs(lsn);
	UnlockReleaseUndoBuffers();

	/* Apply the wal for data */
	if (action == BLK_NEEDS_REDO)
	{
		char	   *tupdata;
		char	   *endptr;
		int			trans_slot_id;
		Size		len;
		OffsetNumber offnum;
		int			j = 0;
		page = BufferGetPage(buffer);

		/* Tuples are stored as block data */
		tupdata = XLogRecGetBlockData(record, 0, &len);
		endptr = tupdata + len;

		offnum = (OffsetNumber)undorecord[j].uur_payload.data[0];
		for (i = 0; i < xlrec->ntuples; i++)
		{
			xl_multi_insert_ztuple *xlhdr;

			/*
			 * If we're reinitializing the page, the tuples are stored in
			 * order from FirstOffsetNumber. Otherwise there's an array of
			 * offsets in the WAL record, and the tuples come after that.
			 */
			if (isinit)
				offnum = FirstOffsetNumber + i;
			else
			{
				/*
				 * Change the offset range if we've reached the end of current
				 * range.
				 */
				if (offnum == (OffsetNumber)undorecord[j].uur_payload.data[1])
				{
					j++;
					offnum = (OffsetNumber)undorecord[j].uur_payload.data[0];
				}
			}
			if (PageGetMaxOffsetNumber(page) + 1 < offnum)
				elog(PANIC, "invalid max offset number");

			xlhdr = (xl_multi_insert_ztuple *) SHORTALIGN(tupdata);
			tupdata = ((char *) xlhdr) + SizeOfMultiInsertZTuple;

			newlen = xlhdr->datalen;
			Assert(newlen <= MaxZHeapTupleSize);
			zhtup = &tbuf.hdr;
			MemSet((char *) zhtup, 0, SizeofZHeapTupleHeader);
			/* PG73FORMAT: get bitmap [+ padding] [+ oid] + data */
			memcpy((char *) zhtup + SizeofZHeapTupleHeader,
				   (char *) tupdata,
				   newlen);
			tupdata += newlen;

			newlen += SizeofZHeapTupleHeader;
			zhtup->t_infomask2 = xlhdr->t_infomask2;
			zhtup->t_infomask = xlhdr->t_infomask;
			zhtup->t_hoff = xlhdr->t_hoff;

			if (ZPageAddItem(page, (Item) zhtup, newlen, offnum,
							 true, true) == InvalidOffsetNumber)
				elog(PANIC, "failed to add tuple");

			/* increase the offset to store next tuple */
			offnum++;

			trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup);
			PageSetUNDO(undorecord[nranges-1], page, trans_slot_id, XLogRecGetXid(record), urecptr);
		}

		PageSetLSN(page, lsn);
		if (xlrec->flags & XLZ_INSERT_ALL_VISIBLE_CLEARED)
			PageClearAllVisible(page);
		MarkBufferDirty(buffer);

		if (BufferIsValid(buffer))
			UnlockReleaseBuffer(buffer);

		if (tupdata != endptr)
			elog(ERROR, "total tuple length mismatch");
	}
}

void
zheap_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info & XLOG_ZHEAP_OPMASK)
	{
		case XLOG_ZHEAP_INSERT:
			zheap_xlog_insert(record);
			break;
		case XLOG_ZHEAP_DELETE:
			zheap_xlog_delete(record);
			break;
		case XLOG_ZHEAP_UPDATE:
			zheap_xlog_update(record);
			break;
		case XLOG_ZHEAP_FREEZE_XACT_SLOT:
			zheap_xlog_freeze_xact_slot(record);
			break;
		case XLOG_ZHEAP_INVALID_XACT_SLOT:
			zheap_xlog_invalid_xact_slot(record);
			break;
		case XLOG_ZHEAP_LOCK:
			zheap_xlog_lock(record);
			break;
		case XLOG_ZHEAP_MULTI_INSERT:
			zheap_xlog_multi_insert(record);
			break;
		default:
			elog(PANIC, "zheap_redo: unknown op code %u", info);
	}
}
