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

#include "access/tpd.h"
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
	UndoRecPtr	urecptr = InvalidUndoRecPtr;
	xl_zheap_header xlhdr;
	uint32		newlen;
	RelFileNode target_node;
	BlockNumber blkno;
	ItemPointerData target_tid;
	XLogRedoAction action;
	int			*tpd_trans_slot_id = NULL;
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	bool	skip_undo;

	xlrec = (xl_zheap_insert *) ((char *) xlundohdr + SizeOfUndoHeader);
	if (xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
		tpd_trans_slot_id = (int *) ((char *) xlrec + SizeOfZHeapInsert);

	XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
	ItemPointerSetBlockNumber(&target_tid, blkno);
	ItemPointerSetOffsetNumber(&target_tid, xlrec->offnum);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
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

	/*
	 * We can skip inserting undo records if the tuples are to be marked
	 * as frozen.
	 */
	skip_undo = (xlrec->flags & XLZ_INSERT_IS_FROZEN);

	if (!skip_undo)
	{
		/* prepare an undo record */
		undorecord.uur_type = UNDO_INSERT;
		undorecord.uur_info = 0;
		undorecord.uur_prevlen = 0;
		undorecord.uur_relfilenode = xlundohdr->relfilenode;
		undorecord.uur_prevxid = FrozenTransactionId;
		undorecord.uur_xid = xid;
		undorecord.uur_cid = FirstCommandId;
		undorecord.uur_tsid = xlundohdr->tsid;
		undorecord.uur_fork = MAIN_FORKNUM;
		undorecord.uur_blkprev = xlundohdr->blkprev;
		undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
		undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);
		undorecord.uur_payload.len = 0;
		undorecord.uur_tuple.len = 0;

		/*
		 * For speculative insertions, we store the dummy speculative token in the
		 * undorecord so that, the size of undorecord in DO function matches with
		 * the size of undorecord in REDO function. This ensures that, for INSERT
		 * ... ON CONFLICT statements, the assert condition used later in this
		 * function to ensure that the undo pointer in DO and REDO function remains
		 * the same is true. However, it might not be useful in the REDO function as
		 * it is just required in the master node to detect conflicts for insert ...
		 * on conflict.
		 *
		 * Fixme - Once we have undo consistency checker that we can remove the
		 * assertion as well dummy speculative token.
		 */
		if (xlrec->flags & XLZ_INSERT_IS_SPECULATIVE)
		{
			uint32 dummy_specToken = 1;

			undorecord.uur_payload.len = sizeof(uint32);
			initStringInfo(&undorecord.uur_payload);
			appendBinaryStringInfo(&undorecord.uur_payload,
				(char *)&dummy_specToken,
				sizeof(uint32));
		}
		else
			undorecord.uur_payload.len = 0;

		urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
		InsertPreparedUndo();

		/*
		 * undo should be inserted at same location as it was during the actual
		 * insert (DO operation).
		 */

		Assert(urecptr == xlundohdr->urec_ptr);
	}

	/*
	 * If we inserted the first and only tuple on the page, re-initialize the
	 * page from scratch.
	 */
	if (XLogRecGetInfo(record) & XLOG_ZHEAP_INIT_PAGE)
	{
		/* It is asked for page init, insert should not have tpd slot. */
		Assert(!(xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT));
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

		if (ZPageAddItem(buffer, NULL, (Item) zhtup, newlen, xlrec->offnum,
						 true, true) == InvalidOffsetNumber)
			elog(PANIC, "failed to add tuple");

		if (!skip_undo)
		{
			if (tpd_trans_slot_id)
				trans_slot_id = *tpd_trans_slot_id;
			else
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup);

			PageSetUNDO(undorecord, buffer, trans_slot_id, false, xid_epoch,
						xid, urecptr, NULL, 0);
		}

		PageSetLSN(page, lsn);

		MarkBufferDirty(buffer);
	}

	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		/* We can't have a valid transaction slot when we are skipping undo. */
		Assert(!skip_undo);

		/*
		 * We need to replay the record for TPD only when this record contains
		 * slot from TPD.
		 */
		Assert(xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT);
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			TPDPageSetUndo(buffer,
						   *tpd_trans_slot_id,
						   true,
						   xid_epoch,
						   xid,
						   urecptr,
						   &undorecord.uur_offset,
						   1);
			TPDPageSetLSN(BufferGetPage(buffer), lsn);
		}
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
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
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	int		*tpd_trans_slot_id = NULL;
	bool		hasPayload = false;

	xlrec = (xl_zheap_delete *) ((char *) xlundohdr + SizeOfUndoHeader);
	if (xlrec->flags & XLZ_DELETE_CONTAINS_TPD_SLOT)
		tpd_trans_slot_id = (int *) ((char *) xlrec + SizeOfZHeapDelete);

	XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
	ItemPointerSetBlockNumber(&target_tid, blkno);
	ItemPointerSetOffsetNumber(&target_tid, xlrec->offnum);

	reln = CreateFakeRelcacheEntry(target_node);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
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

		if (xlrec->flags & XLZ_DELETE_CONTAINS_TPD_SLOT)
		{
			data = (char *) xlrec + SizeOfZHeapDelete +
											sizeof(*tpd_trans_slot_id);
			datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapDelete -
							SizeOfZHeapHeader - sizeof(*tpd_trans_slot_id);
		}
		else
		{
			data = (char *) xlrec + SizeOfZHeapDelete;
			datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapDelete -
											SizeOfZHeapHeader;
		}
		memcpy((char *) &xlhdr, data, SizeOfZHeapHeader);
		data += SizeOfZHeapHeader;

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
	undorecord.uur_xid = xid;
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);

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

	if (xlrec->flags & XLZ_DELETE_CONTAINS_TPD_SLOT)
	{
		initStringInfo(&undorecord.uur_payload);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) tpd_trans_slot_id,
							   sizeof(*tpd_trans_slot_id));
		hasPayload = true;
	}

	/*
	 * For sub-tranasctions, we store the dummy contains subxact token in the
	 * undorecord so that, the size of undorecord in DO function matches with
	 * the size of undorecord in REDO function. This ensures that, for
	 * sub-transactions, the assert condition used later in this
	 * function to ensure that the undo pointer in DO and REDO function remains
	 * the same is true.
	 */
	if (xlrec->flags & XLZ_DELETE_CONTAINS_SUBXACT)
	{
		SubTransactionId dummy_subXactToken = 1;

		if (!hasPayload)
		{
			initStringInfo(&undorecord.uur_payload);
			hasPayload = true;
		}

		undorecord.uur_payload.len = sizeof(SubTransactionId);
		appendBinaryStringInfo(&undorecord.uur_payload,
								(char *) &dummy_subXactToken,
								sizeof(SubTransactionId));
	}

	if (!hasPayload)
		undorecord.uur_payload.len = 0;

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
	InsertPreparedUndo();

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
		zheaptup.t_data->t_infomask = xlrec->infomask;

		PageSetUNDO(undorecord, buffer, xlrec->trans_slot_id,
					false, xid_epoch, xid, urecptr, NULL, 0);

		/* Mark the page as a candidate for pruning */
		ZPageSetPrunable(page, XLogRecGetXid(record));

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			TPDPageSetUndo(buffer,
						   xlrec->trans_slot_id,
						   true,
						   xid_epoch,
						   xid,
						   urecptr,
						   &undorecord.uur_offset,
						   1);
			TPDPageSetLSN(page, lsn);
		}
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	/* be tidy */
	pfree(undorecord.uur_tuple.data);
	if (undorecord.uur_payload.len > 0)
		pfree(undorecord.uur_payload.data);

	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
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
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	int			*old_tup_trans_slot_id = NULL;
	int			*new_trans_slot_id = NULL;
	int			trans_slot_id;
	bool	inplace_update;

	xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xlrec = (xl_zheap_update *) ((char *) xlundohdr + SizeOfUndoHeader);
	recordlen = XLogRecGetDataLen(record);

	if (xlrec->flags & XLZ_UPDATE_OLD_CONTAINS_TPD_SLOT)
	{
		old_tup_trans_slot_id = (int *) ((char *) xlrec + SizeOfZHeapUpdate);
	}
	if (xlrec->flags & XLZ_NON_INPLACE_UPDATE)
	{
		inplace_update = false;
		if (old_tup_trans_slot_id)
			xlnewundohdr = (xl_undo_header *) ((char *) old_tup_trans_slot_id + sizeof(*old_tup_trans_slot_id));
		else
			xlnewundohdr = (xl_undo_header *) ((char *) xlrec + SizeOfZHeapUpdate);

		if (xlrec->flags & XLZ_UPDATE_NEW_CONTAINS_TPD_SLOT)
			new_trans_slot_id = (int *) ((char *) xlnewundohdr + SizeOfUndoHeader);
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

		/* There is an additional undo header for non-inplace-update. */
		if (inplace_update)
		{
			if (old_tup_trans_slot_id)
			{
				data = (char *) ((char *) old_tup_trans_slot_id + sizeof(*old_tup_trans_slot_id));
				datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapUpdate -
							sizeof(*old_tup_trans_slot_id) - SizeOfZHeapHeader;
			}
			else
			{
				data = (char *) xlrec + SizeOfZHeapUpdate;
				datalen = recordlen - SizeOfUndoHeader - SizeOfZHeapUpdate - SizeOfZHeapHeader;
			}
		}
		else
		{
			if (old_tup_trans_slot_id && new_trans_slot_id)
			{
				datalen = recordlen - (2 * SizeOfUndoHeader) - SizeOfZHeapUpdate -
					sizeof(*old_tup_trans_slot_id) - sizeof(*new_trans_slot_id) -
					SizeOfZHeapHeader;
				data = (char *) ((char *) new_trans_slot_id + sizeof(*new_trans_slot_id));
			}
			else if (new_trans_slot_id)
			{
				datalen = recordlen - (2 * SizeOfUndoHeader) - SizeOfZHeapUpdate -
						sizeof(*new_trans_slot_id) - SizeOfZHeapHeader;
				data = (char *) ((char *) new_trans_slot_id + sizeof(*new_trans_slot_id));
			}
			else if (old_tup_trans_slot_id)
			{
				datalen = recordlen - (2 * SizeOfUndoHeader) - SizeOfZHeapUpdate -
						sizeof(*old_tup_trans_slot_id) - SizeOfZHeapHeader;
				data = (char *) xlnewundohdr + SizeOfUndoHeader;
			}
			else
			{
				datalen = recordlen - (2 * SizeOfUndoHeader) - SizeOfZHeapUpdate -
									SizeOfZHeapHeader;
				data = (char *) xlnewundohdr + SizeOfUndoHeader;
			}
		}

		memcpy((char *) &xlhdr, data, SizeOfZHeapHeader);
		data += SizeOfZHeapHeader;

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
	undorecord.uur_xid = xid;
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
		bool	hasPayload = false;

		undorecord.uur_type =  UNDO_INPLACE_UPDATE;
		if (old_tup_trans_slot_id)
		{
			Assert(*old_tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS);
			initStringInfo(&undorecord.uur_payload);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) old_tup_trans_slot_id,
								   sizeof(*old_tup_trans_slot_id));
			hasPayload = true;
		}

		/*
		 * For sub-tranasctions, we store the dummy contains subxact token in the
		 * undorecord so that, the size of undorecord in DO function matches with
		 * the size of undorecord in REDO function. This ensures that, for
		 * sub-transactions, the assert condition used later in this
		 * function to ensure that the undo pointer in DO and REDO function remains
		 * the same is true.
		 */
		if (xlrec->flags & XLZ_UPDATE_CONTAINS_SUBXACT)
		{
			SubTransactionId dummy_subXactToken = 1;

			if (!hasPayload)
			{
				initStringInfo(&undorecord.uur_payload);
				hasPayload = true;
			}

			undorecord.uur_payload.len = sizeof(SubTransactionId);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &dummy_subXactToken,
								   sizeof(SubTransactionId));
		}

		if (!hasPayload)
			undorecord.uur_payload.len = 0;

		urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
	}
	else
	{
		UnpackedUndoRecord	undorec[2];

		undorecord.uur_type = UNDO_UPDATE;
		initStringInfo(&undorecord.uur_payload);
		/* update new tuple location in undo record */
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &newtid,
							   sizeof(ItemPointerData));
		/* add the TPD slot id */
		if (old_tup_trans_slot_id)
		{
			Assert(*old_tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) old_tup_trans_slot_id,
								   sizeof(*old_tup_trans_slot_id));
		}

		/*
		 * For sub-tranasctions, we store the dummy contains subxact token in the
		 * undorecord so that, the size of undorecord in DO function matches with
		 * the size of undorecord in REDO function. This ensures that, for
		 * sub-transactions, the assert condition used later in this
		 * function to ensure that the undo pointer in DO and REDO function remains
		 * the same is true.
		 */
		if (xlrec->flags & XLZ_UPDATE_CONTAINS_SUBXACT)
		{
			SubTransactionId dummy_subXactToken = 1;

			undorecord.uur_payload.len = sizeof(SubTransactionId);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &dummy_subXactToken,
								   sizeof(SubTransactionId));
		}

		/* prepare an undo record for new tuple */
		newundorecord.uur_type = UNDO_INSERT;
		newundorecord.uur_info = 0;
		newundorecord.uur_prevlen = 0;
		newundorecord.uur_relfilenode = xlnewundohdr->relfilenode;
		newundorecord.uur_prevxid = xid;
		newundorecord.uur_xid = xid;
		newundorecord.uur_cid = FirstCommandId;
		newundorecord.uur_tsid = xlnewundohdr->tsid;
		newundorecord.uur_fork = MAIN_FORKNUM;
		newundorecord.uur_blkprev = xlnewundohdr->blkprev;
		newundorecord.uur_block = ItemPointerGetBlockNumber(&newtid);
		newundorecord.uur_offset = ItemPointerGetOffsetNumber(&newtid);
		newundorecord.uur_tuple.len = 0;

		if (new_trans_slot_id)
		{
			Assert(*new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS);
			initStringInfo(&newundorecord.uur_payload);
			appendBinaryStringInfo(&newundorecord.uur_payload,
								   (char *) new_trans_slot_id,
								   sizeof(*new_trans_slot_id));
		}
		else
			newundorecord.uur_payload.len = 0;

		undorec[0] = undorecord;
		undorec[1] = newundorecord;

		UndoSetPrepareSize(2, undorec, xid, UNDO_PERMANENT, NULL);
		undorecord = undorec[0];
		newundorecord = undorec[1];

		urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
		newurecptr = PrepareUndoInsert(&newundorecord, UNDO_PERMANENT, xid, NULL);

		Assert (newurecptr == xlnewundohdr->urec_ptr);
	}

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	InsertPreparedUndo();

	/* Ensure old tuple points to the tuple in page. */
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(oldpage, lp);
	oldtup.t_len = ItemIdGetLength(lp);

	/* First deal with old tuple */
	if (oldaction == BLK_NEEDS_REDO)
	{
		oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		oldtup.t_data->t_infomask = xlrec->old_infomask;
		ZHeapTupleHeaderSetXactSlot(oldtup.t_data, xlrec->old_trans_slot_id);

		if (oldblk != newblk)
			PageSetUNDO(undorecord, oldbuffer, xlrec->old_trans_slot_id,
						false, xid_epoch, xid, urecptr, NULL,
						0);

		/* Mark the page as a candidate for pruning */
		if (!inplace_update)
			ZPageSetPrunable(oldpage, XLogRecGetXid(record));

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
		ZheapInitPage(newpage, BufferGetPageSize(newbuffer));
		newaction = BLK_NEEDS_REDO;
	}
	else
		newaction = XLogReadBufferForRedo(record, 0, &newbuffer);

	newpage = BufferGetPage(newbuffer);

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
		if (new_trans_slot_id)
			trans_slot_id = *new_trans_slot_id;
		else
			trans_slot_id = ZHeapTupleHeaderGetXactSlot(newtup);

		if (inplace_update)
		{
			/*
			 * For inplace updates, we copy the entire data portion including the
			 * tuple header.
			 */
			ItemIdChangeLen(lp, newlen);
			memcpy((char *) oldtup.t_data, (char *) newtup, newlen);

			if (newlen < oldtup.t_len)
			{
				/* new tuple is smaller, a prunable cadidate */
				Assert (oldpage == newpage);
				ZPageSetPrunable(newpage, XLogRecGetXid(record));
			}

			PageSetUNDO(undorecord, newbuffer, xlrec->old_trans_slot_id,
						false, xid_epoch, xid, urecptr,
						NULL, 0);
		}
		else
		{
			if (ZPageAddItem(newbuffer, NULL, (Item) newtup, newlen, xlrec->new_offnum,
						 true, true) == InvalidOffsetNumber)
				elog(PANIC, "failed to add tuple");
			PageSetUNDO((newbuffer == oldbuffer) ? undorecord : newundorecord,
						newbuffer, trans_slot_id, false, xid_epoch, xid,
						newurecptr, NULL, 0);
		}

		freespace = PageGetHeapFreeSpace(newpage); /* needed to update FSM below */

		PageSetLSN(newpage, lsn);
		MarkBufferDirty(newbuffer);
	}

	/* replay the record for tpd buffer corresponding to oldbuf */
	if (XLogRecHasBlockRef(record, 2))
	{
		if (XLogReadTPDBuffer(record, 2) == BLK_NEEDS_REDO)
		{
			OffsetNumber usedoff[2];
			int			 ucnt;

			if (!inplace_update && newbuffer == oldbuffer)
			{
				usedoff[0] = undorecord.uur_offset;
				usedoff[1] = newundorecord.uur_offset;
				ucnt = 2;
			}
			else
			{
				usedoff[0] = undorecord.uur_offset;
				ucnt = 1;
			}
			if (xlrec->old_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			{
				if (inplace_update)
				{
					TPDPageSetUndo(oldbuffer,
								   xlrec->old_trans_slot_id,
								   true,
								   xid_epoch,
								   xid,
								   urecptr,
								   usedoff,
								   ucnt);
				}
				else
				{
					TPDPageSetUndo(oldbuffer,
								   xlrec->old_trans_slot_id,
								   true,
								   xid_epoch,
								   xid,
								   (oldblk == newblk) ? newurecptr : urecptr,
								   usedoff,
								   ucnt);
				}
				TPDPageSetLSN(oldpage, lsn);
			}
		}
	}

	/* replay the record for tpd buffer corresponding to newbuf */
	if (XLogRecHasBlockRef(record, 3))
	{
		if (XLogReadTPDBuffer(record, 3) == BLK_NEEDS_REDO)
		{
			TPDPageSetUndo(newbuffer,
						   *new_trans_slot_id,
						   true,
						   xid_epoch,
						   xid,
						   newurecptr,
						   &newundorecord.uur_offset,
						   1);
			TPDPageSetLSN(newpage, lsn);
		}
	}
	else if (new_trans_slot_id && (*new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS))
	{
		TPDPageSetUndo(newbuffer,
					   *new_trans_slot_id,
					   true,
					   xid_epoch,
					   xid,
					   newurecptr,
					   &newundorecord.uur_offset,
					   1);
		TPDPageSetLSN(newpage, lsn);
	}
	if (BufferIsValid(newbuffer) && newbuffer != oldbuffer)
		UnlockReleaseBuffer(newbuffer);
	if (BufferIsValid(oldbuffer))
		UnlockReleaseBuffer(oldbuffer);

	/* be tidy */
	pfree(undorecord.uur_tuple.data);
	if (undorecord.uur_payload.len > 0)
		pfree(undorecord.uur_payload.data);

	if (!inplace_update && newundorecord.uur_payload.len > 0)
		pfree(newundorecord.uur_payload.data);

	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
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

		frozen = (int *) ((char *) xlrec + SizeOfZHeapFreezeXactSlot);

		page = BufferGetPage(buffer);
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

		/* clear the transaction slot info on tuples */
		if (xlrec->flags & XLZ_FREEZE_TPD_SLOT)
		{
			Assert(XLogRecHasBlockRef(record, 1));
			action = XLogReadTPDBuffer(record, 1);
			zheap_freeze_or_invalidate_tuples(buffer, xlrec->nFrozen, frozen,
											  true, true);
		}
		else
			zheap_freeze_or_invalidate_tuples(buffer, xlrec->nFrozen, frozen,
											  true, false);

		if (xlrec->flags & XLZ_FREEZE_TPD_SLOT)
		{
			if (action == BLK_NEEDS_REDO)
			{
				/* Initialize the frozen slots. */
				for (i = 0; i < xlrec->nFrozen; i++)
				{
					int	tpd_slot_id;

					/* Calculate the actual slot no. */
					tpd_slot_id = frozen[i] + ZHEAP_PAGE_TRANS_SLOTS + 1;

					/* Clear slot information from the TPD slot. */
					TPDPageSetTransactionSlotInfo(buffer, tpd_slot_id, 0,
											  InvalidTransactionId,
											  InvalidUndoRecPtr);
				}

				TPDPageSetLSN(page, lsn);
			}
		}
		else
		{
			/* Initialize the frozen slots. */
			for (i = 0; i < xlrec->nFrozen; i++)
			{
				slot_no = frozen[i];

				opaque->transinfo[slot_no].xid_epoch = 0;
				opaque->transinfo[slot_no].xid = InvalidTransactionId;
				opaque->transinfo[slot_no].urec_ptr = InvalidUndoRecPtr;
			}
		}

		PageSetLSN(page, lsn);

		MarkBufferDirty(buffer);
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	UnlockReleaseTPDBuffers();
}

static void
zheap_xlog_invalid_xact_slot(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer		buffer;
	xl_zheap_invalid_xact_slot *xlrec =
			(xl_zheap_invalid_xact_slot *) XLogRecGetData(record);
	XLogRedoAction action;

	/* There must be some frozen slots.*/
	Assert(xlrec->nCompletedSlots > 0);

	action = XLogReadBufferForRedo(record, 0, &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		Page	page;
		ZHeapPageOpaque	opaque;
		TransInfo	*tpd_slots;
		int		slot_no;
		int	   *completed_slots;
		int		i;

		completed_slots = (int *) ((char *) xlrec + SizeOfZHeapInvalidXactSlot);

		page = BufferGetPage(buffer);
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

		/* clear the transaction slot info on tuples. */
		if (xlrec->flags & XLZ_INVALID_XACT_TPD_SLOT)
		{
			Assert(XLogRecHasBlockRef(record, 1));

			action = XLogReadTPDBuffer(record, 1);
			zheap_freeze_or_invalidate_tuples(buffer, xlrec->nCompletedSlots,
											  completed_slots, false, true);
		}
		else
			zheap_freeze_or_invalidate_tuples(buffer, xlrec->nCompletedSlots,
											  completed_slots, false, false);

		if (xlrec->flags & XLZ_INVALID_XACT_TPD_SLOT)
		{
			if (action == BLK_NEEDS_REDO)
			{
				/*
				 * Read TPD slot array. So that we can keep the slot urec_ptr
				 * intact while clearing the transaction id from the slot.
				 */
				tpd_slots = TPDPageGetTransactionSlots(NULL, buffer,
													   InvalidOffsetNumber,
													   true, false, NULL, NULL,
													   NULL, NULL, NULL);

				for (i = 0; i < xlrec->nCompletedSlots; i++)
				{
					int slot_no, tpd_slot_id;

					slot_no = completed_slots[i];
					tpd_slot_id = slot_no + ZHEAP_PAGE_TRANS_SLOTS + 1;

					/* Clear the XID information from the TPD. */
					TPDPageSetTransactionSlotInfo(buffer, tpd_slot_id, 0,
												  InvalidTransactionId,
												  tpd_slots[slot_no].urec_ptr);
				}

				TPDPageSetLSN(page, lsn);
			}
		}
		else
		{
			/* Clear xid from the slots. */
			for (i = 0; i < xlrec->nCompletedSlots; i++)
			{
				slot_no = completed_slots[i];
				opaque->transinfo[slot_no].xid_epoch = 0;
				opaque->transinfo[slot_no].xid = InvalidTransactionId;
			}
		}

		PageSetLSN(page, lsn);
		if (xlrec->flags & XLZ_INVALID_XACT_TPD_SLOT)
			TPDPageSetLSN(page, lsn);

		MarkBufferDirty(buffer);
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	UnlockReleaseTPDBuffers();
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
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	int		*trans_slot_for_urec = NULL;
	int		*tup_trans_slot_id = NULL;
	int		undo_slot_no;

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
	if (ZHeapTupleHasMultiLockers(xlrec->infomask))
		undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
	else
		undorecord.uur_type = UNDO_XID_LOCK_ONLY;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = xlrec->prev_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = ItemPointerGetBlockNumber(&target_tid);
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&target_tid);

	initStringInfo(&undorecord.uur_payload);
	initStringInfo(&undorecord.uur_tuple);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   tup_hdr,
						   SizeofZHeapTupleHeader);

	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) (tup_hdr + SizeofZHeapTupleHeader),
						   sizeof(LockTupleMode));

	if (xlrec->flags & XLZ_LOCK_TRANS_SLOT_FOR_UREC)
	{
		trans_slot_for_urec = (int *) ((char *) tup_hdr +
							SizeofZHeapTupleHeader + sizeof(LockTupleMode));
		if (xlrec->trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &(xlrec->trans_slot_id),
								   sizeof(int));
	}
	else if (xlrec->flags & XLZ_LOCK_CONTAINS_TPD_SLOT)
	{
		tup_trans_slot_id = (int *) ((char *) tup_hdr +
							SizeofZHeapTupleHeader + sizeof(LockTupleMode));
		/*
		 * We must have logged the tuple's original transaction slot if it is a TPD
		 * slot.
		 */
		Assert(*tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) tup_trans_slot_id,
							   sizeof(*tup_trans_slot_id));
	}

	/*
	 * For sub-tranasctions, we store the dummy contains subxact token in the
	 * undorecord so that, the size of undorecord in DO function matches with
	 * the size of undorecord in REDO function. This ensures that, for
	 * sub-transactions, the assert condition used later in this
	 * function to ensure that the undo pointer in DO and REDO function remains
	 * the same is true.
	 */
	if (xlrec->flags & XLZ_LOCK_CONTAINS_SUBXACT)
	{
		SubTransactionId dummy_subXactToken = 1;

		undorecord.uur_payload.len = sizeof(SubTransactionId);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &dummy_subXactToken,
							   sizeof(SubTransactionId));
	}

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
	InsertPreparedUndo();

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	if (trans_slot_for_urec)
		undo_slot_no = *trans_slot_for_urec;
	else
		undo_slot_no = xlrec->trans_slot_id;

	if (action == BLK_NEEDS_REDO)
	{
		zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zheaptup.t_len = ItemIdGetLength(lp);
		ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, xlrec->trans_slot_id);
		zheaptup.t_data->t_infomask = xlrec->infomask;
		PageSetUNDO(undorecord, buffer, undo_slot_no, false, xid_epoch,
					xid, urecptr, NULL, 0);
		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			TPDPageSetUndo(buffer,
						   undo_slot_no,
						   false,
						   xid_epoch,
						   xid,
						   urecptr,
						   &undorecord.uur_offset,
						   1);
			TPDPageSetLSN(page, lsn);
		}
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	/* be tidy */
	pfree(undorecord.uur_tuple.data);
	pfree(undorecord.uur_payload.data);

	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
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
	UnpackedUndoRecord	*undorecord = NULL;
	UndoRecPtr	urecptr = InvalidUndoRecPtr,
						prev_urecptr = InvalidUndoRecPtr;
	int			i;
	int			nranges;
	int			ucnt = 0;
	OffsetNumber	usedoff[MaxOffsetNumber];
	bool		isinit = (XLogRecGetInfo(record) & XLOG_ZHEAP_INIT_PAGE) != 0;
	XLogRedoAction action;
	char		*ranges_data;
	int			*tpd_trans_slot_id = NULL;
	Size		ranges_data_size = 0;
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	ZHeapFreeOffsetRanges	*zfree_offset_ranges;
	bool		skip_undo;

	xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xlrec = (xl_zheap_multi_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

	XLogRecGetBlockTag(record, 0, &rnode, NULL, &blkno);

	/*
	 * The visibility map may need to be fixed even if the heap page is
	 * already up-to-date.
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
		/* It is asked for page init, insert should not have tpd slot. */
		Assert(!(xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT));
		buffer = XLogInitBufferForRedo(record, 0);
		page = BufferGetPage(buffer);
		ZheapInitPage(page, BufferGetPageSize(buffer));
		action = BLK_NEEDS_REDO;
	}
	else
		action = XLogReadBufferForRedo(record, 0, &buffer);

	/* allocate the information related to offset ranges */
	ranges_data = (char *) xlrec + SizeOfZHeapMultiInsert;

	/* fetch number of distinct ranges */
	nranges = *(int *) ranges_data;
	ranges_data += sizeof(int);
	ranges_data_size += sizeof(int);

	zfree_offset_ranges = (ZHeapFreeOffsetRanges *) palloc0(sizeof(ZHeapFreeOffsetRanges));
	Assert(nranges > 0);
	for (i = 0; i < nranges; i++)
	{
		memcpy(&zfree_offset_ranges->startOffset[i],(char *) ranges_data, sizeof(OffsetNumber));
		ranges_data += sizeof(OffsetNumber);
		memcpy(&zfree_offset_ranges->endOffset[i],(char *) ranges_data, sizeof(OffsetNumber));
		ranges_data += sizeof(OffsetNumber);
	}

	/*
	 * We can skip inserting undo records if the tuples are to be marked
	 * as frozen.
	 */
	skip_undo= (xlrec->flags & XLZ_INSERT_IS_FROZEN);
	if (!skip_undo)
	{
		undorecord = (UnpackedUndoRecord *) palloc(nranges * sizeof(UnpackedUndoRecord));

		/* Start UNDO prepare Stuff */
		prev_urecptr = xlundohdr->blkprev;
		urecptr = prev_urecptr;

		for (i = 0; i < nranges; i++)
		{
			/* prepare an undo record */
			undorecord[i].uur_type = UNDO_MULTI_INSERT;
			undorecord[i].uur_info = 0;
			undorecord[i].uur_prevlen = 0;
			undorecord[i].uur_relfilenode = xlundohdr->relfilenode;
			undorecord[i].uur_prevxid = xid;
			undorecord[i].uur_prevxid = FrozenTransactionId;
			undorecord[i].uur_cid = FirstCommandId;
			undorecord[i].uur_tsid = xlundohdr->tsid;
			undorecord[i].uur_fork = MAIN_FORKNUM;
			undorecord[i].uur_blkprev = urecptr;
			undorecord[i].uur_block = blkno;
			undorecord[i].uur_offset = 0;
			undorecord[i].uur_tuple.len = 0;
			undorecord[i].uur_payload.len = 2 * sizeof(OffsetNumber);
			initStringInfo(&undorecord[i].uur_payload);
			appendBinaryStringInfo(&undorecord[i].uur_payload,
								   (char *) ranges_data,
								   2 * sizeof(OffsetNumber));

			ranges_data += undorecord[i].uur_payload.len;
			ranges_data_size += undorecord[i].uur_payload.len;
		}

		UndoSetPrepareSize(nranges, undorecord, xid,
						   UNDO_PERMANENT, NULL);
		for (i = 0; i < nranges; i++)
		{
			undorecord[i].uur_blkprev = urecptr;
			urecptr = PrepareUndoInsert(&undorecord[i], UNDO_PERMANENT, xid, NULL);
		}

		elog(DEBUG1, "Undo record prepared: %d for Block Number: %d",
			 nranges, blkno);

		/*
		 * undo should be inserted at same location as it was during the actual
		 * insert (DO operation).
		 */
		Assert (urecptr == xlundohdr->urec_ptr);

		InsertPreparedUndo();
	}

	/* Get the tpd transaction slot number */
	if (xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
	{
		tpd_trans_slot_id = (int *) ((char *) xlrec + SizeOfZHeapMultiInsert +
									 ranges_data_size);
	}

	/* Apply the wal for data */
	if (action == BLK_NEEDS_REDO)
	{
		char	   *tupdata;
		char	   *endptr;
		int		trans_slot_id = 0;
		int		prev_trans_slot_id PG_USED_FOR_ASSERTS_ONLY;
		Size		len;
		OffsetNumber offnum;
		int			j = 0;
		bool		first_time = true;

		prev_trans_slot_id = -1;
		page = BufferGetPage(buffer);

		/* Tuples are stored as block data */
		tupdata = XLogRecGetBlockData(record, 0, &len);
		endptr = tupdata + len;

		offnum = zfree_offset_ranges->startOffset[j];
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
				if (offnum > zfree_offset_ranges->endOffset[j])
				{
					j++;
					offnum = zfree_offset_ranges->startOffset[j];
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

			if (ZPageAddItem(buffer, NULL, (Item) zhtup, newlen, offnum,
							 true, true) == InvalidOffsetNumber)
				elog(PANIC, "failed to add tuple");

			/* track used offsets */
			usedoff[ucnt++] = offnum;

			/* increase the offset to store next tuple */
			offnum++;

			if (!skip_undo)
			{
				if (tpd_trans_slot_id)
					trans_slot_id = *tpd_trans_slot_id;
				else
					trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup);
				if (first_time)
				{
					prev_trans_slot_id = trans_slot_id;
					first_time = false;
				}
				else
				{
					/* All the tuples must refer to same transaction slot. */
					Assert(prev_trans_slot_id == trans_slot_id);
					prev_trans_slot_id = trans_slot_id;
				}
			}
		}

		if (!skip_undo)
			PageSetUNDO(undorecord[nranges-1], buffer, trans_slot_id, false,
						xid_epoch, xid, urecptr, NULL, 0);

		PageSetLSN(page, lsn);

		MarkBufferDirty(buffer);

		if (tupdata != endptr)
			elog(ERROR, "total tuple length mismatch");
	}

	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		/*
		 * We need to replay the record for TPD only when this record contains
		 * slot from TPD.
		 */
		Assert(xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT);
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			/* prepare for the case where the data page is restored as is */
			if (ucnt == 0)
			{
				for (i = 0; i < nranges; i++)
				{
					OffsetNumber	start_off,
									end_off;

					start_off = ((OffsetNumber *) undorecord[i].uur_payload.data)[0];
					end_off = ((OffsetNumber *) undorecord[i].uur_payload.data)[1];

					while (start_off <= end_off)
						usedoff[ucnt++] = start_off++;
				}
			}

			TPDPageSetUndo(buffer,
						   *tpd_trans_slot_id,
						   true,
						   xid_epoch,
						   xid,
						   urecptr,
						   usedoff,
						   ucnt);
			TPDPageSetLSN(BufferGetPage(buffer), lsn);
		}
	}

	/* be tidy */
	if (!skip_undo)
	{
		for (i = 0; i < nranges; i++)
			pfree(undorecord[i].uur_payload.data);
		pfree(undorecord);
	}
	pfree(zfree_offset_ranges);

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
}

/*
 * Handles ZHEAP_CLEAN record type
 */
static void
zheap_xlog_clean(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_zheap_clean *xlrec = (xl_zheap_clean *) XLogRecGetData(record);
	Buffer		buffer;
	Size		freespace = 0;
	RelFileNode rnode;
	BlockNumber blkno;
	XLogRedoAction action;
	OffsetNumber	*target_offnum;
	Size			*space_required;

	XLogRecGetBlockTag(record, 0, &rnode, NULL, &blkno);

	/*
	 * We're about to remove tuples. In Hot Standby mode, ensure that there's
	 * no queries running for which the removed tuples are still visible.
	 *
	 * Not all ZHEAP_CLEAN records remove tuples with xids, so we only want to
	 * conflict on the records that cause MVCC failures for user queries. If
	 * latestRemovedXid is invalid, skip conflict processing.
	 */
	if (InHotStandby && TransactionIdIsValid(xlrec->latestRemovedXid))
		ResolveRecoveryConflictWithSnapshot(xlrec->latestRemovedXid, rnode);

	/*
	 * If we have a full-page image, restore it (using a cleanup lock) and
	 * we're done.
	 */
	action = XLogReadBufferForRedoExtended(record, 0, RBM_NORMAL, true,
										   &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		Page		page = (Page)BufferGetPage(buffer);
		OffsetNumber *end;
		OffsetNumber *deleted;
		OffsetNumber *nowdead;
		OffsetNumber *nowunused;
		OffsetNumber tmp_target_off;
		int			ndeleted;
		int			ndead;
		int			nunused;
		Size		datalen;
		Size		tmp_spc_rqd;

		deleted = (OffsetNumber *) XLogRecGetBlockData(record, 0, &datalen);

		ndeleted = xlrec->ndeleted;
		ndead = xlrec->ndead;
		end = (OffsetNumber *) ((char *) deleted + datalen);
		nowdead = deleted + (ndeleted * 2);
		nowunused = nowdead + ndead;
		nunused = (end - nowunused);
		Assert(nunused >= 0);

		/* Update all item pointers per the record, and repair fragmentation */
		if (xlrec->flags & XLZ_CLEAN_CONTAINS_OFFSET)
		{
			target_offnum = (OffsetNumber *) ((char *) xlrec + SizeOfZHeapClean);
			space_required = (Size *) ((char *) target_offnum + sizeof(OffsetNumber));
		}
		else
		{
			target_offnum = &tmp_target_off;
			*target_offnum = InvalidOffsetNumber;
			space_required = &tmp_spc_rqd;
			*space_required = 0;
		}

		zheap_page_prune_execute(buffer, *target_offnum, deleted, ndeleted,
								 nowdead, ndead, nowunused, nunused);

		if (xlrec->flags & XLZ_CLEAN_ALLOW_PRUNING)
		{
			bool	pruned PG_USED_FOR_ASSERTS_ONLY = false;
			Page	tmppage = NULL;

			/*
			 * We prepare the temporary copy of the page so that during page
			 * repair fragmentation we can use it to copy the actual tuples.
			 * See comments atop zheap_page_prune_guts.
			 */
			tmppage = PageGetTempPageCopy(BufferGetPage(buffer));
			ZPageRepairFragmentation(buffer, tmppage, *target_offnum,
									 *space_required, &pruned);

			/*
			 * Pruning must be successful at redo time, otherwise the page
			 * contents on master and standby might differ.
			 */
			Assert(pruned);

			/* be tidy. */
			pfree(tmppage);
		}

		freespace = PageGetZHeapFreeSpace(page); /* needed to update FSM below */

		/*
		 * Note: we don't worry about updating the page's prunability hints.
		 * At worst this will cause an extra prune cycle to occur soon.
		 */

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	/*
	 * Update the FSM as well.
	 *
	 * XXX: Don't do this if the page was restored from full page image. We
	 * don't bother to update the FSM in that case, it doesn't need to be
	 * totally accurate anyway.
	 */
	if (action == BLK_NEEDS_REDO)
		XLogRecordPageWithFreeSpace(rnode, blkno, freespace);
}

/*
 * Handles XLOG_ZHEAP_CONFIRM record type
 */
static void
zheap_xlog_confirm(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_zheap_confirm *xlrec = (xl_zheap_confirm *) XLogRecGetData(record);
	Buffer		buffer;
	Page		page;
	OffsetNumber offnum;
	ItemId		lp = NULL;
	ZHeapTupleHeader zhtup;

	if (XLogReadBufferForRedo(record, 0, &buffer) == BLK_NEEDS_REDO)
	{
		page = BufferGetPage(buffer);

		offnum = xlrec->offnum;
		if (PageGetMaxOffsetNumber(page) >= offnum)
			lp = PageGetItemId(page, offnum);

		if (PageGetMaxOffsetNumber(page) < offnum || !ItemIdIsNormal(lp))
			elog(PANIC, "invalid lp");

		zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);

		if (xlrec->flags == XLZ_SPEC_INSERT_SUCCESS)
		{
			/* Confirm tuple as actually inserted */
			zhtup->t_infomask &= ~ZHEAP_SPECULATIVE_INSERT;
		}
		else
		{
			Assert(xlrec->flags == XLZ_SPEC_INSERT_FAILED);
			ItemIdSetDead(lp);
			ZPageSetPrunable(page, XLogRecGetXid(record));
		}

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
}

/*
 * Handles XLOG_ZHEAP_UNUSED record type
 */
static void
zheap_xlog_unused(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_header	*xlundohdr;
	xl_zheap_unused *xlrec;
	UnpackedUndoRecord	undorecord;
	UndoRecPtr	urecptr;
	TransactionId	xid = XLogRecGetXid(record);
	uint32	xid_epoch = GetEpochForXid(xid);
	uint16	i, uncnt;
	Buffer		buffer;
	OffsetNumber *unused;
	Size		freespace = 0;
	RelFileNode rnode;
	BlockNumber blkno;
	XLogRedoAction action;

	xlundohdr = (xl_undo_header *) XLogRecGetData(record);
	xlrec = (xl_zheap_unused *) ((char *) xlundohdr + SizeOfUndoHeader);
	/* extract the information related to unused offsets */
	unused = (OffsetNumber *) ((char *) xlrec + SizeOfZHeapUnused);
	uncnt = xlrec->nunused;

	XLogRecGetBlockTag(record, 0, &rnode, NULL, &blkno);

	/*
	 * We're about to remove tuples. In Hot Standby mode, ensure that there's
	 * no queries running for which the removed tuples are still visible.
	 *
	 * Not all ZHEAP_UNUSED records remove tuples with xids, so we only want to
	 * conflict on the records that cause MVCC failures for user queries. If
	 * latestRemovedXid is invalid, skip conflict processing.
	 */
	if (InHotStandby && TransactionIdIsValid(xlrec->latestRemovedXid))
		ResolveRecoveryConflictWithSnapshot(xlrec->latestRemovedXid, rnode);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_ITEMID_UNUSED;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = xlundohdr->relfilenode;
	undorecord.uur_prevxid = xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = FirstCommandId;
	undorecord.uur_tsid = xlundohdr->tsid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = xlundohdr->blkprev;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = 0;
	undorecord.uur_tuple.len = 0;
	undorecord.uur_payload.len = uncnt * sizeof(OffsetNumber);
	undorecord.uur_payload.data = 
			(char *) palloc(uncnt * sizeof(OffsetNumber));
	memcpy(undorecord.uur_payload.data,
		   (char *) unused,
		   undorecord.uur_payload.len);

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERMANENT, xid, NULL);
	InsertPreparedUndo();

	/*
	 * undo should be inserted at same location as it was during the actual
	 * insert (DO operation).
	 */
	Assert (urecptr == xlundohdr->urec_ptr);

	/*
	 * If we have a full-page image, restore it (using a cleanup lock) and
	 * we're done.
	 */
	action = XLogReadBufferForRedoExtended(record, 0, RBM_NORMAL, true,
										   &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		Page		page = (Page) BufferGetPage(buffer);

		Assert(uncnt >= 0);

		for (i = 0; i < uncnt; i++)
		{
			ItemId		itemid;

			itemid = PageGetItemId(page, unused[i]);
			ItemIdSetUnusedExtended(itemid, xlrec->trans_slot_id);
		}

		PageSetUNDO(undorecord, buffer, xlrec->trans_slot_id, false, xid_epoch,
					xid, urecptr, NULL, 0);

		if (xlrec->flags & XLZ_UNUSED_ALLOW_PRUNING)
		{
			bool	pruned PG_USED_FOR_ASSERTS_ONLY = false;
			Page	tmppage = NULL;

			/*
			 * We prepare the temporary copy of the page so that during page
			 * repair fragmentation we can use it to copy the actual tuples.
			 * See comments atop zheap_page_prune_guts.
			 */
			tmppage = PageGetTempPageCopy(BufferGetPage(buffer));
			ZPageRepairFragmentation(buffer, tmppage, InvalidOffsetNumber,
									 0, &pruned);

			/*
			 * Pruning must be successful at redo time, otherwise the page
			 * contents on master and standby might differ.
			 */
			Assert(pruned);

			pfree(tmppage);
		}

		freespace = PageGetZHeapFreeSpace(page); /* needed to update FSM below */

		PageSetLSN(page, lsn);
		MarkBufferDirty(buffer);
	}

	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		/*
		 * We need to replay the record for TPD only when this record contains
		 * slot from TPD.
		 */
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			TPDPageSetUndo(buffer,
						   xlrec->trans_slot_id,
						   true,
						   xid_epoch,
						   xid,
						   urecptr,
						   unused,
						   uncnt);
			TPDPageSetLSN(BufferGetPage(buffer), lsn);
		}
	}

	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();

	/*
	 * Update the FSM as well.
	 *
	 * XXX: Don't do this if the page was restored from full page image. We
	 * don't bother to update the FSM in that case, it doesn't need to be
	 * totally accurate anyway.
	 */
	if (action == BLK_NEEDS_REDO)
		XLogRecordPageWithFreeSpace(rnode, blkno, freespace);
}

/*
 * Replay XLOG_ZHEAP_VISIBLE record.
 */
static void
zheap_xlog_visible(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_zheap_visible *xlrec = (xl_zheap_visible *) XLogRecGetData(record);
	Buffer		vmbuffer = InvalidBuffer;
	RelFileNode rnode;

	XLogRecGetBlockTag(record, 0, &rnode, NULL, NULL);

	/*
	 * If there are any Hot Standby transactions running that have an xmin
	 * horizon old enough that this page isn't all-visible for them, they
	 * might incorrectly decide that an index-only scan can skip a zheap fetch.
	 *
	 * NB: It might be better to throw some kind of "soft" conflict here that
	 * forces any index-only scan that is in flight to perform zheap fetches,
	 * rather than killing the transaction outright.
	 */
	if (InHotStandby)
		ResolveRecoveryConflictWithSnapshot(xlrec->cutoff_xid, rnode);

	if (XLogReadBufferForRedoExtended(record, 0, RBM_ZERO_ON_ERROR, false,
									  &vmbuffer) == BLK_NEEDS_REDO)
	{
		Page		vmpage = BufferGetPage(vmbuffer);
		Relation	reln;
		BlockNumber blkno = xlrec->heapBlk;;

		/* initialize the page if it was read as zeros */
		if (PageIsNew(vmpage))
			PageInit(vmpage, BLCKSZ, 0);

		/*
		 * XLogReadBufferForRedoExtended locked the buffer. But
		 * visibilitymap_set will handle locking itself.
		 */
		LockBuffer(vmbuffer, BUFFER_LOCK_UNLOCK);

		reln = CreateFakeRelcacheEntry(rnode);
		visibilitymap_pin(reln, blkno, &vmbuffer);

		/*
		 * Don't set the bit if replay has already passed this point.
		 *
		 * It might be safe to do this unconditionally; if replay has passed
		 * this point, we'll replay at least as far this time as we did
		 * before, and if this bit needs to be cleared, the record responsible
		 * for doing so should be again replayed, and clear it.  For right
		 * now, out of an abundance of conservatism, we use the same test here
		 * we did for the zheap page.  If this results in a dropped bit, no
		 * real harm is done; and the next VACUUM will fix it.
		 */
		if (lsn > PageGetLSN(vmpage))
			visibilitymap_set(reln, blkno, InvalidBuffer, lsn, vmbuffer,
							  xlrec->cutoff_xid, xlrec->flags);

		ReleaseBuffer(vmbuffer);
		FreeFakeRelcacheEntry(reln);
	}
	else if (BufferIsValid(vmbuffer))
		UnlockReleaseBuffer(vmbuffer);
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
		case XLOG_ZHEAP_CLEAN:
			zheap_xlog_clean(record);
			break;
		default:
			elog(PANIC, "zheap_redo: unknown op code %u", info);
	}
}

void
zheap2_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info & XLOG_ZHEAP_OPMASK)
	{
		case XLOG_ZHEAP_CONFIRM:
			zheap_xlog_confirm(record);
			break;
		case XLOG_ZHEAP_UNUSED:
			zheap_xlog_unused(record);
			break;
		case XLOG_ZHEAP_VISIBLE:
			zheap_xlog_visible(record);
			break;
		default:
			elog(PANIC, "zheap2_redo: unknown op code %u", info);
	}
}
