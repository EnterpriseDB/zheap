/*-------------------------------------------------------------------------
 *
 * undoactionxlog.c
 *	  WAL replay logic for undo actions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/undo/undoactionxlog.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/undoaction_xlog.h"
#include "access/visibilitymap.h"
#include "access/xlog.h"
#include "access/xlogutils.h"
#include "access/zheap.h"

#if 0
static void
undo_xlog_insert(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undo_insert *xlrec = (xl_undo_insert *) XLogRecGetData(record);
	Buffer		buffer;
	Page		page;
	ItemId		lp;
	XLogRedoAction action;

	action = XLogReadBufferForRedo(record, 0, &buffer);
	if (action == BLK_NEEDS_REDO)
	{
		page = BufferGetPage(buffer);

		lp = PageGetItemId(page, xlrec->offnum);
		if (xlrec->relhasindex)
		{
			ItemIdSetDead(lp);
		}
		else
		{
			ItemIdSetUnused(lp);
			/* Set hint bit for ZPageAddItem */
			/*PageSetHasFreeLinePointers(page);*/
		}

		PageSetLSN(BufferGetPage(buffer), lsn);
		MarkBufferDirty(buffer);
	}
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);
}
#endif

/*
 * replay of undo page operation
 */
static void
undo_xlog_page(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	Buffer	buf;
	xl_undoaction_page	*xlrec = NULL;
	char	*offsetmap = NULL,
			*data = NULL;
	XLogRedoAction action;
	uint8	*flags = (uint8 *) XLogRecGetData(record);

	if (*flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
		*flags & XLU_CONTAINS_TPD_OFFSET_MAP)
	{
		data = (char *) flags + sizeof(uint8);
		if (*flags & XLU_PAGE_CONTAINS_TPD_SLOT)
		{
			xlrec = (xl_undoaction_page *) data;
			data += sizeof(xl_undoaction_page);
		}
		if (*flags & XLU_CONTAINS_TPD_OFFSET_MAP)
			offsetmap = data;
	}

	if (XLogReadBufferForRedo(record, 0, &buf) != BLK_RESTORED)
		elog(ERROR, "Undo page record did not contain a full-page image");

	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		uint32	xid_epoch = 0;

		/*
		 * We need to replay the record for TPD only when this record contains
		 * slot from TPD.
		 */
		Assert(*flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
			   *flags & XLU_CONTAINS_TPD_OFFSET_MAP);
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			if (*flags & XLU_PAGE_CONTAINS_TPD_SLOT)
			{
				if (TransactionIdIsValid(xlrec->xid))
					xid_epoch = GetEpochForXid(xlrec->xid);
				TPDPageSetTransactionSlotInfo(buf, xlrec->trans_slot_id,
											  xid_epoch,
											  xlrec->xid, xlrec->urec_ptr);
			}

			if (offsetmap)
				TPDPageSetOffsetMap(buf, offsetmap);

			TPDPageSetLSN(BufferGetPage(buf), lsn);
		}
	}

	if (*flags & XLU_PAGE_CLEAR_VISIBILITY_MAP)
	{
		Relation	reln;
		Buffer		vmbuffer = InvalidBuffer;
		RelFileNode target_node;
		BlockNumber blkno;

		XLogRecGetBlockTag(record, 0, &target_node, NULL, &blkno);
		reln = CreateFakeRelcacheEntry(target_node);
		visibilitymap_pin(reln, blkno, &vmbuffer);
		visibilitymap_clear(reln, blkno, vmbuffer, VISIBILITYMAP_VALID_BITS);
		ReleaseBuffer(vmbuffer);
		FreeFakeRelcacheEntry(reln);
	}

	/*
	 * Reset Page only at the end if asked, page level flag
	 * PD_PAGE_HAS_TPD_SLOT and TPD slot are needed before that TPD routines.
	 */
	if (*flags & XLU_INIT_PAGE)
		ZheapInitPage(BufferGetPage(buf), (Size) BLCKSZ);

	UnlockReleaseBuffer(buf);
	UnlockReleaseTPDBuffers();
}

/*
 * replay of undo reset slot operation
 */
static void
undo_xlog_reset_xid(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	xl_undoaction_reset_slot	*xlrec = (xl_undoaction_reset_slot *) XLogRecGetData(record);
	Buffer		buf;
	XLogRedoAction action;

	action = XLogReadBufferForRedo(record, 0, &buf);

	/*
	 * Reseting the TPD slot is handled separately so only handle the page
	 * slot here.
	 */
	if (action == BLK_NEEDS_REDO &&
		xlrec->trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS)
	{
		Page	page;
		ZHeapPageOpaque	opaque;
		int		slot_no = xlrec->trans_slot_id;

		page = BufferGetPage(buf);
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

		opaque->transinfo[slot_no - 1].xid_epoch = 0;
		opaque->transinfo[slot_no - 1].xid = InvalidTransactionId;
		opaque->transinfo[slot_no - 1].urec_ptr = xlrec->urec_ptr;

		PageSetLSN(page, lsn);
		MarkBufferDirty(buf);
	}

	/* replay the record for tpd buffer */
	if (XLogRecHasBlockRef(record, 1))
	{
		Assert(xlrec->flags & XLU_RESET_CONTAINS_TPD_SLOT);
		action = XLogReadTPDBuffer(record, 1);
		if (action == BLK_NEEDS_REDO)
		{
			TPDPageSetTransactionSlotInfo(buf, xlrec->trans_slot_id,
										  0, InvalidTransactionId,
										  xlrec->urec_ptr);
			TPDPageSetLSN(BufferGetPage(buf), lsn);
		}
	}

	if (BufferIsValid(buf))
		UnlockReleaseBuffer(buf);
	UnlockReleaseTPDBuffers();
}

/*
 * Replay of undo apply progress.
 */
static void
undo_xlog_apply_progress(XLogReaderState *record)
{
	xl_undoapply_progress	*xlrec = (xl_undoapply_progress *) XLogRecGetData(record);

	/* Update the progress in the transaction header. */
	PrepareUpdateUndoActionProgress(record, xlrec->urec_ptr, xlrec->progress);
	UndoRecordUpdateTransInfo(0);
	UnlockReleaseUndoBuffers();
}

void
undoaction_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info)
	{
		case XLOG_UNDO_PAGE:
			undo_xlog_page(record);
			break;
		case XLOG_UNDO_RESET_SLOT:
			undo_xlog_reset_xid(record);
			break;
		case XLOG_UNDO_APPLY_PROGRESS:
			undo_xlog_apply_progress(record);
			break;
		default:
			elog(PANIC, "undoaction_redo: unknown op code %u", info);
	}
}
