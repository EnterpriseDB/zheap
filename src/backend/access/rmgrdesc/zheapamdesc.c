/*-------------------------------------------------------------------------
 *
 * zheapamdesc.c
 *	  rmgr descriptor routines for access/zheap/zheapamxlog.c
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/zheapamdesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/zheapam_xlog.h"

void
zheap_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	info &= XLOG_ZHEAP_OPMASK;
	if (info == XLOG_ZHEAP_CLEAN)
	{
		xl_zheap_clean *xlrec = (xl_zheap_clean *) rec;

		appendStringInfo(buf, "remxid %u", xlrec->latestRemovedXid);
	}
	else if (info == XLOG_ZHEAP_INSERT)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_insert *xlrec = (xl_zheap_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, blkprev %lu", xlrec->offnum, xlundohdr->blkprev);
	}
	else if(info == XLOG_ZHEAP_MULTI_INSERT)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_multi_insert *xlrec = (xl_zheap_multi_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "%d tuples", xlrec->ntuples);
	}
	else if (info == XLOG_ZHEAP_DELETE)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_delete *xlrec = (xl_zheap_delete *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, trans_slot %u, hasUndoTuple: %c, blkprev %lu",
						 xlrec->offnum, xlrec->trans_slot_id,
						 (xlrec->flags & XLZ_HAS_DELETE_UNDOTUPLE) ? 'T' : 'F',
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_UPDATE)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_update *xlrec = (xl_zheap_update *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "oldoff %u, trans_slot %u, hasUndoTuple: %c, newoff: %u, blkprev %lu",
						 xlrec->old_offnum, xlrec->old_trans_slot_id,
						 (xlrec->flags & XLZ_HAS_UPDATE_UNDOTUPLE) ? 'T' : 'F',
						 xlrec->new_offnum,
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_FREEZE_XACT_SLOT)
	{
		xl_zheap_freeze_xact_slot *xlrec = (xl_zheap_freeze_xact_slot *) rec;

		appendStringInfo(buf, "latest frozen xid %u nfrozen %u",
						 xlrec->lastestFrozenXid, xlrec->nFrozen);
	}
	else if (info == XLOG_ZHEAP_INVALID_XACT_SLOT)
	{
		xl_zheap_invalid_xact_slot *xlrec = (xl_zheap_invalid_xact_slot *) rec;

		appendStringInfo(buf, "completed_slots %u", xlrec->nCompletedSlots);
	}
	else if (info == XLOG_ZHEAP_LOCK)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_lock *xlrec = (xl_zheap_lock *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, xid %u, trans_slot_id %u",
						 xlrec->offnum, xlrec->prev_xid, xlrec->trans_slot_id);
	}
}

void
zheap2_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	info &= XLOG_ZHEAP_OPMASK;
	if (info == XLOG_ZHEAP_CONFIRM)
	{
		xl_zheap_confirm *xlrec = (xl_zheap_confirm *) rec;

		appendStringInfo(buf, "off %u: flags %u", xlrec->offnum, xlrec->flags);
	}
	else if (info == XLOG_ZHEAP_UNUSED)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_unused *xlrec = (xl_zheap_unused *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "remxid %u, trans_slot_id %u, blkprev %lu",
						 xlrec->latestRemovedXid, xlrec->trans_slot_id,
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_VISIBLE)
	{
		xl_zheap_visible *xlrec = (xl_zheap_visible *) rec;

		appendStringInfo(buf, "cutoff xid %u flags %d",
						 xlrec->cutoff_xid, xlrec->flags);
	}
}

const char *
zheap_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ZHEAP_CLEAN:
			id = "CLEAN";
			break;
		case XLOG_ZHEAP_INSERT:
			id = "INSERT";
			break;
		case XLOG_ZHEAP_INSERT | XLOG_ZHEAP_INIT_PAGE:
			id = "INSERT+INIT";
			break;
		case XLOG_ZHEAP_DELETE:
			id = "DELETE";
			break;
		case XLOG_ZHEAP_UPDATE:
			id = "UPDATE";
			break;
		case XLOG_ZHEAP_UPDATE | XLOG_ZHEAP_INIT_PAGE:
			id = "UPDATE+INIT";
			break;
		case XLOG_ZHEAP_FREEZE_XACT_SLOT:
			id = "FREEZE_XACT_SLOT";
			break;
		case XLOG_ZHEAP_INVALID_XACT_SLOT:
			id = "INVALID_XACT_SLOT";
			break;
		case XLOG_ZHEAP_LOCK:
			id = "LOCK";
			break;
		case XLOG_ZHEAP_MULTI_INSERT:
			id = "MULTI_INSERT";
			break;
		case XLOG_ZHEAP_MULTI_INSERT | XLOG_ZHEAP_INIT_PAGE:
			id = "MULTI_INSERT+INIT";
			break;
	}

	return id;
}

const char *
zheap2_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ZHEAP_CONFIRM:
			id = "CONFIRM";
			break;
		case XLOG_ZHEAP_UNUSED:
			id = "UNUSED";
			break;
		case XLOG_ZHEAP_VISIBLE:
			id = "VISIBLE";
			break;
	}

	return id;
}
