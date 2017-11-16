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
	if (info == XLOG_ZHEAP_INSERT)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_insert *xlrec = (xl_zheap_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, blkprev %lu", xlrec->offnum, xlundohdr->blkprev);
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
}

const char *
zheap_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
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
	}

	return id;
}
