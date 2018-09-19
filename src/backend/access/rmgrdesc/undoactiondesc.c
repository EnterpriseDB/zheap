/*-------------------------------------------------------------------------
 *
 * undoactiondesc.c
 *	  rmgr descriptor routines for access/undo/undoactionxlog.c
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/undoactiondesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/undoaction_xlog.h"

void
undoaction_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_UNDO_PAGE)
	{
		uint8	*flags = (uint8 *) rec;

		appendStringInfo(buf, "page_contains_tpd_slot: %c ",
						 (*flags & XLU_PAGE_CONTAINS_TPD_SLOT) ? 'T' : 'F');
		appendStringInfo(buf, "is_page_initialized: %c ",
						 (*flags & XLU_INIT_PAGE) ? 'T' : 'F');
		if (*flags & XLU_PAGE_CONTAINS_TPD_SLOT)
		{
			xl_undoaction_page *xlrec =
						(xl_undoaction_page *) ((char *) flags + sizeof(uint8));

			appendStringInfo(buf, "urec_ptr %lu xid %u trans_slot_id %u",
							 xlrec->urec_ptr, xlrec->xid, xlrec->trans_slot_id);
		}
	}
	else if (info == XLOG_UNDO_RESET_SLOT)
	{
		xl_undoaction_reset_slot *xlrec = (xl_undoaction_reset_slot *) rec;

		appendStringInfo(buf, "urec_ptr %lu trans_slot_id %u",
						 xlrec->urec_ptr, xlrec->trans_slot_id);
	}
}

const char *
undoaction_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_UNDO_PAGE:
			id = "UNDO PAGE";
			break;
		case XLOG_UNDO_RESET_SLOT:
			id = "UNDO RESET SLOT";
			break;
	}

	return id;
}
