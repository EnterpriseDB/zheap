/*-------------------------------------------------------------------------
 *
 * tpddesc.c
 *	  rmgr descriptor routines for access/undo/tpdxlog.c
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/tpddesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd_xlog.h"

void
tpd_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_ALLOCATE_TPD_ENTRY)
	{
		xl_tpd_allocate_entry *xlrec = (xl_tpd_allocate_entry *) rec;

		appendStringInfo(buf, "prevblk %u nextblk %u offset %u",
						 xlrec->prevblk, xlrec->nextblk, xlrec->offnum);
	}
}

const char *
tpd_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ALLOCATE_TPD_ENTRY:
			id = "ALLOCATE TPD ENTRY";
			break;
		case XLOG_TPD_CLEAN:
			id = "TPD CLEAN";
			break;
		case XLOG_TPD_CLEAR_LOCATION:
			id = "TPD CLEAR LOCATION";
			break;
	}

	return id;
}
