/*-------------------------------------------------------------------------
 *
 * undologdesc.c
 *	  rmgr descriptor routines for access/undo/undolog.c
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/undologdesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/undolog.h"
#include "access/undolog_xlog.h"

void
undolog_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_UNDOLOG_CREATE)
	{
		xl_undolog_create *xlrec = (xl_undolog_create *) rec;

		appendStringInfo(buf, "logno %u", xlrec->logno);
	}
	else if (info == XLOG_UNDOLOG_DISCARD)
	{
		xl_undolog_discard *xlrec = (xl_undolog_discard *) rec;

		appendStringInfo(buf, "logno %u " "discard " UndoLogOffsetFormat,
						 xlrec->logno, xlrec->discard);
	}
	else if (info == XLOG_UNDOLOG_MARK_FULL)
	{
		xl_undolog_mark_full *xlrec = (xl_undolog_mark_full *) rec;

		appendStringInfo(buf, "logno %u full " UndoLogOffsetFormat,
						 xlrec->logno,
						 xlrec->full);
	}
}

const char *
undolog_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_UNDOLOG_CREATE:
			id = "CREATE";
			break;
		case XLOG_UNDOLOG_DISCARD:
			id = "DISCARD";
			break;
		case XLOG_UNDOLOG_MARK_FULL:
			id = "MARK_FULL";
			break;
	}

	return id;
}
