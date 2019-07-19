/*-------------------------------------------------------------------------
 *
 * undoactiondesc.c
 *	  rmgr descriptor routines for access/undo/undoactionxlog.c
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/undoactiondesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/undotest.h"

void
undotest_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_UNDOTEST_INSERT)
	{
		xl_undotest_insert *xlrec = (xl_undotest_insert *) rec;

		appendStringInfo(buf, "urec_ptr %lu", xlrec->undo_ptr);
	}
}

const char *
undotest_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_UNDOTEST_INSERT:
			id = "UNDO_TEST_INSERT";
			break;
	}

	return id;
}
