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
		xl_zheap_insert *xlrec = (xl_zheap_insert *) rec;

		appendStringInfo(buf, "off %u, cid %u, blkprev %lu", xlrec->offnum, xlrec->cid, xlrec->blkprev);
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
	}

	return id;
}
