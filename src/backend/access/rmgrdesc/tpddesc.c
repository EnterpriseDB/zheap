/*-------------------------------------------------------------------------
 *
 * tpddesc.c
 *	  rmgr descriptor routines for access/undo/tpdxlog.c
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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

	info &= XLOG_TPD_OPMASK;
	if (info == XLOG_ALLOCATE_TPD_ENTRY)
	{
		xl_tpd_allocate_entry *xlrec = (xl_tpd_allocate_entry *) rec;

		appendStringInfo(buf, "prevblk %u nextblk %u offset %u",
						 xlrec->prevblk, xlrec->nextblk, xlrec->offnum);
	}
	else if (info == XLOG_TPD_FREE_PAGE)
	{
		xl_tpd_free_page *xlrec = (xl_tpd_free_page *) rec;

		appendStringInfo(buf, "prevblk %u nextblk %u",
						 xlrec->prevblkno, xlrec->nextblkno);
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
		case XLOG_ALLOCATE_TPD_ENTRY | XLOG_TPD_INIT_PAGE:
			id = "ALLOCATE TPD ENTRY+INIT";
			break;
		case XLOG_TPD_CLEAN:
			id = "TPD CLEAN";
			break;
		case XLOG_TPD_CLEAR_LOCATION:
			id = "TPD CLEAR LOCATION";
			break;
		case XLOG_INPLACE_UPDATE_TPD_ENTRY:
			id = "INPLACE UPDATE TPD ENTRY";
			break;
		case XLOG_TPD_FREE_PAGE:
			id = "TPD FREE PAGE";
			break;
		case XLOG_TPD_CLEAN_ALL_ENTRIES:
			id = "TPD CLEAN ALL ENTRIES";
			break;
	}

	return id;
}
