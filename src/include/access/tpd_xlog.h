/*-------------------------------------------------------------------------
 *
 * tpd_xlog.h
 *	  POSTGRES tpd XLOG definitions.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/tpd_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TPD_XLOG_H
#define TPD_XLOG_H

#include "postgres.h"

#include "access/xlogreader.h"
#include "lib/stringinfo.h"
#include "storage/off.h"

/*
 * WAL record definitions for tpd.c's WAL operations
 */
#define XLOG_ALLOCATE_TPD_ENTRY			0x00

#define	XLOG_TPD_OPMASK				0x70

/*
 * When we insert 1st tpd entry on new page during reserve slot, we can (and
 * we do) restore entire page in redo.
 */
#define XLOG_TPD_INIT_PAGE				0x80

/* This is what we need to know about tpd entry allocation */
typedef struct xl_tpd_allocate_entry
{
	/* tpd entry related info */
	BlockNumber	prevblk;
	BlockNumber	nextblk;
	uint16 offset;		/* inserted entry's offset */

	/* TPD entry data in backup block 0 */
} xl_tpd_allocate_entry;

#define SizeOfTPDAllocateEntry	(offsetof(xl_tpd_allocate_entry, offset) + sizeof(uint16))

extern void tpd_redo(XLogReaderState *record);
extern void tpd_desc(StringInfo buf, XLogReaderState *record);
extern const char *tpd_identify(uint8 info);

#endif   /* TPD_XLOG_H */
