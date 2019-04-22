/*-------------------------------------------------------------------------
 *
 * tpd_xlog.h
 *	  POSTGRES tpd XLOG definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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
#define XLOG_TPD_CLEAN					0x10
#define XLOG_TPD_CLEAR_LOCATION			0x20
#define XLOG_INPLACE_UPDATE_TPD_ENTRY	0x30
#define XLOG_TPD_FREE_PAGE				0x40
#define	XLOG_TPD_CLEAN_ALL_ENTRIES		0x50

#define	XLOG_TPD_OPMASK				0x70

/*
 * When we insert 1st tpd entry on new page during reserve slot, we can (and
 * we do) restore entire page in redo.
 */
#define XLOG_TPD_INIT_PAGE				0x80

#define XLOG_OLD_TPD_BUF_EQ_LAST_TPD_BUF	0x01

/* This is what we need to know about tpd entry allocation */
typedef struct xl_tpd_allocate_entry
{
	/* tpd entry related info */
	BlockNumber prevblk;
	BlockNumber nextblk;
	OffsetNumber offnum;		/* inserted entry's offset */

	uint8		flags;
	/* TPD entry data in backup block 0 */
} xl_tpd_allocate_entry;

#define SizeOfTPDAllocateEntry	(offsetof(xl_tpd_allocate_entry, flags) + sizeof(uint8))

/* This is what we need to know about tpd entry cleanup */
#define XL_TPD_CONTAINS_OFFSET			(1<<0)

typedef struct xl_tpd_clean
{
	uint8		flags;
} xl_tpd_clean;

#define SizeOfTPDClean	(offsetof(xl_tpd_clean, flags) + sizeof(uint8))

/* This is what we need to know about tpd free page */

typedef struct xl_tpd_free_page
{
	BlockNumber prevblkno;
	BlockNumber nextblkno;
} xl_tpd_free_page;

#define SizeOfTPDFreePage	(offsetof(xl_tpd_free_page, nextblkno) + sizeof(BlockNumber))

extern void tpd_redo(XLogReaderState *record);
extern void tpd_desc(StringInfo buf, XLogReaderState *record);
extern const char *tpd_identify(uint8 info);

#endif							/* TPD_XLOG_H */
