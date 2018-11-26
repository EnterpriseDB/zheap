/*-------------------------------------------------------------------------
 *
 * undoaction_xlog.h
 *	  undo action XLOG definitions
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoaction_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOACTION_XLOG_H
#define UNDOACTION_XLOG_H

#include "access/undolog.h"
#include "access/xlogreader.h"
#include "lib/stringinfo.h"
#include "storage/off.h"

/*
 * WAL record definitions for undoactions.c's WAL operations
 */
#define XLOG_UNDO_PAGE				0x00
#define XLOG_UNDO_RESET_SLOT		0x10

/*
 * xl_undoaction_page flag values, 8 bits are available.
 */
#define XLU_PAGE_CONTAINS_TPD_SLOT			(1<<0)

/* This is what we need to know about delete */
typedef struct xl_undoaction_page
{
	UndoRecPtr	urec_ptr;
	TransactionId	xid;
	int			trans_slot_id;	/* transaction slot id */
} xl_undoaction_page;

#define SizeOfUndoActionPage	(offsetof(xl_undoaction_page, trans_slot_id) + sizeof(int))

/*
 * xl_undoaction_reset_slot flag values, 8 bits are available.
 */
#define XLU_RESET_CONTAINS_TPD_SLOT			(1<<0)

/* This is what we need to know about delete */
typedef struct xl_undoaction_reset_slot
{
	UndoRecPtr	urec_ptr;
	int			trans_slot_id;	/* transaction slot id */
	uint8		flags;
} xl_undoaction_reset_slot;

#define SizeOfUndoActionResetSlot	(offsetof(xl_undoaction_reset_slot, flags) + sizeof(uint8))

extern void undoaction_redo(XLogReaderState *record);
extern void undoaction_desc(StringInfo buf, XLogReaderState *record);
extern const char *undoaction_identify(uint8 info);

#endif   /* UNDOACTION_XLOG_H */
