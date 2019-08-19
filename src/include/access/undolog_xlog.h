/*-------------------------------------------------------------------------
 *
 * undolog_xlog.h
 *	  undo log access XLOG definitions.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undolog_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOLOG_XLOG_H
#define UNDOLOG_XLOG_H

#include "access/undolog.h"
#include "access/xlogreader.h"
#include "lib/stringinfo.h"

/* XLOG records */
#define XLOG_UNDOLOG_CREATE		0x00
#define XLOG_UNDOLOG_DISCARD	0x10
#define XLOG_UNDOLOG_SWITCH		0x20
#define XLOG_UNDOLOG_MARK_FULL	0x30

/* Create a new undo log. */
typedef struct xl_undolog_create
{
	UndoLogNumber logno;
	Oid		tablespace;
	UndoLogCategory category;
} xl_undolog_create;

#define SizeOfUndologCreate \
	(offsetof(xl_undolog_create, category) + sizeof(UndoLogCategory))

/* Discard space, and possibly destroy or recycle undo log segments. */
typedef struct xl_undolog_discard
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	TransactionId latestxid;	/* latest xid whose undolog are discarded. */
	bool		  entirely_discarded;
} xl_undolog_discard;

#define SizeOfUndologDiscard \
	(offsetof(xl_undolog_discard, entirely_discarded) + sizeof(bool))

/* Switch undo log. */
typedef struct xl_undolog_switch
{
	UndoLogNumber logno;
	UndoRecPtr prevlog_xact_start;
	UndoRecPtr prevlog_last_urp;
} xl_undolog_switch;

#define SizeOfUndologSwitch \
	(offsetof(xl_undolog_switch, prevlog_last_urp) + sizeof(UndoRecPtr))

/* Mark an undo log as full. */
typedef struct xl_undolog_mark_full
{
	UndoLogNumber logno;
	UndoLogOffset full;
} xl_undolog_mark_full;

#define SizeOfUndologMarkFull sizeof(xl_undolog_mark_full)

extern void undolog_desc(StringInfo buf,XLogReaderState *record);
extern const char *undolog_identify(uint8 info);

#endif
