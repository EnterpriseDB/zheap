/*-------------------------------------------------------------------------
 *
 * undolog_xlog.h
 *	  undo log access XLOG definitions.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
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
#define XLOG_UNDOLOG_EXTEND		0x10
#define XLOG_UNDOLOG_ATTACH		0x20
#define XLOG_UNDOLOG_DISCARD	0x30
#define XLOG_UNDOLOG_REWIND		0x40

/* Create a new undo log. */
typedef struct xl_undolog_create
{
	UndoLogNumber logno;
	Oid		tablespace;
} xl_undolog_create;

/* Extend an undo log by adding a new segment. */
typedef struct xl_undolog_extend
{
	UndoLogNumber logno;
	UndoLogOffset end;
} xl_undolog_extend;

/* Record the undo log number used for a transaction. */
typedef struct xl_undolog_attach
{
	TransactionId xid;
	UndoLogNumber logno;
	UndoLogOffset insert;
	UndoLogOffset last_xact_start;

	/*
	 * last undo record's length. We need to WAL log so that the first undo
	 * record after the restart can get this value properly.  This will be used
	 * going to the previous record of the transaction during rollback. In case
	 * the transaction have done some operation before checkpoint and remaining
	 * after checkpoint in such case if we can't get the previous record
	 * prevlen which which before checkpoint we can not properly rollback.
	 * And, undo worker is also fetch this value when rolling back the last
	 * transaction in the undo log for locating the last undo record of the
	 * transaction.
	 */
	uint16		  prevlen;
	bool		  is_first_rec;
} xl_undolog_attach;

/* Discard space, and possibly destroy or recycle undo log segments. */
typedef struct xl_undolog_discard
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	UndoLogOffset end;
	TransactionId latestxid;	/* latest xid whose undolog are discarded. */
} xl_undolog_discard;

/* Rewind insert location of the undo log. */
typedef struct xl_undolog_rewind
{
	UndoLogNumber logno;
	UndoLogOffset insert;
	uint16		  prevlen;
} xl_undolog_rewind;

extern void undolog_desc(StringInfo buf,XLogReaderState *record);
extern const char *undolog_identify(uint8 info);

#endif
