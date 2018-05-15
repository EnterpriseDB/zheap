/*-------------------------------------------------------------------------
 *
 * undolog_xlog.h
 *	  undo log access XLOG definitions.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
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
#define XLOG_UNDOLOG_META		0x50

/* Create a new undo log. */
typedef struct xl_undolog_create
{
	UndoLogNumber logno;
	Oid		tablespace;
	UndoPersistence persistence;
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
	Oid				dbid;
} xl_undolog_attach;

/* Discard space, and possibly destroy or recycle undo log segments. */
typedef struct xl_undolog_discard
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	UndoLogOffset end;
	TransactionId latestxid;	/* latest xid whose undolog are discarded. */
	bool		  entirely_discarded;
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
