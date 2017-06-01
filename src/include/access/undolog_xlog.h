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
	UndoLogOffset capacity;
} xl_undolog_extend;

/* Record the undo log number used for a transaction. */
typedef struct xl_undolog_attach
{
	TransactionId xid;
	UndoLogNumber logno;
	UndoLogOffset insert;
	UndoRecordSize last_size;
} xl_undolog_attach;

extern void undolog_desc(StringInfo buf,XLogReaderState *record);
extern const char *undolog_identify(uint8 info);

#endif
