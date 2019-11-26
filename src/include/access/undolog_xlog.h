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

#include "access/undodefs.h"
#include "access/xlogreader.h"
#include "lib/stringinfo.h"

/* XLOG records */
#define XLOG_UNDOLOG_CREATE		0x00
#define XLOG_UNDOLOG_DISCARD	0x10
#define XLOG_UNDOLOG_TRUNCATE	0x20

/* Create a new undo log. */
typedef struct xl_undolog_create
{
	UndoLogNumber logno;
	Oid			tablespace;
	char		persistence;
} xl_undolog_create;

#define SizeOfUndologCreate \
	(offsetof(xl_undolog_create, persistence) + sizeof(persistence))

/* Discard space, and possibly destroy or recycle undo log segments. */
typedef struct xl_undolog_discard
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	bool		  entirely_discarded;
} xl_undolog_discard;

#define SizeOfUndologDiscard \
	(offsetof(xl_undolog_discard, entirely_discarded) + sizeof(bool))

/* Adjust the size of an undo log, once it is determined to be full. */
typedef struct xl_undolog_truncate
{
	UndoLogNumber logno;
	UndoLogOffset size;
} xl_undolog_truncate;

#define SizeOfUndologTruncate sizeof(xl_undolog_truncate)

extern void undolog_desc(StringInfo buf,XLogReaderState *record);
extern void undolog_redo(XLogReaderState *record);
extern const char *undolog_identify(uint8 info);

#endif
