
/*-------------------------------------------------------------------------
 *
 * undotest.h
 *	  undo test api definitions.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undotest.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UNDOTEST_H
#define UNDOTEST_H

#include "access/undoaccess.h"
#include "storage/block.h"

#define XLOG_UNDOTEST_OPMASK 0xF0
#define XLOG_UNDOTEST_INSERT 0x00

typedef enum undorectype
{
	UNDOTEST_INSERT
} undorectype;

typedef struct xl_undotest_insert
{
	UndoRecPtr	undo_ptr;
	BlockNumber	blockno;
	OffsetNumber	offset;
	Oid	dbid;
	Oid	reloid;
} xl_undotest_insert;

#define SizeOfUndoTestInsert	(offsetof(xl_undotest_insert, reloid) + sizeof(Oid))

extern void undotest_insert(Oid reloid, BlockNumber blkno, OffsetNumber offset,
							int per_level);
extern void undotest_undo_actions(int nrecords, UndoRecInfo *urp_array);
extern void undotest_redo(XLogReaderState *record);

extern void undotest_desc(StringInfo buf, XLogReaderState *record);
extern const char* undotest_identify(uint8 info);

#endif							/* UNDOTEST_H */
