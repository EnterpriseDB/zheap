/*-------------------------------------------------------------------------
 *
 * xactundo.h
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/xactundo.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef XACTUNDO_H
#define XACTUNDO_H

#include "access/undodefs.h"
#include "access/xlogdefs.h"
#include "lib/stringinfo.h"

typedef struct XactUndoContext
{
	char	persistence;
	StringInfoData data;
} XactUndoContext;

typedef struct UndoNode
{
	// XXX replace this with magic stuff from Andres
	int	dummy;
} UndoNode;

extern UndoRecPtr PrepareXactUndoData(XactUndoContext *ctx, char persistence,
									  UndoNode *undo_node);
extern void InsertXactUndoData(XactUndoContext *ctx, uint8 first_block_id);
extern void SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn);
extern void CleanupXactUndoInsertion(XactUndoContext *ctx);

#endif
