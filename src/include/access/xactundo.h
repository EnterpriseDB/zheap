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
	UndoPersistenceLevel plevel;
	StringInfoData data;
} XactUndoContext;

typedef struct UndoNode
{
	// XXX replace this with magic stuff from Andres
	int	dummy;
} UndoNode;

extern Size XactUndoShmemSize(void);
extern void XactUndoShmemInit(void);

extern void StartupXactUndo(UndoCheckpointContext *ctx);
extern void CheckPointXactUndo(UndoCheckpointContext *ctx);

extern UndoRecPtr PrepareXactUndoData(XactUndoContext *ctx, char persistence,
									  UndoNode *undo_node);
extern void InsertXactUndoData(XactUndoContext *ctx, uint8 first_block_id);
extern void SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn);
extern void CleanupXactUndoInsertion(XactUndoContext *ctx);

extern Oid InitializeBackgroundXactUndo(bool minimum_runtime_reached);
extern void FinishBackgroundUndo(void);

extern void PerformUndoActions(int nestingLevel);

extern void AtCommit_XactUndo(void);
extern void AtAbort_XactUndo(bool *perform_foreground_undo);
extern void AtSubCommit_XactUndo(int level);
extern void AtSubAbort_XactUndo(int level, bool *perform_foreground_undo);
extern void AtProcExit_XactUndo(void);

/* XXX what about prepare? */

#endif
