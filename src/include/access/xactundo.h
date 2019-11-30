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
#include "access/xactundo.h"
#include "access/xlogdefs.h"
#include "access/xlogreader.h"
#include "datatype/timestamp.h"
#include "lib/stringinfo.h"

typedef struct XactUndoContext
{
	UndoPersistenceLevel plevel;
	StringInfoData data;
} XactUndoContext;

typedef struct UndoNode
{
	/*
	 * TODO: replace with actual serialization format - to unblock development,
	 * have an absolutely dumb format, for now.
	 */
	uint16		length;
	uint8		type;
	char	   *data;
} UndoNode;

/* initialization */
extern Size XactUndoShmemSize(void);
extern void XactUndoShmemInit(void);

/* undo insertion */
extern void StartupXactUndo(UndoCheckpointContext *ctx);
extern void CheckPointXactUndo(UndoCheckpointContext *ctx);

extern UndoRecPtr PrepareXactUndoData(XactUndoContext *ctx, char persistence,
									  UndoNode *undo_node);
extern void InsertXactUndoData(XactUndoContext *ctx, uint8 first_block_id);
extern void SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn);
extern void CleanupXactUndoInsertion(XactUndoContext *ctx);

/* undo re-insertion during recovery */
extern UndoRecPtr UndoXactReplay(XLogReaderState *xlog_record,
								 UndoNode *undo_node);

/* undo worker infrastructure */
extern long XactUndoWaitTime(TimestampTz now);
extern Oid InitializeBackgroundXactUndo(bool minimum_runtime_reached);
extern void FinishBackgroundXactUndo(void);

/* undo execution */
extern void PerformUndoActions(int nestingLevel);

/* transaction integration */
extern void AtCommit_XactUndo(void);
extern void AtAbort_XactUndo(bool *perform_foreground_undo);
extern void AtSubCommit_XactUndo(int level);
extern void AtSubAbort_XactUndo(int level, bool *perform_foreground_undo);
extern void AtProcExit_XactUndo(void);
extern void AtPrepare_XactUndo(void);
extern void PostPrepare_XactUndo(void);

#endif
