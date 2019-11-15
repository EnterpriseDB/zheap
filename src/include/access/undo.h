/*-------------------------------------------------------------------------
 *
 * undo.h
 *	  common undo code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undo.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UNDO_H
#define UNDO_H

#include "access/undodefs.h"
#include "access/xlogdefs.h"
#include "utils/palloc.h"

/* Shared memory initialization. */
extern Size UndoShmemSize(void);
extern void UndoShmemInit(void);

/* Checkpoint/startup process interfaces. */
extern void StartupUndo(XLogRecPtr checkPointRedo);
extern void CheckPointUndo(XLogRecPtr checkPointRedo,
						   XLogRecPtr priorCheckPointRedo);
extern void ReadUndoCheckpointData(UndoCheckpointContext *ctx,
								   void *buffer, Size nbytes);
extern void WriteUndoCheckpointData(UndoCheckpointContext *ctx,
									void *buffer, Size nbytes);

/* Initialization for normal backends. */
extern void InitializeUndo(void);

/* Context for undo-related data. */
extern MemoryContext UndoContext;

#endif
