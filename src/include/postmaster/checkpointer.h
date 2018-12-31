/*-------------------------------------------------------------------------
 *
 * checkpointer.h
 *	  Exports from postmaster/checkpointer.c.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 *
 * src/include/postmaster/checkpointer.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CHECKPOINTER_H
#define CHECKPOINTER_H

#include "common/relpath.h"
#include "storage/block.h"
#include "storage/relfilenode.h"

/* GUC options */
extern int	CheckPointTimeout;
extern int	CheckPointWarning;
extern double CheckPointCompletionTarget;

extern void CheckpointerMain(void) pg_attribute_noreturn();
extern bool ForwardFsyncRequest(int type, RelFileNode rnode,
								ForkNumber forknum, BlockNumber segno);
extern void RequestCheckpoint(int flags);
extern void CheckpointWriteDelay(int flags, double progress);

extern void AbsorbFsyncRequests(void);
extern void AbsorbAllFsyncRequests(void);

extern Size CheckpointerShmemSize(void);
extern void CheckpointerShmemInit(void);

extern bool FirstCallSinceLastCheckpoint(void);
extern void CountBackendWrite(void);

#endif
