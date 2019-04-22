/*-------------------------------------------------------------------------
 *
 * undoworker.h
 *	  Exports from undoworker.c.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoworker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _UNDOWORKER_H
#define _UNDOWORKER_H

/* GUC options */
/* undo worker sleep time between rounds */
extern int	UndoWorkerDelay;

extern Size UndoLauncherShmemSize(void);
extern void UndoLauncherShmemInit(void);
extern void UndoLauncherRegister(void);
extern void UndoLauncherMain(Datum main_arg);
extern void UndoWorkerMain(Datum main_arg) pg_attribute_noreturn();
extern void WakeupUndoWorker(Oid dbid);

#endif							/* _UNDOWORKER_H */
