/*-------------------------------------------------------------------------
 *
 * undoworker.h
 *	  interfaces for the undo apply launcher and undo apply workes
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoworker.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UNDOWORKER_H
#define UNDOWORKER_H

/* Maximum possible number of undo workers. */
#define MAX_UNDO_WORKER_LIMIT 1024

/* GUCs. */
extern int undo_naptime;
extern int max_undo_workers;

/* Prototypes. */
extern Size UndoWorkerShmemSize(void);
extern void UndoWorkerShmemInit(void);
extern void RegisterUndoLauncher(void);
extern void UndoLauncherMain(Datum main_arg);
extern void UndoWorkerMain(Datum main_arg);
extern void DisturbUndoLauncherHibernation(void);

#endif
