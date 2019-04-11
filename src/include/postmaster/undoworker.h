/*-------------------------------------------------------------------------
 *
 * undoworker.h
 *	  Exports from postmaster/undoworker.c.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/postmaster/undoworker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _UNDOWORKER_H
#define _UNDOWORKER_H

/* GUC options */
/* undo worker sleep time between rounds */
extern int	UndoWorkerDelay;

/*
 * This function will perform multiple actions based on need. (a) retreive
 * transaction and its corresponding undopoiter from shared memory queue and
 * call undoloop to perform undo actions.  After applying all the undo records
 * for a particular transaction, it will increment the tail pointer in undo log.
 * (b) it needs to retrieve transactions which have become all-visible and truncate
 * the associated undo logs or will increment the tail pointer. (c) udjust the
 * number of undo workers based on the work required to perform undo actions
 * (it could be size of shared memory queue containing transactions that needs
 * aborts). (d) drop the buffers corresponding to truncated pages (e) Sleep for
 * UndoWorkerDelay, if there is no more work.
 */
extern void UndoWorkerMain(Datum main_arg) pg_attribute_noreturn();
extern void UndoLauncherRegister(void);
extern void UndoLauncherShmemInit(void);
extern Size UndoLauncherShmemSize(void);
extern void UndoLauncherMain(Datum main_arg);
extern void UndoWorkerMain(Datum main_arg);

#endif   /* _UNDOWORKER_H */
