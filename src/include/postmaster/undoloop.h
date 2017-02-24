/*-------------------------------------------------------------------------
 *
 * undoloop.h
 *	  Exports from postmaster/undoloop.c.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 * src/include/postmaster/undoloop.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _UNDOLOOP_H
#define _UNDOLOOP_H

#include "access/undoinsert.h"

/* Remembers the last seen RecentGlobalXmin */
TransactionId latestRecentGlobalXmin;

/*
 * This function will read the undo records starting from the undo
 * from_urecptr till to_urecptr and if to_urecptr is invalid then till the
 * first undo location of transaction.  This also discards the buffers by
 * calling DropUndoBuffers for which undo log is removed.  This function
 * can be used by RollbackToSavePoint, by Rollback, by undoworker to complete
 * the work of errored out transactions or when there is an error in single
 * user mode.
 */
extern void execute_undo_actions(UndoRecPtr from_urecptr,
					UndoRecPtr to_urecptr);

/*
 * This function will be responsible to truncate the undo logs
 * for transactions that become all-visible after RecentGlobalXmin has
 * advanced (value is different than latestRecentGlobalXmin).  The easiest
 * way could be to traverse the undo log array that contains least transaction
 * id for that undo log and see if it precedes RecentGlobalXmin, then start
 * discarding the undo log for that transaction (moving the tail pointer of
 * undo log) till it finds the transaction which is not all-visible.  This also
 * discards the buffers by calling ForgetBuffer for which undo log is
 * removed.  This function can be invoked by undoworker or after commit in
 * single user mode.
 */
extern void	recover_undo_pages();

#endif   /* _UNDOLOOP_H */
