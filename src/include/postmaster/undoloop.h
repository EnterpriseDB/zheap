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
#include "utils/hsearch.h"
#include "utils/relcache.h"


/* Various options while executing the undo actions for the page. */
#define UNDO_ACTION_UPDATE_TPD		0x0001

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
			UndoRecPtr to_urecptr, bool nopartial, bool rewind, bool rellock);
extern void process_and_execute_undo_actions_page(UndoRecPtr from_urecptr,
							Relation rel, Buffer buffer, uint32 epoch,
							TransactionId xid, int slot_no);

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

/*
 * To increase the efficiency of the zheap system, we create a hash table for
 * the rollbacks. All the rollback requests exceeding certain threshold, are
 * pushed to this table. Undo worker starts reading the entries from this hash
 * table one at a time, performs undo actions related to the respective xid and
 * removes them from the hash table. This way backend is free from performing the
 * undo actions in case of heavy rollbacks. The data structures and the routines
 * required for this infrastructure are as follows.
 */

/* This is the data structure for each hash table entry for rollbacks. */
typedef struct RollbackHashEntry
{
	UndoRecPtr start_urec_ptr;
	UndoRecPtr end_urec_ptr;
	Oid		   dbid;
} RollbackHashEntry;

extern bool RollbackHTIsFull(void);

/* To push the rollback requests from backend to the respective hash table */
extern bool PushRollbackReq(UndoRecPtr start_urec_ptr, UndoRecPtr end_urec_ptr,
							Oid dbid);

/* To perform the undo actions reading from the hash table */
extern void RollbackFromHT(Oid dbid);

extern HTAB *RollbackHTGetDBList(MemoryContext tmpctx);
extern bool ConditionTransactionUndoActionLock(TransactionId xid);
extern void TransactionUndoActionLockRelease(TransactionId xid);
#endif   /* _UNDOLOOP_H */
