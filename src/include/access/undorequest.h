/*-------------------------------------------------------------------------
 *
 * undorequest.h
 *	  Exports from undo/undorequest.c.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 *
 * src/include/access/undorequest.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _UNDOREQUEST_H
#define _UNDOREQUEST_H

#include "access/undoinsert.h"
#include "datatype/timestamp.h"
#include "utils/relcache.h"


/* different types of undo worker */
typedef enum
{
	XID_QUEUE = 0,
	SIZE_QUEUE = 1,
	ERROR_QUEUE
} UndoWorkerQueueType;

#define InvalidUndoWorkerQueue -1

/* Remembers the last seen RecentGlobalXmin */
TransactionId latestRecentGlobalXmin;

/* This is the data structure for each hash table entry for rollbacks. */
typedef struct RollbackHashEntry
{
	FullTransactionId		full_xid; /* must be first entry */
	UndoRecPtr	start_urec_ptr;
	UndoRecPtr	end_urec_ptr;
	Oid			dbid;
	bool		in_progress;	/* indicates that undo actions are being processed */
} RollbackHashEntry;

/* This is the data structure for each hash table key for rollbacks. */
typedef struct RollbackHashKey
{
	FullTransactionId		full_xid;
	UndoRecPtr	start_urec_ptr;
} RollbackHashKey;

/* This is an entry for undo request queue that is sorted by xid. */
typedef struct UndoXidQueue
{
	FullTransactionId			full_xid;
	UndoRecPtr		start_urec_ptr;
	Oid				dbid;
} UndoXidQueue;

/* This is an entry for undo request queue that is sorted by size. */
typedef struct UndoSizeQueue
{
	FullTransactionId			full_xid;
	UndoRecPtr		start_urec_ptr;
	Oid				dbid;
	uint64			request_size;
} UndoSizeQueue;

/*
 * This is an entry for undo request queue that is sorted by time at which an
 * error has occurred.
 */
typedef struct UndoErrorQueue
{
	FullTransactionId			full_xid;
	UndoRecPtr		start_urec_ptr;
	Oid				dbid;
	TimestampTz		err_occurred_at;
} UndoErrorQueue;

/* undo record information */
typedef struct UndoRecInfo
{
	int			index;			/* Index of the element to make qsort stable. */
	UndoRecPtr	urp;			/* undo recptr (undo record location). */
	UnpackedUndoRecord *uur;	/* actual undo record. */
} UndoRecInfo;

/* undo request information */
typedef struct UndoRequestInfo
{
	FullTransactionId				full_xid;
	UndoRecPtr			start_urec_ptr;
	UndoRecPtr			end_urec_ptr;
	Oid					dbid;
	uint64			request_size;
	UndoWorkerQueueType undo_worker_queue;
} UndoRequestInfo;

/* Reset the undo request info */
#define ResetUndoRequestInfo(urinfo) \
( \
	(urinfo)->full_xid = InvalidFullTransactionId, \
	(urinfo)->start_urec_ptr = InvalidUndoRecPtr, \
	(urinfo)->end_urec_ptr = InvalidUndoRecPtr, \
	(urinfo)->dbid = InvalidOid, \
	(urinfo)->request_size = 0, \
	(urinfo)->undo_worker_queue = InvalidUndoWorkerQueue \
)

/* set the undo request info from the rollback request */
#define SetUndoRequestInfoFromRHEntry(urinfo, rh, cur_queue) \
( \
	urinfo->full_xid = rh->full_xid, \
	urinfo->start_urec_ptr = rh->start_urec_ptr, \
	urinfo->end_urec_ptr = rh->end_urec_ptr, \
	urinfo->dbid = rh->dbid, \
	urinfo->undo_worker_queue = cur_queue \
)

/* Exposed functions for rollback request queues. */
extern int	PendingUndoShmemSize(void);
extern void PendingUndoShmemInit(void);
extern bool UndoWorkerQueuesEmpty(void);
extern void InsertRequestIntoUndoQueues(UndoRequestInfo *urinfo);
extern bool InsertRequestIntoErrorUndoQueue(volatile UndoRequestInfo *urinfo);
extern void SetUndoWorkerQueueStart(UndoWorkerQueueType undo_worker_queue);
extern bool UndoGetWork(bool allow_peek, bool is_undo_launcher,
						UndoRequestInfo *urinfo, bool *in_other_db);
/* Exposed functions for rollback hash table. */
extern bool RegisterRollbackReq(UndoRecPtr end_urec_ptr, UndoRecPtr start_urec_ptr,
				Oid dbid, FullTransactionId full_xid);
extern void RollbackHTRemoveEntry(FullTransactionId full_xid, UndoRecPtr start_urec_ptr);
extern bool RollbackHTIsFull(void);
extern void RollbackHTCleanup(Oid dbid);

/* functions exposed from undoaction.c */
extern UndoRecInfo *UndoRecordBulkFetch(UndoRecPtr *from_urecptr,
					UndoRecPtr to_urecptr, int undo_apply_size,
					int *nrecords, bool one_page);
extern void execute_undo_actions(FullTransactionId full_xid, UndoRecPtr from_urecptr,
					UndoRecPtr to_urecptr, bool nopartial, bool rewind, bool rellock);
extern bool execute_undo_actions_page(UndoRecInfo *urp_array, int first_idx,
						  int last_idx, Oid reloid, FullTransactionId full_xid,
						  BlockNumber blkno, bool blk_chain_complete);

#endif							/* _UNDOREQUEST_H */
