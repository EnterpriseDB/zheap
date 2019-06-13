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

#include "access/transam.h"
#include "access/undoaccess.h"
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

extern PGDLLIMPORT int	rollback_overflow_size;
extern PGDLLIMPORT int	pending_undo_queue_size;

/*
 * Current status of the undo request in the hash table.
 */
typedef enum
{
	/*
	 * Request is present in the rollback hash table, but not present in any
	 * of the queues.  In this state, the undo actions can't be executed.
	 *
	 * The request will be marked with this status if a) discard worker finds
	 * that there is no space in the undo worker queue for inserting the undo
	 * request, b) there is an error while backend or undo worker is
	 * executing undo actions and there is no space in the error queue.
	 *
	 * Later when the discard worker finds such entry and if there is a
	 * sufficient space in the undo worker queues, then the request will be
	 * added to them and the status will be changed to UNDO_REQUEST_INQUEUE.
	 *
	 * It is important to keep the request in hash table with this status
	 * intsead of removing it to compute the value of
	 * oldestXidHavingUnappliedUndo.  If we don't do that, then the
	 * corresponding xid won't be considered for computation of
	 * oldestXidHavingUnappliedUndo.
	 */
	UNDO_REQUEST_INVALID,

	/*
	 * When backend or discard worker push the request to undo worker queue the
	 * status will be set to this.  Undo workers pulls such requests from the
	 * queues, change the state as UNDO_REQUEST_INPROGRESS and process the undo
	 * actions.
	 */
	UNDO_REQUEST_INQUEUE,

	/*
	 * Undo action execution is in progress either by backend or by undo worker.
	 */
	UNDO_REQUEST_INPROGRESS
} UndoRequestStatus;

/*
 * UndoRequestIsValid
 *		True iff undo request status is not invalid.
 */
#define UndoRequestIsValid(rh) \
	((bool) ((rh->status) != UNDO_REQUEST_INVALID))

 /*
  * UndoRequestIsInProgress
  *		True iff undo request status is in progress.
  */
#define UndoRequestIsInProgress(rh) \
	((bool) ((rh->status) == UNDO_REQUEST_INPROGRESS))

/*
 * UndoRequestIsInQueue
 *		True iff undo request status is in queue.
 */
#define UndoRequestIsInQueue(rh) \
	((bool) ((rh->status) == UNDO_REQUEST_INQUEUE))

/* This is the data structure for each hash table entry for rollbacks. */
typedef struct RollbackHashEntry
{
	FullTransactionId full_xid; /* must be first entry */
	UndoRecPtr	start_urec_ptr;
	UndoRecPtr	end_urec_ptr;
	UndoRecPtr	last_log_start_urec_ptr;
	Oid			dbid;
	UndoRequestStatus	status;	/* current state of the entry. */
} RollbackHashEntry;

/*
 * This is the data structure for each hash table key for rollbacks.  We need
 * to keep start_urec_ptr as a key element because in the same transaction,
 * there could be rollback requests for both logged and unlogged relations.
 */
typedef struct RollbackHashKey
{
	FullTransactionId full_xid;
	UndoRecPtr	start_urec_ptr;
} RollbackHashKey;

/* This is an entry for undo request queue that is sorted by xid. */
typedef struct UndoXidQueue
{
	FullTransactionId full_xid;
	UndoRecPtr	start_urec_ptr;
	Oid			dbid;
} UndoXidQueue;

/* This is an entry for undo request queue that is sorted by size. */
typedef struct UndoSizeQueue
{
	FullTransactionId full_xid;
	UndoRecPtr	start_urec_ptr;
	Oid			dbid;
	uint64		request_size;
} UndoSizeQueue;

/*
 * This is an entry for undo request queue that is sorted by time at which an
 * error has occurred.
 */
typedef struct UndoErrorQueue
{
	FullTransactionId full_xid;
	UndoRecPtr	start_urec_ptr;
	Oid			dbid;
	TimestampTz next_retry_at;
	TimestampTz err_occurred_at;
} UndoErrorQueue;

/* undo request information */
typedef struct UndoRequestInfo
{
	FullTransactionId full_xid;
	UndoRecPtr	start_urec_ptr;
	UndoRecPtr	end_urec_ptr;
	UndoRecPtr	last_log_start_urec_ptr;
	Oid			dbid;
	uint64		request_size;
	UndoWorkerQueueType undo_worker_queue;
} UndoRequestInfo;

/* Reset the undo request info */
#define ResetUndoRequestInfo(urinfo) \
( \
	(urinfo)->full_xid = InvalidFullTransactionId, \
	(urinfo)->start_urec_ptr = InvalidUndoRecPtr, \
	(urinfo)->end_urec_ptr = InvalidUndoRecPtr, \
	(urinfo)->last_log_start_urec_ptr = InvalidUndoRecPtr, \
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
	urinfo->last_log_start_urec_ptr = rh->last_log_start_urec_ptr, \
	urinfo->dbid = rh->dbid, \
	urinfo->undo_worker_queue = cur_queue \
)

/*
 * From an undo log if all the undo actions have been applied for a particular
 * transaction, we set the uur_progress of the transaction's log in that undo
 * log as MaxBlockNumber.  If none of the undo actions have yet been applied,
 * we set it to InvalidBlockNumber.
 */
#define XACT_APPLY_PROGRESS_COMPLETED MaxBlockNumber
#define XACT_APPLY_PROGRESS_NOT_STARTED InvalidBlockNumber

#define IsXactApplyProgressCompleted(uur_progress) \
	(uur_progress == XACT_APPLY_PROGRESS_COMPLETED)

#define IsXactApplyProgressNotStarted(uur_progress) \
	(uur_progress == XACT_APPLY_PROGRESS_NOT_STARTED)

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
extern uint64 FindUndoEndLocationAndSize(UndoRecPtr start_urecptr,
							UndoRecPtr *end_urecptr_out,
							UndoRecPtr *last_log_start_urecptr_out,
							FullTransactionId full_xid);
extern bool RegisterRollbackReq(UndoRecPtr end_urec_ptr, UndoRecPtr start_urec_ptr,
					Oid dbid, FullTransactionId full_xid);
extern void RollbackHTRemoveEntry(FullTransactionId full_xid, UndoRecPtr start_urec_ptr);
extern bool RollbackHTIsFull(void);
extern int UndoRollbackHashTableSize(void);
extern void RollbackHTMarkEntryInvalid(FullTransactionId full_xid,
								UndoRecPtr start_urec_ptr);
extern UndoRecPtr RollbackHTGetLastLogStartUrp(FullTransactionId full_xid,
											   UndoRecPtr start_urec_ptr);
extern FullTransactionId RollbackHTGetOldestFullXid(FullTransactionId oldestXmin);

/* functions exposed from undoaction.c */
extern void execute_undo_actions(FullTransactionId full_xid, UndoRecPtr from_urecptr,
					 UndoRecPtr to_urecptr, bool nopartial);
extern bool execute_undo_actions_page(UndoRecInfo *urp_array, int first_idx,
						  int last_idx, Oid reloid, FullTransactionId full_xid,
						  BlockNumber blkno, bool blk_chain_complete);

#endif							/* _UNDOREQUEST_H */
