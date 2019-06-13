/*-------------------------------------------------------------------------
 *
 * undorequest.c
 *	  This contains routines to register and fetch undo action requests.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undorequest.c
 *
 * To increase the efficiency of the rollbacks, we create three queues and
 * a hash table for the rollback requests.  A Xid based priority queue which
 * will allow us to process the requests of older transactions and help us
 * to move oldesdXidHavingUndo forward.  A size-based queue which will help
 * us to perform the rollbacks of larger aborts in a timely fashion, so that
 * we don't get stuck while processing them during discard of the logs.
 * An error queue to hold the requests for transactions that failed to apply
 * its undo.  The rollback hash table is used to avoid duplicate undo requests
 * by backends and discard worker.  The table must be able to accommodate all
 * active undo requests.  The undo requests must appear in both xid and size
 * requests queues or neither.  As of now we, process the requests from these
 * queues in a round-robin fashion to give equal priority to all three type
 * of requests.
 *
 * The rollback requests exceeding a certain threshold are pushed into both
 * xid and size based queues.  They are also registered in the hash table.
 *
 * To ensure that backend and discard worker don't register the same request
 * in the hash table, we always register the request with full_xid and the
 * start pointer for the transaction in the hash table as key.  Backends
 * always remember the value of start pointer, but discard worker doesn't know
 * the actual start value in case transaction's undo spans across multiple
 * logs.  The reason for the same is that discard worker might encounter the
 * log which has overflowed undo records of the transaction first.  In such
 * cases, we need to compute the actual start position.  The first record of a
 * transaction in each undo log contains a reference to the first record of
 * this transaction in the previous log.  By following the previous log chain
 * of this transaction, we find the initial location which is used to register
 * the request.
 *
 * To process the request, we get the request from one of the queues, search
 * it in hash table and mark it as in-progress and then remove from the
 * respective queue.  Once we process all the actions, the request is removed
 * from the hash table.  If the worker found the request in the queue, but
 * the request is not present in hash table or is marked as in-progress, then
 * it can ignore such a request (and remove it from that queue) as it must
 * have been already processed or is being processed.
 *
 * Also note that, if the work queues are full, then we put backpressure on
 * backends to complete the requests by themselves.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "miscadmin.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/transam.h"
#include "access/undorequest.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "lib/binaryheap.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"
#include "storage/procarray.h"
#include "utils/fmgroids.h"
#include "access/xlog.h"
#include "storage/proc.h"

#define	MAX_UNDO_WORK_QUEUES	3
#define UNDO_PEEK_DEPTH		10
#define UNDO_FAILURE_RETRY_DELAY_MS 10000

int			rollback_overflow_size = 64;
int			pending_undo_queue_size = 1024;

/* Each worker queue is a binary heap. */
typedef struct
{
	binaryheap *bh;
	union
	{
		UndoXidQueue *xid_elems;
		UndoSizeQueue *size_elems;
		UndoErrorQueue *error_elems;
	}			q_choice;
} UndoWorkerQueue;

/* This is the hash table to store all the rollabck requests. */
static HTAB *RollbackHT;
static UndoWorkerQueue UndoWorkerQueues[MAX_UNDO_WORK_QUEUES];

static uint32 cur_undo_queue = 0;

/* Different operations for XID queue */
#define InitXidQueue(bh, elems) \
( \
	UndoWorkerQueues[XID_QUEUE].bh = bh, \
	UndoWorkerQueues[XID_QUEUE].q_choice.xid_elems = elems \
)

#define XidQueueIsEmpty() \
	(binaryheap_empty(UndoWorkerQueues[XID_QUEUE].bh))

#define GetXidQueueSize() \
	(binaryheap_cur_size(UndoWorkerQueues[XID_QUEUE].bh))

#define GetXidQueueElem(elem) \
	(UndoWorkerQueues[XID_QUEUE].q_choice.xid_elems[elem])

#define GetXidQueueTopElem() \
( \
	AssertMacro(!binaryheap_empty(UndoWorkerQueues[XID_QUEUE].bh)), \
	DatumGetPointer(binaryheap_first(UndoWorkerQueues[XID_QUEUE].bh)) \
)

#define GetXidQueueNthElem(n) \
( \
	AssertMacro(!XidQueueIsEmpty()), \
	DatumGetPointer(binaryheap_nth(UndoWorkerQueues[XID_QUEUE].bh, n)) \
)

#define SetXidQueueElem(elem, e_dbid, e_full_xid, e_start_urec_ptr) \
( \
	GetXidQueueElem(elem).dbid = e_dbid, \
	GetXidQueueElem(elem).full_xid = e_full_xid, \
	GetXidQueueElem(elem).start_urec_ptr = e_start_urec_ptr \
)

/* Different operations for SIZE queue */
#define InitSizeQueue(bh, elems) \
( \
	UndoWorkerQueues[SIZE_QUEUE].bh = bh, \
	UndoWorkerQueues[SIZE_QUEUE].q_choice.size_elems = elems \
)

#define SizeQueueIsEmpty() \
	(binaryheap_empty(UndoWorkerQueues[SIZE_QUEUE].bh))

#define GetSizeQueueSize() \
	(binaryheap_cur_size(UndoWorkerQueues[SIZE_QUEUE].bh))

#define GetSizeQueueElem(elem) \
	(UndoWorkerQueues[SIZE_QUEUE].q_choice.size_elems[elem])

#define GetSizeQueueTopElem() \
( \
	AssertMacro(!SizeQueueIsEmpty()), \
	DatumGetPointer(binaryheap_first(UndoWorkerQueues[SIZE_QUEUE].bh)) \
)

#define GetSizeQueueNthElem(n) \
( \
	AssertMacro(!SizeQueueIsEmpty()), \
	DatumGetPointer(binaryheap_nth(UndoWorkerQueues[SIZE_QUEUE].bh, n)) \
)

#define SetSizeQueueElem(elem, e_dbid, e_full_xid, e_size, e_start_urec_ptr) \
( \
	GetSizeQueueElem(elem).dbid = e_dbid, \
	GetSizeQueueElem(elem).full_xid = e_full_xid, \
	GetSizeQueueElem(elem).request_size = e_size, \
	GetSizeQueueElem(elem).start_urec_ptr = e_start_urec_ptr \
)

/* Different operations for Error queue */
#define InitErrorQueue(bh, elems) \
( \
	UndoWorkerQueues[ERROR_QUEUE].bh = bh, \
	UndoWorkerQueues[ERROR_QUEUE].q_choice.error_elems = elems \
)

#define ErrorQueueIsEmpty() \
	(binaryheap_empty(UndoWorkerQueues[ERROR_QUEUE].bh))

#define GetErrorQueueSize() \
	(binaryheap_cur_size(UndoWorkerQueues[ERROR_QUEUE].bh))

#define GetErrorQueueElem(elem) \
	(UndoWorkerQueues[ERROR_QUEUE].q_choice.error_elems[elem])

#define GetErrorQueueTopElem() \
( \
	AssertMacro(!binaryheap_empty(UndoWorkerQueues[ERROR_QUEUE].bh)), \
	DatumGetPointer(binaryheap_first(UndoWorkerQueues[ERROR_QUEUE].bh)) \
)

#define GetErrorQueueNthElem(n) \
( \
	AssertMacro(!ErrorQueueIsEmpty()), \
	DatumGetPointer(binaryheap_nth(UndoWorkerQueues[ERROR_QUEUE].bh, n)) \
)

#define SetErrorQueueElem(elem, e_dbid, e_full_xid, e_start_urec_ptr, e_retry_at, e_occurred_at) \
( \
	GetErrorQueueElem(elem).dbid = e_dbid, \
	GetErrorQueueElem(elem).full_xid = e_full_xid, \
	GetErrorQueueElem(elem).start_urec_ptr = e_start_urec_ptr, \
	GetErrorQueueElem(elem).next_retry_at = e_retry_at, \
	GetErrorQueueElem(elem).err_occurred_at = e_occurred_at \
)

/*
 * Binary heap comparison function to compare the age of transactions.
 */
static int
undo_age_comparator(Datum a, Datum b, void *arg)
{
	UndoXidQueue *xidQueueElem1 = (UndoXidQueue *) DatumGetPointer(a);
	UndoXidQueue *xidQueueElem2 = (UndoXidQueue *) DatumGetPointer(b);

	if (FullTransactionIdPrecedes(xidQueueElem1->full_xid,
								  xidQueueElem2->full_xid))
		return 1;
	else if (FullTransactionIdFollows(xidQueueElem1->full_xid,
									  xidQueueElem2->full_xid))
		return -1;
	return 0;
}

/*
 * Binary heap comparison function to compare the size of transactions.
 */
static int
undo_size_comparator(Datum a, Datum b, void *arg)
{
	UndoSizeQueue *sizeQueueElem1 = (UndoSizeQueue *) DatumGetPointer(a);
	UndoSizeQueue *sizeQueueElem2 = (UndoSizeQueue *) DatumGetPointer(b);

	if (sizeQueueElem1->request_size > sizeQueueElem2->request_size)
		return 1;
	else if (sizeQueueElem1->request_size < sizeQueueElem2->request_size)
		return -1;
	return 0;
}

/*
 * Binary heap comparison function to compare the time at which an error
 * occurred for transactions.
 *
 * The error queue is sorted by next_retry_at and err_occurred_at.  Currently,
 * the next_retry_at has some constant delay time (see PushErrorQueueElem), so
 * it doesn't make much sense to sort by both values.  However, in future, if
 * we have some different algorithm for next_retry_at, then it will work
 * seamlessly.
 */
static int
undo_err_time_comparator(Datum a, Datum b, void *arg)
{
	UndoErrorQueue *errQueueElem1 = (UndoErrorQueue *) DatumGetPointer(a);
	UndoErrorQueue *errQueueElem2 = (UndoErrorQueue *) DatumGetPointer(b);

	if (errQueueElem1->next_retry_at < errQueueElem2->next_retry_at)
		return 1;
	else if (errQueueElem1->next_retry_at > errQueueElem2->next_retry_at)
		return -1;
	if (errQueueElem1->err_occurred_at < errQueueElem2->err_occurred_at)
		return 1;
	else if (errQueueElem1->err_occurred_at > errQueueElem2->err_occurred_at)
		return -1;
	return 0;
}

/* Returns the size of xid based queue. */
static int
UndoXidQueueElemsShmSize(void)
{
	return mul_size(pending_undo_queue_size, sizeof(UndoXidQueue));
}

/* Returns the size of rollback request size based queue. */
static int
UndoSizeQueueElemsShmSize(void)
{
	return mul_size(pending_undo_queue_size, sizeof(UndoSizeQueue));
}

/* Returns the size of error queue. */
static int
UndoErrorQueueElemsShmSize(void)
{
	return mul_size(pending_undo_queue_size, sizeof(UndoErrorQueue));
}

/* Returns the size of rollback hash table. */
int
UndoRollbackHashTableSize()
{
	/*
	 * The rollback hash table is used to avoid duplicate undo requests by
	 * backends and discard worker.  The table must be able to accomodate all
	 * active undo requests.  The undo requests must appear in both xid and
	 * size requests queues or neither.  In same transaction, there can be two
	 * requests one for logged relations and another for unlogged relations.
	 * So, the rollback hash table size should be equal to two request queues,
	 * an error queue (currently this is same as request queue) and max
	 * backends. This will ensure that it won't get filled.
	 */
	return ((2 * pending_undo_queue_size) + pending_undo_queue_size +
			MaxBackends);
}

/* Get the first free element of xid based request array. */
static int
UndoXidQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < pending_undo_queue_size; i++)
	{
		if (FullTransactionIdEquals(GetXidQueueElem(i).full_xid,
									InvalidFullTransactionId))
			return i;
	}

	/* we should never call this function when the request queue is full. */
	Assert(false);

	/* silence compiler. */
	return -1;
}

/* Push an element in the xid based request queue. */
static void
PushXidQueueElem(UndoRequestInfo * urinfo)
{
	int			elem = UndoXidQueueGetFreeElem();

	SetXidQueueElem(elem, urinfo->dbid, urinfo->full_xid,
					urinfo->start_urec_ptr);

	binaryheap_add(UndoWorkerQueues[XID_QUEUE].bh,
				   PointerGetDatum(&GetXidQueueElem(elem)));
}

/* Pop nth element from the xid based request queue. */
static UndoXidQueue *
PopXidQueueNthElem(int n)
{
	Datum		elem;

	Assert(!XidQueueIsEmpty());
	elem = binaryheap_remove_nth(UndoWorkerQueues[XID_QUEUE].bh, n);

	return (UndoXidQueue *) (DatumGetPointer(elem));
}

/* Get the first free element of size based request array. */
static int
UndoSizeQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < pending_undo_queue_size; i++)
	{
		if (FullTransactionIdEquals(GetSizeQueueElem(i).full_xid,
									InvalidFullTransactionId))
			return i;
	}

	/* we should never call this function when the request queue is full. */
	Assert(false);

	/* silence compiler. */
	return -1;
}

/*
 * Traverse the queue and remove dangling entries, if any.  The queue
 * entry is considered dangling if the hash table doesn't contain the
 * corresponding entry.
 */
static int
RemoveOldElemsFromXidQueue()
{
	int			nCleaned = 0;
	int			i = 0;

	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	while (i < GetXidQueueSize())
	{
		RollbackHashEntry *rh;
		RollbackHashKey hkey;
		UndoXidQueue *elem = (UndoXidQueue *) GetXidQueueNthElem(i);

		hkey.full_xid = elem->full_xid;
		hkey.start_urec_ptr = elem->start_urec_ptr;
		rh = (RollbackHashEntry *) hash_search(RollbackHT,
											   (void *) &hkey,
											   HASH_FIND, NULL);

		/*
		 * If some undo worker is already processing the rollback request or
		 * it is already processed, then we drop that request from the queue.
		 */
		if (!rh || UndoRequestIsInProgress(rh))
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			nCleaned++;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[XID_QUEUE].bh, i);

			continue;
		}

		/*
		 * The request that is present in any queue must be a valid request
		 * and its status must be in_queue.
		 */
		Assert(UndoRequestIsValid(rh));
		Assert(UndoRequestIsInQueue(rh));

		i++;
	}

	binaryheap_build(UndoWorkerQueues[XID_QUEUE].bh);

	return nCleaned;
}

/* Push an element in the size based request queue */
static void
PushSizeQueueElem(UndoRequestInfo * urinfo)
{
	int			elem = UndoSizeQueueGetFreeElem();

	SetSizeQueueElem(elem, urinfo->dbid, urinfo->full_xid,
					 urinfo->request_size, urinfo->start_urec_ptr);

	binaryheap_add(UndoWorkerQueues[SIZE_QUEUE].bh,
				   PointerGetDatum(&GetSizeQueueElem(elem)));
}

/* Pop nth element from the size based request queue */
static UndoSizeQueue *
PopSizeQueueNthElem(int n)
{
	Datum		elem;

	Assert(!binaryheap_empty(UndoWorkerQueues[SIZE_QUEUE].bh));
	elem = binaryheap_remove_nth(UndoWorkerQueues[SIZE_QUEUE].bh, n);

	return (UndoSizeQueue *) DatumGetPointer(elem);
}

/*
 * Traverse the queue and remove dangling entries, if any.  The queue
 * entry is considered dangling if the hash table doesn't contain the
 * corresponding entry.
 */
static int
RemoveOldElemsFromSizeQueue()
{
	int			nCleaned = 0;
	int			i = 0;

	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	while (i < GetSizeQueueSize())
	{
		RollbackHashEntry *rh;
		RollbackHashKey hkey;
		UndoSizeQueue *elem = (UndoSizeQueue *) GetSizeQueueNthElem(i);

		hkey.full_xid = elem->full_xid;
		hkey.start_urec_ptr = elem->start_urec_ptr;
		rh = (RollbackHashEntry *) hash_search(RollbackHT,
											   (void *) &hkey,
											   HASH_FIND, NULL);

		/*
		 * If some undo worker is already processing the rollback request or
		 * it is already processed, then we drop that request from the queue.
		 */
		if (!rh || UndoRequestIsInProgress(rh))
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			elem->request_size = 0;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[SIZE_QUEUE].bh, i);
			nCleaned++;
			continue;
		}

		/*
		 * The request that is present in any queue must be a valid request
		 * and its status must be in_queue.
		 */
		Assert(UndoRequestIsValid(rh));
		Assert(UndoRequestIsInQueue(rh));

		i++;
	}

	binaryheap_build(UndoWorkerQueues[SIZE_QUEUE].bh);

	return nCleaned;
}

/* Get the first free element of error time based request array. */
static int
UndoErrorQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < pending_undo_queue_size; i++)
	{
		if (FullTransactionIdEquals(GetErrorQueueElem(i).full_xid,
									InvalidFullTransactionId))
			return i;
	}

	/* we should never call this function when the request queue is full. */
	Assert(false);

	/* silence compiler. */
	return -1;
}

/* Push an element in the error time based request queue */
static void
PushErrorQueueElem(volatile UndoRequestInfo *urinfo)
{
	int			elem = UndoErrorQueueGetFreeElem();
	TimestampTz now = GetCurrentTimestamp();
	TimestampTz next_retry;

	/*
	 * We want to retry this error request after some constant amount of time,
	 * rather than retrying immediately, otherwise, in some cases (ex. when
	 * all the pending requests are failed requests) worker will keep retrying
	 * such errors constantly.
	 *
	 * In future, we might want some more sophisticated back-off algorithm
	 * to delay the execution of such requests.
	 */
	next_retry = TimestampTzPlusMilliseconds(now, UNDO_FAILURE_RETRY_DELAY_MS);
	SetErrorQueueElem(elem, urinfo->dbid, urinfo->full_xid,
					  urinfo->start_urec_ptr, next_retry, now);

	binaryheap_add(UndoWorkerQueues[ERROR_QUEUE].bh,
				   PointerGetDatum(&GetErrorQueueElem(elem)));
}

/* Pop nth element from the error time based request queue */
static UndoErrorQueue *
PopErrorQueueNthElem(int n)
{
	Datum		elem;

	Assert(!ErrorQueueIsEmpty());
	elem = binaryheap_remove_nth(UndoWorkerQueues[ERROR_QUEUE].bh, n);

	return (UndoErrorQueue *) (DatumGetPointer(elem));
}

/*
 * Traverse the queue and remove dangling entries, if any.  The queue
 * entry is considered dangling if the hash table doesn't contain the
 * corresponding entry.
 */
static int
RemoveOldElemsFromErrorQueue()
{
	int			nCleaned = 0;
	int			i = 0;

	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	while (i < GetErrorQueueSize())
	{
		RollbackHashEntry *rh;
		RollbackHashKey hkey;
		UndoErrorQueue *elem = (UndoErrorQueue *) GetErrorQueueNthElem(i);

		hkey.full_xid = elem->full_xid;
		hkey.start_urec_ptr = elem->start_urec_ptr;
		rh = (RollbackHashEntry *) hash_search(RollbackHT,
											   (void *) &hkey,
											   HASH_FIND, NULL);

		/*
		 * If some undo worker is already processing the rollback request or
		 * it is already processed, then we drop that request from the queue.
		 */
		if (!rh || UndoRequestIsInProgress(rh))
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			elem->next_retry_at = 0;
			elem->err_occurred_at = 0;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[ERROR_QUEUE].bh, i);
			nCleaned++;
			continue;
		}

		/*
		 * The request that is present in any queue must be a valid request
		 * and its status must be in_queue.
		 */
		Assert(UndoRequestIsValid(rh));
		Assert(UndoRequestIsInQueue(rh));

		i++;
	}

	binaryheap_build(UndoWorkerQueues[ERROR_QUEUE].bh);

	return nCleaned;
}

/*
 * Remove nth work item from queue and clear the array element as well from
 * the corresponding queue.
 */
static void
RemoveRequestFromQueue(UndoWorkerQueueType type, int n)
{
	if (type == XID_QUEUE)
	{
		UndoXidQueue *uXidQueueElem = (UndoXidQueue *) PopXidQueueNthElem(n);

		Assert(FullTransactionIdIsValid(uXidQueueElem->full_xid));
		uXidQueueElem->dbid = InvalidOid;
		uXidQueueElem->full_xid = InvalidFullTransactionId;
	}
	else if (type == SIZE_QUEUE)
	{
		UndoSizeQueue *uSizeQueueElem = (UndoSizeQueue *) PopSizeQueueNthElem(n);

		Assert(FullTransactionIdIsValid(uSizeQueueElem->full_xid));
		uSizeQueueElem->dbid = InvalidOid;
		uSizeQueueElem->full_xid = InvalidFullTransactionId;
		uSizeQueueElem->request_size = 0;
	}
	else
	{
		UndoErrorQueue *uErrorQueueElem = (UndoErrorQueue *) PopErrorQueueNthElem(n);

		Assert(type == ERROR_QUEUE);
		Assert(FullTransactionIdIsValid(uErrorQueueElem->full_xid));
		uErrorQueueElem->dbid = InvalidOid;
		uErrorQueueElem->full_xid = InvalidFullTransactionId;
		uErrorQueueElem->next_retry_at = 0;
		uErrorQueueElem->err_occurred_at = 0;
	}
}

/*
 * Returns true, if there is some valid request in the given queue, false,
 * otherwise.
 *
 * It fills hkey with hash key corresponding to the nth element of the
 * specified queue.
 */
static bool
GetRollbackHashKeyFromQueue(UndoWorkerQueueType cur_queue, int n,
							RollbackHashKey *hkey)
{
	if (cur_queue == XID_QUEUE)
	{
		UndoXidQueue *elem;

		/* check if there is a work in the next queue */
		if (GetXidQueueSize() <= n)
			return false;

		elem = (UndoXidQueue *) GetXidQueueNthElem(n);
		hkey->full_xid = elem->full_xid;
		hkey->start_urec_ptr = elem->start_urec_ptr;
	}
	else if (cur_queue == SIZE_QUEUE)
	{
		UndoSizeQueue *elem;

		/* check if there is a work in the next queue */
		if (GetSizeQueueSize() <= n)
			return false;

		elem = (UndoSizeQueue *) GetSizeQueueNthElem(n);
		hkey->full_xid = elem->full_xid;
		hkey->start_urec_ptr = elem->start_urec_ptr;
	}
	else
	{
		UndoErrorQueue *elem;

		/* It must be an error queue. */
		Assert(cur_queue == ERROR_QUEUE);

		/* check if there is a work in the next queue */
		if (GetErrorQueueSize() <= n)
			return false;

		elem = (UndoErrorQueue *) GetErrorQueueNthElem(n);

		/*
		 * If it is too early to try the error request again, then check the
		 * work in some other queue.
		 */
		if (GetCurrentTimestamp() < elem->next_retry_at)
			return false;

		hkey->full_xid = elem->full_xid;
		hkey->start_urec_ptr = elem->start_urec_ptr;
	}

	return true;
}

/*
 * Fetch the end urec pointer for the transaction and the undo request size.
 *
 * end_urecptr_out - This is an INOUT parameter. If end undo pointer is
 * specified, we use the same to calculate the size.  Else, we calculate
 * the end undo pointer and return the same.
 *
 * last_log_start_urec_ptr_out - This is an OUT parameter.  If a transaction
 * writes undo records in multiple undo logs, this is set to the start undo
 * record pointer of this transaction in the last log.  If the transaction
 * writes undo records only in single undo log, it is set to start_urec_ptr.
 * This value is used to update the rollback progress of the transaction in
 * the last log.  Once, we have start location in last log, the start location
 * in all the previous logs can be computed.  See execute_undo_actions for
 * more details.
 *
 * XXX: We don't calculate the exact undo size.  We always skip the size of
 * the last undo record (if not already discarded) from the calculation.  This
 * optimization allows us to skip fetching an undo record for the most
 * frequent cases where the end pointer and current start pointer belong to
 * the same log.  A simple subtraction between them gives us the size.  In
 * future this function can be modified if someone needs the exact undo size.
 * As of now, we use this function to calculate the undo size for inserting
 * in the pending undo actions in undo worker's size queue.
 */
uint64
FindUndoEndLocationAndSize(UndoRecPtr start_urecptr,
						   UndoRecPtr *end_urecptr_out,
						   UndoRecPtr *last_log_start_urecptr_out,
						   FullTransactionId full_xid)
{
	UnpackedUndoRecord *uur = NULL;
	UndoLogSlot *slot = NULL;
	UndoRecPtr	urecptr = start_urecptr;
	UndoRecPtr	end_urecptr = InvalidUndoRecPtr;
	UndoRecPtr	last_log_start_urecptr = InvalidUndoRecPtr;
	uint64		sz = 0;
	UndoLogCategory category;

	Assert(urecptr != InvalidUndoRecPtr);

	while (true)
	{
		UndoRecPtr	next_urecptr = InvalidUndoRecPtr;
		UndoLogOffset next_insert;
		UndoRecordFetchContext	context;

		if (*end_urecptr_out != InvalidUndoRecPtr)
		{
			/*
			 * Check whether end pointer and the current pointer belong to
			 * same log. In that case, we can get the size easily.
			 */
			if (UndoRecPtrGetLogNo(urecptr) == UndoRecPtrGetLogNo(*end_urecptr_out))
			{
				last_log_start_urecptr = urecptr;
				sz += (*end_urecptr_out - urecptr);
				break;
			}
		}

		/*
		 * Fetch the log and undo record corresponding to the current undo
		 * pointer.
		 */
		if ((slot == NULL) || (UndoRecPtrGetLogNo(urecptr) != slot->logno))
			slot = UndoLogGetSlot(UndoRecPtrGetLogNo(urecptr), false);

		Assert(slot != NULL);
		category = slot->meta.category;

		next_insert = UndoLogGetNextInsertPtr(slot->logno);

		/* The corresponding log must be ahead urecptr. */
		Assert(MakeUndoRecPtr(slot->logno, slot->meta.unlogged.insert) >= urecptr);

		/* Fetch the undo record. */
		BeginUndoFetch(&context);
		uur = UndoFetchRecord(&context, urecptr);
		FinishUndoFetch(&context);

		/*
		 * If the corresponding undo record got rolled back and discarded as
		 * well, we return from here.
		 */
		if (uur == NULL)
			break;

		/* The undo must belongs to a same transaction. */
		Assert(FullTransactionIdEquals(full_xid, uur->uur_fxid));

		/*
		 * Since this is the first undo record of this transaction in this
		 * log, this must include the transaction header.
		 */
		Assert(uur->uur_group != NULL);

		/*
		 * Case 1: Check whether any undo records have been applied from this
		 * log.  Else, we've to find the undo location till where the undo
		 * actions have been applied.
		 */
		if (!IsXactApplyProgressNotStarted(uur->uur_group->urec_progress))
		{
			/*
			 * If all the undo records in this log corresponding to this
			 * transaction, has been applied, we return from here.
			 */
			if (IsXactApplyProgressCompleted(uur->uur_group->urec_progress))
				break;

			/*
			 * Find the first undo record of uur_progress block number.  We'll
			 * set end_urec_ptr to this undo record.
			 */
			end_urecptr = UndoBlockGetFirstUndoRecord(uur->uur_group->urec_progress,
													  urecptr, category);

			/*
			 * Since rollbacks from this undo log are in-progress, all undo
			 * records from subsequent undo logs must have been applied.  Hence,
			 * this is the last log.  So, we set last_log_start_urecptr as the
			 * start undo record pointer of this transaction from current log.
			 */
			last_log_start_urecptr = urecptr;
			sz += (end_urecptr - urecptr);
			break;
		}

		next_urecptr = uur->uur_group->urec_next_group;

		/*
		 * Case 2: If this is the last transaction in the log then calculate
		 * the latest urec pointer using next insert location of the undo log.
		 *
		 * Even if some new undo got inserted after we have fetched this
		 * transactions undo record, still the next_insert location will give
		 * us the right point to compute end_urecptr.
		 */
		if (!UndoRecPtrIsValid(next_urecptr))
		{
			last_log_start_urecptr = urecptr;
			end_urecptr = UndoGetPrevUrp(NULL, next_insert, InvalidBuffer, category);
			sz += (end_urecptr - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}

		/*
		 * Case 3: The transaction ended in the same undo log, but this is not
		 * the last transaction.
		 */
		if (UndoRecPtrGetLogNo(next_urecptr) == slot->logno)
		{
			last_log_start_urecptr = urecptr;
			end_urecptr =
				UndoGetPrevUrp(NULL, next_urecptr, InvalidBuffer, category);
			sz += (end_urecptr - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}

		/*
		 * Case 4: If transaction is overflowed to a different undolog and
		 * it's already discarded.  It means that the undo actions for this
		 * transaction which are in the next log are already executed.
		 */
		if (UndoRecPtrIsDiscarded(next_urecptr))
		{
			UndoLogOffset next_insert;

			next_insert = UndoLogGetNextInsertPtr(slot->logno);
			Assert(UndoRecPtrIsValid(next_insert));

			last_log_start_urecptr = urecptr;
			end_urecptr = UndoGetPrevUrp(NULL, next_insert, InvalidBuffer, category);
			sz += (next_insert - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}

		/*
		 * Case 5: The transaction is overflowed to a different log, so
		 * restart the processing from then next log but before that consider
		 * this log for request size computation.
		 */
		{
			UndoLogOffset next_insert;

			next_insert = UndoLogGetNextInsertPtr(slot->logno);
			Assert(UndoRecPtrIsValid(next_insert));

			last_log_start_urecptr = urecptr;
			end_urecptr = UndoGetPrevUrp(NULL, next_insert, InvalidBuffer, category);
			sz += (next_insert - urecptr);

			UndoRecordRelease(uur);
			uur = NULL;
		}

		/* Follow the undo chain */
		urecptr = next_urecptr;
	}

	if (uur != NULL)
		UndoRecordRelease(uur);

	if (end_urecptr_out && (*end_urecptr_out == InvalidUndoRecPtr))
		*end_urecptr_out = end_urecptr;
	if (last_log_start_urecptr_out &&
		(*last_log_start_urecptr_out == InvalidUndoRecPtr))
		*last_log_start_urecptr_out = last_log_start_urecptr;

	return sz;
}

/*
 * Returns true, if we can push the rollback request to undo wrokers, false,
 * otherwise.
 */
static bool
CanPushReqToUndoWorker(UndoRecPtr start_urec_ptr, UndoRecPtr end_urec_ptr,
					   uint64 req_size)
{
	/*
	 * This must be called after acquring RollbackRequestLock as we will check
	 * the binary heaps which can change.
	 */
	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	/*
	 * We normally push the rollback request to undo workers if the size of
	 * same is above a certain threshold.
	 */
	if (req_size >= rollback_overflow_size * 1024 * 1024)
	{
		if (GetXidQueueSize() >= pending_undo_queue_size ||
			GetSizeQueueSize() >= pending_undo_queue_size)
		{
			/*
			 * If one of the queues is full traverse both the queues and
			 * remove dangling entries, if any.  The queue entry is considered
			 * dangling if the hash table doesn't contain the corresponding
			 * entry.  It can happen due to two reasons (a) we have processed
			 * the entry from one of the queues, but not from the other. (b)
			 * the corresponding database has been dropped due to which we
			 * have removed the entries from hash table, but not from the
			 * queues.  This is just a lazy cleanup, if we want we can remove
			 * the entries from the queues when we detect that the database is
			 * dropped and remove the corresponding entries from hash table.
			 */
			if (GetXidQueueSize() >= pending_undo_queue_size)
				RemoveOldElemsFromXidQueue();
			if (GetSizeQueueSize() >= pending_undo_queue_size)
				RemoveOldElemsFromSizeQueue();
		}

		if ((GetXidQueueSize() < pending_undo_queue_size))
		{
			Assert(GetSizeQueueSize() < pending_undo_queue_size);

			/*
			 * XXX - Here, we should return true once we have background
			 * worker facility.
			 */
			return false;
		}
	}

	return false;
}

/*
 * To return the size of the request queues and hash-table for rollbacks.
 */
int
PendingUndoShmemSize(void)
{
	Size		size;

	size = hash_estimate_size(UndoRollbackHashTableSize(), sizeof(RollbackHashEntry));
	size = add_size(size, mul_size(MAX_UNDO_WORK_QUEUES,
								   binaryheap_shmem_size(pending_undo_queue_size)));
	size = add_size(size, UndoXidQueueElemsShmSize());
	size = add_size(size, UndoSizeQueueElemsShmSize());
	size = add_size(size, UndoErrorQueueElemsShmSize());

	return size;
}

/*
 * Initialize the hash-table and priority heap based queues for rollback
 * requests in shared memory.
 */
void
PendingUndoShmemInit(void)
{
	HASHCTL		info;
	bool		foundXidQueue = false;
	bool		foundSizeQueue = false;
	bool		foundErrorQueue = false;
	binaryheap *bh;
	UndoXidQueue *xid_elems;
	UndoSizeQueue *size_elems;
	UndoErrorQueue *error_elems;

	MemSet(&info, 0, sizeof(info));

	info.keysize = sizeof(TransactionId) + sizeof(UndoRecPtr);
	info.entrysize = sizeof(RollbackHashEntry);
	info.hash = tag_hash;

	RollbackHT = ShmemInitHash("Undo Actions Lookup Table",
							   UndoRollbackHashTableSize(),
							   UndoRollbackHashTableSize(), &info,
							   HASH_ELEM | HASH_FUNCTION | HASH_FIXED_SIZE);

	bh = binaryheap_allocate_shm("Undo Xid Binary Heap",
								 pending_undo_queue_size,
								 undo_age_comparator,
								 NULL);

	xid_elems = (UndoXidQueue *) ShmemInitStruct("Undo Xid Queue Elements",
												 UndoXidQueueElemsShmSize(),
												 &foundXidQueue);

	Assert(foundXidQueue || !IsUnderPostmaster);

	if (!IsUnderPostmaster)
		memset(xid_elems, 0, sizeof(UndoXidQueue));

	InitXidQueue(bh, xid_elems);

	bh = binaryheap_allocate_shm("Undo Size Binary Heap",
								 pending_undo_queue_size,
								 undo_size_comparator,
								 NULL);
	size_elems = (UndoSizeQueue *) ShmemInitStruct("Undo Size Queue Elements",
												   UndoSizeQueueElemsShmSize(),
												   &foundSizeQueue);
	Assert(foundSizeQueue || !IsUnderPostmaster);

	if (!IsUnderPostmaster)
		memset(size_elems, 0, sizeof(UndoSizeQueue));

	InitSizeQueue(bh, size_elems);

	bh = binaryheap_allocate_shm("Undo Error Binary Heap",
								 pending_undo_queue_size,
								 undo_err_time_comparator,
								 NULL);

	error_elems = (UndoErrorQueue *) ShmemInitStruct("Undo Error Queue Elements",
													 UndoErrorQueueElemsShmSize(),
													 &foundErrorQueue);
	Assert(foundErrorQueue || !IsUnderPostmaster);

	if (!IsUnderPostmaster)
		memset(error_elems, 0, sizeof(UndoSizeQueue));

	InitErrorQueue(bh, error_elems);
}

/*
 * Returns true, if there is no pending undo apply work, false, otherwise.
 */
bool
UndoWorkerQueuesEmpty(void)
{
	if (XidQueueIsEmpty() && SizeQueueIsEmpty())
		return true;

	return false;
}

/* Insert the request in both xid and size based queues. */
void
InsertRequestIntoUndoQueues(UndoRequestInfo * urinfo)
{
	/*
	 * This must be called after acquring RollbackRequestLock as we will
	 * insert into the binary heaps which can change.
	 */
	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));
	PushXidQueueElem(urinfo);
	PushSizeQueueElem(urinfo);

	elog(DEBUG1, "Undo action pushed Xid: " UINT64_FORMAT ", Size: " UINT64_FORMAT ", "
		 "Start: " UndoRecPtrFormat ", End: " UndoRecPtrFormat "",
		 U64FromFullTransactionId(urinfo->full_xid), urinfo->request_size,
		 urinfo->start_urec_ptr, urinfo->end_urec_ptr);
}

/* Insert the request into an error queue. */
bool
InsertRequestIntoErrorUndoQueue(volatile UndoRequestInfo * urinfo)
{
	RollbackHashEntry *rh;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	/* We can't insert into an error queue if it is already full. */
	if (GetErrorQueueSize() >= pending_undo_queue_size)
	{
		int			num_removed = 0;

		/* Try to remove few elements */
		num_removed = RemoveOldElemsFromErrorQueue();

		if (num_removed == 0)
		{
			LWLockRelease(RollbackRequestLock);
			return false;
		}
	}

	/*
	 * Mark the undo request in hash table as UNDO_REQUEST_INQUEUE so that undo
	 * launcher or other undo worker can process this request.
	 */
	rh = (RollbackHashEntry *) hash_search(RollbackHT, (void *) &urinfo->full_xid,
										   HASH_FIND, NULL);
	rh->status = UNDO_REQUEST_INQUEUE;

	/* Insert the request into error queue for processing it later. */
	PushErrorQueueElem(urinfo);
	LWLockRelease(RollbackRequestLock);

	elog(DEBUG1, "Undo action pushed(error) Xid: " UINT64_FORMAT ", Size: " UINT64_FORMAT ", "
		 "Start: " UndoRecPtrFormat ", End: " UndoRecPtrFormat "",
		 U64FromFullTransactionId(urinfo->full_xid), urinfo->request_size,
		 urinfo->start_urec_ptr, urinfo->end_urec_ptr);

	return true;
}

/*
 * Set the undo worker queue from which the undo worker should start looking
 * for work.
 */
void
SetUndoWorkerQueueStart(UndoWorkerQueueType undo_worker_queue)
{
	cur_undo_queue = undo_worker_queue;
}

/*
 * Get the next set of pending rollback request for undo worker.
 *
 * allow_peek - if true, peeks a few element from each queue to check whether
 * any request matches current dbid.
 * remove_from_queue - if true, picks an element from the queue whose dbid
 * matches current dbid and remove it from the queue before returning the same
 * to caller.
 * urinfo - this is an OUT parameter that returns the details of undo request
 * whose undo action is still pending.
 * in_other_db_out - this is an OUT parameter.  If we've not found any work
 * for current database, but there is work for some other database, we set
 * this parameter as true.
 */
bool
UndoGetWork(bool allow_peek, bool remove_from_queue, UndoRequestInfo *urinfo,
			bool *in_other_db_out)
{
	int			i;
	bool		found_work = false;
	bool		in_other_db = false;

	/* Reset the undo request info */
	ResetUndoRequestInfo(urinfo);

	/* Search the queues under lock as they can be modified concurrently. */
	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	/* Here, we check each of the work queues in a round-robin way. */
	for (i = 0; i < MAX_UNDO_WORK_QUEUES; i++)
	{
		RollbackHashKey hkey;
		RollbackHashEntry *rh;
		int			cur_queue = (int) (cur_undo_queue % MAX_UNDO_WORK_QUEUES);

		if (!GetRollbackHashKeyFromQueue(cur_queue, 0, &hkey))
		{
			cur_undo_queue++;
			continue;
		}

		rh = (RollbackHashEntry *) hash_search(RollbackHT,
											   (void *) &hkey,
											   HASH_FIND, NULL);

		/*
		 * If some undo worker is already processing the rollback request or
		 * it is already processed, then we drop that request from the queue
		 * and fetch the next entry from the queue.
		 */
		if (!rh || UndoRequestIsInProgress(rh))
		{
			RemoveRequestFromQueue(cur_queue, 0);
			cur_undo_queue++;
			continue;
		}

		/*
		 * The request that is present in any queue must be a valid request
		 * and its status must be in_queue.
		 */
		Assert(UndoRequestIsValid(rh));
		Assert(UndoRequestIsInQueue(rh));

		found_work = true;

		/*
		 * We've found a work for some database.  If we don't want to remove
		 * the request, we return from here and spawn a worker process to
		 * apply the same.
		 */
		if (!remove_from_queue)
		{
			bool		exists;

			StartTransactionCommand();
			exists = dbid_exists(rh->dbid);
			CommitTransactionCommand();

			/*
			 * If the database doesn't exist, just remove the request since we
			 * no longer need to apply the undo actions.
			 */
			if (!exists)
			{
				RemoveRequestFromQueue(cur_queue, 0);
				RollbackHTRemoveEntry(rh->full_xid, rh->start_urec_ptr, true);
				cur_undo_queue++;
				continue;
			}

			/* set the undo request info to process */
			SetUndoRequestInfoFromRHEntry(urinfo, rh, cur_queue);

			cur_undo_queue++;
			LWLockRelease(RollbackRequestLock);
			return true;
		}

		/*
		 * The worker can perform this request if it is either not connected
		 * to any database or the request belongs to the same database to
		 * which it is connected.
		 */
		if ((MyDatabaseId == InvalidOid) ||
			(MyDatabaseId != InvalidOid && MyDatabaseId == rh->dbid))
		{
			/* found a work for current database */
			if (in_other_db_out)
				*in_other_db_out = false;

			/*
			 * Mark the undo request in hash table as in_progress so that
			 * other undo worker doesn't pick the same entry for rollback.
			 */
			rh->status = UNDO_REQUEST_INPROGRESS;

			/* set the undo request info to process */
			SetUndoRequestInfoFromRHEntry(urinfo, rh, cur_queue);

			/*
			 * Remove the request from queue so that other undo worker doesn't
			 * process the same entry.
			 */
			RemoveRequestFromQueue(cur_queue, 0);

			cur_undo_queue++;
			LWLockRelease(RollbackRequestLock);
			return true;
		}
		else
			in_other_db = true;

		cur_undo_queue++;
	}

	/*
	 * Iff a worker would need to switch databases in less than
	 * undo_worker_quantum ms after starting, it peeks a few entries deep into
	 * each queue to see whether there's work for that database.  This ensures
	 * that one worker doesn't have to restart quickly to switch databases.
	 */
	if (allow_peek)
	{
		int			depth,
					cur_queue;
		RollbackHashKey hkey;
		RollbackHashEntry *rh;

		/*
		 * We shouldn't have come here if we've found a work above for our
		 * database.
		 */
		Assert(!found_work || in_other_db);

		for (depth = 0; depth < UNDO_PEEK_DEPTH; depth++)
		{
			for (cur_queue = 0; cur_queue < MAX_UNDO_WORK_QUEUES; cur_queue++)
			{
				if (!GetRollbackHashKeyFromQueue(cur_queue, depth, &hkey))
					continue;

				rh = (RollbackHashEntry *) hash_search(RollbackHT,
													   (void *) &hkey,
													   HASH_FIND, NULL);

				/*
				 * If some undo worker is already processing the rollback
				 * request or it is already processed, then fetch the next
				 * entry from the queue.
				 */
				if (!rh || UndoRequestIsInProgress(rh))
					continue;

				/*
				 * The request that is present in any queue must be a valid request
				 * and its status must be in_queue.
				 */
				Assert(UndoRequestIsValid(rh));
				Assert(UndoRequestIsInQueue(rh));

				found_work = true;

				/*
				 * The worker can perform this request if it is either not
				 * connected to any database or the request belongs to the
				 * same database to which it is connected.
				 */
				if ((MyDatabaseId == InvalidOid) ||
					(MyDatabaseId != InvalidOid && MyDatabaseId == rh->dbid))
				{
					/* found a work for current database */
					if (in_other_db_out)
						*in_other_db_out = false;

					/*
					 * Mark the undo request in hash table as in_progress so
					 * that other undo worker doesn't pick the same entry for
					 * rollback.
					 */
					rh->status = UNDO_REQUEST_INPROGRESS;

					/* set the undo request info to process */
					SetUndoRequestInfoFromRHEntry(urinfo, rh, cur_queue);

					/*
					 * Remove the request from queue so that other undo worker
					 * doesn't process the same entry.
					 */
					RemoveRequestFromQueue(cur_queue, depth);
					LWLockRelease(RollbackRequestLock);
					return true;
				}
				else
					in_other_db = true;
			}
		}
	}

	LWLockRelease(RollbackRequestLock);

	if (in_other_db_out)
		*in_other_db_out = in_other_db;

	return found_work;
}

/*
 * This function registers the rollback requests.
 *
 * Returns true, if the request is registered and will be processed by undo
 * worker at some later point of time, false, otherwise in which case caller
 * can process the undo request by itself.
 *
 * The caller may execute undo actions itself if the request is not already
 * present in rollback hash table and can't be pushed to pending undo request
 * queues.  The two reasons why request can't be pushed are (a) the size of
 * request is smaller than a threshold and the request is not from discard
 * worker, (b) the undo request queues are full.
 *
 * It is not advisable to apply the undo actions of a very large transaction
 * in the foreground as that can lead to a delay in retruning the control back
 * to user after abort.
 */
bool
RegisterUndoRequest(UndoRecPtr end_urec_ptr, UndoRecPtr start_urec_ptr,
					Oid dbid, FullTransactionId full_xid)
{
	bool		found = false;
	bool		can_push;
	bool		pushed = false;
	RollbackHashEntry *rh;
	uint64		req_size = 0;
	UndoRecPtr	last_log_start_urec_ptr = InvalidUndoRecPtr;
	RollbackHashKey hkey;

	Assert(UndoRecPtrIsValid(start_urec_ptr));
	Assert(dbid != InvalidOid);

	/*
	 * Find the rollback request size and the end_urec_ptr (in case of discard
	 * worker only).
	 */
	req_size = FindUndoEndLocationAndSize(start_urec_ptr, &end_urec_ptr,
										  &last_log_start_urec_ptr, full_xid);

	/* Do not push any rollback request if working in single user-mode */
	if (!IsUnderPostmaster)
		return false;

	/* The transaction got rolled back. */
	if (!UndoRecPtrIsValid(end_urec_ptr))
		return false;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	/*
	 * Check whether we can push the rollback request to the undo worker. This
	 * must be done under lock, see CanPushReqToUndoWorker.
	 */
	can_push = CanPushReqToUndoWorker(start_urec_ptr, end_urec_ptr, req_size);

	hkey.full_xid = full_xid;
	hkey.start_urec_ptr = start_urec_ptr;

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &hkey,
										   HASH_ENTER_NULL, &found);

	/*
	 * It can only fail, if the value of pending_undo_queue_size or
	 * max_connections guc is reduced after restart of the server.
	 */
	if (rh == NULL)
	{
		Assert(RollbackHTIsFull());

		ereport(PANIC,
				(errcode(ERRCODE_INSUFFICIENT_RESOURCES),
				 errmsg("rollback hash table is full, try running with higher value of pending_undo_queue_size")));
	}

	/* We shouldn't try to add the same rollback request again. */
	if (!found)
	{
		rh->start_urec_ptr = start_urec_ptr;
		rh->end_urec_ptr = end_urec_ptr;
		rh->last_log_start_urec_ptr = last_log_start_urec_ptr;
		rh->dbid = dbid;
		rh->full_xid = full_xid;

		/* Increment the pending request counter. */
		ProcGlobal->xactsHavingPendingUndo++;

		if (can_push)
		{
			UndoRequestInfo urinfo;

			ResetUndoRequestInfo(&urinfo);

			urinfo.full_xid = rh->full_xid;
			urinfo.start_urec_ptr = rh->start_urec_ptr;
			urinfo.end_urec_ptr = rh->end_urec_ptr;
			urinfo.last_log_start_urec_ptr = rh->last_log_start_urec_ptr;
			urinfo.dbid = rh->dbid;
			urinfo.request_size = req_size;

			InsertRequestIntoUndoQueues(&urinfo);

			/*
			 * Indicates that the request will be processed by undo
			 * worker.
			 */
			rh->status = UNDO_REQUEST_INQUEUE;
			pushed = true;
		}
		/*
		 * The request can't be pushed into the undo worker queue.  The
		 * backends will try executing by itself.
		 */
		else
			rh->status = UNDO_REQUEST_INPROGRESS;
	}
	else if (!UndoRequestIsValid(rh) && can_push)
	{
		/*
		 * If we found the request which is still not in queue or not in
		 * progress then add it to the queue if there is a space in the queue.
		 */
		UndoRequestInfo urinfo;

		ResetUndoRequestInfo(&urinfo);

		urinfo.full_xid = rh->full_xid;
		urinfo.start_urec_ptr = rh->start_urec_ptr;
		urinfo.end_urec_ptr = rh->end_urec_ptr;
		urinfo.last_log_start_urec_ptr = rh->last_log_start_urec_ptr;
		urinfo.dbid = rh->dbid;
		urinfo.request_size = req_size;

		InsertRequestIntoUndoQueues(&urinfo);

		/* Indicates that the request will be processed by the undo worker */
		rh->status = UNDO_REQUEST_INQUEUE;
		pushed = true;
	}

	LWLockRelease(RollbackRequestLock);

	return pushed;
}

/*
 * Remove the rollback request entry from the rollback hash table.
 */
void
RollbackHTRemoveEntry(FullTransactionId full_xid, UndoRecPtr start_urec_ptr,
					  bool lock)
{
	RollbackHashKey hkey;

	hkey.full_xid = full_xid;
	hkey.start_urec_ptr = start_urec_ptr;

	if (!lock)
		LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	hash_search(RollbackHT, &hkey, HASH_REMOVE, NULL);

	/* Decrement the pending request counter. */
	ProcGlobal->xactsHavingPendingUndo--;

	if (!lock)
		LWLockRelease(RollbackRequestLock);
}

/*
 * Mark the entry status as invalid in the rollback hash table.
 */
void
RollbackHTMarkEntryInvalid(FullTransactionId full_xid,
						   UndoRecPtr start_urec_ptr)
{
	RollbackHashKey hkey;
	RollbackHashEntry *rh;

	hkey.full_xid = full_xid;
	hkey.start_urec_ptr = start_urec_ptr;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &hkey, HASH_FIND, NULL);
	Assert(rh != NULL);
	rh->status = UNDO_REQUEST_INVALID;

	LWLockRelease(RollbackRequestLock);
}

/*
 * Returns the start undo record pointer for the last undo log in which
 * transaction has spanned.  This will be different from start_urec_ptr only
 * when the undo for a transaction has spanned across multiple undo logs.
 */
UndoRecPtr
RollbackHTGetLastLogStartUrp(FullTransactionId full_xid,
							 UndoRecPtr start_urec_ptr)
{
	RollbackHashKey hkey;
	RollbackHashEntry *rh;
	UndoRecPtr	last_log_start_urecptr;

	hkey.full_xid = full_xid;
	hkey.start_urec_ptr = start_urec_ptr;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &hkey, HASH_FIND, NULL);
	Assert(rh != NULL);
	last_log_start_urecptr = rh->last_log_start_urec_ptr;
	LWLockRelease(RollbackRequestLock);

	return last_log_start_urecptr;
}

/*
 * Returns true, if the rollback hash table is full, false, otherwise.
 */
bool
RollbackHTIsFull(void)
{
	bool		result = false;

	LWLockAcquire(RollbackRequestLock, LW_SHARED);

	if (hash_get_num_entries(RollbackHT) >= UndoRollbackHashTableSize())
		result = true;

	LWLockRelease(RollbackRequestLock);

	return result;
}

/*
 * Get the smallest of 'xid having pending undo' and 'oldestXmin'.
 */
FullTransactionId
RollbackHTGetOldestFullXid(FullTransactionId oldestXmin)
{
	RollbackHashEntry   *rh;
	FullTransactionId	oldestXid = oldestXmin;
	HASH_SEQ_STATUS		status;

	/* Fetch the pending undo requests */
	LWLockAcquire(RollbackRequestLock, LW_SHARED);

	Assert(hash_get_num_entries(RollbackHT) <= UndoRollbackHashTableSize());
	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		   (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
	{
		if (!FullTransactionIdIsValid(oldestXid) ||
			FullTransactionIdPrecedes(rh->full_xid, oldestXid))
			oldestXid = rh->full_xid;
	}

	LWLockRelease(RollbackRequestLock);

	return oldestXid;
}
