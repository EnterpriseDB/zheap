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
 * To process the request, we get the request from one of the queues, search
 * it in hash table and mark it as in-progress and then remove from the
 * respective queue.  Once we process all the actions, the request is removed
 * from the hash table.  If the other worker found the same request in other
 * queue, it can just ignore the request (and remove it from that queue) if
 * the request is not found in the hash table or is marked as in-progress.
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
#include "access/discardworker.h"
#include "access/undodiscard.h"
#include "access/undorequest.h"
#include "access/undoworker.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "lib/binaryheap.h"
#include "storage/shmem.h"
#include "utils/fmgroids.h"
#include "access/xlog.h"

#define ROLLBACK_REQUEST_QUEUE_SIZE 1024
#define	MAX_UNDO_WORK_QUEUES	3
#define UNDO_PEEK_DEPTH		10

typedef struct
{
	binaryheap *bh;
	union
	{
		UndoXidQueue *xid_elems;
		UndoSizeQueue *size_elems;
		UndoErrorQueue *error_elems;
	}			q_choice;
}			UndoWorkerQueue;

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

#define SetErrorQueueElem(elem, e_dbid, e_full_xid, e_occurred_at) \
( \
	GetErrorQueueElem(elem).dbid = e_dbid, \
	GetErrorQueueElem(elem).full_xid = e_full_xid, \
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
	else if (FullTransactionIdEquals(xidQueueElem1->full_xid,
									 xidQueueElem2->full_xid))
		return 0;
	return -1;
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
	else if (sizeQueueElem1->request_size == sizeQueueElem2->request_size)
		return 0;
	return -1;
}

/*
 * Binary heap comparison function to compare the time at which an error
 * occurred for transactions.
 */
static int
undo_err_time_comparator(Datum a, Datum b, void *arg)
{
	UndoErrorQueue *errQueueElem1 = (UndoErrorQueue *) DatumGetPointer(a);
	UndoErrorQueue *errQueueElem2 = (UndoErrorQueue *) DatumGetPointer(b);

	if (errQueueElem1->err_occurred_at < errQueueElem2->err_occurred_at)
		return 1;
	else if (errQueueElem1->err_occurred_at == errQueueElem2->err_occurred_at)
		return 0;
	return -1;
}

static int
UndoXidQueueElemsShmSize(void)
{
	return mul_size(ROLLBACK_REQUEST_QUEUE_SIZE, sizeof(UndoXidQueue));
}

static int
UndoSizeQueueElemsShmSize(void)
{
	return mul_size(ROLLBACK_REQUEST_QUEUE_SIZE, sizeof(UndoSizeQueue));
}

static int
UndoErrorQueueElemsShmSize(void)
{
	return mul_size(ROLLBACK_REQUEST_QUEUE_SIZE, sizeof(UndoErrorQueue));
}

static int
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
	return ((2 * ROLLBACK_REQUEST_QUEUE_SIZE) + ROLLBACK_REQUEST_QUEUE_SIZE +
			MaxBackends);
}

/* Get the first free element of xid based request array. */
static int
UndoXidQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < ROLLBACK_REQUEST_QUEUE_SIZE; i++)
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

/* Push an element in the xid based request queue */
static void
PushXidQueueElem(UndoRequestInfo * urinfo)
{
	int			elem = UndoXidQueueGetFreeElem();

	SetXidQueueElem(elem, urinfo->dbid, urinfo->full_xid, urinfo->start_urec_ptr);

	binaryheap_add(UndoWorkerQueues[XID_QUEUE].bh,
				   PointerGetDatum(&GetXidQueueElem(elem)));
}

/* Pop nth element from the xid based request queue */
static UndoXidQueue *
PopXidQueueNthElem(int n)
{
	Datum		elem;

	Assert(!XidQueueIsEmpty());
	elem = binaryheap_remove_nth(UndoWorkerQueues[XID_QUEUE].bh, n);

	return (UndoXidQueue *) (DatumGetPointer(elem));
}

/* Get the first free element of size based request array. */
static inline int
UndoSizeQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < ROLLBACK_REQUEST_QUEUE_SIZE; i++)
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
	int			queue_size = GetXidQueueSize();
	int			i;

	Assert(queue_size > 0);
	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	for (i = 0; i < queue_size; i++)
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
		if (!rh || rh->in_progress)
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			nCleaned++;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[XID_QUEUE].bh, i);
		}
	}

	binaryheap_build(UndoWorkerQueues[XID_QUEUE].bh);
	Assert(queue_size - GetXidQueueSize() == nCleaned);

	return nCleaned;
}

/* Push an element in the size based request queue */
static void
PushSizeQueueElem(UndoRequestInfo * urinfo)
{
	int			elem = UndoSizeQueueGetFreeElem();

	SetSizeQueueElem(elem, urinfo->dbid, urinfo->full_xid, urinfo->request_size,
					 urinfo->start_urec_ptr);

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
	int			queue_size = GetSizeQueueSize();
	int			i;

	Assert(queue_size > 0);
	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	for (i = 0; i < queue_size; i++)
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
		if (!rh || rh->in_progress)
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			elem->request_size = 0;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[SIZE_QUEUE].bh, i);
			nCleaned++;
		}
	}

	binaryheap_build(UndoWorkerQueues[SIZE_QUEUE].bh);
	Assert(queue_size - GetSizeQueueSize() == nCleaned);

	return nCleaned;
}

/* Get the first free element of error time based request array. */
static int
UndoErrorQueueGetFreeElem(void)
{
	int			i;

	for (i = 0; i < ROLLBACK_REQUEST_QUEUE_SIZE; i++)
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
PushErrorQueueElem(volatile UndoRequestInfo * urinfo)
{
	int			elem = UndoErrorQueueGetFreeElem();
	TimestampTz now = GetCurrentTimestamp();

	SetErrorQueueElem(elem, urinfo->dbid, urinfo->full_xid, now);

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
	int			queue_size = GetErrorQueueSize();
	int			i;

	Assert(queue_size > 0);
	Assert(LWLockHeldByMeInMode(RollbackRequestLock, LW_EXCLUSIVE));

	for (i = 0; i < queue_size; i++)
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
		if (!rh || rh->in_progress)
		{
			elem->dbid = InvalidOid;
			elem->full_xid = InvalidFullTransactionId;
			elem->err_occurred_at = 0;
			binaryheap_remove_nth_unordered(UndoWorkerQueues[ERROR_QUEUE].bh, i);
			nCleaned++;
		}
	}

	binaryheap_build(UndoWorkerQueues[ERROR_QUEUE].bh);
	Assert(queue_size - GetErrorQueueSize() == nCleaned);

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
		uErrorQueueElem->err_occurred_at = 0;
	}
}

/*
 * Returns the hash key corresponding to the nth element of the specified
 * queue.
 */
static bool
GetRollbackHashKeyFromQueue(UndoWorkerQueueType cur_queue, int n,
							RollbackHashKey * hkey)
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
		{
			cur_undo_queue++;
			return false;
		}

		elem = (UndoErrorQueue *) GetErrorQueueNthElem(n);
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
 * XXX: We don't calculate the exact undo size.  We always skip the size of
 * the last undo record (if not already discarded) from the calculation.  This
 * optimization allows us to skip fetching an undo record for the most
 * frequent cases where the end pointer and current start pointer belong to
 * the same log.  A simple subtraction between them gives us the size.  In
 * future this function can be modified if someone needs the exact undo size.
 * As of now, we use this function to calculate the undo size for inserting
 * in the pending undo actions in undo worker's size queue.
 */
static uint64
FindUndoEndLocationAndSize(UndoRecPtr start_urecptr,
						   UndoRecPtr *end_urecptr_out,
						   FullTransactionId full_xid)
{
	UnpackedUndoRecord *uur = NULL;
	UndoLogControl *log = NULL;
	UndoRecPtr	urecptr = start_urecptr;
	UndoRecPtr	end_urecptr = InvalidUndoRecPtr;
	uint64		sz = 0;

	Assert(urecptr != InvalidUndoRecPtr);
	Assert(!TransactionIdIsInProgress(XidFromFullTransactionId(full_xid)));

	while (true)
	{
		UndoRecPtr	next_urecptr = InvalidUndoRecPtr;

		if (*end_urecptr_out != InvalidUndoRecPtr)
		{
			/*
			 * Check whether end pointer and the current pointer belong to
			 * same log. In that case, we can get the size easily.
			 */
			if (UndoRecPtrGetLogNo(urecptr) == UndoRecPtrGetLogNo(*end_urecptr_out))
			{
				sz += (*end_urecptr_out - urecptr);
				break;
			}
		}

		/*
		 * Fetch the log and undo record corresponding the current undo
		 * pointer
		 */
		if ((log == NULL) || (UndoRecPtrGetLogNo(urecptr) != log->logno))
			log = UndoLogGet(UndoRecPtrGetLogNo(urecptr));
		Assert(log != NULL);

		/*
		 * If the corresponding log got rewinded to a location prior to
		 * urecptr, the undo actions are already applied.  In that case, we
		 * return from here. XXX: Remove this check once UndofetchRecord
		 * handles this itself.
		 */
		if (MakeUndoRecPtr(log->logno, log->meta.insert) <= urecptr)
			break;

		uur = UndoFetchRecord(urecptr,
							  InvalidBlockNumber,
							  InvalidOffsetNumber,
							  InvalidTransactionId,
							  NULL, NULL);

		/*
		 * If the corresponding undo record got rolled back and rewound, we
		 * return from here.
		 */
		if (uur == NULL)
			break;

		/*
		 * If the undo belongs to a different transaction, this is possible,
		 * if someone rewinds the undo and same space is used by another
		 * transaction, we return from here.
		 */
		if (!FullTransactionIdEquals(full_xid,
									 FullTransactionIdFromEpochAndXid(uur->uur_xidepoch,
																	  uur->uur_xid)))
			break;

		/*
		 * Since this is the first undo record of this transaction in this
		 * log, this must include the transaction header.
		 */
		Assert(uur->uur_info & UREC_INFO_TRANSACTION);
		next_urecptr = uur->uur_next;

		/*
		 * Case 1: If this is the last transaction in the log then calculate
		 * the latest urec pointer using next insert location of the undo log.
		 */
		if (!UndoRecPtrIsValid(next_urecptr))
		{
			UndoLogOffset next_insert;

			/*
			 * While fetching the next insert location if the new transaction
			 * has already started in this log then lets re-fetch the undo
			 * record.
			 */
			next_insert = UndoLogGetNextInsertPtr(log->logno, uur->uur_xid);
			if (!UndoRecPtrIsValid(next_insert))
			{
				UndoRecordRelease(uur);
				uur = NULL;
				continue;
			}

			/*
			 * If next_insert location points to the starting location of a
			 * new page, we should subtract the page header size from the
			 * insert location.
			 */
			if (UndoRecPtrGetPageOffset(next_insert) == UndoLogBlockHeaderSize)
				next_insert -= UndoLogBlockHeaderSize;

			end_urecptr = UndoGetPrevUndoRecptr(next_insert, InvalidUndoRecPtr,
												InvalidBuffer);
			sz += (end_urecptr - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}


		/*
		 * Case 2: The transaction ended in the same undo log, but this is not
		 * the last transaction.
		 */
		if (UndoRecPtrGetLogNo(next_urecptr) == log->logno)
		{
			end_urecptr =
				UndoGetPrevUndoRecptr(next_urecptr, InvalidUndoRecPtr,
									  InvalidBuffer);
			sz += (end_urecptr - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}

		/*
		 * Case 3: If transaction is overflowed to a different undolog and
		 * it's already discarded. It means that the undo actions for this
		 * transaction which are in the next log has already been executed.
		 */
		if (UndoLogIsDiscarded(next_urecptr))
		{
			UndoLogOffset next_insert;

			next_insert = UndoLogGetNextInsertPtr(log->logno, uur->uur_xid);
			Assert(UndoRecPtrIsValid(next_insert));

			end_urecptr = UndoGetPrevUndoRecptr(next_insert, InvalidUndoRecPtr,
												InvalidBuffer);
			sz += (next_insert - urecptr);
			Assert(UndoRecPtrIsValid(end_urecptr));
			break;
		}

		/*
		 * Case 4: The transaction is overflowed to a different log, so
		 * restart the processing from then next log.
		 */
		{
			UndoLogOffset next_insert;

			next_insert = UndoLogGetNextInsertPtr(log->logno, uur->uur_xid);
			Assert(UndoRecPtrIsValid(next_insert));

			end_urecptr = UndoGetPrevUndoRecptr(next_insert, InvalidUndoRecPtr,
												InvalidBuffer);
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
	 * same is above a certain threshold.  However, discard worker is allowed
	 * to push any size request provided there is a space in rollback request
	 * queue.  This is mainly because discard worker can be processing the
	 * rollback requests after crash recovery when no backend is alive.
	 *
	 * We have a race condition where discard worker can process the request
	 * before the backend which has aborted the transaction in which case
	 * backend won't do anything.  Normally, this won't happen because
	 * backends try to apply the undo actions immediately after marking the
	 * transaction as aborted in the clog.  One way to avoid this race
	 * condition is that we register the request by backend in hash table but
	 * not in rollback queues before marking abort in clog and then later add
	 * them in rollback queues.  However, we are not sure how important it is
	 * avoid such a race as this won't lead to any problem and OTOH, we might
	 * need some more trickery in the code to avoid such a race condition.
	 */
	if (req_size >= rollback_overflow_size * 1024 * 1024 ||
		IsDiscardProcess())
	{
		if (GetXidQueueSize() >= ROLLBACK_REQUEST_QUEUE_SIZE ||
			GetSizeQueueSize() >= ROLLBACK_REQUEST_QUEUE_SIZE)
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
			if (GetXidQueueSize() >= ROLLBACK_REQUEST_QUEUE_SIZE)
				RemoveOldElemsFromXidQueue();
			if (GetSizeQueueSize() >= ROLLBACK_REQUEST_QUEUE_SIZE)
				RemoveOldElemsFromSizeQueue();
		}

		if ((GetXidQueueSize() < ROLLBACK_REQUEST_QUEUE_SIZE))
		{
			Assert(GetSizeQueueSize() < ROLLBACK_REQUEST_QUEUE_SIZE);
			return true;
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
								   binaryheap_shmem_size(ROLLBACK_REQUEST_QUEUE_SIZE)));
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

	info.keysize = sizeof(TransactionId);
	info.entrysize = sizeof(RollbackHashEntry);
	info.hash = tag_hash;

	RollbackHT = ShmemInitHash("Undo Actions Lookup Table",
							   UndoRollbackHashTableSize(),
							   UndoRollbackHashTableSize(), &info,
							   HASH_ELEM | HASH_FUNCTION | HASH_FIXED_SIZE);

	bh = binaryheap_allocate_shm("Undo Xid Binary Heap",
								 ROLLBACK_REQUEST_QUEUE_SIZE,
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
								 ROLLBACK_REQUEST_QUEUE_SIZE,
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
								 ROLLBACK_REQUEST_QUEUE_SIZE,
								 undo_err_time_comparator,
								 NULL);

	error_elems = (UndoErrorQueue *) ShmemInitStruct("Undo Size Queue Elements",
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
	if (GetErrorQueueSize() >= ROLLBACK_REQUEST_QUEUE_SIZE)
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
	 * Mark the undo request in hash table as not in_progress so that undo
	 * launcher or other undo worker don't remove the entry from queues.
	 */
	rh = (RollbackHashEntry *) hash_search(RollbackHT, (void *) &urinfo->full_xid,
										   HASH_FIND, NULL);
	rh->in_progress = false;

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
 * remove_from_queue - if true, picks an element from the queue whose dbid matches
 * current dbid and remove it from the queue before returning the same to
 * caller.
 * urinfo - this is an OUT parameter that returns the details of undo request
 * whose undo action is still pending.
 * in_other_db_out - this is an OUT parameter. If we've not found any work for
 * current database, but there are work for some other database, we set this
 * parameter as true.
 */
bool
UndoGetWork(bool allow_peek, bool remove_from_queue, UndoRequestInfo * urinfo,
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
		if (!rh || rh->in_progress)
		{
			RemoveRequestFromQueue(cur_queue, 0);
			cur_undo_queue++;
			continue;
		}

		found_work = true;

		/*
		 * We've found a work for some database. If we don't want to remove
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
				RollbackHTRemoveEntry(rh->full_xid, rh->start_urec_ptr);
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
			rh->in_progress = true;

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
	 * Iff a worker would need to switch databases less than
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
				if (!rh || rh->in_progress)
					continue;

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
					rh->in_progress = true;

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
 * The caller may execute undo actions itself (a) if the entry is not already
 * present in rollback hash table and can't be pushed to pending undo request
 * queues, (b) if the entry is present, but the size is small enough that
 * backend can execute by itself and undo worker hasn't started processing it
 * yet.
 */
bool
RegisterRollbackReq(UndoRecPtr end_urec_ptr, UndoRecPtr start_urec_ptr,
					Oid dbid, FullTransactionId full_xid)
{
	bool		found = false;
	bool		can_push;
	bool		pushed = false;
	bool		request_registered = false;
	RollbackHashEntry *rh;
	uint64		req_size = 0;

	/* Do not push any rollback request if working in single user-mode */
	if (!IsUnderPostmaster)
		return false;

	Assert(UndoRecPtrIsValid(start_urec_ptr));
	Assert(dbid != InvalidOid);

	/*
	 * There must be space to accommodate the new request.  See
	 * UndoRollbackHashTableSize.
	 */
	Assert(!RollbackHTIsFull());

	req_size = FindUndoEndLocationAndSize(start_urec_ptr, &end_urec_ptr, full_xid);

	/* The transaction got rolled back and rewound. */
	if (!UndoRecPtrIsValid(end_urec_ptr))
		return false;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	/*
	 * Check whether we can push the rollback request to the undo worker. This
	 * must be done under lock, see CanPushReqToUndoWorker.
	 */
	can_push = CanPushReqToUndoWorker(start_urec_ptr, end_urec_ptr, req_size);

	/*
	 * Backends always register the rollback request in the rollback hash
	 * table irrespective of whether we push it to undo worker.  This ensures
	 * that discard worker won't try to process the request on which backend
	 * is working.  OTOH, discard worker won't add an entry to the hash table
	 * unless it can push the request to undo worker.  This is because
	 * otherwise backends might not process the request by themselves even
	 * though no undo worker is going to process such a request.
	 */
	if (can_push ||
		(!can_push && !IsDiscardProcess()))
	{
		RollbackHashKey hkey;

		hkey.full_xid = full_xid;
		hkey.start_urec_ptr = start_urec_ptr;

		rh = (RollbackHashEntry *) hash_search(RollbackHT, &hkey,
											   HASH_ENTER_NULL, &found);
		if (!rh)
		{
			LWLockRelease(RollbackRequestLock);
			return false;
		}

		/* We shouldn't try to add the same rollback request again. */
		if (!found)
		{
			rh->start_urec_ptr = start_urec_ptr;
			rh->end_urec_ptr = end_urec_ptr;
			rh->dbid = dbid;
			rh->full_xid = full_xid;
			rh->in_progress = false;

			if (can_push)
			{
				UndoRequestInfo urinfo;

				ResetUndoRequestInfo(&urinfo);

				urinfo.full_xid = rh->full_xid;
				urinfo.start_urec_ptr = rh->start_urec_ptr;
				urinfo.end_urec_ptr = rh->end_urec_ptr;
				urinfo.dbid = rh->dbid;
				urinfo.request_size = req_size;

				InsertRequestIntoUndoQueues(&urinfo);

				/*
				 * Indicates that the request will be processed by undo
				 * worker.
				 */
				request_registered = true;
				pushed = true;
			}
			else
			{
				/* Indicates that the request can be processed by backend. */
				request_registered = false;
			}
		}
		else if (!rh->in_progress && !can_push)
		{
			/*
			 * Indicates that the request can be processed by backend. This is
			 * the case where discard worker would have pushed the request of
			 * smaller size which backend itself can process. Mark the request
			 * as in-progress, so that discard worker doesn't try to process
			 * it.
			 */
			rh->in_progress = true;
			request_registered = false;
		}
		else
		{
			/* Indicates that the request will be processed by undo worker. */
			request_registered = true;
		}
	}

	LWLockRelease(RollbackRequestLock);

	/*
	 * If we are able to successfully push the request, wakeup the undo worker
	 * so that it can be processed in a timely fashion.
	 */
	if (pushed)
		WakeupUndoWorker(dbid);

	return request_registered;
}

/*
 * Remove the rollback request entry from the rollback hash table.
 */
void
RollbackHTRemoveEntry(FullTransactionId full_xid, UndoRecPtr start_urec_ptr)
{
	RollbackHashKey hkey;

	hkey.full_xid = full_xid;
	hkey.start_urec_ptr = start_urec_ptr;

	LWLockAcquire(RollbackRequestLock, LW_EXCLUSIVE);

	hash_search(RollbackHT, &hkey, HASH_REMOVE, NULL);

	LWLockRelease(RollbackRequestLock);
}

/*
 * To check if the rollback requests in the hash table are all
 * completed or not. This is required because we don't not want to
 * expose RollbackHT in xact.c, where it is required to ensure
 * that we push the resuests only when there is some space in
 * the hash-table.
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
 * Remove all the entries for the given dbid. This is required in cases when
 * the database is dropped and there were rollback requests pushed to the
 * hash-table.
 */
void
RollbackHTCleanup(Oid dbid)
{
	RollbackHashEntry *rh;
	HASH_SEQ_STATUS status;

	/* Fetch the rollback requests */
	LWLockAcquire(RollbackRequestLock, LW_SHARED);

	Assert(hash_get_num_entries(RollbackHT) <= UndoRollbackHashTableSize());
	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		   (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
	{
		if (rh->dbid == dbid)
		{
			RollbackHashKey hkey;

			hkey.full_xid = rh->full_xid;
			hkey.start_urec_ptr = rh->start_urec_ptr;

			hash_search(RollbackHT, &hkey, HASH_REMOVE, NULL);
		}
	}

	LWLockRelease(RollbackRequestLock);
}
