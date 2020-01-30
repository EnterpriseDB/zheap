/*-------------------------------------------------------------------------
 *
 * xactundo.c
 *	  management of undo record sets for transactions
 *
 * Undo records that need to be applied after a transaction or
 * subtransaction abort should be inserted using the functions defined
 * in this file; thus, every table or index access method that wants to
 * use undo for post-abort cleanup should invoke these interfaces.
 *
 * The reason for this design is that we want to pack all of the undo
 * records for a single transaction into one place, regardless of the
 * AM which generated them. That way, we can apply the undo actions
 * which pertain to that transaction in the correct order; namely,
 * backwards as compared with the order in which the records were
 * generated.
 *
 * Actually, we may use up to three undo record sets per transaction,
 * one per persistence level (permanent, unlogged, temporary). We
 * assume that it's OK to apply the undo records for each persistence
 * level independently of the others. At least insofar as undo records
 * describe page modifications to relations with a persistence level
 * matching the undo log in which undo pertaining to those modifications
 * is stored, this assumption seems safe, since the modifications
 * must necessarily touch disjoint sets of pages.
 *
 * All undo record sets of type URST_TRANSACTION are managed here;
 * the undo system supports at most one such record set per persistence
 * level per transaction.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/xactundo.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undo.h"
#include "access/undolog.h"
#include "access/undopage.h"
#include "access/undorecordset.h"
#include "access/undorequest.h"
#include "access/undoworker.h"
#include "access/xact.h"
#include "access/xactundo.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "storage/ipc.h"
#include "storage/shmem.h"
#include "utils/builtins.h"

/*
 * The capacity of the UndoRequestManager represents the maximum number of
 * in-progress or aborted transactions that have written undo which still needs
 * to be tracked.  Once an aborted transaction's undo actions have been
 * executed, it no longer counts against this limit.
 *
 * We could make the multiplier or the absolute value user-settable, but for
 * now we just hard-code the capacity as a fixed multiple of MaxBackends.
 * Hopefully, we'll never get very close to this limit, because if we do,
 * it means that the system is aborting transactions faster than the undo
 * machinery can perform the undo actions.
 */
#define UNDO_CAPACITY_PER_BACKEND		10

/*
 * If the UndoRequestManager is almost full, then we start refusing all
 * requests to perform undo in the background. Instead, the aborting
 * transactions will need to execute their own undo actions.  The point is
 * to avoid hitting the hard limit, at which stage we would have to start
 * refusing undo-writing transactions completely. This constant represents
 * the percentage of UndoRequestManager space that may be consumed before we
 * hit the soft limit.
 *
 * Note that this should be set so that the remaining capacity when the limit
 * is hit is at least MaxBackends; if this is done, it shouldn't be possible
 * to hit the hard limit unless the system crashes at least once while the
 * number of tracked transactions is already above the soft limit.  We set it
 * a bit lower than that here so as to make it unlikely that we'll hit the
 * hard limit even if there are multiple crashes.
 */
#define UNDO_SOFT_LIMIT_MULTIPLIER		0.85

static void
SerializeUndoData(StringInfo buf, UndoNode *undo_node)
{
	/* TODO: replace with actual serialization */
	appendBinaryStringInfo(buf, (char *) &undo_node->length, sizeof(((UndoNode*) NULL)->length));
	appendBinaryStringInfo(buf, (char *) &undo_node->type, sizeof(((UndoNode*) NULL)->type));
	appendBinaryStringInfo(buf, undo_node->data, undo_node->length);
}

/* Saved state for pg_xact_undo_status. */
typedef struct
{
	unsigned	nrequests;
	unsigned	index;
	UndoRequestData *request_data;
} XactUndoStatusData;

/* Per-subtransaction backend-private undo state. */
typedef struct XactUndoSubTransaction
{
	SubTransactionId nestingLevel;
	UndoRecPtr	start_location[NUndoPersistenceLevels];
	struct XactUndoSubTransaction *next;
} XactUndoSubTransaction;

/* Backend-private undo state (but with pointers into shared memory). */
typedef struct XactUndoData
{
	UndoRequestManager *manager;
	UndoRequest *my_request;
	bool		is_undo;
	bool		is_background_undo;
	bool		has_undo;
	XactUndoSubTransaction *subxact;
	UndoRecPtr	last_location[NUndoPersistenceLevels];
	uint64		last_size[NUndoPersistenceLevels];
	uint64		total_size[NUndoPersistenceLevels];
	UndoRecordSet *record_set[NUndoPersistenceLevels];
} XactUndoData;

static XactUndoData XactUndo;
static XactUndoSubTransaction XactUndoTopState;

static void CollapseXactUndoSubTransactions(void);
static void ResetXactUndo(void);
static UndoRecPtr XactUndoEndLocation(UndoPersistenceLevel plevel);
static void XactUndoFinalizeRequest(bool mark_as_ready);
static const char *UndoPersistenceLevelString(UndoPersistenceLevel plevel);

/*
 * How much shared memory do we need for undo state management?
 */
Size
XactUndoShmemSize(void)
{
	Size		capacity = mul_size(UNDO_CAPACITY_PER_BACKEND, MaxBackends);

	return EstimateUndoRequestManagerSize(capacity);
}

/*
 * Initialize UndoRequestManager if required.
 *
 * Otherwise, just stash a pointer to it.
 */
void
XactUndoShmemInit(void)
{
	Size		capacity = UNDO_CAPACITY_PER_BACKEND * MaxBackends;
	Size		soft_limit = capacity * UNDO_SOFT_LIMIT_MULTIPLIER;
	Size		size = EstimateUndoRequestManagerSize(capacity);
	bool		found;

	XactUndo.manager = (UndoRequestManager *)
		ShmemInitStruct("undo request manager", size, &found);
	if (!found)
		InitializeUndoRequestManager(XactUndo.manager, UndoRequestLock,
									 capacity, soft_limit);
	Assert(XactUndo.my_request == NULL);
	ResetXactUndo();
}

/*
 * During cluster startup, reinitialize in-memory state from the checkpoint
 * from which we are starting up.
 */
void
StartupXactUndo(UndoCheckpointContext *ctx)
{
	Size	nbytes;

	ReadUndoCheckpointData(ctx, &nbytes, sizeof(nbytes));
	if (nbytes > 0)
	{
		char *data = palloc(nbytes);

		ReadUndoCheckpointData(ctx, data, nbytes);
		RestoreUndoRequestData(XactUndo.manager, nbytes, data);
	}
}

/*
 * At checkpoint time, save relevant state, so that we can reinitialize it
 * after a restart.
 */
void
CheckPointXactUndo(UndoCheckpointContext *ctx)
{
	Size	nbytes;
	char   *data;

	data = SerializeUndoRequestData(XactUndo.manager, &nbytes);
	WriteUndoCheckpointData(ctx, &nbytes, sizeof(nbytes));
	if (nbytes > 0)
		WriteUndoCheckpointData(ctx, data, nbytes);
}

/*
 * Prepare to insert a transactional undo record.
 */
UndoRecPtr
PrepareXactUndoData(XactUndoContext *ctx, char persistence,
					UndoNode *undo_node)
{
	int			nestingLevel = GetCurrentTransactionNestLevel();
	UndoPersistenceLevel plevel = GetUndoPersistenceLevel(persistence);
	FullTransactionId	fxid = GetTopFullTransactionId();
	UndoRecPtr	result;
	UndoRecPtr *sub_start_location;
	UndoRecordSet *urs;
	UndoRecordSize	size;

	/* We should be connected to a database. */
	Assert(OidIsValid(MyDatabaseId));

	/* Remember that we've done something undo-related. */
	XactUndo.has_undo = true;

	/*
	 * If we've entered a subtransaction, spin up a new XactUndoSubTransaction
	 * so that we can track the start locations for the subtransaction
	 * separately from any parent (sub)transactions.
	 */
	if (nestingLevel > XactUndo.subxact->nestingLevel)
	{
		XactUndoSubTransaction *subxact;
		int			i;

		subxact = MemoryContextAlloc(TopMemoryContext,
									 sizeof(XactUndoSubTransaction));
		subxact->nestingLevel = nestingLevel;
		subxact->next = XactUndo.subxact;
		XactUndo.subxact = subxact;

		for (i = 0; i < NUndoPersistenceLevels; ++i)
			subxact->start_location[i] = InvalidUndoRecPtr;
	}

	/*
	 * Unless we're writing temporary undo, we must ensure that an UndoRequest
	 * has been allocated to this transaction, so that if this transaction
	 * aborts, any undo that it generated is certain to get processed even
	 * if our session is not around any longer.
	 *
	 * (For temporary undo, we don't need this, because if our session ceases
	 * to exist, then it's not important to apply undo that affects only
	 * session-local objects; moreover, no other backend could do so anyway,
	 * since no other backend can read our local buffers.)
	 */
	if (XactUndo.my_request == NULL && (plevel == UNDOPERSISTENCE_PERMANENT ||
		 plevel == UNDOPERSISTENCE_UNLOGGED))
		XactUndo.my_request = RegisterUndoRequest(XactUndo.manager, fxid,
												  MyDatabaseId);

	/*
	 * Make sure we have an UndoRecordSet of the appropriate type open for
	 * this persistence level.
	 *
	 * These record sets are always associated with the toplevel transaction,
	 * not a subtransaction, in order to avoid fragmentation.
	 */
	urs = XactUndo.record_set[plevel];
	if (urs == NULL)
	{
		urs = UndoCreate(URST_TRANSACTION, persistence, 1,
						 sizeof(FullTransactionId), (char *) &fxid);
		XactUndo.record_set[plevel] = urs;
	}

	/* Remember persistence level. */
	ctx->plevel = plevel;

	/* Prepare serialized undo data. */
	initStringInfo(&ctx->data);
	SerializeUndoData(&ctx->data, undo_node);
	size = ctx->data.len;

	/*
	 * Find sufficient space for this undo insertion and lock the necessary
	 * buffers.
	 */
	result = UndoPrepareToInsert(urs, size);

	/*
	 * If this is the first undo for this persistence level in this
	 * subtransaction, record the start location.
	 */
	sub_start_location = &XactUndo.subxact->start_location[plevel];
	if (!UndoRecPtrIsValid(*sub_start_location))
		*sub_start_location = result;

	/*
	 * Remember this as the last start location and record size for the
	 * persistence level.
	 */
	XactUndo.last_location[plevel] = result;
	XactUndo.last_size[plevel] = size;

	/* Add to total size for persistence level. */
	XactUndo.total_size[plevel] += size;

	return result;
}

/*
 * Insert transactional undo data.
 */
void
InsertXactUndoData(XactUndoContext *ctx, uint8 first_block_id)
{
	UndoRecordSet *urs = XactUndo.record_set[ctx->plevel];

	Assert(urs != NULL);
	UndoInsert(urs, ctx->data.data, ctx->data.len);
	UndoXLogRegisterBuffers(urs, first_block_id);
}

/*
 * Set page LSNs for just-inserted transactional undo data.
 */
void
SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn)
{
	UndoRecordSet *urs = XactUndo.record_set[ctx->plevel];

	Assert(urs != NULL);
	UndoPageSetLSN(urs, lsn);
}

/*
 * Clean up after inserting transactional undo data.
 */
void
CleanupXactUndoInsertion(XactUndoContext *ctx)
{
	UndoRecordSet *urs = XactUndo.record_set[ctx->plevel];

	UndoRelease(urs);
	pfree(ctx->data.data);
}

/*
 * Recreate UNDO during WAL replay.
 *
 * XXX: Should this live here? Or somewhere around the serialization code?
 */
UndoRecPtr
XactUndoReplay(XLogReaderState *xlog_record, UndoNode *undo_node)
{
	StringInfoData data;

	/* Prepare serialized undo data. */
	initStringInfo(&data);
	SerializeUndoData(&data, undo_node);

	return UndoReplay(xlog_record, data.data, data.len);
}

/*
 * Handle a report that an UndoRecordSet was closed.
 *
 * Normally, record sets are closed when a transaction ends, or at least when
 * a backend exits, but in the case of a crash, this might not happen, or
 * might need to be redone after restarting. In that case, this function will
 * be called for each URST_TRANSACTION record set which is observed to need
 * to be closed. This allows us to fix up the UndoRequest state.
 */
void
XactUndoCloseRecordSet(void *type_header, UndoRecPtr begin, UndoRecPtr end,
					   bool isCommit, bool isPrepare)
{
	FullTransactionId fxid;
	UndoRequest *req;

	/* Can't have both isCommit and isPrepare. */
	Assert(!isCommit || !isPrepare);

	/*
	 * Currently, the type header is just a FullTransactionId, but it need
	 * not be aligned.
	 */
	memcpy(&fxid, type_header, sizeof(fxid));
	req = FindUndoRequestByFXID(XactUndo.manager, fxid);

	/*
	 * If the transaction committed, drop any UndoRequest. Transactions which
	 * began after the checkpoint from which recovery began will not have an
	 * UndoRequest, so that case is expected and harmless and we don't need
	 * to do anything at all.
	 */
	if (isCommit)
	{
		if (req != NULL)
			UnregisterUndoRequest(XactUndo.manager, req);
		return;
	}

	/*
	 * XXX. The rest of this function isn't correct yet, so just print a
	 * debugging message and return until we can fix it. For details, see the
	 * two XXX comments, below.
	 */
	elog(LOG, "XXX XactUndoCloseRecordSet(%zx -> %zx, fxid = " UINT64_FORMAT ")",
		 begin, end, U64FromFullTransactionId(fxid));
	return;

	/*
	 * If the transaction aborted or was prepared after the checkpoint from
	 * which recovery began, no UndoRequest will exist yet; create one.
	 */
	if (req == NULL)
	{
		/*
		 * XXX. It's not OK to pass InvalidOid here, but we don't know the
		 * correct database OID. Can we get that from the caller?
		 */
		req = RegisterUndoRequest(XactUndo.manager, fxid, InvalidOid);
		if (req == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TRANSACTION_STATE),
					 errmsg("no more undo requests")));
	}

	/*
	 * Update the UndoRequest with the details we obtained from the caller.
	 * Here, 'begin' and 'end' refer only to logged undo. Any unlogged undo
	 * that may have been generated before the system restart is not relevant,
	 * because we'll only reach this code in cases where unlogged relations
	 * get reset. (Temporary undo doesn't matter, either.)
	 *
	 * XXX. We're supposed to pass the request size to FinalizeUndoRequest
	 * to aid in prioritizations, but we don't know what it is here. Can the
	 * caller tell us? For now, let's go with 42. Note that end - begin would
	 * be OK if there's only one chunk, but not otherwise.
	 */
	FinalizeUndoRequest(XactUndo.manager, req, 42,
						begin, InvalidUndoRecPtr, end, InvalidUndoRecPtr,
						isPrepare);

	/*
	 * If we are preparing this transaction, then we don't need to do anything
	 * else right now; a final decision about how to proceed will be made when
	 * the transaction commits or aborts.
	 *
	 * If this is an abort, we need to trigger undo execution. We can't do
	 * that here, though, so force it into the background.
	 */
	if (!isPrepare)
		PerformUndoInBackground(XactUndo.manager, req, true);
}

/*
 * Return the amount of time until InitializeBackgroundXactUndo can obtain
 * an undo request.
 *
 * If there are no undo requests, returns -1. If there are undo requests
 * available for processing immediately, returns 0. Otherwise, returns the
 * number of milliseconds until an undo request is available for processing.
 *
 * The caller should pass the current time, as returned by GetCurrentTimestamp.
 */
long
XactUndoWaitTime(TimestampTz now)
{
	Assert(XactUndo.manager != NULL);
	return UndoRequestWaitTime(XactUndo.manager, now);
}

/*
 * Attempt to obtain an UndoRequest for background processing.
 *
 * If there is no work to be done right now, returns InvalidOid.  Otherwise,
 * the return value is the OID of the database to which the caller must be
 * connected to perform the necessary undo work.
 *
 * When this function returns a database OID, any subsequent transaction abort
 * will reschedule the UndoRequest for later reprocessing, and it's no longer
 * this backend's responsibility. However, a transaction commit does not
 * automatically unregister the request as successfully completed; to do that,
 * call FinishBackgroundXactUndo.
 *
 * The minimum_runtime_reached parameter is passed to GetNextUndoRequest, q.v.
 */
Oid
InitializeBackgroundXactUndo(bool minimum_runtime_reached)
{
	Oid			dbid;
	FullTransactionId fxid;
	UndoRecPtr	start_location_logged;
	UndoRecPtr	start_location_unlogged;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	end_location_unlogged;

	Assert(!XactUndo.has_undo && !XactUndo.is_undo);
	Assert(XactUndo.my_request == NULL);

	XactUndo.my_request =
		GetNextUndoRequest(XactUndo.manager, MyDatabaseId,
						   minimum_runtime_reached, &dbid, &fxid,
						   &start_location_logged, &end_location_logged,
						   &start_location_unlogged, &end_location_unlogged);
	if (XactUndo.my_request == NULL)
		return InvalidOid;

	XactUndo.has_undo = true;
	XactUndo.is_undo = true;
	XactUndo.is_background_undo = true;
	XactUndo.subxact->start_location[UNDOPERSISTENCE_PERMANENT] =
		start_location_logged;
	XactUndo.subxact->start_location[UNDOPERSISTENCE_UNLOGGED] =
		start_location_unlogged;

	/*
	 * The "last location" and "last size" data we set up here isn't really
	 * accurate; our goal is just to get the correct end location through to
	 * the code that actually processes undo.
	 */
	XactUndo.last_location[UNDOPERSISTENCE_PERMANENT] = end_location_logged;
	XactUndo.last_location[UNDOPERSISTENCE_UNLOGGED] = end_location_unlogged;
	XactUndo.last_size[UNDOPERSISTENCE_PERMANENT] = 0;
	XactUndo.last_size[UNDOPERSISTENCE_UNLOGGED] = 0;

	Assert(OidIsValid(dbid));
	return dbid;
}

/*
 * If background undo processing succeeds, call this function.
 *
 * It will unregister the undo request.
 */
void
FinishBackgroundXactUndo(void)
{
	Assert(XactUndo.is_background_undo);
	Assert(XactUndo.my_request != NULL);

	UnregisterUndoRequest(XactUndo.manager, XactUndo.my_request);
	ResetXactUndo();
}

/*
 * Perform undo actions.
 *
 * This function might be called either to process undo actions in the
 * background or to perform foreground undo.  Caller must ensure that we have a
 * valid transaction context so that it's safe for us to do things that might
 * fail.
 *
 * Our job is to apply all undo for transaction nesting levels greater than or
 * equal to the level supplied as an argument.
 */
void
PerformUndoActions(int nestingLevel)
{
	XactUndoSubTransaction *mysubxact = XactUndo.subxact;

	/* Sanity checks. */
	Assert(XactUndo.has_undo);
	Assert(mysubxact != NULL);
	Assert(mysubxact->nestingLevel == nestingLevel);

	/*
	 * XXX. NOT IMPLEMENTED.
	 *
	 * Invoke facilities to actually apply undo actions from here, passing the
	 * relevant information from the XactUndo so that they know what to do.
	 *
	 * NOTE: No code called from this function can use rely on
	 * XactUndo.record_set being set, because that will be true only in
	 * foreground undo paths.
	 */

	for (UndoPersistenceLevel p = UNDOPERSISTENCE_PERMANENT;
		 p < NUndoPersistenceLevels; p++)
	{
		UndoRecPtr start_location;
		UndoRecPtr end_location;

		start_location = mysubxact->start_location[p];
		if (!UndoRecPtrIsValid(start_location))
			continue;
		end_location = XactUndoEndLocation(p);

		/*
		 * AFIXME: until we can show the actual effects of undo processing,
		 * show a debug message showing when undo is being executed.
		 *
		 * To make it possible to write regression tests, only show values
		 * that won't change from run to run.
		 */
		elog(WARNING, "executing undo: persistence: %s, nestingLevel: %d, bytes: %lu",
			 UndoPersistenceLevelString(p),
			 nestingLevel,
			 end_location - start_location
			);
	}
}

/*
 * Post-commit cleanup of the undo state.
 *
 * NB: This code MUST NOT FAIL, since it is run as a post-commit cleanup step.
 * Don't put anything complicated in this function!
 */
void
AtCommit_XactUndo(void)
{
	/*
	 * For background undo processing, the fact that the transaction is
	 * committing doesn't necessarily mean we're done.  For example, we might
	 * have just been connecting to the database or something of that sort.
	 * Client code must call FinishBackgroundXactUndo() to report successful
	 * completion. So, do nothing in that case.
	 */
	if (XactUndo.is_background_undo)
		return;

	/* Also exit quickly if we never did anything undo-related. */
	if (!XactUndo.has_undo)
		return;

	/*
	 * We could arrive at this point either because a foreground transaction
	 * committed, or because a foreground transaction successfully completed
	 * undo. Either way, it's appropriate to releas our UndoReuqest, if any.
	 */
	if (XactUndo.my_request != NULL)
	{
		UnregisterUndoRequest(XactUndo.manager, XactUndo.my_request);
		XactUndo.my_request = NULL;
	}

	/* Reset state for next transaction. */
	ResetXactUndo();
}

/*
 * Post-abort cleanup of the undo state.
 *
 * Our main goals here are to (1) tell the caller whether foreground undo is
 * required and (2) avoid losing track of any UndoRequest that we own.
 *
 * If the caller is unable or unwilling to perform foreground undo, it is
 * possible to pass NULL to this function.  In that case, permanent or
 * unlogged undo will be forcibly scheduled for background processing, and
 * temporary undo will just be ignored.
 */
void
AtAbort_XactUndo(bool *perform_foreground_undo)
{
	bool		has_temporary_undo = false;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if this transaction generated no undo. */
	if (!XactUndo.has_undo)
		return;

	/* This is a toplevel abort, so collapse all subtransaction state. */
	CollapseXactUndoSubTransactions();

	/* Figure out whether there any relevant temporary undo. */
	has_temporary_undo =
		UndoRecPtrIsValid(XactUndo.subxact->start_location[UNDOPERSISTENCE_TEMP]);

	if (XactUndo.is_undo)
	{
		/*
		 * Regrettably, we seem to have failed when attempting to perform undo
		 * actions. First, try to reschedule any undo request for later
		 * background processing, so that we don't lose track of it.
		 */
		Assert(XactUndo.my_request != NULL);
		RescheduleUndoRequest(XactUndo.manager, XactUndo.my_request);

		/*
		 * XXX. If we have any temporary undo, we're in big trouble, because
		 * there's no way for background workers to process it, and apparently
		 * we're also unable to process it.  Should we throw FATAL?  Just
		 * leave the undo unapplied and somehow retry at a later point in the
		 * session?
		 */
		if (has_temporary_undo)
			 /* experience_intense_sadness */ ;

		ResetXactUndo();
		return;
	}

	/*
	 * If we have no UndoRequest, then the either we have no undo, or we have
	 * only temporary undo. In the latter case, hopefully the caller can
	 * handle it. (If not, we'll just have to open that the backend exits soon
	 * or the caller takes care of the problem in some other way.)
	 */
	if (XactUndo.my_request == NULL)
	{
		if (!has_temporary_undo)
			ResetXactUndo();
		else if (perform_foreground_undo != NULL)
		{
			*perform_foreground_undo = true;
			XactUndo.is_undo = true;
		}
		return;
	}

	/* Finalize UndoRequest details. */
	XactUndoFinalizeRequest(false);

	/*
	 * We have generated undo for permanent and/or unlogged tables.  If the
	 * caller can't perform foreground undo, force the request into the
	 * background; otherwise, let PerformUndoInBackground tell us whether
	 * background undo is appropriate.
	 */
	if (PerformUndoInBackground(XactUndo.manager, XactUndo.my_request,
								perform_foreground_undo == NULL))
	{
		if (!has_temporary_undo)
		{
			/* No temporary undo, and everything else in the background. */
			ResetXactUndo();
		}
		else
		{
			/*
			 * Permanent and unlogged undo in the background, but temporary
			 * undo is still our problem.
			 */
			XactUndo.my_request = NULL;
			XactUndo.subxact->start_location[UNDOPERSISTENCE_PERMANENT] =
				InvalidUndoRecPtr;
			XactUndo.subxact->start_location[UNDOPERSISTENCE_UNLOGGED] =
				InvalidUndoRecPtr;
			XactUndo.last_location[UNDOPERSISTENCE_PERMANENT] =
				InvalidUndoRecPtr;
			XactUndo.last_location[UNDOPERSISTENCE_UNLOGGED] =
				InvalidUndoRecPtr;
			XactUndo.last_size[UNDOPERSISTENCE_PERMANENT] = 0;
			XactUndo.last_size[UNDOPERSISTENCE_UNLOGGED] = 0;
			XactUndo.total_size[UNDOPERSISTENCE_PERMANENT] = 0;
			XactUndo.total_size[UNDOPERSISTENCE_UNLOGGED] = 0;

			/* Instruct caller to perform foreground undo, if possible. */
			if (perform_foreground_undo)
			{
				*perform_foreground_undo = true;
				XactUndo.is_undo = true;
			}
		}

		/* Poke the undo launcher, if it's hibernating. */
		DisturbUndoLauncherHibernation();
	}
	else
	{
		/* Instruct caller to perform foreground undo, if possible. */
		if (perform_foreground_undo)
		{
			*perform_foreground_undo = true;
			XactUndo.is_undo = true;
		}
	}
}

/*
 * Clean up of the undo state following a subtransaction commit.
 *
 * Like AtCommit_XactUndo, this must not fail.
 */
void
AtSubCommit_XactUndo(int level)
{
	XactUndoSubTransaction *cursubxact = XactUndo.subxact;
	XactUndoSubTransaction *nextsubxact = cursubxact->next;
	int			i;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!XactUndo.has_undo || cursubxact->nestingLevel < level)
		return;

	/* If this fails, some other subtransaction failed to clean up properly. */
	Assert(cursubxact->nestingLevel == level);

	/* If this fails, things are really messed up. */
	Assert(nextsubxact->nestingLevel < cursubxact->nestingLevel);

	/*
	 * We might reach here after performing undo for a subtransaction that
	 * previously aborted. If so, we should discard the XactUndoSubTransaction
	 * which we were keeping around for that purpose.
	 */
	if (XactUndo.is_undo)
	{
		XactUndo.subxact = cursubxact->next;
		pfree(cursubxact);
		Assert(XactUndo.subxact->nestingLevel < level);
		XactUndo.is_undo = false;
		return;
	}

	/*
	 * If we have undo but our parent subtransaction doesn't, we can just
	 * adjust the nesting level of the current XactUndoSubTransaction.
	 */
	if (nextsubxact->nestingLevel < cursubxact->nestingLevel - 1)
	{
		cursubxact->nestingLevel--;
		return;
	}

	/* Merge our data with parent. */
	for (i = 0; i < NUndoPersistenceLevels; ++i)
		if (!UndoRecPtrIsValid(nextsubxact->start_location[i]))
			nextsubxact->start_location[i] = cursubxact->start_location[i];
	pfree(cursubxact);
	XactUndo.subxact = nextsubxact;
}

/*
 * Clean up of the undo state following a subtransaction abort.
 *
 * If the caller is unable or unwilling to perform foreground undo, it is
 * possible to pass NULL to this function.  In that case, any undo for this
 * subtransaction level processed.  It can't even be scheduled for future
 * processing, since that only works for entire transactions. Consequently,
 * such an approach should only taken if some parent subtransaction or the
 * toplevel transaction will be aborted afterwards.
 *
 * XXX. We need to avoid doing foreground undo for things that have
 * already been successfully undone as a result of previous subtransaction
 * aborts. That's not really this function's problem but we need to deal with
 * it somewhere.
 */
void
AtSubAbort_XactUndo(int level, bool *perform_foreground_undo)
{
	XactUndoSubTransaction *cursubxact = XactUndo.subxact;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!XactUndo.has_undo || cursubxact->nestingLevel < level)
		return;

	/*
	 * If we fail when attempting to perform undo actions, it's impossible to
	 * continue with the parent (sub)transaction. We currently handle this by
	 * killing off the entire backend.
	 *
	 * Note that we need a defense here against reentering this function from
	 * within proc_exit and failing again.
	 */
	if (XactUndo.is_undo && !proc_exit_inprogress)
	{
		/*
		 * XXX. This is non-optimal.
		 *
		 * We don't necessarily need to kill the entire backend; it
		 * would probably be good enough to kill off the top-level transaction,
		 * maybe by somehow (how?) forcing the parent subtransaction to also
		 * fail (and thus retry our undo) and so forth until we either succeed
		 * during undo or get to the outermost level. Or perhaps we should
		 * force all of the transactions up to the top level into a failed
		 * state immediately (again, how?).
		 *
		 * Another thing that sucks about this is that throwing FATAL here
		 * will probably lose the original error message that might give the
		 * user some hint as to the cause of the failure. We probably need
		 * to improve that somehow.
		 */
		ereport(FATAL,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("unable to continue transaction after undo failure")));
	}

	/* Instruct caller to perform foreground undo, if possible. */
	if (perform_foreground_undo)
	{
		*perform_foreground_undo = true;
		XactUndo.is_undo = true;
		return;
	}

	/*
	 * Since the caller is unable or unwilling to perform foreground undo
	 * for this subtransaction, we can and should discard the state that would
	 * be used for that purpose at this stage.
	 */
	XactUndo.subxact = cursubxact->next;
	pfree(cursubxact);
	Assert(XactUndo.subxact->nestingLevel < level);
}

/*
 * Get ready to PREPARE a transaction that has undo. Any errors must be
 * thrown at this stage.
 */
void
AtPrepare_XactUndo(GlobalTransaction gxact)
{
	UndoRecPtr	temp_undo_start;

	/* Exit quickly if this transaction generated no undo. */
	if (!XactUndo.has_undo)
		return;

	/*
	 * Whether PREPARE succeeds or fails, this session will no longer be in a
	 * transaction, so collapse all subtransaction state. This simplifies the
	 * check for temporary undo which follows.
	 */
	CollapseXactUndoSubTransactions();

	/*
	 * If we have temporary undo, we cannot PREPARE.
	 *
	 * The earlier check for operations on temporary objects will presumaby
	 * catch most problems, but there might be corner cases where temporary
	 * undo exists but those checks don't trip. So, to be safe, add another
	 * check here.
	 */
	temp_undo_start = XactUndo.subxact->start_location[UNDOPERSISTENCE_TEMP];
	if (UndoRecPtrIsValid(temp_undo_start))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot PREPARE a transaction that has temporary undo")));

	/*
	 * Store a pointer to our UndoRequest in the GlobalTransaction.
	 */
	SetPreparedUndoRequest(gxact, XactUndo.my_request);
}

/*
 * Post-PREPARE resource cleanup.
 *
 * It's too late for an ERROR at this point, so everything we do here must
 * be guaranteed to succeed.
 */
void
PostPrepare_XactUndo(void)
{
	/* Exit quickly if this transaction generated no undo. */
	if (!XactUndo.has_undo)
		return;

	/* Finalize the undo request details. */
	XactUndoFinalizeRequest(true);

	/* And clear the undo state for the next transaction. */
	ResetXactUndo();
}

/*
 * Change UndoRequest state at COMMIT PREPARED or ROLLBACK PREPARED.
 *
 * Currently, we never attempt to perform foreground undo for prepared
 * transactions. That might be a liability: if someone uses many prepared
 * transactions that all use undo and then abort, they could potentially
 * fill up the UndoRequestManager faster than the undo apply workers can
 * handle the request stream, leading eventually to failures when attempting
 * to use undo. If this proves to be a problem, the solution would be to
 * force a backend executing ROLLBACK PREPARED to apply undo in the
 * foreground under the same conditions that would have applied to a regular
 * ROLLBACK.
 */
void
XactUndoTwoPhaseFinish(UndoRequest *req, bool isCommit)
{
	if (isCommit)
		UnregisterUndoRequest(XactUndo.manager, req);
	else
		PerformUndoInBackground(XactUndo.manager, req, true);
}

/*
 * Reassociate a GlobalTransaction with the appropriate UndoRequest after
 * a system restart.
 */
void
XactUndoTwoPhaseRecover(FullTransactionId fxid, GlobalTransaction gxact)
{
	UndoRequest *req = FindUndoRequestByFXID(XactUndo.manager, fxid);

	if (req != NULL)
		SetPreparedUndoRequest(gxact, req);
}

/*
 * Make sure that we never leak an UndoRequest.
 */
void
AtProcExit_XactUndo(void)
{
	if (XactUndo.my_request != NULL)
		elog(PANIC, "undo request not handled before backend exit");
}

/*
 * Collapse the subtransaction stack.
 *
 * In effect, we're pretending that all subtransactions has committed, in
 * preparation for making some decision about the fate of the top-level
 * transaction.
 */
static void
CollapseXactUndoSubTransactions(void)
{
	while (XactUndo.subxact->next != NULL)
	{
		XactUndoSubTransaction *cursubxact = XactUndo.subxact;
		XactUndoSubTransaction *nextsubxact = cursubxact->next;
		int			i;

		for (i = 0; i < NUndoPersistenceLevels; ++i)
			if (!UndoRecPtrIsValid(nextsubxact->start_location[i]))
				nextsubxact->start_location[i] = cursubxact->start_location[i];
		pfree(cursubxact);
		XactUndo.subxact = nextsubxact;
	}
}

/*
 * Reset backend-local undo state.
 */
static void
ResetXactUndo(void)
{
	int			i;

	XactUndo.my_request = NULL;
	XactUndo.is_undo = false;
	XactUndo.is_background_undo = false;
	XactUndo.has_undo = false;
	XactUndo.subxact = &XactUndoTopState;
	XactUndoTopState.nestingLevel = 1;
	XactUndoTopState.next = NULL;

	for (i = 0; i < NUndoPersistenceLevels; ++i)
	{
		XactUndoTopState.start_location[i] = InvalidUndoRecPtr;
		XactUndo.last_location[i] = InvalidUndoRecPtr;
		XactUndo.last_size[i] = 0;
		XactUndo.total_size[i] = 0;
		XactUndo.record_set[i] = NULL;
	}
}

/*
 * Get end location for a persistence level by adding the last size to
 * the last location.
 *
 * NB: This supposes that a single record never spans two separate undo logs.
 */
static UndoRecPtr
XactUndoEndLocation(UndoPersistenceLevel plevel)
{
	UndoRecPtr	last_location;
	uint64		last_size;

	last_location = XactUndo.last_location[plevel];
	if (!UndoRecPtrIsValid(last_location))
		return InvalidUndoRecPtr;
	last_size = XactUndo.last_size[plevel];
	return UndoRecPtrPlusUsableBytes(last_location, last_size);
}

/*
 * Store the final start and end locations for an UndoRequest.
 *
 * We've been updating the information in backend-private memory, but must
 * copy it into shared memory.
 *
 * If the transaction is being prepared, we should also mark it as ready,
 * so that other sessions know that the details within are valid. We can
 * skip that if this is an aborted transaction, since we'll change the
 * status again momentarily.
 *
 * NB: Background processing facilities don't care about our temporary
 * undo.
 */
static void
XactUndoFinalizeRequest(bool mark_as_ready)
{
	Size		request_size;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	end_location_unlogged;

	request_size = XactUndo.total_size[UNDOPERSISTENCE_PERMANENT] +
		XactUndo.total_size[UNDOPERSISTENCE_UNLOGGED];
	end_location_logged = XactUndoEndLocation(UNDOPERSISTENCE_PERMANENT);
	end_location_unlogged = XactUndoEndLocation(UNDOPERSISTENCE_UNLOGGED);
	FinalizeUndoRequest(XactUndo.manager, XactUndo.my_request, request_size,
						XactUndo.subxact->start_location[UNDOPERSISTENCE_PERMANENT],
						XactUndo.subxact->start_location[UNDOPERSISTENCE_UNLOGGED],
						end_location_logged,
						end_location_unlogged,
						mark_as_ready);
}

/*
 * Set-returning, SQL-callable function to display transaction undo status.
 */
Datum
pg_xact_undo_status(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	XactUndoStatusData *mystatus;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext	oldcontext;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		mystatus = palloc(sizeof(XactUndoStatusData));
		mystatus->nrequests =
			SnapshotActiveUndoRequests(XactUndo.manager,
									   &mystatus->request_data);
		mystatus->index = 0;
		funcctx->user_fctx = mystatus;
		funcctx->tuple_desc = MakeUndoRequestDataTupleDesc();
		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	mystatus = (XactUndoStatusData *) funcctx->user_fctx;

	while (mystatus->index < mystatus->nrequests)
	{
		HeapTuple	tuple;

		tuple = MakeUndoRequestDataTuple(funcctx->tuple_desc,
										 mystatus->request_data,
										 mystatus->index++);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}

	SRF_RETURN_DONE(funcctx);
}

/*
 * Wait for an undo request for the given transaction no longer exists, or
 * until it is observed to have failed. If the former occurs, return true;
 * otherwise return false.
 *
 * This is mostly intended as an aid to writing regression tests.
 */
Datum
pg_xact_undo_wait(PG_FUNCTION_ARGS)
{
	int64	txid = PG_GETARG_INT64(0);
	FullTransactionId	fxid;
	bool	exists;
	bool	is_failed_request;

	fxid.value = (uint64) txid;

	while (1)
	{
		CHECK_FOR_INTERRUPTS();

		exists = UndoRequestExists(XactUndo.manager, fxid, &is_failed_request);
		if (is_failed_request)
			PG_RETURN_BOOL(false);
		if (!exists)
			PG_RETURN_BOOL(true);
		pg_usleep(10000L);
	}
}

/*
 * Get undo persistence level as a C string.
 */
static const char *
UndoPersistenceLevelString(UndoPersistenceLevel plevel)
{
	switch (plevel)
	{
		case UNDOPERSISTENCE_PERMANENT:
			return "permanent";
		case UNDOPERSISTENCE_UNLOGGED:
			return "permanent";
		case UNDOPERSISTENCE_TEMP:
			return "permanent";
	}

	pg_unreachable();
}
