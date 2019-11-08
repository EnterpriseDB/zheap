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
#include "miscadmin.h"
#include "storage/shmem.h"

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
	// DUMMY: replace with magic stuff from Andres
	appendStringInfo(buf, "hi mom");
}

/* Per-subtransaction backend-private undo state. */
typedef struct UndoSubTransaction
{
	SubTransactionId nestingLevel;
	UndoRecPtr	start_location[NUndoPersistenceLevels];
	struct UndoSubTransaction *next;
} UndoSubTransaction;

/* Backend-private undo state (but with pointers into shared memory). */
typedef struct XactUndoData
{
	UndoRequestManager *manager;
	UndoRequest *my_request;
	bool		is_undo;
	bool		is_background_undo;
	bool		has_undo;
	UndoSubTransaction *subxact;
	UndoRecPtr	last_location[NUndoPersistenceLevels];
	uint64		last_size[NUndoPersistenceLevels];
	uint64		total_size[NUndoPersistenceLevels];
	UndoRecordSet *record_set[NUndoPersistenceLevels];
} XactUndoData;

XactUndoData XactUndo;
UndoSubTransaction UndoTopState;

static void ResetXactUndo(void);
static UndoRecPtr XactUndoEndLocation(UndoPersistenceLevel plevel);

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
	 * If we've entered a subtransaction, spin up a new UndoSubTransaction so
	 * that we can track the start locations for the subtransaction separately
	 * from any parent (sub)transactions.
	 */
	if (nestingLevel > XactUndo.subxact->nestingLevel)
	{
		UndoSubTransaction *subxact;
		int			i;

		subxact = MemoryContextAlloc(TopMemoryContext,
									 sizeof(UndoSubTransaction));
		subxact->nestingLevel = nestingLevel;
		subxact->next = XactUndo.subxact;

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
						   &start_location_logged, &start_location_unlogged,
						   &end_location_logged, &end_location_unlogged);
	if (XactUndo.my_request == NULL)
		return InvalidOid;

	XactUndo.has_undo = true;
	XactUndo.is_undo = true;
	XactUndo.is_background_undo = true;
	XactUndo.subxact->start_location[UNDOPERSISTENCE_PERMANENT] = start_location_logged;
	XactUndo.subxact->start_location[UNDOPERSISTENCE_UNLOGGED] = start_location_unlogged;

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
	/*
	 * XXX. NOT IMPLEMENTED.
	 *
	 * Invoke facilities to actually apply undo actions from here, passing the
	 * relevant information from the XactUndo so that they know what to do.
	 *
	 * In the case of subtransaction undo, this also needs to tear down the
	 * relevant UndoSubTransaction (or else we need a separate entrypoint for
	 * that). For a top-level transaction, AtCommit_XactUndo() or
	 * FinishBackgroundXactUndo() will take care of it.
	 */
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

	/* Shouldn't commit after beginning foreground undo. */
	Assert(!XactUndo.is_undo);

	/* Also exit quickly if we never did anything undo-related. */
	if (!XactUndo.has_undo)
		return;

	/*
	 * Since our (foreground) transaction committed, we know that no undo
	 * actions for any undo we wrote will need to be performed, and can
	 * therefore unregister our UndoRequest, if any.
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
	Size		request_size;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	end_location_unlogged;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if this transaction generated no undo. */
	if (!XactUndo.has_undo)
		return;

	/* This is a toplevel abort, so collapse all subtransaction state. */
	while (XactUndo.subxact->next != NULL)
	{
		UndoSubTransaction *cursubxact = XactUndo.subxact;
		UndoSubTransaction *nextsubxact = cursubxact->next;
		int			i;

		for (i = 0; i < NUndoPersistenceLevels; ++i)
			if (!UndoRecPtrIsValid(nextsubxact->start_location[i]))
				nextsubxact->start_location[i] = cursubxact->start_location[i];
		pfree(cursubxact);
		XactUndo.subxact = nextsubxact;
	}

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
		if (XactUndo.my_request != NULL)
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
			*perform_foreground_undo = true;
		return;
	}

	/*
	 * Update UndoRequest details.
	 *
	 * NB: Background processing facilities don't care about our temporary
	 * undo.
	 */
	request_size = XactUndo.total_size[UNDOPERSISTENCE_PERMANENT] +
		XactUndo.total_size[UNDOPERSISTENCE_UNLOGGED];
	end_location_logged = XactUndoEndLocation(UNDOPERSISTENCE_PERMANENT);
	end_location_unlogged = XactUndoEndLocation(UNDOPERSISTENCE_UNLOGGED);
	FinalizeUndoRequest(XactUndo.manager, XactUndo.my_request, request_size,
						XactUndo.subxact->start_location[UNDOPERSISTENCE_PERMANENT],
						XactUndo.subxact->start_location[UNDOPERSISTENCE_UNLOGGED],
						end_location_logged,
						end_location_unlogged);

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
				*perform_foreground_undo = true;
		}

		/* Poke the undo launcher, if it's hibernating. */
		DisturbUndoLauncherHibernation();
	}
	else
	{
		/* Instruct caller to perform foreground undo, if possible. */
		if (perform_foreground_undo)
			*perform_foreground_undo = true;
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
	UndoSubTransaction *cursubxact = XactUndo.subxact;
	UndoSubTransaction *nextsubxact = cursubxact->next;
	int			i;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!XactUndo.has_undo || cursubxact->nestingLevel < level)
		return;

	/* If this fails, some other subtransaction failed to clean up properly. */
	Assert(cursubxact->nestingLevel == level);

	/* If this fails, things are really messed up. */
	Assert(nextsubxact->nestingLevel < cursubxact->nestingLevel);

	/*
	 * If we have undo but our parent subtransaction doesn't, we can just
	 * adjust the nesting level of the current UndoSubTransaction.
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
 */
void
AtSubAbort_XactUndo(int level, bool *perform_foreground_undo)
{
	UndoSubTransaction *cursubxact = XactUndo.subxact;
	bool		has_temporary_undo = false;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!XactUndo.has_undo || cursubxact->nestingLevel < level)
		return;

	/* Figure out whether there any relevant temporary undo. */
	has_temporary_undo =
		UndoRecPtrIsValid(XactUndo.subxact->start_location[UNDOPERSISTENCE_TEMP]);

	if (has_temporary_undo)
		 /* experience_intense_sadness */ ;

	/*
	 * Regrettably, we seem to have failed when attempting to perform undo
	 * actions. It's impossible to continue with the parent (sub)transaction
	 * without completing undo.
	 */
	if (XactUndo.is_undo)
		 /* XXX. How do we fail the parent subtransaction, exactly? */ ;

	/*
	 * XXX. We need to avoid doing foreground undo for things that have
	 * already been successfully undone as a result of previous subtransaction
	 * aborts.
	 */
}

/*
 * Make sure we're not leaking an UndoRequest.
 */
void
AtProcExit_XactUndo(void)
{
	if (XactUndo.my_request != NULL)
		elog(PANIC, "undo request not handled before backend exit");
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
	XactUndo.subxact = &UndoTopState;
	UndoTopState.nestingLevel = 1;
	UndoTopState.next = NULL;

	for (i = 0; i < NUndoPersistenceLevels; ++i)
	{
		UndoTopState.start_location[i] = InvalidUndoRecPtr;
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

	if (!XactUndo.record_set[plevel])
		return InvalidUndoRecPtr;

	last_location = XactUndo.last_location[plevel];
	last_size = XactUndo.last_size[plevel];
	return UndoRecPtrPlusUsableBytes(last_location, last_size);
}
