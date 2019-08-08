/*-------------------------------------------------------------------------
 *
 * undostate.c
 *		Undo system state management and transaction integration.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undostate.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undorequest.h"
#include "access/undostate.h"
#include "access/xact.h"
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

/* Per-subtransaction backend-private undo state. */
typedef struct UndoSubTransaction
{
	SubTransactionId nestingLevel;
	UndoRecPtr	start_location[NUndoPersistenceLevels];
	struct UndoSubTransaction *next;
} UndoSubTransaction;

/* Backend-private undo state (but with pointers into shared memory). */
typedef struct UndoStateData
{
	UndoRequestManager *manager;
	UndoRequest *my_request;
	bool		is_undo;
	bool		is_background_undo;
	bool		has_undo;
	UndoSubTransaction *subxact;
	UndoRecPtr	last_location[NUndoPersistenceLevels];
	Size		last_size[NUndoPersistenceLevels];
	Size		total_size[NUndoPersistenceLevels];
} UndoStateData;

UndoStateData UndoState;
UndoSubTransaction UndoTopState;

static void ResetUndoState(void);
static UndoRecPtr GetUndoRecordEndPtr(UndoRecPtr start_location, Size size);

/*
 * How much shared memory do we need for undo state management?
 */
Size
UndoStateShmemSize(void)
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
UndoStateShmemInit(void)
{
	Size		capacity = UNDO_CAPACITY_PER_BACKEND * MaxBackends;
	Size		soft_limit = capacity * UNDO_SOFT_LIMIT_MULTIPLIER;
	Size		size = EstimateUndoRequestManagerSize(capacity);
	bool		found;

	UndoState.manager = (UndoRequestManager *)
		ShmemInitStruct("undo request manager", size, &found);
	if (!found)
		InitializeUndoRequestManager(UndoState.manager, UndoRequestLock,
									 capacity, soft_limit);
	Assert(UndoState.my_request == NULL);
	ResetUndoState();
}

/*
 * Accumulate information about one undo record insertion within the current
 * transaction.
 *
 * This must be called for before every undo record insertion. We will need
 * these details to decide what to do if the transaction aborts. It's important
 * that this is called before the undo is actually inserted, because if we need
 * to register an UndoRequest and fail to do so, the failure needs to occur
 * while we still have no undo that will potentially require background
 * processing.
 */
void
UndoStateAccumulateRecord(UndoPersistenceLevel plevel, UndoRecPtr start_location,
						  Size size)
{
	int			nestingLevel = GetCurrentTransactionNestLevel();
	UndoRecPtr *sub_start_location;

	/* Remember that we've done something undo-related. */
	UndoState.has_undo = true;

	/* We should be connected to a database. */
	Assert(OidIsValid(MyDatabaseId));

	/* Register new UndoRequest if required for this persistence level. */
	if (UndoState.my_request == NULL && (plevel == UNDOPERSISTENCE_PERMANENT ||
		 plevel == UNDOPERSISTENCE_UNLOGGED))
		UndoState.my_request = RegisterUndoRequest(UndoState.manager,
												   GetTopFullTransactionId(),
												   MyDatabaseId);

	/*
	 * If we've entered a subtransaction, spin up a new UndoSubTransaction so
	 * that we can track the start locations for the subtransaction separately
	 * from any parent (sub)transactions.
	 */
	if (nestingLevel > UndoState.subxact->nestingLevel)
	{
		UndoSubTransaction *subxact;
		int			i;

		subxact = MemoryContextAlloc(TopMemoryContext,
									 sizeof(UndoSubTransaction));
		subxact->nestingLevel = nestingLevel;
		subxact->next = UndoState.subxact;

		for (i = 0; i < NUndoPersistenceLevels; ++i)
			subxact->start_location[i] = InvalidUndoRecPtr;
	}

	/*
	 * If this is the first undo for this persistence level in this
	 * subtransaction, record the start location.
	 */
	sub_start_location = &UndoState.subxact->start_location[plevel];
	if (!UndoRecPtrIsValid(*sub_start_location))
		*sub_start_location = start_location;

	/*
	 * Remember this as the last start location and record size for the
	 * persistence level.
	 */
	UndoState.last_location[plevel] = start_location;
	UndoState.last_size[plevel] = size;

	/* Add to total size for persistence level. */
	UndoState.total_size[plevel] += size;
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
 * call FinishBackgroundUndo.
 *
 * The minimum_runtime_reached parameter is passed to GetNextUndoRequest, q.v.
 */
Oid
InitializeBackgroundUndoState(bool minimum_runtime_reached)
{
	Oid			dbid;
	FullTransactionId fxid;
	UndoRecPtr	start_location_logged;
	UndoRecPtr	start_location_unlogged;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	end_location_unlogged;

	Assert(!UndoState.has_undo && !UndoState.is_undo);
	Assert(UndoState.my_request == NULL);

	UndoState.my_request =
		GetNextUndoRequest(UndoState.manager, MyDatabaseId,
						   minimum_runtime_reached, &dbid, &fxid,
						   &start_location_logged, &start_location_unlogged,
						   &end_location_logged, &end_location_unlogged);
	if (UndoState.my_request == NULL)
		return InvalidOid;

	UndoState.has_undo = true;
	UndoState.is_undo = true;
	UndoState.is_background_undo = true;
	UndoState.subxact->start_location[UNDOPERSISTENCE_PERMANENT] = start_location_logged;
	UndoState.subxact->start_location[UNDOPERSISTENCE_UNLOGGED] = start_location_unlogged;

	/*
	 * The "last location" and "last size" data we set up here isn't really
	 * accurate; our goal is just to get the correct end location through to
	 * the code that actually processes undo.
	 */
	UndoState.last_location[UNDOPERSISTENCE_PERMANENT] = end_location_logged;
	UndoState.last_location[UNDOPERSISTENCE_UNLOGGED] = end_location_unlogged;
	UndoState.last_size[UNDOPERSISTENCE_PERMANENT] = 0;
	UndoState.last_size[UNDOPERSISTENCE_UNLOGGED] = 0;

	Assert(OidIsValid(dbid));
	return dbid;
}

/*
 * If background undo processing succeeds, call this function.
 *
 * It will unregister the undo request.
 */
void
FinishBackgroundUndo(void)
{
	Assert(UndoState.is_background_undo);
	Assert(UndoState.my_request != NULL);

	UnregisterUndoRequest(UndoState.manager, UndoState.my_request);
	ResetUndoState();
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
	 * relevant information from the UndoState so that they know what to do.
	 *
	 * In the case of subtransaction undo, this also needs to tear down the
	 * relevant UndoSubTransaction (or else we need a separate entrypoint for
	 * that). For a top-level transaction, AtCommit_UndoState() or
	 * FinishBackgroundUndo() will take care of it.
	 */
}

/*
 * Post-commit cleanup of the undo state.
 *
 * NB: This code MUST NOT FAIL, since it is run as a post-commit cleanup step.
 * Don't put anything complicated in this function!
 */
void
AtCommit_UndoState(void)
{
	/*
	 * For background undo processing, the fact that the transaction is
	 * committing doesn't necessarily mean we're done.  For example, we might
	 * have just been connecting to the database or something of that sort.
	 * Client code must call FinishBackgroundUndo() to report successful
	 * completion. So, do nothing in that case.
	 */
	if (UndoState.is_background_undo)
		return;

	/* Shouldn't commit after beginning foreground undo. */
	Assert(!UndoState.is_undo);

	/* Also exit quickly if we never did anything undo-related. */
	if (!UndoState.has_undo)
		return;

	/*
	 * Since our (foreground) transaction committed, we know that no undo
	 * actions for any undo we wrote will need to be performed, and can
	 * therefore unregister our UndoRequest, if any.
	 */
	if (UndoState.my_request != NULL)
	{
		UnregisterUndoRequest(UndoState.manager, UndoState.my_request);
		UndoState.my_request = NULL;
	}

	/* Reset state for next transaction. */
	ResetUndoState();
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
AtAbort_UndoState(bool *perform_foreground_undo)
{
	bool		has_temporary_undo = false;
	Size		request_size;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	end_location_unlogged;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if this transaction generated no undo. */
	if (!UndoState.has_undo)
		return;

	/* This is a toplevel abort, so collapse all subtransaction state. */
	while (UndoState.subxact->next != NULL)
	{
		UndoSubTransaction *cursubxact = UndoState.subxact;
		UndoSubTransaction *nextsubxact = cursubxact->next;
		int			i;

		for (i = 0; i < NUndoPersistenceLevels; ++i)
			if (!UndoRecPtrIsValid(nextsubxact->start_location[i]))
				nextsubxact->start_location[i] = cursubxact->start_location[i];
		pfree(cursubxact);
		UndoState.subxact = nextsubxact;
	}

	/* Figure out whether there any relevant temporary undo. */
	has_temporary_undo =
		UndoRecPtrIsValid(UndoState.subxact->start_location[UNDOPERSISTENCE_TEMP]);

	if (UndoState.is_undo)
	{
		/*
		 * Regrettably, we seem to have failed when attempting to perform undo
		 * actions. First, try to reschedule any undo request for later
		 * background processing, so that we don't lose track of it.
		 */
		if (UndoState.my_request != NULL)
			RescheduleUndoRequest(UndoState.manager, UndoState.my_request);

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
	if (UndoState.my_request == NULL)
	{
		if (!has_temporary_undo)
			ResetUndoState();
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
	request_size = UndoState.total_size[UNDOPERSISTENCE_PERMANENT] +
		UndoState.total_size[UNDOPERSISTENCE_UNLOGGED];
	end_location_logged =
		GetUndoRecordEndPtr(UndoState.last_location[UNDOPERSISTENCE_PERMANENT],
							UndoState.last_size[UNDOPERSISTENCE_PERMANENT]);
	end_location_unlogged =
		GetUndoRecordEndPtr(UndoState.last_location[UNDOPERSISTENCE_UNLOGGED],
							UndoState.last_size[UNDOPERSISTENCE_UNLOGGED]);
	FinalizeUndoRequest(UndoState.manager, UndoState.my_request, request_size,
						UndoState.subxact->start_location[UNDOPERSISTENCE_PERMANENT],
						UndoState.subxact->start_location[UNDOPERSISTENCE_UNLOGGED],
						end_location_logged,
						end_location_unlogged);

	/*
	 * We have generated undo for permanent and/or unlogged tables.  If the
	 * caller can't perform foreground undo, force the request into the
	 * background; otherwise, let PerformUndoInBackground tell us whether
	 * background undo is appropriate.
	 */
	if (PerformUndoInBackground(UndoState.manager, UndoState.my_request,
								perform_foreground_undo == NULL))
	{
		if (!has_temporary_undo)
		{
			/* No temporary undo, and everything else in the background. */
			ResetUndoState();
			return;
		}

		/*
		 * Permanent and unloged undo in the background, but temporary undo is
		 * still our problem.
		 */
		UndoState.my_request = NULL;
		UndoState.subxact->start_location[UNDOPERSISTENCE_PERMANENT] = InvalidUndoRecPtr;
		UndoState.subxact->start_location[UNDOPERSISTENCE_UNLOGGED] = InvalidUndoRecPtr;
		UndoState.last_location[UNDOPERSISTENCE_PERMANENT] = InvalidUndoRecPtr;
		UndoState.last_location[UNDOPERSISTENCE_UNLOGGED] = InvalidUndoRecPtr;
		UndoState.last_size[UNDOPERSISTENCE_PERMANENT] = 0;
		UndoState.last_size[UNDOPERSISTENCE_UNLOGGED] = 0;
		UndoState.total_size[UNDOPERSISTENCE_PERMANENT] = 0;
		UndoState.total_size[UNDOPERSISTENCE_UNLOGGED] = 0;
	}

	/* Instruct caller to perform foreground undo, if possible. */
	if (perform_foreground_undo)
		*perform_foreground_undo = true;
}

/*
 * Clean up of the undo state following a subtransaction commit.
 *
 * Like AtCommit_UndoState, this must not fail.
 */
void
AtSubCommit_UndoState(int level)
{
	UndoSubTransaction *cursubxact = UndoState.subxact;
	UndoSubTransaction *nextsubxact = cursubxact->next;
	int			i;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!UndoState.has_undo || cursubxact->nestingLevel < level)
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
	UndoState.subxact = nextsubxact;
}

/*
 * Clean up of the undo state following a subtransaction abort.
 */
void
AtSubAbort_UndoState(int level, bool *perform_foreground_undo)
{
	UndoSubTransaction *cursubxact = UndoState.subxact;
	bool		has_temporary_undo = false;

	if (perform_foreground_undo)
		*perform_foreground_undo = false;

	/* Exit quickly if the transaction or this subtransaction has no undo. */
	if (!UndoState.has_undo || cursubxact->nestingLevel < level)
		return;

	/* Figure out whether there any relevant temporary undo. */
	has_temporary_undo =
		UndoRecPtrIsValid(UndoState.subxact->start_location[UNDOPERSISTENCE_TEMP]);

	/*
	 * Regrettably, we seem to have failed when attempting to perform undo
	 * actions. It's impossible to continue with the parent (sub)transaction
	 * without completing undo.
	 */
	if (UndoState.is_undo)
		 /* XXX. How do we fail the parent subtransaction, exactly? */ ;

	/*
	 * XXX. We need to avoid doing foreground undo for things that have
	 * already been successfully undone as a result of previous subtransaction
	 * aborts.
	 */
}

/*
 * Reset backend-local undo state.
 */
static void
ResetUndoState(void)
{
	int			i;

	UndoState.my_request = NULL;
	UndoState.is_undo = false;
	UndoState.is_background_undo = false;
	UndoState.has_undo = false;
	UndoState.subxact = &UndoTopState;
	UndoTopState.nestingLevel = 1;
	UndoTopState.next = NULL;

	for (i = 0; i < NUndoPersistenceLevels; ++i)
	{
		UndoTopState.start_location[i] = InvalidUndoRecPtr;
		UndoState.last_location[i] = InvalidUndoRecPtr;
		UndoState.last_size[i] = 0;
		UndoState.total_size[i] = 0;
	}
}

/*
 * Add the size of an undo record to the location where it starts to find the end
 * location.
 */
static UndoRecPtr
GetUndoRecordEndPtr(UndoRecPtr start_location, Size size)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(start_location);
	UndoLogOffset offset = UndoRecPtrGetOffset(start_location);

	offset = UndoLogOffsetPlusUsableBytes(offset, size);
	return MakeUndoRecPtr(logno, offset);
}
