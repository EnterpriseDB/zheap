/*-------------------------------------------------------------------------
 *
 * undoworker.c
 *	  undo launcher and undo worker process.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/undoworker.c
 *
 * Undo launcher is responsible for launching the workers iff there is some
 * work available in one of work queues and there are more workers available.
 * To know more about work queues, see undorequest.c.  The worker is launched
 * to handle requests for a particular database.
 *
 * Each undo worker then start reading from one of the queue the requests for
 * that particular database.  A worker would peek into each queue for the
 * requests from a particular database, if it needs to switch a database in
 * less than undo_worker_quantum ms after starting.  Also, if there is no
 * work, it lingers for UNDO_WORKER_LINGER_MS.  This avoids restarting
 * the workers too frequently.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "funcapi.h"
#include "miscadmin.h"
#include "pgstat.h"

#include "access/genam.h"
#include "access/table.h"
#include "access/xact.h"
#include "access/undorequest.h"
#include "access/undoworker.h"

#include "libpq/pqsignal.h"

#include "postmaster/bgworker.h"
#include "postmaster/fork_process.h"
#include "postmaster/postmaster.h"

#include "replication/slot.h"
#include "replication/worker_internal.h"

#include "storage/ipc.h"
#include "storage/lmgr.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "storage/procsignal.h"

#include "tcop/tcopprot.h"

#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/resowner.h"


/*
 * GUC parameters
 */
int			max_undo_workers = 4;

/*
 * If a worker would need to switch databases in less than undo_worker_quantum
 * (10s as default) after starting, it peeks a few entries deep into each
 * queue to see whether there's work for that database.
 */
int			undo_worker_quantum_ms = 10000;

/* max sleep time between cycles (100 milliseconds) */
#define DEFAULT_NAPTIME_PER_CYCLE 100L

/*
 * Time for which undo worker can linger if there is no work, in
 * milliseconds.  This has to be more than UNDO_FAILURE_RETRY_DELAY_MS,
 * otherwise, worker can exit before retrying the failed requests.
 */
#define UNDO_WORKER_LINGER_MS 20000

/* Flags set by signal handlers */
static volatile sig_atomic_t got_SIGHUP = false;
static volatile sig_atomic_t got_SIGTERM = false;

static TimestampTz last_xact_processed_at;

typedef struct UndoApplyWorker
{
	/* Indicates if this slot is used or free. */
	bool		in_use;

	/* Increased every time the slot is taken by new worker. */
	uint16		generation;

	/* Pointer to proc array. NULL if not running. */
	PGPROC	   *proc;

	/* Database id this worker is connected to. */
	Oid			dbid;

	/* this tells whether worker is lingering. */
	bool		lingering;

	/*
	 * This tells the undo worker from which undo worker queue it should start
	 * processing.
	 */
	UndoWorkerQueueType undo_worker_queue;
} UndoApplyWorker;

UndoApplyWorker *MyUndoWorker = NULL;

typedef struct UndoApplyCtxStruct
{
	/* Supervisor process. */
	pid_t		launcher_pid;

	/* latch to wake up undo launcher. */
	Latch	   *undo_launcher_latch;

	/* Background workers. */
	UndoApplyWorker workers[FLEXIBLE_ARRAY_MEMBER];
} UndoApplyCtxStruct;

UndoApplyCtxStruct *UndoApplyCtx;

static void UndoWorkerOnExit(int code, Datum arg);
static void UndoWorkerCleanup(UndoApplyWorker *worker);
static void UndoWorkerIsLingering(bool sleep);
static void UndoWorkerGetSlotInfo(int slot, UndoRequestInfo *urinfo);
static void UndoworkerSigtermHandler(SIGNAL_ARGS);

/*
 * Cleanup function for undo worker launcher.
 *
 * Called on undo worker launcher exit.
 */
static void
UndoLauncherOnExit(int code, Datum arg)
{
	UndoApplyCtx->launcher_pid = 0;
	UndoApplyCtx->undo_launcher_latch = NULL;
}

/* SIGTERM: set flag to exit at next convenient time */
static void
UndoworkerSigtermHandler(SIGNAL_ARGS)
{
	got_SIGTERM = true;

	/* Waken anything waiting on the process latch */
	SetLatch(MyLatch);
}

/* SIGHUP: set flag to reload configuration at next convenient time */
static void
UndoLauncherSighup(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGHUP = true;

	/* Waken anything waiting on the process latch */
	SetLatch(MyLatch);

	errno = save_errno;
}

/*
 * Wait for a background worker to start up and attach to the shmem context.
 *
 * This is only needed for cleaning up the shared memory in case the worker
 * fails to attach.
 */
static void
WaitForUndoWorkerAttach(UndoApplyWorker * worker,
						uint16 generation,
						BackgroundWorkerHandle *handle)
{
	BgwHandleStatus status;
	int			rc;

	for (;;)
	{
		pid_t		pid;

		CHECK_FOR_INTERRUPTS();

		LWLockAcquire(UndoWorkerLock, LW_SHARED);

		/* Worker either died or has started; no need to do anything. */
		if (!worker->in_use || worker->proc)
		{
			LWLockRelease(UndoWorkerLock);
			return;
		}

		LWLockRelease(UndoWorkerLock);

		/* Check if worker has died before attaching, and clean up after it. */
		status = GetBackgroundWorkerPid(handle, &pid);

		if (status == BGWH_STOPPED)
		{
			LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);
			/* Ensure that this was indeed the worker we waited for. */
			if (generation == worker->generation)
				UndoWorkerCleanup(worker);
			LWLockRelease(UndoWorkerLock);
			return;
		}

		/*
		 * We need timeout because we generally don't get notified via latch
		 * about the worker attach.  But we don't expect to have to wait long.
		 */
		rc = WaitLatch(MyLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   10L, WAIT_EVENT_BGWORKER_STARTUP);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		if (rc & WL_LATCH_SET)
		{
			ResetLatch(MyLatch);
			CHECK_FOR_INTERRUPTS();
		}
	}

	return;
}

/*
 * Attach to a slot.
 */
static void
UndoWorkerAttach(int slot)
{
	/* Block concurrent access. */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	MyUndoWorker = &UndoApplyCtx->workers[slot];

	if (!MyUndoWorker->in_use)
	{
		LWLockRelease(UndoWorkerLock);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("undo worker slot %d is empty, cannot attach",
						slot)));
	}

	if (MyUndoWorker->proc)
	{
		LWLockRelease(UndoWorkerLock);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("undo worker slot %d is already used by "
						"another worker, cannot attach", slot)));
	}

	MyUndoWorker->proc = MyProc;
	before_shmem_exit(UndoWorkerOnExit, (Datum) 0);

	LWLockRelease(UndoWorkerLock);
}

/*
 * Returns whether an undo worker is available.
 */
static int
IsUndoWorkerAvailable(void)
{
	int			i;
	int			alive_workers = 0;

	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	/* Search for attached workers. */
	for (i = 0; i < max_undo_workers; i++)
	{
		UndoApplyWorker *w = &UndoApplyCtx->workers[i];

		if (w->in_use)
			alive_workers++;
	}

	LWLockRelease(UndoWorkerLock);

	return (alive_workers < max_undo_workers);
}

/* Sets the worker's lingering status. */
static void
UndoWorkerIsLingering(bool sleep)
{
	/* Block concurrent access. */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	MyUndoWorker->lingering = sleep;

	LWLockRelease(UndoWorkerLock);
}

/* Get the dbid and undo worker queue set by the undo launcher. */
static void
UndoWorkerGetSlotInfo(int slot, UndoRequestInfo *urinfo)
{
	/* Block concurrent access. */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	MyUndoWorker = &UndoApplyCtx->workers[slot];

	if (!MyUndoWorker->in_use)
	{
		LWLockRelease(UndoWorkerLock);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("undo worker slot %d is empty",
						slot)));
	}

	urinfo->dbid = MyUndoWorker->dbid;
	urinfo->undo_worker_queue = MyUndoWorker->undo_worker_queue;

	LWLockRelease(UndoWorkerLock);
}

/*
 * Start new undo apply background worker, if possible otherwise return false.
 */
static bool
UndoWorkerLaunch(UndoRequestInfo urinfo)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;
	uint16		generation;
	int			i;
	int			slot = 0;
	UndoApplyWorker *worker = NULL;

	/*
	 * We need to do the modification of the shared memory under lock so that
	 * we have consistent view.
	 */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	/* Find unused worker slot. */
	for (i = 0; i < max_undo_workers; i++)
	{
		UndoApplyWorker *w = &UndoApplyCtx->workers[i];

		if (!w->in_use)
		{
			worker = w;
			slot = i;
			break;
		}
	}

	/* We must not try to start a worker if there are no available workers. */
	Assert(worker != NULL);

	/* Prepare the worker slot. */
	worker->in_use = true;
	worker->proc = NULL;
	worker->dbid = urinfo.dbid;
	worker->lingering = false;
	worker->undo_worker_queue = urinfo.undo_worker_queue;
	worker->generation++;

	generation = worker->generation;
	LWLockRelease(UndoWorkerLock);

	/* Register the new dynamic worker. */
	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "UndoWorkerMain");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "undo apply worker");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "undo apply worker");

	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = Int32GetDatum(slot);

	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
	{
		/* Failed to start worker, so clean up the worker slot. */
		LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);
		UndoWorkerCleanup(worker);
		LWLockRelease(UndoWorkerLock);

		return false;
	}

	/* Now wait until it attaches. */
	WaitForUndoWorkerAttach(worker, generation, bgw_handle);

	return true;
}

/*
 * Detach the worker (cleans up the worker info).
 */
static void
UndoWorkerDetach(void)
{
	/* Block concurrent access. */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	UndoWorkerCleanup(MyUndoWorker);

	LWLockRelease(UndoWorkerLock);
}

/*
 * Clean up worker info.
 */
static void
UndoWorkerCleanup(UndoApplyWorker * worker)
{
	Assert(LWLockHeldByMeInMode(UndoWorkerLock, LW_EXCLUSIVE));

	worker->in_use = false;
	worker->proc = NULL;
	worker->dbid = InvalidOid;
	worker->lingering = false;
	worker->undo_worker_queue = InvalidUndoWorkerQueue;
}

/*
 * Cleanup function.
 *
 * Called on undo worker exit.
 */
static void
UndoWorkerOnExit(int code, Datum arg)
{
	UndoWorkerDetach();
}

/*
 * Perform rollback request.  We need to connect to the database for first
 * request and that is required because we access system tables while
 * performing undo actions.
 */
static void
UndoWorkerPerformRequest(UndoRequestInfo * urinfo)
{
	bool error = false;

	/* must be connected to the database. */
	Assert(MyDatabaseId != InvalidOid);

	StartTransactionCommand();
	PG_TRY();
	{
		execute_undo_actions(urinfo->full_xid, urinfo->end_urec_ptr,
							 urinfo->start_urec_ptr, true);
	}
	PG_CATCH();
	{
		error = true;

		/*
		 * Register the unprocessed request in an error queue, so that it can
		 * be processed in a timely fashion.  If we fail to add the request in
		 * an error queue, then mark the entry status invalid.  This request
		 * will be later added back to the queue by the discard worker.
		 */
		if (!InsertRequestIntoErrorUndoQueue(urinfo))
			RollbackHTMarkEntryInvalid(urinfo->full_xid,
									   urinfo->start_urec_ptr);

		/* Prevent interrupts while cleaning up. */
		HOLD_INTERRUPTS();

		/* Send the error only to server log. */
		err_out_to_client(false);
		EmitErrorReport();

		/*
		 * Abort the transaction and continue processing pending undo requests.
		 */
		AbortOutOfAnyTransaction();
		FlushErrorState();

		RESUME_INTERRUPTS();
	}
	PG_END_TRY();

	if (!error)
		CommitTransactionCommand();
}

/*
 * UndoLauncherShmemSize
 *		Compute space needed for undo launcher shared memory
 */
Size
UndoLauncherShmemSize(void)
{
	Size		size;

	/*
	 * Need the fixed struct and the array of LogicalRepWorker.
	 */
	size = sizeof(UndoApplyCtxStruct);
	size = MAXALIGN(size);
	size = add_size(size, mul_size(max_undo_workers,
								   sizeof(UndoApplyWorker)));
	return size;
}

/*
 * UndoLauncherShmemInit
 *		Allocate and initialize undo worker launcher shared memory
 */
void
UndoLauncherShmemInit(void)
{
	bool		found;

	UndoApplyCtx = (UndoApplyCtxStruct *)
		ShmemInitStruct("Undo Worker Launcher Data",
						UndoLauncherShmemSize(),
						&found);

	if (!found)
		memset(UndoApplyCtx, 0, UndoLauncherShmemSize());
}

/*
 * UndoLauncherRegister
 *		Register a background worker running the undo worker launcher.
 */
void
UndoLauncherRegister(void)
{
	BackgroundWorker bgw;

	if (max_undo_workers == 0)
		return;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "UndoLauncherMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN,
			 "undo worker launcher");
	snprintf(bgw.bgw_type, BGW_MAXLEN,
			 "undo worker launcher");
	bgw.bgw_restart_time = 5;
	bgw.bgw_notify_pid = 0;
	bgw.bgw_main_arg = (Datum)0;

	RegisterBackgroundWorker(&bgw);
}

/*
 * Main loop for the undo worker launcher process.
 */
void
UndoLauncherMain(Datum main_arg)
{
	UndoRequestInfo urinfo;

	ereport(DEBUG1,
			(errmsg("undo launcher started")));

	before_shmem_exit(UndoLauncherOnExit, (Datum) 0);

	Assert(UndoApplyCtx->launcher_pid == 0);
	UndoApplyCtx->launcher_pid = MyProcPid;

	/* Establish signal handlers. */
	pqsignal(SIGHUP, UndoLauncherSighup);
	pqsignal(SIGTERM, UndoworkerSigtermHandler);
	BackgroundWorkerUnblockSignals();

	/* Establish connection to nailed catalogs. */
	BackgroundWorkerInitializeConnection(NULL, NULL, 0);

	/*
	 * Advertise our latch that undo request enqueuer can use to wake us up
	 * while we're sleeping.
	 */
	UndoApplyCtx->undo_launcher_latch = &MyProc->procLatch;

	/* Enter main loop */
	while (!got_SIGTERM)
	{
		int			rc;

		CHECK_FOR_INTERRUPTS();

		ResetUndoRequestInfo(&urinfo);

		if (UndoGetWork(false, false, &urinfo, NULL) &&
			IsUndoWorkerAvailable())
			UndoWorkerLaunch(urinfo);

		/* Wait for more work. */
		rc = WaitLatch(MyLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   DEFAULT_NAPTIME_PER_CYCLE,
					   WAIT_EVENT_UNDO_LAUNCHER_MAIN);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		if (rc & WL_LATCH_SET)
		{
			ResetLatch(MyLatch);
			CHECK_FOR_INTERRUPTS();
		}

		if (got_SIGHUP)
		{
			got_SIGHUP = false;
			ProcessConfigFile(PGC_SIGHUP);
		}
	}

	/* Normal exit from undo launcher main */
	ereport(LOG,
			(errmsg("undo launcher shutting down")));
	proc_exit(0);
}

/*
 * UndoWorkerMain -- Main loop for the undo apply worker.
 */
void
UndoWorkerMain(Datum main_arg)
{
	UndoRequestInfo urinfo;
	int			worker_slot = DatumGetInt32(main_arg);
	bool		in_other_db;
	bool		found_work;
	TimestampTz started_at;

	/* Setup signal handling */
	pqsignal(SIGTERM, UndoworkerSigtermHandler);
	BackgroundWorkerUnblockSignals();

	ResetUndoRequestInfo(&urinfo);
	started_at = GetCurrentTimestamp();

	/*
	 * Get the dbid where the wroker should connect to and get the worker
	 * request queue from which the worker should start looking for an undo
	 * request.
	 */
	UndoWorkerGetSlotInfo(worker_slot, &urinfo);

	/* Connect to the requested database. */
	BackgroundWorkerInitializeConnectionByOid(urinfo.dbid, 0, 0);

	/*
	 * Set the undo worker request queue from which the undo worker start
	 * looking for a work.
	 */
	SetUndoWorkerQueueStart(urinfo.undo_worker_queue);

	/*
	 * Before attaching the worker, fetch and remove the undo request for
	 * which the undo launcher has launched this worker.  This restricts the
	 * undo launcher from launching multiple workers for the same request.
	 * But, it's possible that the undo request has already been processed by
	 * other in-progress undo worker.  In that case, we enter the undo worker
	 * main loop and fetch the next request.
	 */
	found_work = UndoGetWork(false, true, &urinfo, &in_other_db);

	/* Attach to slot */
	UndoWorkerAttach(worker_slot);

	if (found_work && !in_other_db)
	{
		/* We must have got the pending undo request. */
		Assert(FullTransactionIdIsValid(urinfo.full_xid));
		UndoWorkerPerformRequest(&urinfo);
		last_xact_processed_at = GetCurrentTimestamp();
	}

	while (!got_SIGTERM)
	{
		int			rc;
		bool		allow_peek;

		CHECK_FOR_INTERRUPTS();

		allow_peek = !TimestampDifferenceExceeds(started_at,
												 GetCurrentTimestamp(),
												 undo_worker_quantum_ms);

		found_work = UndoGetWork(allow_peek, true, &urinfo, &in_other_db);

		if (found_work && in_other_db)
		{
			proc_exit(0);
		}
		else if (found_work)
		{
			/* We must have got the pending undo request. */
			Assert(FullTransactionIdIsValid(urinfo.full_xid));
			UndoWorkerPerformRequest(&urinfo);
			last_xact_processed_at = GetCurrentTimestamp();
		}
		else
		{
			TimestampTz timeout = 0;

			timeout = TimestampTzPlusMilliseconds(last_xact_processed_at,
												  UNDO_WORKER_LINGER_MS);

			/*
			 * We don't need to linger if we have already spent
			 * UNDO_WORKER_LINGER_MS since last transaction has processed.
			 */
			if (timeout <= GetCurrentTimestamp())
			{
				proc_exit(0);
			}

			/*
			 * Update the shared state to reflect that this worker is
			 * lingering so that if there is new work request, requester can
			 * wake us up.
			 */
			UndoWorkerIsLingering(true);

			/* Wait for more work. */
			rc = WaitLatch(MyLatch,
						   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
						   DEFAULT_NAPTIME_PER_CYCLE,
						   WAIT_EVENT_UNDO_WORKER_MAIN);

			/* reset the shared state. */
			UndoWorkerIsLingering(false);

			/* emergency bailout if postmaster has died */
			if (rc & WL_POSTMASTER_DEATH)
				proc_exit(1);

			if (rc & WL_LATCH_SET)
			{
				ResetLatch(MyLatch);
				CHECK_FOR_INTERRUPTS();
			}

			if (got_SIGHUP)
			{
				got_SIGHUP = false;
				ProcessConfigFile(PGC_SIGHUP);
			}
		}
	}

	/* Normal exit from undo worker main */
	proc_exit(0);
}

/*
 * Wake up undo worker so that undo requests can be processed in a timely
 * fashion.
 *
 * We first try to wake up the lingering worker in the given database.  If we
 * found even one such worker, we are done.
 *
 * Next, we try to stop some worker which is lingering, but doesn't belong to
 * the given database.  We know that any worker which is lingering doesn't have
 * any pending work, so it is fine to stop it when we know that there is going
 * to be some work in the other database.
 *
 * Finally, we wakeup launcher so that it can either restart the worker we have
 * stopped or find some other worker who can take up this request.
 */
void
WakeupUndoWorker(Oid dbid)
{
	int			i;

	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	/* wake up lingering worker in the given database. */
	for (i = 0; i < max_undo_workers; i++)
	{
		UndoApplyWorker *w = &UndoApplyCtx->workers[i];

		if (w->in_use && w->lingering && w->dbid == dbid)
		{
			SetLatch(&w->proc->procLatch);

			LWLockRelease(UndoWorkerLock);
			return;
		}
	}

	/*
	 * Stop one of the lingering worker which is not processing the requests
	 * in the given database.
	 */
	for (i = 0; i < max_undo_workers; i++)
	{
		UndoApplyWorker *w = &UndoApplyCtx->workers[i];

		if (w->in_use && w->lingering && w->dbid != dbid)
			kill(w->proc->pid, SIGTERM);
	}

	if (UndoApplyCtx->undo_launcher_latch)
		SetLatch(UndoApplyCtx->undo_launcher_latch);

	LWLockRelease(UndoWorkerLock);

	return;
}
