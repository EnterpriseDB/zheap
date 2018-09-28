/*-------------------------------------------------------------------------
 *
 * undoworker.c
 *	  undo launcher and undo worker process.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/undoworker.c
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "funcapi.h"
#include "miscadmin.h"
#include "pgstat.h"

#include "access/heapam.h"
#include "access/htup.h"
#include "access/htup_details.h"
#include "access/xact.h"

#include "libpq/pqsignal.h"

#include "postmaster/bgworker.h"
#include "postmaster/fork_process.h"
#include "postmaster/postmaster.h"
#include "postmaster/undoloop.h"
#include "postmaster/undoworker.h"

#include "replication/slot.h"
#include "replication/worker_internal.h"

#include "storage/ipc.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "storage/procsignal.h"

#include "tcop/tcopprot.h"

#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/resowner.h"

/* max sleep time between cycles (100 milliseconds) */
#define DEFAULT_NAPTIME_PER_CYCLE 100L
#define DEFAULT_RETRY_NAPTIME 50L

int			max_undo_workers = 5;

typedef struct UndoApplyWorker
{
	/* Indicates if this slot is used or free. */
	bool		in_use;

	/* Increased everytime the slot is taken by new worker. */
	uint16		generation;

	/* Pointer to proc array. NULL if not running. */
	PGPROC	   *proc;

	/* Database id to connect to. */
	Oid			dbid;
} UndoApplyWorker;

UndoApplyWorker *MyUndoWorker = NULL;

typedef struct UndoApplyCtxStruct
{
	/* Supervisor process. */
	pid_t		launcher_pid;

	/* Background workers. */
	UndoApplyWorker workers[FLEXIBLE_ARRAY_MEMBER];
} UndoApplyCtxStruct;

UndoApplyCtxStruct *UndoApplyCtx;

static void undo_worker_onexit(int code, Datum arg);
static void undo_worker_cleanup(UndoApplyWorker *worker);

static volatile sig_atomic_t got_SIGHUP = false;

/*
 * Wait for a background worker to start up and attach to the shmem context.
 *
 * This is only needed for cleaning up the shared memory in case the worker
 * fails to attach.
 */
static void
WaitForUndoWorkerAttach(UndoApplyWorker *worker,
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
				undo_worker_cleanup(worker);
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
static Oid
undo_worker_attach(int slot)
{
	Oid dbid;

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
	dbid = MyUndoWorker->dbid;
	before_shmem_exit(undo_worker_onexit, (Datum) 0);

	LWLockRelease(UndoWorkerLock);

	return dbid;
}

/*
 * Walks the workers array and searches for one that matches given
 * dbid.
 */
static UndoApplyWorker *
undo_worker_find(Oid dbid)
{
	int			i;
	UndoApplyWorker *res = NULL;

	Assert(LWLockHeldByMe(UndoWorkerLock));

	/* Search for attached worker for a given db id. */
	for (i = 0; i < max_undo_workers; i++)
	{
		UndoApplyWorker *w = &UndoApplyCtx->workers[i];

		if (w->in_use && w->dbid == dbid)
		{
			res = w;
			break;
		}
	}

	return res;
}

/*
 * Start new undo apply background worker, if possible otherwise return false.
 */
static bool
undo_worker_launch(Oid dbid)
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

	/* There are no more free worker slots */
	if (worker == NULL)
		return false;

	/* Prepare the worker slot. */
	worker->in_use = true;
	worker->proc = NULL;
	worker->dbid = dbid;
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
		undo_worker_cleanup(worker);
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
undo_worker_detach(void)
{
	/* Block concurrent access. */
	LWLockAcquire(UndoWorkerLock, LW_EXCLUSIVE);

	undo_worker_cleanup(MyUndoWorker);

	LWLockRelease(UndoWorkerLock);
}

/*
 * Clean up worker info.
 */
static void
undo_worker_cleanup(UndoApplyWorker *worker)
{
	Assert(LWLockHeldByMeInMode(UndoWorkerLock, LW_EXCLUSIVE));

	worker->in_use = false;
	worker->proc = NULL;
	worker->dbid = InvalidOid;
}

/*
 * Cleanup function for undo worker launcher.
 *
 * Called on undo worker launcher exit.
 */
static void
undo_launcher_onexit(int code, Datum arg)
{
	UndoApplyCtx->launcher_pid = 0;
}

/* SIGHUP: set flag to reload configuration at next convenient time */
static void
undo_launcher_sighup(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGHUP = true;

	/* Waken anything waiting on the process latch */
	SetLatch(MyLatch);

	errno = save_errno;
}

/*
 * Cleanup function.
 *
 * Called on logical replication worker exit.
 */
static void
undo_worker_onexit(int code, Datum arg)
{
	undo_worker_detach();
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
	bgw.bgw_main_arg = (Datum) 0;

	RegisterBackgroundWorker(&bgw);
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
 * Main loop for the undo worker launcher process.
 */
void
UndoLauncherMain(Datum main_arg)
{
	MemoryContext tmpctx;
	MemoryContext oldctx;

	ereport(DEBUG1,
			(errmsg("undo launcher started")));

	before_shmem_exit(undo_launcher_onexit, (Datum) 0);

	Assert(UndoApplyCtx->launcher_pid == 0);
	UndoApplyCtx->launcher_pid = MyProcPid;

	/* Establish signal handlers. */
	pqsignal(SIGHUP, undo_launcher_sighup);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	/*
	 * Establish connection to nailed catalogs (we only ever access
	 * pg_subscription).
	 */
	BackgroundWorkerInitializeConnection(NULL, NULL, 0);

	/* Use temporary context for the database list and worker info. */
	tmpctx = AllocSetContextCreate(TopMemoryContext,
								   "Undo worker Launcher context",
								   ALLOCSET_DEFAULT_SIZES);
	/* Enter main loop */
	for (;;)
	{
		int			rc;
		HTAB	   *dbhash;
		Oid		   *dbid;
		HASH_SEQ_STATUS status;

		CHECK_FOR_INTERRUPTS();

		oldctx = MemoryContextSwitchTo(tmpctx);

		dbhash = RollbackHTGetDBList(tmpctx);

		hash_seq_init(&status, dbhash);
		while ((dbid = (Oid *) hash_seq_search(&status)) != NULL)
		{
			UndoApplyWorker *w;

			LWLockAcquire(UndoWorkerLock, LW_SHARED);
			w = undo_worker_find(*dbid);
			LWLockRelease(UndoWorkerLock);

			if (w == NULL)
			{
retry:
				if (!undo_worker_launch(*dbid))
				{
					/* Could not launch the worker, retry after sometime, */
					rc = WaitLatch(MyLatch,
								   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
								   DEFAULT_RETRY_NAPTIME,
								   WAIT_EVENT_UNDO_LAUNCHER_MAIN);
					goto retry;
				}
			}
		}

		/* Switch back to original memory context. */
		MemoryContextSwitchTo(oldctx);

		/* Clean the temporary memory. */
		MemoryContextReset(tmpctx);

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
}

/*
 * UndoWorkerMain -- Main loop for the undo apply worker.
 */
void
UndoWorkerMain(Datum main_arg)
{
	int		worker_slot = DatumGetInt32(main_arg);
	Oid		dbid;

	/* Attach to slot */
	dbid = undo_worker_attach(worker_slot);

	/* Setup signal handling */
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	BackgroundWorkerInitializeConnectionByOid(dbid, 0, 0);

	/*
	 * Create resource owner for undo worker.  Undo worker need this as it
	 * need to read the undo records  outside the transaction blocks which
	 * intern access buffer read routine.
	 */
	CreateAuxProcessResourceOwner();

	RollbackFromHT(dbid);

	ReleaseAuxProcessResources(true);

	proc_exit(0);
}
