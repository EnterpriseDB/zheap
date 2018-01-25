/*-------------------------------------------------------------------------
 * undoworker.c
 *	   The undo worker for asynchronous undo management.
 *
 * Copyright (c) 2016-2017, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/undo/undoworker.c
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include <unistd.h>

/* These are always necessary for a bgworker. */
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/shmem.h"

#include "access/undodiscard.h"
#include "pgstat.h"
#include "postmaster/undoworker.h"
#include "storage/procarray.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"

static void undoworker_sigterm_handler(SIGNAL_ARGS);

/* max sleep time between cycles (100 milliseconds) */
#define MIN_NAPTIME_PER_CYCLE 100L
#define DELAYED_NAPTIME 10 * MIN_NAPTIME_PER_CYCLE
#define MAX_NAPTIME_PER_CYCLE 100 * MIN_NAPTIME_PER_CYCLE

static bool got_SIGTERM = false;
static bool hibernate = false;
static	long		wait_time = MIN_NAPTIME_PER_CYCLE;

/* SIGTERM: set flag to exit at next convenient time */
static void
undoworker_sigterm_handler(SIGNAL_ARGS)
{
	got_SIGTERM = true;

	/* Waken anything waiting on the process latch */
	SetLatch(MyLatch);
}

/*
 * UndoLauncherRegister -- Register a undo worker.
 */
void
UndoLauncherRegister(void)
{
	BackgroundWorker bgw;

	/* TODO: This should be configurable. */

	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_name, BGW_MAXLEN, "undo launcher");
	sprintf(bgw.bgw_library_name, "postgres");
	sprintf(bgw.bgw_function_name, "UndoWorkerMain");
	bgw.bgw_restart_time = 5;
	bgw.bgw_notify_pid = 0;
	bgw.bgw_main_arg = (Datum) 0;

	RegisterBackgroundWorker(&bgw);
}

/*
 * UndoWorkerMain -- Main loop for the undo launcher process.
 */
void
UndoWorkerMain(Datum main_arg)
{
	ereport(LOG,
			(errmsg("undo launcher started")));

	/* Establish signal handlers. */
	pqsignal(SIGTERM, undoworker_sigterm_handler);
	BackgroundWorkerUnblockSignals();

	/* Make it easy to identify our processes. */
	SetConfigOption("application_name", MyBgworkerEntry->bgw_name,
					PGC_USERSET, PGC_S_SESSION);

	/*
	 * FIXME: This is to ensure that we can have a database connection for
	 * undo worker, which is required while performing undo actions. In future,
	 * this should either be done without a database connection or there should
	 * be a means to specify which database to connect.
	 */
	BackgroundWorkerInitializeConnection("postgres", NULL, 0);

	/* Enter main loop */
	while (!got_SIGTERM)
	{
		int			rc;
		TransactionId OldestXmin, oldestXidHavingUndo;

		OldestXmin = GetOldestXmin(NULL, true);
		oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

		/*
		 * Discard UNDO's if xid < OldestXmin and
		 * OldestXmin is greater than oldestXidHavingUndo.
		 */
		if (OldestXmin != InvalidTransactionId &&
			TransactionIdPrecedes(oldestXidHavingUndo, OldestXmin))
		{
			UndoDiscard(OldestXmin, &hibernate);

			/*
			 * If we got some undo logs to discard or discarded something,
			 * then reset the wait_time as we have got work to do.
			 * Note that if there are some undologs that cannot be discarded,
			 * then above condition will remain unsatisified till oldestXmin
			 * remains unchanged and the wait_time will not reset in that case.
			 */
			if (!hibernate)
				wait_time = MIN_NAPTIME_PER_CYCLE;
		}

		/* Wait for more work. */
		rc = WaitLatch(&MyProc->procLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   wait_time,
					   WAIT_EVENT_UNDO_LAUNCHER_MAIN);

		ResetLatch(&MyProc->procLatch);

		/*
		 * Increase the wait_time based on the length of inactivity. If wait_time
		 * is within one second, then increment it by 100 ms at a time. Henceforth,
		 * increment it one second at a time, till it reaches ten seconds. Never
		 * increase the wait_time more than ten seconds, it will be too much of
		 * waiting otherwise.
		 */

		if (rc & WL_TIMEOUT && hibernate)
		{
			wait_time += (wait_time < DELAYED_NAPTIME ?
							MIN_NAPTIME_PER_CYCLE : DELAYED_NAPTIME);
			if (wait_time > MAX_NAPTIME_PER_CYCLE)
				wait_time = MAX_NAPTIME_PER_CYCLE;
		}

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);
	}

	/* we're done */
	ereport(LOG,
			(errmsg("undo launcher shutting down")));

	proc_exit(0);
}
