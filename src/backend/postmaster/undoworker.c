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
#define DEFAULT_NAPTIME_PER_CYCLE 100L

static bool got_SIGTERM = false;

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

	BackgroundWorkerInitializeConnection(NULL, NULL);

	/* Enter main loop */
	while (!got_SIGTERM)
	{
		int			rc;
		long		wait_time = DEFAULT_NAPTIME_PER_CYCLE;
		TransactionId OldestXmin;

		OldestXmin = GetOldestXmin(NULL, true);

		/* Discard UNDO's of xid < OldestXmin */
		if (OldestXmin != InvalidTransactionId)
			UndoDiscard(OldestXmin);

		/* Wait for more work. */
		rc = WaitLatch(&MyProc->procLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   wait_time,
					   WAIT_EVENT_UNDO_LAUNCHER_MAIN);

		ResetLatch(&MyProc->procLatch);

		/* emergency bailout if postmaster has died */
		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);
	}

	/* we're done */
	ereport(LOG,
			(errmsg("undo launcher shutting down")));

	proc_exit(0);
}
