/*-------------------------------------------------------------------------
 *
 * discardworker.c
 *	  The undo discard worker for asynchronous undo management.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/discardworker.c
 *
 * The main responsibility of the discard worker is to discard the undo log
 * of transactions that are committed and all-visible or are rolledback.  It
 * also registers the request for aborted transactions in the work queues.
 * To know more about work queues, see undorequest.c.  It iterates through all
 * the active logs one-by-one and try to discard the transactions that are old
 * enough to matter.
 *
 * For tranasctions that spans across multiple logs, the log for committed and
 * all-visible transactions are discarded seprately for each log.  This is
 * possible as the transactions that span across logs have separate transaction
 * header for each log.  For aborted transactions, we try to process the actions
 * of entire transaction at one-shot as we need to perform the actions starting
 * from end location to start location.  However, it is possbile that the later
 * portion of transaction that is overflowed into a separate log can be
 * processed separately if we encounter the corresponding log first.  If we
 * want we can combine the log for processing in that case as well, but there
 * is no clear advantage of the same.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include <unistd.h>

#include "access/discardworker.h"
#include "access/undodiscard.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "storage/shmem.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"
#include "utils/resowner.h"

static void undoworker_sigterm_handler(SIGNAL_ARGS);

/* minimum and maximum sleep time for discard worker */
#define MIN_NAPTIME_PER_CYCLE 100L
#define DELAYED_NAPTIME 10 * MIN_NAPTIME_PER_CYCLE
#define MAX_NAPTIME_PER_CYCLE 100 * MIN_NAPTIME_PER_CYCLE

static volatile sig_atomic_t got_SIGTERM = false;
static bool hibernate = false;
static long wait_time = MIN_NAPTIME_PER_CYCLE;
static bool am_discard_worker = false;

/* SIGTERM: set flag to exit at next convenient time */
static void
undoworker_sigterm_handler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGTERM = true;

	/* Waken anything waiting on the process latch */
	SetLatch(MyLatch);

	errno = save_errno;
}

/*
 * DiscardWorkerRegister -- Register a undo discard worker.
 */
void
DiscardWorkerRegister(void)
{
	BackgroundWorker bgw;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS |
		BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_name, BGW_MAXLEN, "discard worker");
	sprintf(bgw.bgw_library_name, "postgres");
	sprintf(bgw.bgw_function_name, "DiscardWorkerMain");
	bgw.bgw_restart_time = 5;
	bgw.bgw_notify_pid = 0;
	bgw.bgw_main_arg = (Datum) 0;

	RegisterBackgroundWorker(&bgw);
}

/*
 * DiscardWorkerMain -- Main loop for the undo discard worker.
 */
void
DiscardWorkerMain(Datum main_arg)
{
	DiscardWorkerState worker_state;
	HASHCTL wait_table_control = {
		.keysize = sizeof(UndoLogNumber),
		.entrysize = sizeof(DiscardWaitTableEntry)
	};

	ereport(LOG,
			(errmsg("discard worker started")));

	/* Establish signal handlers. */
	pqsignal(SIGTERM, undoworker_sigterm_handler);
	BackgroundWorkerUnblockSignals();

	am_discard_worker = true;

	/* Make it easy to identify our processes. */
	SetConfigOption("application_name", MyBgworkerEntry->bgw_name,
					PGC_USERSET, PGC_S_SESSION);

	/* Establish connection to nailed catalogs. */
	BackgroundWorkerInitializeConnection(NULL, NULL, 0);

	/*
	 * Scan all the undo logs and intialize the rollback hash table with all
	 * the pending rollback requests.  This need to be done as a first step
	 * because only after this the transactions will be allowed to write new
	 * undo.  See comments atop UndoLogProcess.
	 */
	UndoLogProcess();

	/* Initialize the state UndoDiscard() will use between invocations. */
	worker_state.wait_table = hash_create("discard worker wait table",
										  1024,
										  &wait_table_control,
										  HASH_ELEM | HASH_BLOBS);

	/* Enter main loop */
	while (!got_SIGTERM)
	{
		TransactionId OldestXmin,
					oldestXidHavingUndo;
		FullTransactionId oldestFullXidHavingUndo;
		int			rc;

		/*
		 * It is okay to ignore vacuum transaction here, as we can discard the
		 * undo of the vacuuming transaction if the transaction is committed.
		 * We don't need to hold its undo for the visibility purpose.
		 */
		OldestXmin = GetOldestXmin(NULL, PROCARRAY_FLAGS_AUTOVACUUM |
								   PROCARRAY_FLAGS_VACUUM);

		oldestFullXidHavingUndo =
			FullTransactionIdFromU64(pg_atomic_read_u64(&ProcGlobal->oldestFullXidHavingUnappliedUndo));
		oldestXidHavingUndo = XidFromFullTransactionId(oldestFullXidHavingUndo);

		/*
		 * Call the discard routine if oldestXidHavingUndo is lagging behind
		 * OldestXmin.
		 */
		if (OldestXmin != InvalidTransactionId &&
			TransactionIdPrecedes(oldestXidHavingUndo, OldestXmin))
		{
			UndoDiscard(&worker_state, OldestXmin, &hibernate);

			/*
			 * If we got some undo logs to discard or discarded something,
			 * then reset the wait_time as we have got work to do.  Note that
			 * if there are some undologs that cannot be discarded, then above
			 * condition will remain unsatisfied till oldestXmin remains
			 * unchanged and the wait_time will not reset in that case.
			 */
			if (!hibernate)
				wait_time = MIN_NAPTIME_PER_CYCLE;
		}

		/* Wait for more work. */
		rc = WaitLatch(&MyProc->procLatch,
					   WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   wait_time,
					   WAIT_EVENT_UNDO_DISCARD_WORKER_MAIN);

		if (rc & WL_LATCH_SET)
		{
			ResetLatch(&MyProc->procLatch);
			CHECK_FOR_INTERRUPTS();
		}

		/*
		 * Increase the wait_time based on the length of inactivity.  If
		 * wait_time is within one second, then increment it by 100 ms at a
		 * time.  Henceforth, increment it one second at a time, till it
		 * reaches ten seconds.  Never increase the wait_time more than ten
		 * seconds, it will be too much of waiting otherwise.
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

	/* Normal exit from discard worker */
	ereport(LOG,
			(errmsg("discard worker shutting down")));

	proc_exit(0);
}

/*
 * IsDiscardProcess -- Tells whether the current process is a discard worker
 *	process.
 */
bool
IsDiscardProcess(void)
{
	return am_discard_worker;
}
