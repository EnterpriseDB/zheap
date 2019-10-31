/*-------------------------------------------------------------------------
 *
 * undoworker.c
 *	  interfaces for the undo apply launcher and undo apply workers
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoworker.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undoworker.h"
#include "access/xact.h"
#include "access/xactundo.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "tcop/tcopprot.h"
#include "utils/timestamp.h"

/*
 * To avoid excessive power consumption on low-usage systems, we put the undo
 * launcher into a state of hibernation if no work is found for a period of
 * at least HIBERNATE_THRESHOLD_SECONDS. When in hibernation, the effective
 * undo_naptime increases to at least HIBERNATE_NAPTIME_SECONDS.
 *
 * If an abort requiring undo processing occurs, the backend will attempt to
 * rouse us from hibernation.
 */
#define	HIBERNATE_NAPTIME_SECONDS		60
#define HIBERNATE_THRESHOLD_SECONDS	   120

/*
 * If we're woken up early, we can go ahead and launch a worker anyway provided
 * that the difference is no more than this number of milliseconds.
 */
#define WAKEUP_VARIANCE_TOLERANCE		20

/*
 * 'pgprocno' is the index into ProcGlobal->allProcs of the undo launcher.
 * It might be inaccurate if the undo launcher isn't running, or if it just
 * started and hasn't set the value yet.
 *
 * 'hibernate' indicates whether the undo launcher is sleeping for longer than
 * normal periods due to low system activity. If it's true, a backend can set
 * the undo launcher's latch and then change it to false.
 *
 * There's no locking around anything in this structure, so it's possible that
 * a signal intended to wake up the undo launcher could be sent to some other
 * process by mistake, or that we could be working with a stale value of
 * 'hibernate'. But even if a race occurs here, which should be rare, the
 * worst case scenario should be that we'll try to launch the next undo worker
 * after 1 minute rather than after the configured value of undo_naptime, which
 * shouldn't be catastrophic.
 */
typedef struct
{
	int			pgprocno;
	bool		hibernate;
} UndoLauncherData;

static long TimestampDifferenceInMilliseconds(TimestampTz older_ts,
											  TimestampTz newer_ts);
static void UndoLaunchWorker(void);

/* Shared memory state. */
UndoLauncherData *UndoLauncher;

/* GUCs. */
int			undo_naptime;
int			max_undo_workers;

/*
 * Compute the amount of shared memory needed by this module.
 */
Size
UndoWorkerShmemSize(void)
{
	return sizeof(UndoLauncherData);
}

/*
 * Initialize shared memory (or access to shared memory) for this module.
 */
void
UndoWorkerShmemInit(void)
{
	bool		found;

	UndoLauncher = (UndoLauncherData *)
		ShmemInitStruct("UndoLauncher", sizeof(UndoLauncherData), &found);

	if (!found)
		memset(UndoLauncher, 0, sizeof(UndoLauncherData));
}

/*
 * Register the undo launcher as a permanent background worker.
 */
void
RegisterUndoLauncher(void)
{
	BackgroundWorker bgw;

	memset(&bgw, 0, sizeof(BackgroundWorker));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "UndoLauncherMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "undo launcher");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "undo launcher");
	bgw.bgw_restart_time = 60;

	RegisterBackgroundWorker(&bgw);
}

/*
 * Attempt to disturb the undo launcher, if it's gone into hibernation.
 *
 * It's possible that the undo launcher died, or hasn't been started yet,
 * and that UndoLauncher->pgprocno consequently doesn't point to the undo
 * launcher process. If so, we'll send somebody a spurious wakeup, which
 * should be harmless.
 *
 * It's also possible, since there's no locking here, that we check
 * UndoLauncher->hibernate just before it gets set, or even, due to CPU
 * ordering effects, just after it gets set. In that unfortunate event,
 * the launcher might be less responsive than we would hope, but it shouldn't
 * be a catastrophe.
 */
void
DisturbUndoLauncherHibernation(void)
{
	if (UndoLauncher->hibernate)
	{
		UndoLauncher->hibernate = false;
		SetLatch(&ProcGlobal->allProcs[UndoLauncher->pgprocno].procLatch);
	}
}

/*
 * Entry point and main loop for the undo launcher process.
 */
void
UndoLauncherMain(Datum main_arg)
{
	TimestampTz last_launch_time;
	TimestampTz	sleep_until_time;

	/* Announce that we are running. */
	elog(DEBUG1, "undo launcher started");

	/* Configure appropriate signal handling. */
	pqsignal(SIGHUP, PostgresSigHupHandler);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	/* Advertise our pgprocno. */
	UndoLauncher->pgprocno = MyProc->pgprocno;

	/*
	 * Set up the initial state so that it looks as though undo_naptime has
	 * just expired, so that we will launch a worker immediately if there's
	 * any work to do.
	 */
	sleep_until_time = GetCurrentTimestamp();
	last_launch_time =
		TimestampTzPlusMilliseconds(sleep_until_time,
									undo_naptime * -1000L);

	/* Main loop. */
	for (;;)
	{
		TimestampTz now;
		long		minimum_time_between_workers;
		long		timeout;

		ResetLatch(MyLatch);
		CHECK_FOR_INTERRUPTS();

		/* Reload configuration, if required. */
		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		/*
		 * Get the current time.
		 */
		now = GetCurrentTimestamp();
		if (timestamp_cmp_internal(now, last_launch_time) < 0)
		{
			/*
			 * If the system time has jumped backward, pretend that we've
			 * just launched workers. This avoids waking for an arbitrary
			 * amount of time for the system clock to catch up to its previous
			 * value.
			 */
			elog(DEBUG1, "system clock reset detected");
			last_launch_time = now;
			sleep_until_time = now;
		}
		else if (TimestampDifferenceExceeds(sleep_until_time, now, 1000L) ||
				 TimestampDifferenceExceeds(now, sleep_until_time, 1000L))
		{
			/*
			 * To avoid drift, if we were woken up within 1 second of
			 * the expected time, compute the duration of the next sleep based
			 * on when we expected to wake up rather than when we actually
			 * woke up.
			 *
			 * If we've drifted more than a second off schedule, then either
			 * the system can't keep up, in which case trying to stick to
			 * the schedule is probably not helpful, or we've been woken up
			 * early for some reason.
			 */
			sleep_until_time = now;
		}

		/*
		 * Check whether enough time has passed to permit us to launch
		 * a worker.
		 */
		minimum_time_between_workers =
			undo_naptime * 1000L - WAKEUP_VARIANCE_TOLERANCE;
		if (!TimestampDifferenceExceeds(last_launch_time, now,
										minimum_time_between_workers))
		{
			/*
			 * We're short of undo_naptime by more than the tolerance amount,
			 * so we'll need to go back to slepe until it's reached. (Note that
			 * if WAKEUP_VARIANCE_TOLERANCE were set to 0, we might
			 * busy-loop here, since TimestampTz has microsecond precision.)
			 */
			sleep_until_time =
				TimestampTzPlusMilliseconds(last_launch_time,
											undo_naptime * 1000L);
		}
		else
		{
			/* Check whether work is available. */
			timeout = XactUndoWaitTime(now);
			if (timeout == 0)
			{
				/* There's work available now - launch a worker! */
				elog(DEBUG4, "undo launcher starting worker");
				UndoLaunchWorker();

				/* Prepare for next cycle. */
				last_launch_time = sleep_until_time;
				timeout = undo_naptime * 1000L;
			}
			else if (timeout > 0)
			{
				/*
				 * There's no work available right now, but there will be when
				 * the retry timeout expires for something that has failed.
				 * Wait for that to happen, but not more than undo_naptime,
				 * since new work may arrive meanwhile.
				 */
				timeout = Min(undo_naptime * 1000L, timeout);
			}
			else
			{
				bool		hibernate = UndoLauncher->hibernate;
				long		sleep_time_in_seconds = undo_naptime;

				/*
				 * There's no outstanding work at all. Keep hibernating if
				 * we are, and consider hibernating if we aren't.
				 *
				 * Note that it is useful to hibernate even if the
				 * undo_naptime is large, because while hibernating, we'll
				 * leap into action as soon as anything interesting happens.
				 * (Of course, anyone who really cares about responsiveness
				 * probably shouldn't raise undo_naptime in the first place.)
				 */
				if (hibernate ||
					TimestampDifferenceExceeds(last_launch_time,
											   now,
											   HIBERNATE_THRESHOLD_SECONDS * 1000L))
				{
					if (!hibernate)
						elog(DEBUG4, "undo launcher hibernating");
					UndoLauncher->hibernate = true;
					if (sleep_time_in_seconds < HIBERNATE_NAPTIME_SECONDS)
						sleep_time_in_seconds = HIBERNATE_NAPTIME_SECONDS;
				}

				timeout = sleep_time_in_seconds * 1000L;
			}

			Assert(timeout > 0);
			sleep_until_time = TimestampTzPlusMilliseconds(sleep_until_time,
														   timeout);
		}

		/* Sleep until the timeout is reached. */
		timeout = TimestampDifferenceInMilliseconds(now, sleep_until_time);
		elog(DEBUG4, "undo launcher sleeping for %ld milliseconds",
			 timeout);
		WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
				  timeout, WAIT_EVENT_UNDO_LAUNCHER_MAIN);
	}
}

/*
 * Launch a new undo worker.
 *
 * Unlike most places where we launch background workers dynamically, the
 * undo launcher really doesn't care whether this actually works, or whether
 * the worker manages to start, or when it ends up exiting. It just keeps
 * trying to start workers so long as there seems to be work to do, and it
 * hopes (without really caring) that those workers get something useful
 * done.
 */
static void
UndoLaunchWorker(void)
{
	BackgroundWorker bgw;

	memset(&bgw, 0, sizeof(BackgroundWorker));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_CLASS_UNDO;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "UndoWorkerMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "undo worker");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "undo worker");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;

	RegisterDynamicBackgroundWorker(&bgw, NULL);
}

/*
 * Entry point and main loop for undo worker processes.
 */
void
UndoWorkerMain(Datum main_arg)
{
	TimestampTz		start_time = GetCurrentTimestamp();
	bool			minimum_runtime_reached = false;

	/* Announce that we are running. */
	elog(DEBUG2, "undo worker started");

	/* Configure appropriate signal handling. */
	pqsignal(SIGHUP, PostgresSigHupHandler);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();

	/* Main loop. */
	for (;;)
	{
		Oid		dbid;

		CHECK_FOR_INTERRUPTS();

		/* Reload configuration, if required. */
		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		/* Try to acquire an undo request for processing. */
		dbid = InitializeBackgroundXactUndo(minimum_runtime_reached);
		if (!OidIsValid(dbid))
			break;

		/*
		 * If this is the first undo request we've acquired, we need to
		 * connect to the appropriate database. (InitializeBackgroundXactUndo
		 * will never give us a request from a database other than the one
		 * to which we are connected, but the first request is unconstrained
		 * because we don't have a database connection yet.)
		 */
		if (!OidIsValid(MyDatabaseId))
			BackgroundWorkerInitializeConnectionByOid(dbid, InvalidOid, 0);

		/* Sanity check. */
		Assert(dbid == MyDatabaseId);

		/* Now do the work. */
		PerformBackgroundUndo();

		/* Job's done! */
		FinishBackgroundXactUndo();

		/*
		 * See whether we've reached the minimum runtime. If so, future
		 * calls to InitializeBackgroundXactUndo won't acquire a new request
		 * unless one of the next requests in priority order is for this
		 * database.
		 *
		 * For now, the minimum runtime is just the same as undo_naptime.
		 * The point here is to avoid starting and stopping workers at high
		 * speed if the undo requests are small in terms of processing time
		 * and spread across multiple databases. So, when we've only run for
		 * a short time, we're willing to work harder to find a request from
		 * the current database. When we've run for a longer time, it's
		 * better to exit so that a new worker can be launched and connect
		 * to the database in which the highest-priority request is to be
		 * found.
		 */
		if (!minimum_runtime_reached)
		{
			TimestampTz	now = GetCurrentTimestamp();

			if (TimestampDifferenceExceeds(start_time, now,
										   undo_naptime * 1000L))
				minimum_runtime_reached = true;
			elog(DEBUG4, "undo worker has reached minimum runtime");
		}
	}

	elog(DEBUG2, "undo worker exiting");
	proc_exit(0);
}

/*
 * Subtract two timestamps and convert the result to milliseconds.
 *
 * NB: TimestampDifference never returns a negative value, and this function
 * inherits that behavior; callers may depend upon it.
 */
static long
TimestampDifferenceInMilliseconds(TimestampTz older_ts, TimestampTz newer_ts)
{
	long		secs;
	int			microsecs;

	TimestampDifference(older_ts, newer_ts, &secs, &microsecs);
	Assert(secs >= 0 && microsecs >= 0);
	return (secs * 1000) + (microsecs / 1000);
}
