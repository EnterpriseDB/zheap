/*-------------------------------------------------------------------------
 *
 * undolog.c
 *	  management of undo logs
 *
 * PostgreSQL undo log manager.  This module is responsible for lifecycle
 * management of undo logs and backing files, associating undo logs with
 * backends, allocating and managing space within undo logs.
 *
 * For the code that reads and writes blocks of data, see undofile.c.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undolog.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/transam.h"
#include "access/undolog.h"
#include "access/undolog_xlog.h"
#include "access/xact.h"
#include "access/xlogreader.h"
#include "catalog/catalog.h"
#include "catalog/pg_tablespace.h"
#include "commands/tablespace.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/execnodes.h"
#include "pgstat.h"
#include "storage/buf.h"
#include "storage/dsm.h"
#include "storage/fd.h"
#include "storage/lwlock.h"
#include "storage/spin.h"
#include "storage/shmem.h"
#include "utils/memutils.h"

#include <unistd.h>

/* End-of-list value when building linked lists of undo logs. */
#define InvalidUndoLogNumber -1

/*
 * Number of bits of an undo log number used to identify a bank of
 * UndoLogDescriptor objects.  This allows us to break up our array of
 * UndoLogDesctiptor objects into many smaller arrays, called banks, and find
 * our way to an UndoLogDescriptor object in O(1) complexity in two steps.
 */
#define UndoLogBankBits 14 /* 2^14 entries = a 64KB banks array */

/* Extract the undo bank number from an undo log number (upper bits). */
#define UndoLogNoGetBankNo(logno)				\
	((logno) >> (UndoLogNumberBits - UndoLogBankBits))

/* Extract the slot within a bank from an undo log number (lower bits). */
#define UndoLogNoGetSlotNo(logno)				\
	((logno) & ((1 << (UndoLogNumberBits - UndoLogBankBits)) - 1))

/*
 * During recovery we maintain a mapping of transaction ID to undo logs
 * numbers.  We do this with another two-level array, so that we use memory
 * only for chunks of the array that overlap with the range of active xids.
 */
#define UndoLogXidLowBits 16

/* Extract the upper bits of an xid, for undo log mapping purposes. */
#define UndoLogGetXidHigh(xid) ((xid) >> UndoLogXidLowBits)

/* Extract the lower bits of an xid, for undo log mapping purposes. */
#define UndoLogGetXidLow(xid) ((xid) & ((1 << UndoLogXidLowBits) - 1))

/*
 * The in-memory control object for an undo log.  Wraps an UndoLogMetaData and
 * adds a mutex and some link pointers.
 *
 * Conceptually the set of UndoLogControl objects is arranged into a very
 * large array for access by log number, but because we typically need only a
 * smallish number of adjacent undo logs to be active at a time we arrange
 * them into smaller fragments called 'banks'.
 */
typedef struct UndoLogControl
{
	UndoLogMetaData meta;			/* control data */
	slock_t		mutex;				/* protects the above */

	pid_t		pid;				/* InvalidPid for unattached */
	TransactionId xid;

	UndoLogNumber next_free;		/* protected by UndoLogLock */

	/* TODO: links for work_list */
} UndoLogControl;

/*
 * Main control structure for undo log management in shared memory.
 */
typedef struct UndoLogSharedData
{
	UndoLogNumber free_list;
	UndoLogNumber attached_list;
	int low_bankno; /* the lowest bank */
	int high_bankno; /* one past the highest bank */
	UndoLogNumber low_logno; /* the lowest logno */
	UndoLogNumber high_logno; /* one past the highest logno */

	/*
	 * Array of DSM handles pointing to the arrays of UndoLogControl objects.
	 * We don't expect there to be many banks active at a time -- usually 1 or
	 * 2, but we need random access by log number so we arrange them into
	 * 'banks'.
	 */
	dsm_handle banks[1 << UndoLogBankBits];
} UndoLogSharedData;

/*
 * Per-backend state for the undo log module.
 * Backend-local pointers to undo subsystem state in shared memory.
 */
struct
{
	UndoLogSharedData *shared;

	/*
	 * The control object for the undo log that this backend is currently
	 * attached to, or NULL if not attached.
	 */
	UndoLogControl *log;

	/* For assertions only, the log number of the undo log. */
	UndoLogNumber logno;

	/*
	 * The address where each bank of control objects is mapped into memory in
	 * this backend.  We map banks into memory on demand, and (for now) they
	 * stay mapped in until every backend that mapped them exits.
	 */
	UndoLogControl *banks[1 << UndoLogBankBits];

	/*
	 * During recovery, the startup process maintains a mapping of xid to undo
	 * log number, instead of using 'log' above.  This is not used in regular
	 * backends.
	 */
	UndoLogNumber **xidToLogNumber;
} MyUndoLogState;

static UndoLogControl *get_undo_log_by_number(UndoLogNumber logno);
static void ensure_undo_log_number(UndoLogNumber logno);
static void attach_undo_log(void);
static void detach_current_undo_log(void);
static void extend_undo_log(UndoLogNumber logno, UndoLogOffset capacity);

PG_FUNCTION_INFO_V1(pg_stat_get_undo_logs);

/*
 * Return the amount of traditional smhem required for undo log management.
 * Extra shared memory will be managed using DSM segments.
 */
Size
UndoLogShmemSize(void)
{
	return sizeof(UndoLogSharedData);
}

/*
 * Initialize the undo log subsystem.  Called in each backend.
 */
void
UndoLogShmemInit(void)
{
	bool found;

	MyUndoLogState.shared = (UndoLogSharedData *)
		ShmemInitStruct("UndoLogShared", UndoLogShmemSize(), &found);

	if (!IsUnderPostmaster)
	{
		UndoLogSharedData *shared = MyUndoLogState.shared;

		Assert(!found);

		/*
		 * For now there are no undo logs.  StartUpUndoLogs() will recreate
		 * undo logs that were known at last checkpoint.
		 */
		memset(shared, 0, sizeof(*shared));
		shared->free_list = InvalidUndoLogNumber;
		shared->low_bankno = 0;
		shared->high_bankno = 0;
	}
	else
		Assert(found);
}

/*
 * Compute the pathname to use for an undo log segment file.  Also return the
 * parent pathname separately, so that it can be fsync'ed if necessary.
 */
void
UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace,
				   char *dir, char *path)
{
	/* Figure out which directory holds the segment, based on tablespace. */
	if (tablespace == DEFAULTTABLESPACE_OID ||
		tablespace == InvalidOid)
		snprintf(dir, MAXPGPATH, "base/%u", UndoLogDatabaseOid);
	else
		snprintf(dir, MAXPGPATH, "pg_tblspc/%u/%s/%u",
				 tablespace, TABLESPACE_VERSION_DIRECTORY,
				 UndoLogDatabaseOid);
	/* Build the path from the top bits of the offset. */
	snprintf(path, MAXPGPATH, "%s/%06X.%02X", dir, logno, segno);

	/*
	 * XXX Make the number of characters used to represent segno dependent on
	 * the compile time segment size?
	 */
}

/*
 * Iterate through the set of currently active logs.  That is, logs that have
 * not yet been entirely discarded.
 *
 * Intially, *logno should contain -1.  Then it should be called repeatedly
 * until it returns false.  When it returns true, the next log number and its
 * tablespace OID have been written to *logno and *spcNode.
 */
bool
UndoLogNextActiveLog(UndoLogNumber *logno, Oid *spcNode)
{
	/* TODO write me */
	return false;
}

/*
 * Get an instantaneous snapshot of the range of segments that might be dirty,
 * for checkpointing purposes.
 *
 * XXX Currently this claims that the current segment is dirty, whether or not
 * it's actually been written to recently.  Could do better.
 */
void
UndoLogGetDirtySegmentRange(UndoLogNumber logno,
							int *low_segno, int *high_segno)
{
	/* TODO write me */
}

/*
 * Record that all segments up to 'segno' have been flushed to disk.
 */
void
UndoLogSetHighestSyncedSegment(UndoLogNumber logno, int segno)
{
	/* TODO write me */
}

/*
 * Detach from the undo log we are currently attached to, returning it to the
 * free list if it still has space.
 */
static void
detach_current_undo_log()
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log = MyUndoLogState.log;
	UndoLogNumber logno = MyUndoLogState.logno;

	Assert(log != NULL);

	MyUndoLogState.log = NULL;
	MyUndoLogState.logno = InvalidUndoLogNumber;

	log->pid = InvalidPid;
	log->xid = InvalidTransactionId;

	/* If it doesn't have a useful amount of space left, just forget about it. */
	if (log->meta.capacity < (UndoLogMaxSize - 1024)) /* TODO: ??? */
	{
		/* TODO: mark as retired */
	}
	else
	{
		/* Push back onto the freelist. */
		LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
		log->next_free = shared->free_list;
		shared->free_list = logno;
		LWLockRelease(UndoLogLock);
	}
}

/*
 * Create and zero-fill a new segment for the undo log we are currently
 * attached to.
 */
static void
extend_undo_log(UndoLogNumber logno, UndoLogOffset capacity)
{
	UndoLogControl *log;
	char	dir[MAXPGPATH];
	char	path[MAXPGPATH];
	Size	total_written = 0;
	int		fd;
	void   *zeroes;

	log = get_undo_log_by_number(logno);

	/* This must be a request to add exactly one segment to an existing log. */
	Assert(log != NULL);
	Assert(log->meta.capacity % (UNDOSEG_SIZE * BLCKSZ) == 0);
	Assert(capacity == log->meta.capacity + (UNDOSEG_SIZE * BLCKSZ));

	/* Create (pseudo) database directory if it doesn't exist. */
	if (log->meta.tablespace != InvalidOid &&
		log->meta.tablespace != DEFAULTTABLESPACE_OID)
		TablespaceCreateDbspace(log->meta.tablespace, UndoLogDatabaseOid,
								false /* TODO: redo flag */);

	UndoLogSegmentPath(logno, log->meta.capacity / BLCKSZ,
					   log->meta.tablespace, dir, path);

	if (false) /* TODO: if was can rename an existing file into place... */
	{
		/*
		 * Rename an old file into place.  If we crashed and recovered then
		 * this might already have been done, and we'll need to tolerate that.
		 */

		/* TODO */
	}
	else
	{
		/*
		 * Create and fully allocate a new file.  If we crashed and recovered
		 * then the file might already exist, so use flags that tolerate that.
		 */
		fd = OpenTransientFile(path, O_RDWR | O_CREAT | PG_BINARY);
		zeroes = palloc0(8192);
		while (total_written < (UNDOSEG_SIZE * BLCKSZ))
		{
			ssize_t written;

			written = write(fd, zeroes,
							Min(8192, (UNDOSEG_SIZE * BLCKSZ) - total_written));
			if (written < 0)
				elog(ERROR, "cannot initialize undo log segment file \"%s\": %m",
					 path);
			total_written += written;
		}
		if (pg_fsync(fd) != 0)
			elog(ERROR, "cannot fsync file \"%s\": %m", path);
		CloseTransientFile(fd);
	}

	/*
	 * Flush the parent dir so that the directory metadata survives a crash after
	 * this point.
	 */
	fsync_fname(dir, true);

	/*
	 * If we're not in recovery, we need to WAL-log the file creation.  We do
	 * that after the above filesystem modifications, in violation of the
	 * data-before-WAL rule as exempted by src/backend/access/transam/README.
	 * This means that it's possible for us to crash having made the
	 * filesystem changes but before WAL logging, but in that case we'll
	 * eventually try to create the same segment again which is tolerated.
	 */
	if (!InRecovery)
	{
		xl_undolog_extend xlrec;
		XLogRecPtr	ptr;

		xlrec.logno = logno;
		xlrec.capacity = capacity;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		ptr = XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_EXTEND);
		XLogFlush(ptr);
	}

	/*
	 * We didn't need to acquire the mutex to read capacity above because only
	 * we write to it.  But we need the mutex to update it, because the
	 * checkpointer might read it concurrently.
	 */
	SpinLockAcquire(&log->mutex);
	log->meta.capacity = capacity;
	SpinLockRelease(&log->mutex);
}

/*
 * Get an insertion point that is guaranteed to be backed by enough space to
 * hold 'size' bytes of data.  To actually write into the undo log, client
 * code should call this first and then use bufmgr routines to access buffers
 * and provide WAL logs and redo handlers.  In other words, while this module
 * looks after making sure the undo log has sufficient space and the undo meta
 * data is crash safe, the *contents* of the undo log and (indirectly) the
 * insertion point are the responsibility of client code.
 *
 * Returns an undo log insertion point that can be converted to a buffer tag
 * and an insertion point within a buffer page using the macros above.
 */
UndoRecPtr
UndoLogAllocate(UndoRecordSize size, UndoPersistence level)
{
	UndoLogControl *log = MyUndoLogState.log;

 retry:

	/* Ensure that we are attached to an undo log. */
	if (unlikely(log == NULL))
	{
		attach_undo_log();
		log = MyUndoLogState.log;
	}

	/*
	 * We don't need to acquire log->mutex to read log->meta.insert and
	 * log->meta.capacity, because this backend is the only one that can
	 * modify them.
	 */
	if (unlikely(log->meta.insert + size > log->meta.capacity))
	{
		if (log->meta.insert + size > UndoLogMaxSize)
		{
			/* This undo log is entirely full.  Get a new one. */
			log = MyUndoLogState.log = NULL;
			detach_current_undo_log();
			goto retry;
		}
		else
		{
			/* Extend the capacity of this undo log by one segment. */
			extend_undo_log(MyUndoLogState.logno,
							log->meta.capacity + (UNDOSEG_SIZE * BLCKSZ));
			/*
			 * That must be enough, because segments are bigger than the
			 * maximum value for UndoRecordSize.
			 *
			 * XXX static assert that?
			 */
			Assert(log->meta.insert + size <= log->meta.capacity);
		}
	}

	/*
	 * If we haven't already done so since the last checkpoint, associate the
	 * current transaction ID with this undo log, so that
	 * UndoLogAllocateInRecovery knows how to replay this undo space
	 * allocation.  XXX TODO for now it's every time; probably need
	 * interlocking with checkpoint to make this work :-(
	 */
	if (true)
	{
		xl_undolog_attach xlrec;

		xlrec.xid = GetTopTransactionId();
		xlrec.logno = MyUndoLogState.logno;
		xlrec.insert = log->meta.insert;
		xlrec.last_size = log->meta.last_size;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_ATTACH);
	}

	return MakeUndoRecPtr(MyUndoLogState.logno, log->meta.insert);
}

/*
 * In recovery, we expect the xid to map to a known log which already has
 * enough space in it.
 */
UndoRecPtr
UndoLogAllocateInRecovery(TransactionId xid, UndoRecordSize size,
						  UndoPersistence level)
{
	uint16		high_bits = UndoLogGetXidHigh(xid);
	uint16		low_bits = UndoLogGetXidLow(xid);
	UndoLogNumber logno;
	UndoLogControl *log;

	/*
	 * The sequence of calls to UndoLogAllocateRecovery during REDO (recovery)
	 * must match the sequence of calls to UndoLogAllocate during DO, for any
	 * given session.  The XXX_redo code for any UNDO-generating operation
	 * must use UndoLogAllocateRecovery rather than UndoLogAllocate, because
	 * it must supply the extra 'xid' argument so that we can find out which
	 * undo log number to use.  During DO, that's tracked per-backend, but
	 * during REDO the original backends/sessions are lost and we have only
	 * the Xids.
	 */
	Assert(InRecovery);

	/*
	 * Look up the undo log number for this xid.  The mapping must already
	 * have been created by an XLOG_UNDOLOG_ATTACH record emitted during the
	 * first call to UndoLogAllocate for this xid after the most recent
	 * checkpoint.
	 */
	if (MyUndoLogState.xidToLogNumber == NULL)
		elog(ERROR, "xid to undo log number map not initialized");
	if (MyUndoLogState.xidToLogNumber[high_bits] == NULL)
		elog(ERROR, "cannot find undo log number for xid %u", xid);
	logno = MyUndoLogState.xidToLogNumber[high_bits][low_bits];
	if (logno == InvalidUndoLogNumber)
		elog(ERROR, "cannot find undo log number for xid %u", xid);

	/*
	 * This log must already have been created by XLOG_UNDOLOG_CREATE records
	 * emitted by UndoLogAllocate.
	 */
	log = get_undo_log_by_number(logno);
	if (log == NULL)
		elog(ERROR, "cannot find undo log number %d for xid %u", logno, xid);

	/*
	 * This log must already have been extended to cover the requested size by
	 * XLOG_UNDOLOG_EXTEND records emitted by UndoLogAllocate.
	 */
	if (log->meta.capacity < log->meta.insert + size)
		elog(ERROR,
			 "unexpectedly couldn't allocate %u bytes in undo log number %d",
			 size, logno);

	return MakeUndoRecPtr(logno, log->meta.insert);
}

/*
 * Advance the insertion pointer.
 *
 * Caller must WAL-log this operation first, and must replay it during
 * recovery.
 */
void
UndoLogAdvance(UndoRecPtr insertion_point, UndoRecordSize size)
{
	UndoLogControl *log = MyUndoLogState.log;

	Assert(log != NULL);
	Assert(UndoRecPtrGetLogNo(insertion_point) == MyUndoLogState.logno);
	Assert(UndoRecPtrGetOffset(insertion_point) == log->meta.insert);

	SpinLockAcquire(&log->mutex);
	log->meta.insert += size;
	log->meta.last_size = size;
	SpinLockRelease(&log->mutex);
}

Oid
UndoRecPtrGetTablespace(UndoRecPtr ptr)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(ptr);
	UndoLogControl *log = get_undo_log_by_number(logno);

	/*
	 * XXX What should the behaviour of this function be if you ask for the
	 * tablespace of a discarded log, where even the shmem bank is gone?
	 */

	/*
	 * No need to acquire log->mutex, because log->meta.tablespace is constant
	 * for the lifetime of the log.
	 */
	if (log != NULL)
		return log->meta.tablespace;
	else
		return InvalidOid;
}

/*
 * Delete unreachable files under pg_undo.  Any files corresponding to LSN
 * positions before the previous checkpoint are no longer needed.
 */
static void
CleanUpUndoCheckPointFiles(XLogRecPtr checkPointRedo)
{
	DIR	   *dir;
	struct dirent *de;
	char	path[MAXPGPATH];
	char	oldest_path[MAXPGPATH];

	snprintf(oldest_path, MAXPGPATH, "%016" INT64_MODIFIER "X",
			 checkPointRedo);
	dir = AllocateDir("pg_undo");
	while ((de = ReadDir(dir, "pg_undo")) != NULL)
	{
		/*
		 * Assume that fixed width uppercase hex strings sort the same way as
		 * the values they represent, so we can use memcmp to identify undo
		 * log snapshot files corresponding to checkpoints that we don't need
		 * anymore.  This assumption holds for ASCII.
		 */
		if (strlen(de->d_name) == 16 &&
			memcmp(de->d_name, oldest_path, 16) < 0)
		{
			snprintf(path, MAXPGPATH, "pg_undo/%s", de->d_name);
			if (unlink(path) != 0)
				elog(ERROR, "could not unlink file \"%s\": %m", path);
		}
	}
	FreeDir(dir);
}

/*
 * Write out the undo log meta data to the pg_undo directory.  The actual
 * contents of undo logs is in shared buffers and therefore handled by
 * CheckPointBuffers(), but here we record the table of undo logs and their
 * properties.
 */
void
CheckPointUndoLogs(XLogRecPtr checkPointRedo)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogMetaData *serialized = NULL;
	UndoLogNumber low_logno;
	UndoLogNumber high_logno;
	UndoLogNumber logno;
	size_t	serialized_size = 0;
	char   *data;
	char	path[MAXPGPATH];
	int		num_logs;
	int		fd;

	/*
	 * We acquire UndoLogLock to prevent any undo logs from being created or
	 * discarded while we build a snapshot of them.  This isn't expected to
	 * take long on a healthy system because the number of active logs should
	 * be around the number of backends.  Holding this lock won't prevent
	 * concurrent access to the undo log, except when segments need to be
	 * added or removed.
	 */
	LWLockAcquire(UndoLogLock, LW_SHARED);

	low_logno = shared->low_logno;
	high_logno = shared->high_logno;
	num_logs = high_logno - low_logno;

	/*
	 * Rather than doing the file IO while we hold the lock, we'll copy it
	 * into a palloc'd buffer.
	 */
	if (num_logs > 0)
	{
		serialized_size = sizeof(UndoLogMetaData) * num_logs;
		serialized = (UndoLogMetaData *) palloc0(serialized_size);

		/*
		 * TODO: Here we should try to increase low_logno by spinning through
		 * the existing range looking for logs that are marked retired, so
		 * that we can make the file smaller.
		 */
		for (logno = shared->low_logno; logno != shared->high_logno; ++logno)
		{
			UndoLogControl *log;

			log = get_undo_log_by_number(logno);
			if (log == NULL) /* XXX can this happen? */
				continue;

			/* Snapshot while holding the spinlock. */
			SpinLockAcquire(&log->mutex);
			memcpy(&serialized[logno], &log->meta, sizeof(UndoLogMetaData));
			SpinLockRelease(&log->mutex);
		}
	}

	LWLockRelease(UndoLogLock);

	/* Dump into a file under pg_undo. */
	snprintf(path, MAXPGPATH, "pg_undo/%016" INT64_MODIFIER "X",
			 checkPointRedo);
	fd = OpenTransientFile(path, O_RDWR | O_CREAT | PG_BINARY);
	if (fd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create file \"%s\": %m", path)));

	/* Write out range of active log numbers. */
	if ((write(fd, &low_logno, sizeof(low_logno)) != sizeof(low_logno)) ||
		(write(fd, &high_logno, sizeof(high_logno)) != sizeof(high_logno)))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m", path)));

	/* Write out the meta data for all undo logs in that range. */
	data = (char *) serialized;
	while (serialized_size > 0)
	{
		ssize_t written;

		written = write(fd, data, serialized_size);
		if (written < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m", path)));
		serialized_size -= written;
		data += written;
	}

	/* Flush file and directory entry. */
	pg_fsync(fd);
	CloseTransientFile(fd);
	fsync_fname("pg_undo", true);

	if (serialized)
		pfree(serialized);

	CleanUpUndoCheckPointFiles(checkPointRedo);
}

void
StartupUndoLogs(XLogRecPtr checkPointRedo)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	char	path[MAXPGPATH];
	int		num_logs;
	int		logno;
	int		fd;

	/* If initdb is calling, there is no file to read yet. */
	if (IsBootstrapProcessingMode())
		return;

	/* Open the pg_undo file corresponding to the given checkpoint. */
	snprintf(path, MAXPGPATH, "pg_undo/%016" INT64_MODIFIER "X",
			 checkPointRedo);
	fd = OpenTransientFile(path, O_RDONLY | PG_BINARY);
	if (fd < 0)
		elog(ERROR, "cannot open pg_undo file \"%s\": %m", path);

	/* Read the active log number range. */
	if ((read(fd, &shared->low_logno, sizeof(shared->low_logno))
		 != sizeof(shared->low_logno)) ||
		(read(fd, &shared->high_logno, sizeof(shared->high_logno))
		 != sizeof(shared->high_logno)))
		elog(ERROR, "pg_undo file \"%s\" is corrupted", path);
	num_logs = shared->high_logno - shared->low_logno;

	/* Initialize all the logs and set up the freelist. */
	for (logno = shared->low_logno; logno < shared->high_logno; ++logno)
	{
		UndoLogControl *log;

		/* Get a zero-initialized control objects. */
		ensure_undo_log_number(logno);
		log = get_undo_log_by_number(logno);

		/* Read in the meta data for this undo log. */
		if (read(fd, &log->meta, sizeof(log->meta)) != sizeof(log->meta))
			elog(ERROR, "corrupted pg_undo meta data in file \"%s\": %m",
				 path);

		/*
		 * Set up the rest of the control object.  During recovery, all active
		 * undo logs go on the free list.
		 */
		log->pid = InvalidPid;
		log->xid = InvalidTransactionId;
		log->next_free = shared->free_list;
		shared->free_list = logno;
		SpinLockInit(&log->mutex);
	}
	CloseTransientFile(fd);
}

/*
 * Get an UndoLogControl pointer for a given logno.  This may require
 * attaching to a DSM segment if it isn't already attached in this backend.
 * Return NULL if there is no such logno because it has been entirely
 * discarded.
 */
static UndoLogControl *
get_undo_log_by_number(UndoLogNumber logno)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	int bankno = UndoLogNoGetBankNo(logno);
	int slotno = UndoLogNoGetSlotNo(logno);

	/* See if we need to attach to the bank that holds logno. */
	if (unlikely(MyUndoLogState.banks[bankno] == NULL))
	{
		dsm_segment *segment;

		if (shared->banks[bankno] != DSM_HANDLE_INVALID)
		{
			segment = dsm_attach(shared->banks[bankno]);
			if (segment != NULL)
			{
				MyUndoLogState.banks[bankno] = dsm_segment_address(segment);
				dsm_pin_mapping(segment);
			}
		}

		if (unlikely(MyUndoLogState.banks[bankno] == NULL))
			return NULL;
	}

	return &MyUndoLogState.banks[bankno][slotno];
}

/*
 * Create shared memory space for a given undo log number, if it doesn't exist
 * already.
 */
static void
ensure_undo_log_number(UndoLogNumber logno)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	int		bankno = UndoLogNoGetBankNo(logno);

	/* Do we need to create a bank in shared memory for this undo log number? */
	if (shared->banks[bankno] == DSM_HANDLE_INVALID)
	{
		dsm_segment *segment;
		size_t size;

		size = sizeof(UndoLogControl) * (1 << UndoLogBankBits);
		segment = dsm_create(size, 0);
		dsm_pin_mapping(segment);
		dsm_pin_segment(segment);
		memset(dsm_segment_address(segment), 0, size);
		shared->banks[bankno] = dsm_segment_handle(segment);
		MyUndoLogState.banks[bankno] = dsm_segment_address(segment);
	}
}

/*
 * Attach to an undo log, possibly creating or recycling one.
 */
static void
attach_undo_log(void)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log;
	UndoLogNumber logno;

	Assert(!InRecovery);
	Assert(MyUndoLogState.log == NULL);

	/*
	 * We have to acquire a lock to attach to a log.
	 *
	 * XXX We could have partitioned freelists to decrease contention, and
	 * then make backends attach and detach aggressively so that we settle on
	 * a smallish number of undo logs.  Or we could remain attached until
	 * session end, hogging a whole log per backend but not needing to
	 * communicate much.
	 */

	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
	if (shared->free_list != InvalidUndoLogNumber)
	{
		logno = shared->free_list;

		/* Pop first free undo log slot from list. */
		log = get_undo_log_by_number(logno);
		if (log == NULL)
			elog(ERROR, "corrupted undo log freelist");
		shared->free_list = log->next_free;
	}
	else
	{
		/* All existing undo logs are busy.  Create a new one. */

		if (shared->high_logno > (1 << UndoLogNumberBits))
		{
			/*
			 * You've used up all 16 exabytes of undo log addressing space.
			 * This is a difficult state to reach using only 16 exabytes of
			 * WAL.
			 */
			elog(ERROR, "cannot create new undo log");
		}

		logno = shared->high_logno;
		ensure_undo_log_number(logno);

		/* Get new zero-filled UndoLogControl object. */
		log = get_undo_log_by_number(logno);

		Assert(log->meta.tablespace == InvalidOid);
		Assert(log->meta.last_size == 0);
		Assert(log->meta.insert == 0);
		Assert(log->meta.capacity == 0);
		Assert(log->meta.mvcc == 0);
		Assert(log->meta.rollback == 0);
		Assert(log->pid == 0);
		Assert(log->xid == 0);
		Assert(log->next_free == 0);

		/* Initialize. */
		SpinLockInit(&log->mutex);

		/* TODO: Choose log->meta.tablespace */

		/* Move the high log number pointer past this one. */
		++shared->high_logno;

		/* WAL-log the creation of this new undo log. */
		{
			xl_undolog_create xlrec;

			xlrec.logno = logno;
			xlrec.tablespace = log->meta.tablespace;

			XLogBeginInsert();
			XLogRegisterData((char *) &xlrec, sizeof(xlrec));
			XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_CREATE);
		}

		/*
		 * This undo log has no segments.  UndoLogPrepare will create the
		 * first one on demand.
		 */
	}
	LWLockRelease(UndoLogLock);

	SpinLockAcquire(&log->mutex);
	log->pid = MyProcPid;
	log->xid = GetTopTransactionId();
	SpinLockRelease(&log->mutex);

	MyUndoLogState.logno = logno;
	MyUndoLogState.log = log;
}

Datum
pg_stat_get_undo_logs(PG_FUNCTION_ARGS)
{
#define PG_STAT_GET_UNDO_LOGS_COLS 8
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	bool nulls[PG_STAT_GET_UNDO_LOGS_COLS] = { false };
	Datum values[PG_STAT_GET_UNDO_LOGS_COLS];
	UndoLogNumber low_logno;
	UndoLogNumber high_logno;
	UndoLogNumber logno;
	UndoLogSharedData *shared = MyUndoLogState.shared;

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	/* Find the range of active log numbers. */
	LWLockAcquire(UndoLogLock, LW_SHARED);
	low_logno = shared->low_logno;
	high_logno = shared->high_logno;
	LWLockRelease(UndoLogLock);

	/* Scan all undo logs to build the results. */
	for (logno = low_logno; logno < high_logno; ++logno)
	{
		UndoLogControl *log = get_undo_log_by_number(logno);

		if (log == NULL)
			continue;

		/*
		 * This won't be a consistent result overall, but the values for each
		 * log will be consistent because we'll take the per-log spinlock
		 * while copying them.
		 */
		SpinLockAcquire(&log->mutex);
		values[0] = ObjectIdGetDatum((Oid) logno);
		values[1] = ObjectIdGetDatum(log->meta.tablespace);
		values[2] = Int64GetDatum(log->meta.capacity);
		values[3] = Int64GetDatum(log->meta.insert);
		values[4] = Int64GetDatum(log->meta.mvcc);
		values[5] = Int64GetDatum(log->meta.rollback);
		values[6] = TransactionIdGetDatum(log->xid);
		values[7] = Int32GetDatum((int64) log->pid);
		SpinLockRelease(&log->mutex);

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}
	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}

/*
 * replay the creation of a new undo log
 */
static void
undolog_xlog_create(XLogReaderState *record)
{
	xl_undolog_create *xlrec = (xl_undolog_create *) XLogRecGetData(record);
	UndoLogControl *log;
	UndoLogSharedData *shared = MyUndoLogState.shared;

	/* Create meta-data space in shared memory. */
	ensure_undo_log_number(xlrec->logno);

	log = get_undo_log_by_number(xlrec->logno);
	log->meta.tablespace = xlrec->tablespace;
	SpinLockInit(&log->mutex);

	LWLockAcquire(UndoLogLock, LW_SHARED);
	shared->high_logno = Max(xlrec->logno + 1, shared->high_logno);
	LWLockRelease(UndoLogLock);
}

/*
 * replay the addition of a new segment to an undo log
 */
static void
undolog_xlog_extend(XLogReaderState *record)
{
	xl_undolog_extend *xlrec = (xl_undolog_extend *) XLogRecGetData(record);
	UndoLogControl *log;

	log = get_undo_log_by_number(xlrec->logno);

	/*
	 * It's possible that the checkpoint snapshot already includes the
	 * extension, due to races between extension and checkpointing.  So we
	 * have to tolerate that possibility here.
	 */
	if (log->meta.capacity >= xlrec->capacity)
		return;

	/* Otherwise, extend exactly as we would during DO phase. */
	extend_undo_log(xlrec->logno, xlrec->capacity);
}

/*
 * replay the association of an xid with a specific undo log
 */
static void
undolog_xlog_attach(XLogReaderState *record)
{
	xl_undolog_attach *xlrec = (xl_undolog_attach *) XLogRecGetData(record);
	uint16		high_bits;
	uint16		low_bits;
	UndoLogControl *log;

	high_bits = UndoLogGetXidHigh(xlrec->xid);
	low_bits = UndoLogGetXidLow(xlrec->xid);

	if (unlikely(MyUndoLogState.xidToLogNumber == NULL))
	{
		/* First time through.  Create mapping array. */
		MyUndoLogState.xidToLogNumber =
			MemoryContextAllocZero(TopMemoryContext,
								   sizeof(UndoLogNumber *) *
								   (1 << (32 - UndoLogXidLowBits)));
	}

	if (unlikely(MyUndoLogState.xidToLogNumber[high_bits] == NULL))
	{
		/* This bank of mappings doesn't exist yet.  Create it. */
		MyUndoLogState.xidToLogNumber[high_bits] =
			MemoryContextAllocZero(TopMemoryContext,
								   sizeof(UndoLogNumber) *
								   (1 << UndoLogXidLowBits));

		/*
		 * TODO: When we replay a checkpoint record (or some other periodic
		 * occasion) we should blow away all banks of mappings that are
		 * outside the range of active xids.  Then on typical systems we'll
		 * have only one or two banks allocated at a time.
		 */
	}

	/* Associate this xid with this undo log number. */
	MyUndoLogState.xidToLogNumber[high_bits][low_bits] = xlrec->logno;

	log = get_undo_log_by_number(xlrec->logno);
	if (log == NULL)
		elog(ERROR, "cannot attach to unknown undo log %u", xlrec->logno);

	/*
	 * Update the insertion point.  While this races against a checkpoint,
	 * XLOG_UNDOLOG_ATTACH always wins because it must be correct for any
	 * subsequent data appended by this transaction, so we can simply
	 * overwrite it here.
	 */
	SpinLockAcquire(&log->mutex);
	log->meta.insert = xlrec->insert;
	log->xid = xlrec->xid;
	log->pid = MyProcPid; /* show as recovery process */
	SpinLockRelease(&log->mutex);
}

void
undolog_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	elog(LOG, "undolog_redo!");
	switch (info)
	{
		case XLOG_UNDOLOG_CREATE:
			undolog_xlog_create(record);
			break;
		case XLOG_UNDOLOG_EXTEND:
			undolog_xlog_extend(record);
			break;
		case XLOG_UNDOLOG_ATTACH:
			undolog_xlog_attach(record);
			break;
		default:
			elog(PANIC, "undo_redo: unknown op code %u", info);
	}
}
