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
#include "storage/bufmgr.h"
#include "storage/dsm.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/builtins.h"
#include "utils/memutils.h"

#include <sys/stat.h>
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

/* What is the offset of the i'th non-header byte? */
#define UndoLogOffsetFromUsableByteNo(i)								\
	(((i) / UndoLogUsableBytesPerPage) * BLCKSZ +						\
	 UndoLogBlockHeaderSize +											\
	 ((i) % UndoLogUsableBytesPerPage))

/* How many non-header bytes are there before a given offset? */
#define UndoLogOffsetToUsableByteNo(offset)				\
	(((offset) % BLCKSZ - UndoLogBlockHeaderSize) +		\
	 ((offset) / BLCKSZ) * UndoLogUsableBytesPerPage)

/* Add 'n' usable bytes to offset stepping over headers to find new offset. */
#define UndoLogOffsetPlusUsableBytes(offset, n)							\
	UndoLogOffsetFromUsableByteNo(UndoLogOffsetToUsableByteNo(offset) + (n))

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
	bool	need_attach_wal_record;		/* need_attach_wal_record */
	LWLock	mutex;					/* protects the above */

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
static void extend_undo_log(UndoLogNumber logno, UndoLogOffset new_end);
static void undo_log_before_exit(int code, Datum value);

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
		 * We start with no undo logs.  StartUpUndoLogs() will recreate undo
		 * logs that were known at last checkpoint.
		 */
		memset(shared, 0, sizeof(*shared));
		shared->free_list = InvalidUndoLogNumber;
		shared->low_bankno = 0;
		shared->high_bankno = 0;
	}
	else
		Assert(found);
}

void
UndoLogInit(void)
{
	before_shmem_exit(undo_log_before_exit, 0);
}

/*
 * Figure out which directory holds an undo log based on tablespace.
 */
static void
UndoLogDirectory(Oid tablespace, char *dir)
{
	if (tablespace == DEFAULTTABLESPACE_OID ||
		tablespace == InvalidOid)
		snprintf(dir, MAXPGPATH, "base/undo");
	else
		snprintf(dir, MAXPGPATH, "pg_tblspc/%u/%s/undo",
				 tablespace, TABLESPACE_VERSION_DIRECTORY);

	/* XXX Should we use UndoLogDatabaseOid (9) instead of "undo"? */

	/*
	 * XXX Should we add an extra directory between log number and segment
	 * files?  If all undo logs are in the same directory then
	 * fsync(directory) may create contention in the OS between unrelated
	 * backends that as they rotate segment files.
	 */
}

/*
 * Compute the pathname to use for an undo log segment file.
 */
void
UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace, char *path)
{
	char		dir[MAXPGPATH];

	/* Figure out which directory holds the segment, based on tablespace. */
	UndoLogDirectory(tablespace, dir);

	/*
	 * Build the path from log number and offset.  The pathname is the
	 * UndoRecPtr of the first byte in the segment in hexadecimal, with a
	 * period inserted between the components.
	 */
	snprintf(path, MAXPGPATH, "%s/%06X.%010zX", dir, logno,
			 segno * UndoLogSegmentSize);
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
 * Check if an undo log position has been discarded.  'point' must be an undo
 * log pointer that was allocated at some point in the past, otherwise the
 * result is undefined.
 */
bool
UndoLogIsDiscarded(UndoRecPtr point)
{
	UndoLogControl *log = get_undo_log_by_number(UndoRecPtrGetLogNo(point));
	bool	result;

	/*
	 * If we don't recognize the log number, it's either entirely discarded or
	 * it's never been allocated (ie from the future) and our result is
	 * undefined.
	 */
	if (log == NULL)
		return true;

	/*
	 * XXX For a super cheap locked operation, it's better to use LW_EXLUSIVE
	 * even though we don't need exclusivity, right?
	 */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	result = UndoRecPtrGetOffset(point) < log->meta.discard;
	LWLockRelease(&log->mutex);

	return result;
}

/*
 * Store latest transaction's start undo record point in undo meta data.  It
 * will fetched by the backend when it's reusing the undo log and preparing
 * it's first undo.
 */
void
UndoLogSetLastXactStartPoint(UndoRecPtr point)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(point);
	UndoLogControl *log = get_undo_log_by_number(logno);

	/* Update shmem to show the new discard and end pointers. */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.last_xact_start = UndoRecPtrGetOffset(point);
	LWLockRelease(&log->mutex);

	/* WAL log. */
	{
		xl_undolog_xactstart xlrec;

		xlrec.logno = logno;
		xlrec.last_xact_start = UndoRecPtrGetOffset(point);

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_XACTSTART);
	}
}

/*
 * Fetch the previous transaction's start undo record point.  Return Invalid
 * undo pointer if backend is not attached to any log.
 */
UndoRecPtr
UndoLogGetLastXactStartPoint()
{
	UndoLogControl *log = MyUndoLogState.log;
	uint64 last_xact_start = 0;

	if (unlikely(log == NULL))
		return InvalidUndoRecPtr;

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	last_xact_start = log->meta.last_xact_start;
	LWLockRelease(&log->mutex);

	if (last_xact_start == 0)
		return InvalidUndoRecPtr;

	return MakeUndoRecPtr(MyUndoLogState.logno, last_xact_start);
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

	/*
	 * XXX: If it's almost completely full, mark it as retired somehow rather
	 * than putting in in the freelist.
	 */

	/* Push back onto the freelist. */
	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
	log->next_free = shared->free_list;
	shared->free_list = logno;
	LWLockRelease(UndoLogLock);
}

static void
undo_log_before_exit(int code, Datum arg)
{
	if (MyUndoLogState.log != NULL)
		detach_current_undo_log();
}

/*
 * Create a fully allocated empty segment file on disk for the byte starting
 * at 'end'.
 */
static void
allocate_empty_undo_segment(UndoLogNumber logno, Oid tablespace,
							UndoLogOffset end)
{
	struct stat	stat_buffer;
	off_t	size;
	char	path[MAXPGPATH];
	void   *zeroes;
	size_t	nzeroes = 8192;
	int		fd;

	UndoLogSegmentPath(logno, end / UndoLogSegmentSize, tablespace, path);

	/*
	 * Create and fully allocate a new file.  If we crashed and recovered
	 * then the file might already exist, so use flags that tolerate that.
	 * It's also possible that it exists but is too short, in which case
	 * we'll write the rest.  We don't really care what's in the file, we
	 * just want to make sure that the filesystem has allocated physical
	 * blocks for it, so that non-COW filesystems will report ENOSPACE now
	 * rather than later when the space is needed and we'll avoid creating
	 * files with holes.
	 */
	fd = OpenTransientFile(path,
						   O_RDWR | O_CREAT | PG_BINARY);
	if (fd < 0)
		elog(ERROR, "could not create new file \"%s\": %m", path);
	if (fstat(fd, &stat_buffer) < 0)
		elog(ERROR, "could not stat \"%s\": %m", path);
	size = stat_buffer.st_size;

	/* A buffer full of zeroes we'll use to fill up new segment files. */
	zeroes = palloc0(nzeroes);

	while (size < UndoLogSegmentSize)
	{
		ssize_t written;

		written = write(fd, zeroes, Min(nzeroes, UndoLogSegmentSize - size));
		if (written < 0)
			elog(ERROR, "cannot initialize undo log segment file \"%s\": %m",
				 path);
		size += written;
	}

	/* Flush the contents of the file to disk. */
	if (pg_fsync(fd) != 0)
		elog(ERROR, "cannot fsync file \"%s\": %m", path);
	CloseTransientFile(fd);

	pfree(zeroes);

	elog(NOTICE, "created undo segment \"%s\"", path); /* XXX: remove me */
}

/*
 * Create and zero-fill a new segment for the undo log we are currently
 * attached to.
 */
static void
extend_undo_log(UndoLogNumber logno, UndoLogOffset new_end)
{
	UndoLogControl *log;
	char		dir[MAXPGPATH];
	size_t		end;

	log = get_undo_log_by_number(logno);

	Assert(log != NULL);
	Assert(log->meta.end % UndoLogSegmentSize == 0);
	Assert(new_end % UndoLogSegmentSize == 0);
	Assert(MyUndoLogState.log == log || InRecovery);

	/* Create (pseudo) database directory if it doesn't exist. */
	if (log->meta.tablespace != InvalidOid &&
		log->meta.tablespace != DEFAULTTABLESPACE_OID)
		TablespaceCreateDbspace(log->meta.tablespace, UndoLogDatabaseOid,
								false /* TODO: redo flag */);

	/*
	 * Create all the segments needed to increase 'end' to the requested
	 * size.  This is quite expensive, so we will try to avoid it completely
	 * by renaming files into place in UndoLogDiscard instead.
	 */
	end = log->meta.end;
	while (end < new_end)
	{
		allocate_empty_undo_segment(logno, log->meta.tablespace, end);
		end += UndoLogSegmentSize;
	}

	Assert(end == new_end);

	/*
	 * Flush the parent dir so that the directory metadata survives a crash
	 * after this point.
	 */
	UndoLogDirectory(log->meta.tablespace, dir);
	fsync_fname(dir, true);

	/*
	 * If we're not in recovery, we need to WAL-log the creation of the new
	 * file(s).  We do that after the above filesystem modifications, in
	 * violation of the data-before-WAL rule as exempted by
	 * src/backend/access/transam/README.  This means that it's possible for
	 * us to crash having made some or all of the filesystem changes but
	 * before WAL logging, but in that case we'll eventually try to create the
	 * same segment(s) again which is tolerated.
	 */
	if (!InRecovery)
	{
		xl_undolog_extend xlrec;
		XLogRecPtr	ptr;

		xlrec.logno = logno;
		xlrec.end = end;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		ptr = XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_EXTEND);
		XLogFlush(ptr);
	}

	/*
	 * We didn't need to acquire the mutex to read 'end' above because only
	 * we write to it.  But we need the mutex to update it, because the
	 * checkpointer might read it concurrently.
	 *
	 * XXX It's possible for meta.end to be higher already during
	 * recovery, because of the timing of a checkpoint; in that case we did
	 * nothing above and we shouldn't update shmem here.  That interaction
	 * needs more analysis.
	 */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	if (log->meta.end < end)
		log->meta.end = end;
	LWLockRelease(&log->mutex);
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
 * XXX As an optimization, we could take a third argument 'discard_last'.  If
 * the caller knows that the last transaction it committed is all visible and
 * has its undo pointer, it could supply that value.  Then while we hold
 * log->mutex we could check if log->meta.discard == discard_last, and if it's
 * in the same undo log segment as the current insert then it could cheaply
 * update it in shmem and include the value in the existing
 * XLOG_UNDOLOG_ATTACH WAL record.  We'd be leaving the heavier lifting of
 * dealing with segment roll-over to undo workers, but avoiding work for undo
 * workers by folding a super cheap common case into the next foreground xact.
 * (Not sure how we actually avoid waking up the undo work though...)
 *
 * XXX Problem: if foreground processes can move the discard pointer as well
 * as background processes (undo workers), then how is the undo worker
 * supposed to access the undo data pointed to by the discard pointer so that
 * it can read the xid?  We certainly don't want to hold the undo log lock
 * while doing stuff like that, because it would interfere with read-only
 * sessions that need to check the discard pointer.  Possible solution: we may
 * need a way to 'pin' the discard pointer while the undo worker is
 * considering what to do.  If we add 'discard_last' as described in the
 * previous paragraph, that optimisation would need to be skipped if the
 * foreground process running UndoLogAllocate sees that the discard pointer is
 * currently pinned by a background worker.  Going to sit on this thought for
 * a little while before writing any code... need to contemplate undo workers
 * some more.
 *
 * Returns an undo log insertion point that can be converted to a buffer tag
 * and an insertion point within a buffer page using the macros above.
 */
UndoRecPtr
UndoLogAllocate(size_t size, UndoPersistence level)
{
	UndoLogControl *log = MyUndoLogState.log;
	bool	need_attach_wal_record = false;
	UndoLogOffset new_insert;

 retry:

	/* Ensure that we are attached to an undo log. */
	if (unlikely(log == NULL))
	{
		attach_undo_log();
		log = MyUndoLogState.log;
	}

	/*
	 * 'size' is expressed in usable non-header bytes.  Figure out how far we
	 * have to move insert to create space for 'size' usable bytes (stepping
	 * over any intervening headers).
	 */
	Assert(log->meta.insert % BLCKSZ >= UndoLogBlockHeaderSize);
	new_insert = UndoLogOffsetPlusUsableBytes(log->meta.insert, size);
	Assert(new_insert % BLCKSZ >= UndoLogBlockHeaderSize);

	/*
	 * We don't need to acquire log->mutex to read log->meta.insert and
	 * log->meta.end, because this backend is the only one that can
	 * modify them.
	 */
	if (unlikely(new_insert > log->meta.end))
	{
		if (new_insert > UndoLogMaxSize)
		{
			/* This undo log is entirely full.  Get a new one. */
			/*
			 * TODO: do we need to do something more here?  How will the
			 * caller or later the undo worker deal with a transaction being
			 * split over two undo logs?
			 */
			log = MyUndoLogState.log = NULL;
			detach_current_undo_log();
			goto retry;
		}
		/*
		 * Extend the end of this undo log to cover new_insert (in other words
		 * round up to the segment size).
		 */
		extend_undo_log(MyUndoLogState.logno,
						new_insert + UndoLogSegmentSize -
						new_insert % UndoLogSegmentSize);
		Assert(new_insert <= log->meta.end);
	}

	/*
	 * If we haven't already done so since the last checkpoint, associate the
	 * current transaction ID with this undo log, so that
	 * UndoLogAllocateInRecovery knows how to replay this undo space
	 * allocation.
	 */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	if (log->need_attach_wal_record || log->xid != GetTopTransactionId())
	{
		need_attach_wal_record = true;
		log->xid = GetTopTransactionId();
		log->need_attach_wal_record = false;
	}
	LWLockRelease(&log->mutex);

	if (need_attach_wal_record)
	{
		xl_undolog_attach xlrec;

		xlrec.xid = GetTopTransactionId();
		xlrec.logno = MyUndoLogState.logno;
		xlrec.insert = log->meta.insert;

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
UndoLogAllocateInRecovery(TransactionId xid, size_t size,
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
	 * XLOG_UNDOLOG_EXTEND records emitted by UndoLogAllocate, or by
	 * XLOG_UNDLOG_DISCARD records recycling segments.
	 */
	if (log->meta.end < UndoLogOffsetPlusUsableBytes(log->meta.insert, size))
		elog(ERROR,
			 "unexpectedly couldn't allocate %zu bytes in undo log number %d",
			 size, logno);

	return MakeUndoRecPtr(logno, log->meta.insert);
}

/*
 * Advance the insertion pointer by 'size' usable (non-header) bytes.
 *
 * Caller must WAL-log this operation first, and must replay it during
 * recovery.
 */
void
UndoLogAdvance(UndoRecPtr insertion_point, size_t size)
{
	UndoLogControl *log = MyUndoLogState.log;

	Assert(log != NULL);
	Assert(UndoRecPtrGetLogNo(insertion_point) == MyUndoLogState.logno);
	Assert(UndoRecPtrGetOffset(insertion_point) == log->meta.insert);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.insert = UndoLogOffsetPlusUsableBytes(log->meta.insert, size);
	LWLockRelease(&log->mutex);
}

/*
 * Advance the discard pointer in one undo log, discarding all undo data
 * relating to one or more whole transactions.  The passed in undo pointer is
 * the address of the oldest data that the called would like to keep, and the
 * affected undo log is implied by this pointer, ie
 * UndoRecPtrGetLogNo(discard_pointer).
 *
 * The caller asserts that there will be no attempts to access the undo log
 * region being discarded after this moment.  This operation will cause the
 * relevant buffers to be dropped immediately, without writing any data out to
 * disk.  Any attempt to read the buffers (except a partial buffer at the end
 * of this range which will remain) may result in IO errors, because the
 * underlying segment file may physically removed.
 *
 * Only one backend should call this for a given undo log concurrently, or
 * data structures will become corrupted.  It is expected that the caller will
 * be an undo worker; only one undo worker should be working on a given undo
 * log at a time.
 *
 * XXX Special case for when we wrapped past the end of an undo log, spilling
 * into a new one.  How do we discard that?  Essentially we'll be discarding
 * the whole undo log, but not sure how the caller should know that or deal
 * with it and how this code should handle it.
 */
void
UndoLogDiscard(UndoRecPtr discard_point)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(discard_point);
	UndoLogControl *log = get_undo_log_by_number(logno);
	UndoLogOffset old_discard;
	UndoLogOffset discard = UndoRecPtrGetOffset(discard_point);
	UndoLogOffset end;
	BlockNumber old_blockno;
	BlockNumber blockno;
	RelFileNode	rnode;
	int		segno;
	int		new_segno;
	bool		need_to_flush_wal = false;

	if (log == NULL)
		elog(ERROR, "cannot advance discard pointer for unknown undo log %d",
			 logno);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	if (discard > log->meta.insert)
		elog(ERROR, "cannot move discard point past insert point");
	old_discard = log->meta.discard;
	if (discard < old_discard)
		elog(ERROR, "cannot move discard pointer backwards");
	end = log->meta.end;
	LWLockRelease(&log->mutex);

	/*
	 * Check if we crossed a segment boundary and need to do some synchronous
	 * filesystem operations.
	 */
	segno = old_discard / UndoLogSegmentSize;
	new_segno = discard / UndoLogSegmentSize;
	if (segno < new_segno)
	{
		int		recycle;
		UndoLogOffset pointer;

		/*
		 * We always WAL-log discards, but we only need to flush the WAL if we
		 * have performed a filesystem operation.
		 */
		need_to_flush_wal = true;

		/*
		 * XXX When we rename or unlink a file, it's possible that some
		 * backend still has it open because it has recently read a page from
		 * it.  smgr/undofile.c in any such backend will eventually close it,
		 * because it considers that fd to belong to the file with the name
		 * that we're unlinking or renaming and it doesn't like to keep more
		 * than one open at a time.  No backend should ever try to read from
		 * such a file descriptor; that is what it means when we say that the
		 * caller of UndoLogDiscard() asserts that there will be no attempts
		 * to access the discarded range of undo log!  In the case of a
		 * rename, if a backend were to attempt to read undo data in the range
		 * being discarded, it would read entirely the wrong data.
		 *
		 * XXX What defenses could we build against that happening due to
		 * bugs/corruption?  One way would be for undofile.c to refuse to read
		 * buffers from before the current discard point, but currently
		 * undofile.c doesn't need to deal with shmem/locks.  That may be
		 * false economy, but we really don't want reader to have to wait to
		 * acquire the undo log lock just to read undo data while we are doing
		 * filesystem stuff in here.
		 */

		/*
		 * XXX Decide how many segments to recycle (= rename from tail
		 * position to head position).
		 *
		 * XXX For now it's always 1 unless there is already a spare one, but
		 * we could have an adaptive algorithm with the following goals:
		 *
		 * (1) handle future workload without having to create new segment
		 * files from scratch
		 *
		 * (2) reduce the rate of fsyncs require for recycling by doing
		 * several at once
		 */
		if (log->meta.end - log->meta.insert < UndoLogSegmentSize)
			recycle = 1;
		else
			recycle = 0;

		/* Rewind to the start of the segment. */
		pointer = segno * UndoLogSegmentSize;

		while (pointer < new_segno * UndoLogSegmentSize)
		{
			char	discard_path[MAXPGPATH];

			UndoLogSegmentPath(logno, pointer / UndoLogSegmentSize,
							   log->meta.tablespace, discard_path);

			/* Can we recycle the oldest segment? */
			if (recycle > 0)
			{
				char	recycle_path[MAXPGPATH];

				/*
				 * End points one byte past the end of the current undo space,
				 * ie to the first byte of the segment file we want to create.
				 */
				UndoLogSegmentPath(logno, end / UndoLogSegmentSize,
								   log->meta.tablespace, recycle_path);
				if (rename(discard_path, recycle_path) == 0)
				{
					elog(NOTICE, "renamed undo segment \"%s\" -> \"%s\"", discard_path, recycle_path); /* XXX: remove me */
					end += UndoLogSegmentSize;
					--recycle;
				}
				else
				{
					elog(ERROR, "could not rename \"%s\" to \"%s\": %m",
						 discard_path, recycle_path);
				}
			}
			else
			{
				if (unlink(discard_path) == 0)
					elog(NOTICE, "unlinked \"%s\"", discard_path); /* XXX: remove me */
				else
					elog(ERROR, "could not unlink \"%s\": %m", discard_path);
			}
			pointer += UndoLogSegmentSize;
		}
	}

	/* WAL log the discard. */
	{
		xl_undolog_discard xlrec;
		XLogRecPtr ptr;

		xlrec.logno = logno;
		xlrec.discard = discard;
		xlrec.end = end;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		ptr = XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_DISCARD);

		if (need_to_flush_wal)
			XLogFlush(ptr);
	}

	/*
	 * Drop all buffers holding this undo data out of the buffer pool (except
	 * the last one, if the new location is in the middle of it somewhere), so
	 * that the contained data doesn't ever touch the disk.  The caller
	 * promises that this data will not be needed again.
	 */
	UndoRecPtrAssignRelFileNode(rnode, MakeUndoRecPtr(logno, old_discard));
	old_blockno = old_discard / BLCKSZ;
	blockno = discard / BLCKSZ;
	while (old_blockno < blockno)
		ForgetBuffer(rnode, UndoLogForkNum, old_blockno++);

	/* Update shmem to show the new discard and end pointers. */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.discard = discard;
	log->meta.end = end;
	LWLockRelease(&log->mutex);
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
 * Return first valid UndoRecPtr for a given undo logno.  If logno is invalid
 * then return InvalidUndoRecPtr.
 */
UndoRecPtr
UndoLogGetFirstValidRecord(UndoLogNumber logno)
{
	UndoLogControl *log = get_undo_log_by_number(logno);

	if (log == NULL || log->meta.discard == log->meta.insert)
		return InvalidUndoRecPtr;

	return MakeUndoRecPtr(logno, log->meta.discard);
}

/*
 * Return the Next insert location.  This will also validate the input xid
 * if latest insert point is not for the same transaction id then this will
 * return Invalid Undo pointer.
 */
UndoRecPtr
UndoLogGetNextInsertPtr(UndoLogNumber logno, TransactionId xid)
{
	UndoLogControl *log = get_undo_log_by_number(logno);
	TransactionId	logxid;
	UndoRecPtr	insert;

	LWLockAcquire(&log->mutex, LW_SHARED);
	insert = log->meta.insert;
	logxid = log->xid;
	LWLockRelease(&log->mutex);

	if (TransactionIdIsValid(logxid) && !TransactionIdEquals(logxid, xid))
		return InvalidUndoRecPtr;

	return MakeUndoRecPtr(logno, insert);
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

	/*
	 * If a base backup is in progress, we can't delete any checkpoint
	 * snapshot files because one of them corresponds to the backup label but
	 * there could be any number of checkpoints during the backup.
	 */
	if (BackupInProgress())
		return;

	/* Otherwise keep only those >= the previous checkpoint's redo point. */
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

			/* Snapshot while holding the mutex. */
			LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
			log->need_attach_wal_record = true;
			memcpy(&serialized[logno], &log->meta, sizeof(UndoLogMetaData));
			LWLockRelease(&log->mutex);
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
		elog(ERROR, "cannot open undo checkpoint snapshot \"%s\": %m", path);

	/* Read the active log number range. */
	if ((read(fd, &shared->low_logno, sizeof(shared->low_logno))
		 != sizeof(shared->low_logno)) ||
		(read(fd, &shared->high_logno, sizeof(shared->high_logno))
		 != sizeof(shared->high_logno)))
		elog(ERROR, "pg_undo file \"%s\" is corrupted", path);

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
		LWLockInitialize(&log->mutex, LWTRANCHE_UNDOLOG);
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
		elog(LOG, "size = %zd", size);
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
		Assert(log->meta.discard == 0);
		Assert(log->meta.insert == 0);
		Assert(log->meta.end == 0);
		Assert(log->pid == 0);
		Assert(log->xid == 0);
		Assert(log->next_free == 0);

		/*
		 * The insert and discard pointers start after the first block's
		 * header.  XXX That means that insert is > end for a short time in a
		 * newly created undo log.  Is there any problem with that?
		 */
		log->meta.insert = UndoLogBlockHeaderSize;
		log->meta.discard = UndoLogBlockHeaderSize;

		/* Initialize. */
		LWLockInitialize(&log->mutex, LWTRANCHE_UNDOLOG);

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

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->pid = MyProcPid;
	log->xid = GetTopTransactionId();
	log->need_attach_wal_record = true;
	LWLockRelease(&log->mutex);

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
		char buffer[17];

		if (log == NULL)
			continue;

		/*
		 * This won't be a consistent result overall, but the values for each
		 * log will be consistent because we'll take the per-log lock while
		 * copying them.
		 */
		LWLockAcquire(&log->mutex, LW_SHARED);
		values[0] = ObjectIdGetDatum((Oid) logno);
		values[1] = ObjectIdGetDatum(log->meta.tablespace);
		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(logno, log->meta.discard));
		values[2] = CStringGetTextDatum(buffer);
		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(logno, log->meta.insert));
		values[3] = CStringGetTextDatum(buffer);
		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(logno, log->meta.end));
		values[4] = CStringGetTextDatum(buffer);
		values[5] = TransactionIdGetDatum(log->xid);
		values[6] = Int32GetDatum((int64) log->pid);
		LWLockRelease(&log->mutex);

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
	log->meta.insert = UndoLogBlockHeaderSize;
	log->meta.discard = UndoLogBlockHeaderSize;
	LWLockInitialize(&log->mutex, LWTRANCHE_UNDOLOG);

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

	/* Extend exactly as we would during DO phase. */
	extend_undo_log(xlrec->logno, xlrec->end);
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
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.insert = xlrec->insert;
	log->xid = xlrec->xid;
	log->pid = MyProcPid; /* show as recovery process */
	LWLockRelease(&log->mutex);
}

/*
 * replay an undo segment discard record
 */
static void
undolog_xlog_discard(XLogReaderState *record)
{
	xl_undolog_discard *xlrec = (xl_undolog_discard *) XLogRecGetData(record);
	UndoLogControl *log;
	UndoLogOffset discard;
	UndoLogOffset end;
	UndoLogOffset old_segment_begin;
	UndoLogOffset new_segment_begin;
	char	dir[MAXPGPATH];

	log = get_undo_log_by_number(xlrec->logno);
	if (log == NULL)
		elog(ERROR, "unknown undo log %d", xlrec->logno);

	/*
	 * See if we need to unlink or rename any files, but don't consider it an
	 * error if we find that files are missing.  Since UndoLogDiscard()
	 * performs filesystem operations before WAL logging or updating shmem
	 * which could be checkpointed, a crash could have left files already
	 * deleted, but we could replay WAL that expects the files to be there.
	 */

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	discard = log->meta.discard;
	end = log->meta.end;
	LWLockRelease(&log->mutex);

	/* Rewind to the start of the segment. */
	old_segment_begin = discard - discard % UndoLogSegmentSize;
	new_segment_begin = xlrec->discard - xlrec->discard % UndoLogSegmentSize;

	/* Unlink or rename segments that are no longer in range. */
	while (old_segment_begin < new_segment_begin)
	{
		char	discard_path[MAXPGPATH];

		UndoLogSegmentPath(xlrec->logno, old_segment_begin / UndoLogSegmentSize,
						   log->meta.tablespace, discard_path);

		/* Can we recycle the oldest segment? */
		if (end < xlrec->end)
		{
			char	recycle_path[MAXPGPATH];

			UndoLogSegmentPath(xlrec->logno, end / UndoLogSegmentSize,
							   log->meta.tablespace, recycle_path);
			if (rename(discard_path, recycle_path) == 0)
			{
				elog(NOTICE, "renamed undo segment \"%s\" -> \"%s\"", discard_path, recycle_path); /* XXX: remove me */
				end += UndoLogSegmentSize;
			}
			else
			{
				elog(LOG, "could not rename \"%s\" to \"%s\": %m",
					 discard_path, recycle_path);
			}
		}
		else
		{
			if (unlink(discard_path) == 0)
				elog(NOTICE, "unlinked \"%s\"", discard_path); /* XXX: remove me */
			else
				elog(LOG, "could not unlink \"%s\": %m", discard_path);
		}
		old_segment_begin += UndoLogSegmentSize;
	}

	/* Create any further new segments that are needed the slow way. */
	while (end < xlrec->end)
	{
		allocate_empty_undo_segment(xlrec->logno, log->meta.tablespace, end);
		end += UndoLogSegmentSize;
	}

	/* Flush the directory entries. */
	UndoLogDirectory(log->meta.tablespace, dir);
	fsync_fname(dir, true);

	/* Update shmem. */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.discard = xlrec->discard;
	log->meta.end = end;
	LWLockRelease(&log->mutex);
}

/*
 * replay an undo last xact start record
 */
static void
undolog_xlog_xactstart(XLogReaderState *record)
{
	xl_undolog_xactstart *xlrec = (xl_undolog_xactstart *) XLogRecGetData(record);
	UndoLogControl *log;

	log = get_undo_log_by_number(xlrec->logno);
	if (log == NULL)
		elog(ERROR, "unknown undo log %d", xlrec->logno);

	/* Update shmem. */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.last_xact_start = xlrec->last_xact_start;
	LWLockRelease(&log->mutex);
}

void
undolog_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

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
		case XLOG_UNDOLOG_DISCARD:
			undolog_xlog_discard(record);
			break;
		case XLOG_UNDOLOG_XACTSTART:
			undolog_xlog_xactstart(record);
			break;
		default:
			elog(PANIC, "undo_redo: unknown op code %u", info);
	}
}
