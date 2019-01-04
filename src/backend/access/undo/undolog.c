/*-------------------------------------------------------------------------
 *
 * undolog.c
 *	  management of undo logs
 *
 * PostgreSQL undo log manager.  This module is responsible for managing the
 * lifecycle of undo logs and their segment files, associating undo logs with
 * backends, and allocating space within undo logs.
 *
 * For the code that reads and writes blocks of data, see undofile.c.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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
#include "access/xlog.h"
#include "access/xlogreader.h"
#include "access/xlogutils.h"
#include "catalog/catalog.h"
#include "catalog/pg_tablespace.h"
#include "commands/tablespace.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/execnodes.h"
#include "pgstat.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/procarray.h"
#include "storage/shmem.h"
#include "storage/smgrsync.h"
#include "storage/standby.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/varlena.h"

#include <sys/stat.h>
#include <unistd.h>

/*
 * During recovery we maintain a mapping of transaction ID to undo logs
 * numbers.  We do this with a two-level array, so that we use memory only for
 * chunks of the array that overlap with the range of active xids.
 */
#define UndoLogXidLowBits 16

/*
 * Number of high bits.
 */
#define UndoLogXidHighBits \
	(sizeof(TransactionId) * CHAR_BIT - UndoLogXidLowBits)

/* Extract the upper bits of an xid, for undo log mapping purposes. */
#define UndoLogGetXidHigh(xid) ((xid) >> UndoLogXidLowBits)

/* Extract the lower bits of an xid, for undo log mapping purposes. */
#define UndoLogGetXidLow(xid) ((xid) & ((1 << UndoLogXidLowBits) - 1))

/*
 * Main control structure for undo log management in shared memory.
 * UndoLogControl objects are arranged in a fixed-size array, at a position
 * determined by the undo log number.
 */
typedef struct UndoLogSharedData
{
	UndoLogNumber free_lists[UndoPersistenceLevels];
	UndoLogNumber low_logno; /* the lowest logno */
	UndoLogNumber next_logno; /* one past the highest logno */
	UndoLogNumber array_size; /* how many UndoLogControl objects do we have? */
	UndoLogControl logs[FLEXIBLE_ARRAY_MEMBER];
} UndoLogSharedData;

/*
 * Per-backend state for the undo log module.
 * Backend-local pointers to undo subsystem state in shared memory.
 */
typedef struct UndoLogSession
{
	UndoLogSharedData *shared;

	/*
	 * The control object for the undo logs that this session is currently
	 * attached to at each persistence level.  This is where it will write new
	 * undo data.
	 */
	UndoLogControl *logs[UndoPersistenceLevels];

	/*
	 * If the undo_tablespaces GUC changes we'll remember to examine it and
	 * attach to a new undo log using this flag.
	 */
	bool			need_to_choose_tablespace;

	/* Current dbid.  Used during recovery. */
	Oid				dbid;
} UndoLogSession;

UndoLogSession MyUndoLogState;

undologtable_hash *undologtable_cache;

/* GUC variables */
char	   *undo_tablespaces = NULL;

static UndoLogControl *get_undo_log(UndoLogNumber logno, bool locked);
static UndoLogControl *allocate_undo_log(void);
static void free_undo_log(UndoLogControl *log);
static void attach_undo_log(UndoPersistence level, Oid tablespace);
static void detach_current_undo_log(UndoPersistence level, bool full);
static void extend_undo_log(UndoLogNumber logno, UndoLogOffset new_end);
static void undo_log_before_exit(int code, Datum value);
static void forget_undo_buffers(int logno, UndoLogOffset old_discard,
								UndoLogOffset new_discard,
								bool drop_tail);
static bool choose_undo_tablespace(bool force_detach, Oid *oid);

/*
 * The maximum number of undo logs that a single WAL record could touch.
 * Typically the number is 1, but it might touch a couple or more in rare
 * cases where space runs out.
 */
#define MAX_META_DATA_IMAGES 8
static struct
{
	UndoLogNumber logno;
	UndoLogUnloggedMetaData data;
} meta_data_images[MAX_META_DATA_IMAGES];
/*
static UndoLogNumber meta_data_images_lognos[MAX_META_DATA_IMAGES];
static UndoLogUnloggedMetaData meta_data_images[MAX_META_DATA_IMAGES];
*/
static int num_meta_data_images;
static UndoLogNumber allocate_in_recovery_logno;
static uint8 allocate_in_recovery_block_id;

PG_FUNCTION_INFO_V1(pg_stat_get_undo_logs);

/*
 * How many undo logs can be active at a time?  This creates a theoretical
 * maximum transaction size, but if we set it to a multiple of the maximum
 * number of backends it will be a very high limit.  Alternative designs
 * involving demand paging or dynamic shared memory could remove this limit
 * but introduce other problems.
 */
static inline size_t
UndoLogNumSlots(void)
{
	return MaxBackends * 4;
}

/*
 * Return the amount of traditional shmem required for undo log management.
 */
Size
UndoLogShmemSize(void)
{
	return sizeof(UndoLogSharedData) +
		UndoLogNumSlots() * sizeof(UndoLogControl);
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

	/* The postmaster initialized the shared memory state. */
	if (!IsUnderPostmaster)
	{
		UndoLogSharedData *shared = MyUndoLogState.shared;
		int		i;

		Assert(!found);

		/*
		 * We start with no active undo logs.  StartUpUndoLogs() will recreate
		 * the undo logs that were known at the last checkpoint.
		 */
		memset(shared, 0, sizeof(*shared));
		shared->array_size = UndoLogNumSlots();
		for (i = 0; i < UndoPersistenceLevels; ++i)
			shared->free_lists[i] = InvalidUndoLogNumber;
		for (i = 0; i < shared->array_size; ++i)
		{
			memset(&shared->logs[i], 0, sizeof(shared->logs[i]));
			shared->logs[i].logno = InvalidUndoLogNumber;
			LWLockInitialize(&shared->logs[i].mutex,
							 LWTRANCHE_UNDOLOG);
			LWLockInitialize(&shared->logs[i].discard_lock,
							 LWTRANCHE_UNDODISCARD);
			LWLockInitialize(&shared->logs[i].rewind_lock,
							 LWTRANCHE_REWIND);
		}
	}
	else
		Assert(found);

	/* All backends prepare their per-backend lookup table. */
	undologtable_cache = undologtable_create(TopMemoryContext,
											 UndoLogNumSlots(),
											 NULL);
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
 * Iterate through the set of currently active logs.  Pass in NULL to get the
 * first undo log.  NULL indicates the end of the set of logs.  The caller
 * must lock the returned log before accessing its members, and must skip if
 * logno is not valid.
 */
UndoLogControl *
UndoLogNext(UndoLogControl *log)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;

	LWLockAcquire(UndoLogLock, LW_SHARED);
	for (;;)
	{
		/* Advance to the next log. */
		if (log == NULL)
		{
			/* Start at the beginning. */
			log = &shared->logs[0];
		}
		else if (++log == &shared->logs[shared->array_size])
		{
			/* Past the end. */
			log = NULL;
			break;
		}
		/* Have we found a slot with a valid log? */
		if (log->logno != InvalidUndoLogNumber)
			break;
	}
	LWLockRelease(UndoLogLock);

	/* XXX: erm, which lock should the caller hold!? */
	return log;
}

/*
 * Check if an undo log position has been discarded.  'point' must be an undo
 * log pointer that was allocated at some point in the past, otherwise the
 * result is undefined.
 */
bool
UndoLogIsDiscarded(UndoRecPtr point)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(point);
	UndoLogControl *log;
	bool	result;

	log = get_undo_log(logno, false);

	/*
	 * If we couldn't find the undo log number, then it must be entirely
	 * discarded.
	 */
	if (log == NULL)
		return true;

	LWLockAcquire(&log->mutex, LW_SHARED);
	if (unlikely(logno != log->logno))
	{
		/*
		 * The undo log has been entirely discarded since we looked it up, and
		 * the UndoLogControl slot is now unused or being used for some other
		 * undo log.  That means that any pointer within it must be discarded.
		 */
		result = true;
	}
	else
	{
		/* Check if this point is before the discard pointer. */
		result = UndoRecPtrGetOffset(point) < log->meta.discard;
	}
	LWLockRelease(&log->mutex);

	return result;
}

/*
 * Fetch the previous transaction's start undo record point.
 */
UndoRecPtr
UndoLogGetLastXactStartPoint(UndoLogNumber logno)
{
	UndoLogControl *log = get_undo_log(logno, false);
	uint64 last_xact_start = 0;

	if (unlikely(log == NULL))
		return InvalidUndoRecPtr;

	LWLockAcquire(&log->mutex, LW_SHARED);
	/* TODO: review */
	last_xact_start = log->meta.unlogged.last_xact_start;
	LWLockRelease(&log->mutex);

	if (last_xact_start == 0)
		return InvalidUndoRecPtr;

	return MakeUndoRecPtr(logno, last_xact_start);
}

/*
 * Get the last undo record's length.
 */
uint16
UndoLogGetPrevLen(UndoLogNumber logno)
{
	UndoLogControl *log = get_undo_log(logno, false);
	uint16	prevlen;

	Assert(log != NULL);

	LWLockAcquire(&log->mutex, LW_SHARED);
	/* TODO review */
	prevlen = log->meta.unlogged.prevlen;
	LWLockRelease(&log->mutex);

	return prevlen;
}

/*
 * Detach from the undo log we are currently attached to, returning it to the
 * appropriate free list if it still has space.
 */
static void
detach_current_undo_log(UndoPersistence persistence, bool full)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log = MyUndoLogState.logs[persistence];

	Assert(log != NULL);

	MyUndoLogState.logs[persistence] = NULL;

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->pid = InvalidPid;
	log->meta.unlogged.xid = InvalidTransactionId;
	if (full)
		log->meta.status = UNDO_LOG_STATUS_FULL;
	LWLockRelease(&log->mutex);

	/* Push back onto the appropriate free list, unless it's full. */
	if (!full)
	{
		LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
		log->next_free = shared->free_lists[persistence];
		shared->free_lists[persistence] = log->logno;
		LWLockRelease(UndoLogLock);
	}
}

/*
 * Exit handler, detaching from all undo logs.
 */
static void
undo_log_before_exit(int code, Datum arg)
{
	int		i;

	for (i = 0; i < UndoPersistenceLevels; ++i)
	{
		if (MyUndoLogState.logs[i] != NULL)
			detach_current_undo_log(i, false);
	}
}

/*
 * Create a new empty segment file on disk for the byte starting at 'end'.
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
	 * blocks for it, so that non-COW filesystems will report ENOSPC now
	 * rather than later when the space is needed and we'll avoid creating
	 * files with holes.
	 */
	fd = OpenTransientFile(path, O_RDWR | O_CREAT | PG_BINARY);
	if (fd < 0 && tablespace != 0)
	{
		char undo_path[MAXPGPATH];

		/* Try creating the undo directory for this tablespace. */
		UndoLogDirectory(tablespace, undo_path);
		if (mkdir(undo_path, S_IRWXU) != 0 && errno != EEXIST)
		{
			char	   *parentdir;

			if (errno != ENOENT || !InRecovery)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not create directory \"%s\": %m",
								undo_path)));

			/*
			 * In recovery, it's possible that the tablespace directory
			 * doesn't exist because a later WAL record removed the whole
			 * tablespace.  In that case we create a regular directory to
			 * stand in for it.  This is similar to the logic in
			 * TablespaceCreateDbspace().
			 */

			/* create two parents up if not exist */
			parentdir = pstrdup(undo_path);
			get_parent_directory(parentdir);
			get_parent_directory(parentdir);
			/* Can't create parent and it doesn't already exist? */
			if (mkdir(parentdir, S_IRWXU) < 0 && errno != EEXIST)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not create directory \"%s\": %m",
								parentdir)));
			pfree(parentdir);

			/* create one parent up if not exist */
			parentdir = pstrdup(undo_path);
			get_parent_directory(parentdir);
			/* Can't create parent and it doesn't already exist? */
			if (mkdir(parentdir, S_IRWXU) < 0 && errno != EEXIST)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not create directory \"%s\": %m",
								parentdir)));
			pfree(parentdir);

			if (mkdir(undo_path, S_IRWXU) != 0 && errno != EEXIST)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not create directory \"%s\": %m",
								undo_path)));
		}

		fd = OpenTransientFile(path, O_RDWR | O_CREAT | PG_BINARY);
	}
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

	elog(LOG, "created undo segment \"%s\"", path); /* XXX: remove me */
}

/*
 * Create a new undo segment, when it is unexpectedly not present.
 */
void
UndoLogNewSegment(UndoLogNumber logno, Oid tablespace, int segno)
{
	Assert(InRecovery);
	allocate_empty_undo_segment(logno, tablespace, segno * UndoLogSegmentSize);
}

/*
 * Create and zero-fill a new segment for a given undo log number.
 */
static void
extend_undo_log(UndoLogNumber logno, UndoLogOffset new_end)
{
	UndoLogControl *log;
	char		dir[MAXPGPATH];
	size_t		end;

	log = get_undo_log(logno, false);

	/* TODO review interlocking */

	Assert(log != NULL);
	Assert(log->meta.end % UndoLogSegmentSize == 0);
	Assert(new_end % UndoLogSegmentSize == 0);
	Assert(MyUndoLogState.logs[log->meta.persistence] == log || InRecovery);

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
	 * same segment(s) again, which is tolerated.
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
 * This function must be called before all of the undo log activity that will
 * be covered by a single WAL record.
 */
void
UndoLogBeginInsert(void)
{
	/*
	 * Tell UndoLogAllocate() to capture undo log meta-data before-change
	 * images, so that UndoLogRegister() can find them and they can be written
	 * to the WAL once per checkpoint.
	 */
	num_meta_data_images = 0;

	/*
	 * Tell UndoLogAllocateInRecovery() that we don't know which undo log to
	 * allocate in yet, and to start its search for registered blocks at
	 * the lowest-numbered block_id.
	 */
	allocate_in_recovery_logno = InvalidUndoLogNumber;
	allocate_in_recovery_block_id = 0;
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
 * A suggested insertion point can optionally be passed in as 'try_location',
 * and will be returned if possible.  If not InvalidUndoRecPtr, it must fall
 * with, or exactly one byte after, the most recent allocation for the same
 * persistence level.  This interface allows for a series of allocation to be
 * made without committing to using the space yet; call UndoLogAdvance() to
 * actually advance the insert pointer.
 *
 * Return an undo log insertion point that can be converted to a buffer tag
 * and an insertion point within a buffer page.
 */
UndoRecPtr
UndoLogAllocate(uint16 size,
				UndoRecPtr try_location,
				UndoPersistence persistence,
				bool *need_xact_header)
{
	UndoLogControl *log = MyUndoLogState.logs[persistence];
	UndoLogOffset new_insert;
	UndoLogNumber prevlogno = InvalidUndoLogNumber;
	TransactionId logxid;

	/*
	 * We may need to attach to an undo log, either because this is the first
	 * time this backend as needed to write to an undo log at all or because
	 * the undo_tablespaces GUC was changed.  When doing that, we'll need
	 * interlocking against tablespaces being concurrently dropped.
	 */

 retry:
	/* See if we need to check the undo_tablespaces GUC. */
	if (unlikely(MyUndoLogState.need_to_choose_tablespace || log == NULL))
	{
		Oid		tablespace;
		bool	need_to_unlock;

		need_to_unlock =
			choose_undo_tablespace(MyUndoLogState.need_to_choose_tablespace,
								   &tablespace);
		attach_undo_log(persistence, tablespace);
		if (need_to_unlock)
			LWLockRelease(TablespaceCreateLock);
		log = MyUndoLogState.logs[persistence];
		log->meta.unlogged.prevlogno = prevlogno;
		MyUndoLogState.need_to_choose_tablespace = false;
	}

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	logxid = log->meta.unlogged.xid;

	if (logxid != GetTopTransactionId())
	{
		/*
		 * While we have the lock, check if we have been forcibly detached by
		 * DROP TABLESPACE.  That can only happen between transactions (see
		 * DropUndoLogsInsTablespace()).
		 */
		if (log->pid == InvalidPid)
		{
			LWLockRelease(&log->mutex);
			log = NULL;
			goto retry;
		}
		log->meta.unlogged.xid = GetTopTransactionId();
		if (log->meta.unlogged.this_xact_start != log->meta.unlogged.insert)
		{
			log->meta.unlogged.last_xact_start =
				log->meta.unlogged.this_xact_start;
			log->meta.unlogged.this_xact_start = log->meta.unlogged.insert;
		}
		LWLockRelease(&log->mutex);
	}
	else
	{
		LWLockRelease(&log->mutex);
	}

	/*
	 * 'size' is expressed in usable non-header bytes.  Figure out how far we
	 * have to move insert to create space for 'size' usable bytes, stepping
	 * over any intervening headers.
	 */
	Assert(log->meta.unlogged.insert % BLCKSZ >= UndoLogBlockHeaderSize);
	if (try_location != InvalidUndoRecPtr)
	{
		/*
		 * The try location must be in the log we're attached to, at most one
		 * byte past the end of space backed by files.
		 */
		UndoLogOffset try_offset = UndoRecPtrGetOffset(try_location);

		Assert(UndoRecPtrGetLogNo(try_location) == log->logno);
		Assert(try_offset <= log->meta.end);
		new_insert = UndoLogOffsetPlusUsableBytes(try_offset, size);
	}
	else
	{
		new_insert = UndoLogOffsetPlusUsableBytes(log->meta.unlogged.insert,
												  size);
	}
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
			if (logxid == GetTopTransactionId())
			{
				/*
				 * If the same transaction is split over two undo logs then
				 * store the previous log number in new log.  See detailed
				 * comments in undorecord.c file header.
				 */
				prevlogno = log->logno;
			}
			elog(LOG, "undo log %u is full, switching to a new one", log->logno);
			log = NULL;
			detach_current_undo_log(persistence, true);
			try_location = InvalidUndoRecPtr;
			goto retry;
		}
		/*
		 * Extend the end of this undo log to cover new_insert (in other words
		 * round up to the segment size).
		 */
		extend_undo_log(log->logno,
						new_insert + UndoLogSegmentSize -
						new_insert % UndoLogSegmentSize);
		Assert(new_insert <= log->meta.end);
	}

	/*
	 * Create a back-up image of the unlogged part of the undo log's
	 * meta-data, if we haven't already done so since UndoLogBeginInsert() (ie
	 * for the WAL record that this undo allocation will be replayed by).
	 */
	if (num_meta_data_images == 0 ||
		meta_data_images[num_meta_data_images - 1].logno != log->logno)
	{
		if (num_meta_data_images >= MAX_META_DATA_IMAGES)
			elog(ERROR, "too many undo log meta data images");
		meta_data_images[num_meta_data_images].logno = log->logno;
		meta_data_images[num_meta_data_images++].data = log->meta.unlogged;
	}

	/* Is this location the first in this undo log for a transaction? */
	*need_xact_header =
		try_location == InvalidUndoRecPtr &&
		UndoRecPtrGetOffset(try_location) == log->meta.unlogged.this_xact_start;

	/*
	 * If no try_location was passed in, or if we switched logs, then we'll
	 * return the current insertion point.
	 */
	if (try_location == InvalidUndoRecPtr)
		try_location = MakeUndoRecPtr(log->logno, log->meta.unlogged.insert);

	return try_location;
}

void
UndoLogRegister(uint8 block_id, UndoLogNumber logno)
{
	int		i;

	for (i = 0; i < num_meta_data_images; ++i)
	{
		if (meta_data_images[i].logno == logno)
		{
			XLogRegisterBufData(block_id,
								(char *) &meta_data_images[i].data,
								sizeof(meta_data_images[i].data));
			return;
		}
	}
	elog(ERROR,
		 "could not find undo log meta-data for logno %d", logno);
}

/*
 * In recovery, we expect exactly the same sequence of allocation sizes, but
 * we also need the WAL record that is being replayed so we can figure out
 * where the undo space was allocated.
 */
UndoRecPtr
UndoLogAllocateInRecovery(TransactionId xid,
						  uint16 size,
						  UndoRecPtr try_location,
						  bool *need_xact_header,
						  XLogReaderState *xlog_record)
{
	UndoLogControl *log;

	Assert(InRecovery);

	/*
	 * Just as in UndoLogAllocate(), the caller may be extending an existing
	 * allocation before committing with UndoLogAdvance().
	 */
	if (try_location != InvalidUndoRecPtr)
	{
		/*
		 * The try location must be in the log we're attached to, at most one
		 * byte past the end of space backed by files.
		 */
		UndoLogOffset try_offset = UndoRecPtrGetOffset(try_location);
		UndoLogNumber logno = UndoRecPtrGetLogNo(try_location);

		/*
		 * You can only have a try_location on your second or later allocation
		 * for a given WAL record.  It had better be in the same log as the
		 * previous allocation for this WAL record (though it may not turn out
		 * to have enough space, below).
		 */
		Assert(logno == allocate_in_recovery_logno);

		/*
		 * Any log extension triggered by UndoLogAllocate() must have been
		 * replayed by now, so we can just check if this log has enough space,
		 * and if so, return.
		 */
		log = get_undo_log(logno, false);
		if (UndoLogOffsetPlusUsableBytes(try_offset, size) <= log->meta.end)
			return try_offset;

		/* Full.  Ignore try_location and find the next log that was used. */
		Assert(log->meta.status == UNDO_LOG_STATUS_FULL);
	}
	else
	{
		/*
		 * For now we only support one allocation per WAL record that doesn't
		 * have a try_location (ie the first one).  We'll have to find out
		 * which log was used first.
		 */
		Assert(allocate_in_recovery_logno == InvalidUndoLogNumber);
	}

	/*
	 * In order to find the undo log that was used by UndoLogAllocate(), we
	 * consult the list of registered blocks to figure out which undo logs
	 * should be written to by this WAL record.
	 */
	while (allocate_in_recovery_block_id <= xlog_record->max_block_id)
	{
		DecodedBkpBlock *block;

		/* We're looking for the first block referencing a new undo log. */
		block = &xlog_record->blocks[allocate_in_recovery_block_id];
		if (block->rnode.dbNode == UndoLogDatabaseOid &&
			block->rnode.relNode != allocate_in_recovery_logno)
		{
			UndoLogNumber logno = block->rnode.relNode;
			const void *backup;
			size_t backup_size;

			/* We found a reference to a different (or first) undo log. */
			log = get_undo_log(logno, false);

			/*
			 * Since on-line checkpoints capture an inconsistent snapshot of
			 * undo log meta-data, we'll restore the unlogged part of the
			 * meta-data image if one was attached to the WAL record (that is,
			 * the members that don't have WAL records for every change
			 * already).
			 */
			backup =
				XLogRecGetBlockData(xlog_record, allocate_in_recovery_block_id,
									&backup_size);
			if (unlikely(backup))
			{
				Assert(backup_size == sizeof(UndoLogUnloggedMetaData));

				/* Restore the unlogged members from the backup-imaged. */
				LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
				memcpy(&log->meta.unlogged, backup, sizeof(UndoLogUnloggedMetaData));
				LWLockRelease(&log->mutex);
			}
			else
			{
				/*
				 * Otherwise we need to do our own transaction tracking
				 * whenever we see a new xid, to match the logic in
				 * UndoLogAllocate().
				 */
				if (xid != log->meta.unlogged.xid)
				{
					log->meta.unlogged.xid = xid;
					if (log->meta.unlogged.this_xact_start != log->meta.unlogged.insert)
						log->meta.unlogged.last_xact_start =
							log->meta.unlogged.this_xact_start;
					log->meta.unlogged.this_xact_start =
						log->meta.unlogged.insert;
				}
			}

			/* TODO: check locking against undo log slot recycling? */

			/*
			 * At this stage we should have an undo log that can handle this
			 * allocation.  If we don't, something is screwed up.
			 */
			if (UndoLogOffsetPlusUsableBytes(log->meta.unlogged.insert, size) > log->meta.end)
				elog(ERROR,
					 "cannot allocate %d bytes in undo log %d",
					 (int) size, log->logno);

			*need_xact_header =
				try_location == InvalidUndoLogNumber &&
				log->meta.unlogged.insert == log->meta.unlogged.this_xact_start;
			allocate_in_recovery_logno = log->logno;
			return MakeUndoRecPtr(log->logno, log->meta.unlogged.insert);
		}
		++allocate_in_recovery_block_id;
	}

	/*
	 * If we've run out of blocks to inspect, then we must have replayed a
	 * different sequence of allocation sizes, or screwed up the
	 * XLOG_UNDOLOG_EXTEND records, indicating a bug somewhere.
	 */
	elog(ERROR, "cannot determine undo log to allocate from");
}

/*
 * Advanced the insertion pointer by 'size' usable (non-header) bytes.
 */
void
UndoLogAdvance(UndoRecPtr insertion_point, size_t size)
{
	UndoLogControl *log = NULL;
	UndoLogNumber	logno = UndoRecPtrGetLogNo(insertion_point) ;

	log = get_undo_log(logno, false);

	/*
	 * Either we're in recovery, or is a log we are currently attached to, or
	 * recently detached from because it was full.
	 */
	Assert(InRecovery ||
		   AmAttachedToUndoLog(log) ||
		   log->meta.status == UNDO_LOG_STATUS_FULL);

	/*
	 * The caller has the current insertion point, as returned by
	 * UndoLogAllocate[InRecovery]().
	 */
	Assert(UndoRecPtrGetOffset(insertion_point) == log->meta.unlogged.insert);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.unlogged.insert =
		UndoLogOffsetPlusUsableBytes(log->meta.unlogged.insert, size);
	log->meta.unlogged.prevlen = size;
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
 * underlying segment file may have been physically removed.
 *
 * Only one backend should call this for a given undo log concurrently, or
 * data structures will become corrupted.  It is expected that the caller will
 * be an undo worker; only one undo worker should be working on a given undo
 * log at a time.
 */
void
UndoLogDiscard(UndoRecPtr discard_point, TransactionId xid)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(discard_point);
	UndoLogOffset discard = UndoRecPtrGetOffset(discard_point);
	UndoLogOffset old_discard;
	UndoLogOffset end;
	UndoLogControl *log;
	int			segno;
	int			new_segno;
	bool		need_to_flush_wal = false;
	bool		entirely_discarded = false;

	log = get_undo_log(logno, false);
	if (unlikely(log == NULL))
		elog(ERROR,
			 "cannot advance discard pointer for undo log %d because it is already entirely discarded",
			 logno);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	if (unlikely(log->logno != logno))
		elog(ERROR,
			 "cannot advance discard pointer for undo log %d because it is entirely discarded",
			 logno);
	if (discard > log->meta.unlogged.insert)
		elog(ERROR, "cannot move discard point past insert point");
	old_discard = log->meta.discard;
	if (discard < old_discard)
		elog(ERROR, "cannot move discard pointer backwards");
	end = log->meta.end;
	/* Are we discarding the last remaining data in a log marked as full? */
	if (log->meta.status == UNDO_LOG_STATUS_FULL &&
		discard == log->meta.unlogged.insert)
	{
		/*
		 * Adjust the discard and insert pointers so that the final segment is
		 * deleted from disk, and remember not to recycle it.
		 */
		entirely_discarded = true;
		log->meta.unlogged.insert = log->meta.end;
		discard = log->meta.end;
	}
	LWLockRelease(&log->mutex);

	/*
	 * Drop all buffers holding this undo data out of the buffer pool (except
	 * the last one, if the new location is in the middle of it somewhere), so
	 * that the contained data doesn't ever touch the disk.  The caller
	 * promises that this data will not be needed again.  We have to drop the
	 * buffers from the buffer pool before removing files, otherwise a
	 * concurrent session might try to write the block to evict the buffer.
	 */
	forget_undo_buffers(logno, old_discard, discard, entirely_discarded);

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
		 * to access the discarded range of undo log.  In the case of a
		 * rename, if a backend were to attempt to read undo data in the range
		 * being discarded, it would read entirely the wrong data.
		 */

		/*
		 * How many segments should we recycle (= rename from tail position to
		 * head position)?  For now it's always 1 unless there is already a
		 * spare one, but we could have an adaptive algorithm that recycles
		 * multiple segments at a time and pays just one fsync().
		 */
		LWLockAcquire(&log->mutex, LW_SHARED);
		if ((log->meta.end - log->meta.unlogged.insert) < UndoLogSegmentSize &&
			log->meta.status == UNDO_LOG_STATUS_ACTIVE)
			recycle = 1;
		else
			recycle = 0;
		LWLockRelease(&log->mutex);

		/* Rewind to the start of the segment. */
		pointer = segno * UndoLogSegmentSize;

		while (pointer < new_segno * UndoLogSegmentSize)
		{
			RelFileNode rnode;
			char	discard_path[MAXPGPATH];

			/*
			 * Before removing the file, make sure that smgrsync.c knows
			 * that it might be missing.
			 */
			rnode.dbNode = UndoLogDatabaseOid;
			rnode.spcNode = log->meta.tablespace;
			rnode.relNode = log->logno;
			ForgetSegmentFsyncRequests(rnode,
									   UndoLogForkNum,
									   pointer / UndoLogSegmentSize);

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
					elog(LOG, "recycled undo segment \"%s\" -> \"%s\"", discard_path, recycle_path); /* XXX: remove me */
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
					elog(LOG, "unlinked undo segment \"%s\"", discard_path); /* XXX: remove me */
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
		xlrec.latestxid = xid;
		xlrec.entirely_discarded = entirely_discarded;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		ptr = XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_DISCARD);

		if (need_to_flush_wal)
			XLogFlush(ptr);
	}

	/* Update shmem to show the new discard and end pointers. */
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.discard = discard;
	log->meta.end = end;
	LWLockRelease(&log->mutex);

	/* If we discarded everything, the slot can be given up. */
	if (entirely_discarded)
		free_undo_log(log);
}

/*
 * Return an UndoRecPtr to the oldest valid data in an undo log, or
 * InvalidUndoRecPtr if it is empty.
 */
UndoRecPtr
UndoLogGetFirstValidRecord(UndoLogControl *log, bool *full)
{
	UndoRecPtr	result;

	LWLockAcquire(&log->mutex, LW_SHARED);
	if (log->meta.discard == log->meta.unlogged.insert)
		result = InvalidUndoRecPtr;
	else
		result = MakeUndoRecPtr(log->logno, log->meta.discard);
	*full = log->meta.status == UNDO_LOG_STATUS_FULL;
	LWLockRelease(&log->mutex);

	return result;
}

/*
 * Return the Next insert location.  This will also validate the input xid
 * if latest insert point is not for the same transaction id then this will
 * return Invalid Undo pointer.
 */
UndoRecPtr
UndoLogGetNextInsertPtr(UndoLogNumber logno, TransactionId xid)
{
	UndoLogControl *log = get_undo_log(logno, false);
	TransactionId	logxid;
	UndoRecPtr	insert;

	LWLockAcquire(&log->mutex, LW_SHARED);
	insert = log->meta.unlogged.insert;
	logxid = log->meta.unlogged.xid;
	LWLockRelease(&log->mutex);

	if (TransactionIdIsValid(logxid) && !TransactionIdEquals(logxid, xid))
		return InvalidUndoRecPtr;

	return MakeUndoRecPtr(logno, insert);
}

/*
 * Rewind the undo log insert position also set the prevlen in the mata
 */
void
UndoLogRewind(UndoRecPtr insert_urp, uint16 prevlen)
{
	UndoLogNumber	logno = UndoRecPtrGetLogNo(insert_urp);
	UndoLogControl *log = get_undo_log(logno, false);
	UndoLogOffset	insert = UndoRecPtrGetOffset(insert_urp);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->meta.unlogged.insert = insert;
	log->meta.unlogged.prevlen = prevlen;
	LWLockRelease(&log->mutex);

	/* WAL log the rewind. */
	{
		xl_undolog_rewind xlrec;

		xlrec.logno = logno;
		xlrec.insert = insert;
		xlrec.prevlen = prevlen;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));
		XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_REWIND);
	}
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
		 * the values they represent, so we can use strcmp to identify undo
		 * log snapshot files corresponding to checkpoints that we don't need
		 * anymore.  This assumption holds for ASCII.
		 */
		if (!(strlen(de->d_name) == UNDO_CHECKPOINT_FILENAME_LENGTH))
			continue;

		if (UndoCheckPointFilenamePrecedes(de->d_name, oldest_path))
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
CheckPointUndoLogs(XLogRecPtr checkPointRedo, XLogRecPtr priorCheckPointRedo)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogMetaData *serialized = NULL;
	size_t	serialized_size = 0;
	char   *data;
	char	path[MAXPGPATH];
	int		num_logs;
	int		fd;
	int		i;
	pg_crc32c crc;

	/*
	 * We acquire UndoLogLock to prevent any undo logs from being created or
	 * discarded while we build a snapshot of them.  This isn't expected to
	 * take long on a healthy system because the number of active logs should
	 * be around the number of backends.  Holding this lock won't prevent
	 * concurrent access to the undo log, except when segments need to be
	 * added or removed.
	 */
	LWLockAcquire(UndoLogLock, LW_SHARED);

	/*
	 * Rather than doing the file IO while we hold locks, we'll copy the
	 * meta-data into a palloc'd buffer.
	 */
	serialized_size = sizeof(UndoLogMetaData) * UndoLogNumSlots();
	serialized = (UndoLogMetaData *) palloc0(serialized_size);

	/* Scan through all slots looking for non-empty ones. */
	num_logs = 0;
	for (i = 0; i < UndoLogNumSlots(); ++i)
	{
		UndoLogControl *slot = &shared->logs[i];

		/* Skip empty slots. */
		if (slot->logno == InvalidUndoLogNumber)
			continue;

		/* Capture snapshot while holding each mutex. */
		LWLockAcquire(&slot->mutex, LW_EXCLUSIVE);
		serialized[num_logs++] = slot->meta;
		LWLockRelease(&slot->mutex);
	}

	LWLockRelease(UndoLogLock);

	/* Dump into a file under pg_undo. */
	snprintf(path, MAXPGPATH, "pg_undo/%016" INT64_MODIFIER "X",
			 checkPointRedo);
	pgstat_report_wait_start(WAIT_EVENT_UNDO_CHECKPOINT_WRITE);
	fd = OpenTransientFile(path, O_RDWR | O_CREAT | PG_BINARY);
	if (fd < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not create file \"%s\": %m", path)));

	/* Compute header checksum. */
	INIT_CRC32C(crc);
	COMP_CRC32C(crc, &shared->low_logno, sizeof(shared->low_logno));
	COMP_CRC32C(crc, &shared->next_logno, sizeof(shared->next_logno));
	COMP_CRC32C(crc, &num_logs, sizeof(num_logs));
	FIN_CRC32C(crc);

	/* Write out the number of active logs + crc. */
	if ((write(fd, &shared->low_logno, sizeof(shared->low_logno)) != sizeof(shared->low_logno)) ||
		(write(fd, &shared->next_logno, sizeof(shared->next_logno)) != sizeof(shared->next_logno)) ||
		(write(fd, &num_logs, sizeof(num_logs)) != sizeof(num_logs)) ||
		(write(fd, &crc, sizeof(crc)) != sizeof(crc)))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m", path)));

	/* Write out the meta data for all active undo logs. */
	data = (char *) serialized;
	INIT_CRC32C(crc);
	serialized_size = num_logs * sizeof(UndoLogMetaData);
	while (serialized_size > 0)
	{
		ssize_t written;

		written = write(fd, data, serialized_size);
		if (written < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m", path)));
		COMP_CRC32C(crc, data, written);
		serialized_size -= written;
		data += written;
	}
	FIN_CRC32C(crc);

	if (write(fd, &crc, sizeof(crc)) != sizeof(crc))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m", path)));


	/* Flush file and directory entry. */
	pgstat_report_wait_start(WAIT_EVENT_UNDO_CHECKPOINT_SYNC);
	pg_fsync(fd);
	CloseTransientFile(fd);
	fsync_fname("pg_undo", true);
	pgstat_report_wait_end();

	if (serialized)
		pfree(serialized);

	CleanUpUndoCheckPointFiles(priorCheckPointRedo);
}

void
StartupUndoLogs(XLogRecPtr checkPointRedo)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	char	path[MAXPGPATH];
	int		i;
	int		fd;
	int		nlogs;
	pg_crc32c crc;
	pg_crc32c new_crc;

	/* If initdb is calling, there is no file to read yet. */
	if (IsBootstrapProcessingMode())
		return;

	/* Open the pg_undo file corresponding to the given checkpoint. */
	snprintf(path, MAXPGPATH, "pg_undo/%016" INT64_MODIFIER "X",
			 checkPointRedo);
	pgstat_report_wait_start(WAIT_EVENT_UNDO_CHECKPOINT_READ);
	fd = OpenTransientFile(path, O_RDONLY | PG_BINARY);
	if (fd < 0)
		elog(ERROR, "cannot open undo checkpoint snapshot \"%s\": %m", path);

	/* Read the active log number range. */
	if ((read(fd, &shared->low_logno, sizeof(shared->low_logno))
		 != sizeof(shared->low_logno)) ||
		(read(fd, &shared->next_logno, sizeof(shared->next_logno))
		 != sizeof(shared->next_logno)) ||
		(read(fd, &nlogs, sizeof(nlogs)) != sizeof(nlogs)) ||
		(read(fd, &crc, sizeof(crc)) != sizeof(crc)))
		elog(ERROR, "pg_undo file \"%s\" is corrupted", path);

	/* Verify the header checksum. */
	INIT_CRC32C(new_crc);
	COMP_CRC32C(new_crc, &shared->low_logno, sizeof(shared->low_logno));
	COMP_CRC32C(new_crc, &shared->next_logno, sizeof(shared->next_logno));
	COMP_CRC32C(new_crc, &nlogs, sizeof(shared->next_logno));
	FIN_CRC32C(new_crc);

	if (crc != new_crc)
		elog(ERROR,
			 "pg_undo file \"%s\" has incorrect checksum", path);

	/*
	 * We'll acquire UndoLogLock just because allocate_undo_log() asserts we
	 * hold it (we don't actually expect concurrent access yet).
	 */
	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);

	/* Initialize all the logs and set up the freelist. */
	INIT_CRC32C(new_crc);
	for (i = 0; i < nlogs; ++i)
	{
		ssize_t size;
		UndoLogControl *log;

		/*
		 * Get a new slot to hold this UndoLogControl object.  If this
		 * checkpoint was created on a system with a higher max_connections
		 * setting, it's theoretically possible that we don't have enough
		 * space and cannot start up.
		 */
		log = allocate_undo_log();
		if (!log)
			ereport(ERROR,
					(errmsg("not enough undo log slots to recover from checkpoint: need at least %d, have %zu",
							nlogs, UndoLogNumSlots()),
					 errhint("Consider increasing max_connections")));

		/* Read in the meta data for this undo log. */
		if ((size = read(fd, &log->meta, sizeof(log->meta))) != sizeof(log->meta))
			elog(ERROR, "short read of pg_undo meta data in file \"%s\": %m (got %zu, wanted %zu)",
				 path, size, sizeof(log->meta));
		COMP_CRC32C(new_crc, &log->meta, sizeof(log->meta));

		/*
		 * At normal start-up, or during recovery, all active undo logs start
		 * out on the appropriate free list.
		 */
		log->logno = log->meta.logno;
		log->pid = InvalidPid;
		if (log->meta.status == UNDO_LOG_STATUS_ACTIVE)
		{
			log->next_free = shared->free_lists[log->meta.persistence];
			shared->free_lists[log->meta.persistence] = log->logno;
		}
	}
	FIN_CRC32C(new_crc);

	LWLockRelease(UndoLogLock);

	/* Verify body checksum. */
	if (read(fd, &crc, sizeof(crc)) != sizeof(crc))
		elog(ERROR, "pg_undo file \"%s\" is corrupted", path);
	if (crc != new_crc)
		elog(ERROR,
			 "pg_undo file \"%s\" has incorrect checksum", path);

	CloseTransientFile(fd);
	pgstat_report_wait_end();
}

/*
 * Allocate a new UndoLogControl object.
 */
static UndoLogControl *
allocate_undo_log(void)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log;
	int		i;

	Assert(LWLockHeldByMeInMode(UndoLogLock, LW_EXCLUSIVE));

	for (i = 0; i < UndoLogNumSlots(); ++i)
	{
		log = &shared->logs[i];
		if (log->logno == InvalidUndoLogNumber)
		{
			memset(&log->meta, 0, sizeof(log->meta));
			log->pid = 0;
			log->oldest_xid = 0;
			log->oldest_xidepoch = 0;
			log->oldest_data =0;
			log->next_free = -1;
			log->logno = -1;
			return log;
		}
	}

	return NULL;
}

/*
 * Free an UndoLogControl object in shared memory, so that it can be reused.
 */
static void
free_undo_log(UndoLogControl *log)
{
	/*
	 * When removing an undo log from a slot in shared memory, we acquire
	 * UndoLogLock and log->mutex, so that other code can hold either lock to
	 * prevent the object from disappearing.
	 */
	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	Assert(log->logno != InvalidUndoLogNumber);
	log->logno = InvalidUndoLogNumber;
	memset(&log->meta, 0, sizeof(log->meta));
	LWLockRelease(&log->mutex);
	LWLockRelease(UndoLogLock);
}

/*
 * Get the UndoLogControl object for a given log number.
 *
 * The caller may or may not already hold UndoLogLock, and should indicate
 * this by passing 'locked'.  We'll acquire it in the slow path if necessary.
 * Either way, the caller must deal with the possibility that the returned
 * UndoLogControl object pointed to no longer contains the requested logno by
 * the time it is accessed.
 *
 * To do that, one of the following approaches must be taken by the calling
 * code:
 *
 * 1.  If it is known that the calling backend is attached to the log, then it
 * can be assumed that the UndoLogControl slot still holds the same undo log
 * number.  The UndoLogControl slot can only change with the cooperation of
 * the undo log that is attached to it (it must first be marked as
 * UNDO_LOG_STATUS_FULL, which happens when a backend detaches).  Calling
 * code should probably assert that it is attached and the logno is as
 * expected, however.
 *
 * 2.  Acquire log->mutex before accessing any members, and after doing so,
 * check that the logno is as expected.  If it is not, the entire undo log
 * must be assumed to be discarded and the caller must behave accordingly.
 *
 * Return NULL if the undo log has been entirely discarded.  It is an error to
 * ask for undo logs that have never been created.
 */
static UndoLogControl *
get_undo_log(UndoLogNumber logno, bool locked)
{
	UndoLogControl *result = NULL;
	UndoLogTableEntry *entry;
	bool	   found;

	Assert(locked == LWLockHeldByMe(UndoLogLock));

	/* First see if we already have it in our cache. */
	entry = undologtable_lookup(undologtable_cache, logno);
	if (likely(entry))
		result = entry->control;
	else
	{
		UndoLogSharedData *shared = MyUndoLogState.shared;
		int		i;

		/* Nope.  Linear search for the slot in shared memory. */
		if (!locked)
			LWLockAcquire(UndoLogLock, LW_SHARED);
		for (i = 0; i < UndoLogNumSlots(); ++i)
		{
			if (shared->logs[i].logno == logno)
			{
				/* Found it. */

				/*
				 * TODO: Should this function be usable in a critical section?
				 * Would it make sense to detect that we are in a critical
				 * section and just return the pointer to the log without
				 * updating the cache, to avoid any chance of allocating
				 * memory?
				 */

				entry = undologtable_insert(undologtable_cache, logno, &found);
				entry->number = logno;
				entry->control = &shared->logs[i];
				entry->tablespace = entry->control->meta.tablespace;
				result = entry->control;
				break;
			}
		}

		/*
		 * If we didn't find it, then it must already have been entirely
		 * discarded.  We create a negative cache entry so that we can answer
		 * this question quickly next time.
		 *
		 * TODO: We could track the lowest known undo log number, to reduce
		 * the negative cache entry bloat.
		 */
		if (result == NULL)
		{
			/*
			 * Sanity check: the caller should not be asking about undo logs
			 * that have never existed.
			 */
			if (logno >= shared->next_logno)
				elog(ERROR, "undo log %u hasn't been created yet", logno);
			entry = undologtable_insert(undologtable_cache, logno, &found);
			entry->number = logno;
			entry->control = NULL;
			entry->tablespace = 0;
		}
		if (!locked)
			LWLockRelease(UndoLogLock);
	}

	return result;
}

/*
 * Get a pointer to an UndoLogControl object corresponding to a given logno.
 *
 * In general, the caller must acquire the UndoLogControl's mutex to access
 * the contents, and at that time must consider that the logno might have
 * changed because the undo log it contained has been entirely discarded.
 *
 * If the calling backend is currently attached to the undo log, that is not
 * possible, because logs can only reach UNDO_LOG_STATUS_DISCARDED after first
 * reaching UNDO_LOG_STATUS_FULL, and that only happens while detaching.
 */
UndoLogControl *
UndoLogGet(UndoLogNumber logno, bool missing_ok)
{
	UndoLogControl *log = get_undo_log(logno, false);

	if (log == NULL && !missing_ok)
		elog(ERROR, "unknown undo log number %d", logno);

	return log;
}

/*
 * Attach to an undo log, possibly creating or recycling one as required.
 */
static void
attach_undo_log(UndoPersistence persistence, Oid tablespace)
{
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log = NULL;
	UndoLogNumber logno;
	UndoLogNumber *place;

	Assert(!InRecovery);
	Assert(MyUndoLogState.logs[persistence] == NULL);

	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);

	/*
	 * For now we have a simple linked list of unattached undo logs for each
	 * persistence level.  We'll grovel though it to find something for the
	 * tablespace you asked for.  If you're not using multiple tablespaces
	 * it'll be able to pop one off the front.  We might need a hash table
	 * keyed by tablespace if this simple scheme turns out to be too slow when
	 * using many tablespaces and many undo logs, but that seems like an
	 * unusual use case not worth optimizing for.
	 */
	place = &shared->free_lists[persistence];
	while (*place != InvalidUndoLogNumber)
	{
		UndoLogControl *candidate = get_undo_log(*place, true);

		/*
		 * There should never be an undo log on the freelist that has been
		 * entirely discarded, or hasn't been created yet.  The persistence
		 * level should match the freelist.
		 */
		if (unlikely(candidate == NULL))
			elog(ERROR,
				 "corrupted undo log freelist, no such undo log %u", *place);
		if (unlikely(candidate->meta.persistence != persistence))
			elog(ERROR,
				 "corrupted undo log freelist, undo log %u with persistence %d found on freelist %d",
				 *place, candidate->meta.persistence, persistence);

		if (candidate->meta.tablespace == tablespace)
		{
			logno = *place;
			log = candidate;
			*place = candidate->next_free;
			break;
		}
		place = &candidate->next_free;
	}

	/*
	 * All existing undo logs for this tablespace and persistence level are
	 * busy, so we'll have to create a new one.
	 */
	if (log == NULL)
	{
		if (shared->next_logno > MaxUndoLogNumber)
		{
			/*
			 * You've used up all 16 exabytes of undo log addressing space.
			 * This is a difficult state to reach using only 16 exabytes of
			 * WAL.
			 */
			elog(ERROR, "undo log address space exhausted");
		}

		/* Allocate a slot from the UndoLogControl pool. */
		log = allocate_undo_log();
		if (unlikely(!log))
			ereport(ERROR,
					(errmsg("could not create new undo log"),
					 errdetail("The maximum number of active undo logs is %zu.",
							   UndoLogNumSlots()),
					 errhint("Consider increasing max_connections.")));
		log->logno = logno = shared->next_logno;

		/*
		 * The insert and discard pointers start after the first block's
		 * header.  XXX That means that insert is > end for a short time in a
		 * newly created undo log.  Is there any problem with that?
		 */
		log->meta.unlogged.insert = UndoLogBlockHeaderSize;
		log->meta.discard = UndoLogBlockHeaderSize;

		log->meta.logno = logno;
		log->meta.tablespace = tablespace;
		log->meta.persistence = persistence;
		log->meta.status = UNDO_LOG_STATUS_ACTIVE;

		/* Move the high log number pointer past this one. */
		++shared->next_logno;

		/* WAL-log the creation of this new undo log. */
		{
			xl_undolog_create xlrec;

			xlrec.logno = logno;
			xlrec.tablespace = log->meta.tablespace;
			xlrec.persistence = log->meta.persistence;

			XLogBeginInsert();
			XLogRegisterData((char *) &xlrec, sizeof(xlrec));
			XLogInsert(RM_UNDOLOG_ID, XLOG_UNDOLOG_CREATE);
		}

		/*
		 * This undo log has no segments.  UndoLogAllocate will create the
		 * first one on demand.
		 */
	}
	LWLockRelease(UndoLogLock);

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->pid = MyProcPid;
	LWLockRelease(&log->mutex);

	MyUndoLogState.logs[persistence] = log;
}

/* check_hook: validate new undo_tablespaces */
bool
check_undo_tablespaces(char **newval, void **extra, GucSource source)
{
	char	   *rawname;
	List	   *namelist;

	/* Need a modifiable copy of string */
	rawname = pstrdup(*newval);

	/*
	 * Parse string into list of identifiers, just to check for
	 * well-formedness (unfortunateley we can't validate the names in the
	 * catalog yet).
	 */
	if (!SplitIdentifierString(rawname, ',', &namelist))
	{
		/* syntax error in name list */
		GUC_check_errdetail("List syntax is invalid.");
		pfree(rawname);
		list_free(namelist);
		return false;
	}

	/*
	 * Make sure we aren't already in a transaction that has been assigned an
	 * XID.  This ensures we don't detach from an undo log that we might have
	 * started writing undo data into for this transaction.
	 */
	if (GetTopTransactionIdIfAny() != InvalidTransactionId)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 (errmsg("undo_tablespaces cannot be changed while a transaction is in progress"))));
	list_free(namelist);

	return true;
}

/* assign_hook: do extra actions as needed */
void
assign_undo_tablespaces(const char *newval, void *extra)
{
	/*
	 * This is normally called only when GetTopTransactionIdIfAny() ==
	 * InvalidTransactionId (because you can't change undo_tablespaces in the
	 * middle of a transaction that's been asigned an xid), but we can't
	 * assert that because it's also called at the end of a transaction that's
	 * rolling back, to reset the GUC if it was set inside the transaction.
	 */

	/* Tell UndoLogAllocate() to reexamine undo_tablespaces. */
	MyUndoLogState.need_to_choose_tablespace = true;
}

static bool
choose_undo_tablespace(bool force_detach, Oid *tablespace)
{
	char   *rawname;
	List   *namelist;
	bool	need_to_unlock;
	int		length;
	int		i;

	/* We need a modifiable copy of string. */
	rawname = pstrdup(undo_tablespaces);

	/* Break string into list of identifiers. */
	if (!SplitIdentifierString(rawname, ',', &namelist))
		elog(ERROR, "undo_tablespaces is unexpectedly malformed");

	length = list_length(namelist);
	if (length == 0 ||
		(length == 1 && ((char *) linitial(namelist))[0] == '\0'))
	{
		/*
		 * If it's an empty string, then we'll use the default tablespace.  No
		 * locking is required because it can't be dropped.
		 */
		*tablespace = DEFAULTTABLESPACE_OID;
		need_to_unlock = false;
	}
	else
	{
		/*
		 * Choose an OID using our pid, so that if several backends have the
		 * same multi-tablespace setting they'll spread out.  We could easily
		 * do better than this if more serious load balancing is judged
		 * useful.
		 */
		int		index = MyProcPid % length;
		int		first_index = index;
		Oid		oid = InvalidOid;

		/*
		 * Take the tablespace create/drop lock while we look the name up.
		 * This prevents the tablespace from being dropped while we're trying
		 * to resolve the name, or while the called is trying to create an
		 * undo log in it.  The caller will have to release this lock.
		 */
		LWLockAcquire(TablespaceCreateLock, LW_EXCLUSIVE);
		for (;;)
		{
			const char *name = list_nth(namelist, index);

			oid = get_tablespace_oid(name, true);
			if (oid == InvalidOid)
			{
				/* Unknown tablespace, try the next one. */
				index = (index + 1) % length;
				/*
				 * But if we've tried them all, it's time to complain.  We'll
				 * arbitrarily complain about the last one we tried in the
				 * error message.
				 */
				if (index == first_index)
					ereport(ERROR,
							(errcode(ERRCODE_UNDEFINED_OBJECT),
							 errmsg("tablespace \"%s\" does not exist", name),
							 errhint("Create the tablespace or set undo_tablespaces to a valid or empty list.")));
				continue;
			}
			if (oid == GLOBALTABLESPACE_OID)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("undo logs cannot be placed in pg_global tablespace")));
			/* If we got here we succeeded in finding one. */
			break;
		}

		Assert(oid != InvalidOid);
		*tablespace = oid;
		need_to_unlock = true;
	}

	/*
	 * If we came here because the user changed undo_tablesaces, then detach
	 * from any undo logs we happen to be attached to.
	 */
	if (force_detach)
	{
		for (i = 0; i < UndoPersistenceLevels; ++i)
		{
			UndoLogControl *log = MyUndoLogState.logs[i];
			UndoLogSharedData *shared = MyUndoLogState.shared;

			if (log != NULL)
			{
				LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
				log->pid = InvalidPid;
				log->meta.unlogged.xid = InvalidTransactionId;
				LWLockRelease(&log->mutex);

				LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
				log->next_free = shared->free_lists[i];
				shared->free_lists[i] = log->logno;
				LWLockRelease(UndoLogLock);

				MyUndoLogState.logs[i] = NULL;
			}
		}
	}

	return need_to_unlock;
}

bool
DropUndoLogsInTablespace(Oid tablespace)
{
	DIR *dir;
	char undo_path[MAXPGPATH];
	UndoLogSharedData *shared = MyUndoLogState.shared;
	UndoLogControl *log;
	int		i;

	Assert(LWLockHeldByMe(TablespaceCreateLock));
	Assert(tablespace != DEFAULTTABLESPACE_OID);

	/* First, try to kick everyone off any undo logs in this tablespace. */
	for (log = UndoLogNext(NULL); log != NULL; log = UndoLogNext(log))
	{
		bool ok;
		bool return_to_freelist = false;

		/* Skip undo logs in other tablespaces. */
		if (log->meta.tablespace != tablespace)
			continue;

		/* Check if this undo log can be forcibly detached. */
		LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
		if (log->meta.discard == log->meta.unlogged.insert &&
			(log->meta.unlogged.xid == InvalidTransactionId ||
			 !TransactionIdIsInProgress(log->meta.unlogged.xid)))
		{
			log->meta.unlogged.xid = InvalidTransactionId;
			if (log->pid != InvalidPid)
			{
				log->pid = InvalidPid;
				return_to_freelist = true;
			}
			ok = true;
		}
		else
		{
			/*
			 * There is data we need in this undo log.  We can't force it to
			 * be detached.
			 */
			ok = false;
		}
		LWLockRelease(&log->mutex);

		/* If we failed, then give up now and report failure. */
		if (!ok)
			return false;

		/*
		 * Put this undo log back on the appropriate free-list.  No one can
		 * attach to it while we hold TablespaceCreateLock, but if we return
		 * earlier in a future go around this loop, we need the undo log to
		 * remain usable.  We'll remove all appropriate logs from the
		 * free-lists in a separate step below.
		 */
		if (return_to_freelist)
		{
			LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
			log->next_free = shared->free_lists[log->meta.persistence];
			shared->free_lists[log->meta.persistence] = log->logno;
			LWLockRelease(UndoLogLock);
		}
	}

	/*
	 * We detached all backends from undo logs in this tablespace, and no one
	 * can attach to any non-default-tablespace undo logs while we hold
	 * TablespaceCreateLock.  We can now drop the undo logs.
	 */
	for (log = UndoLogNext(NULL); log != NULL; log = UndoLogNext(log))
	{
		/* Skip undo logs in other tablespaces. */
		if (log->meta.tablespace != tablespace)
			continue;

		/*
		 * Make sure no buffers remain.  When that is done by UndoDiscard(),
		 * the final page is left in shared_buffers because it may contain
		 * data, or at least be needed again very soon.  Here we need to drop
		 * even that page from the buffer pool.
		 */
		forget_undo_buffers(log->logno, log->meta.discard, log->meta.discard, true);

		/*
		 * TODO: For now we drop the undo log, meaning that it will never be
		 * used again.  That wastes the rest of its address space.  Instead,
		 * we should put it onto a special list of 'offline' undo logs, ready
		 * to be reactivated in some other tablespace.  Then we can keep the
		 * unused portion of its address space.
		 */
		LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
		log->meta.status = UNDO_LOG_STATUS_DISCARDED;
		LWLockRelease(&log->mutex);
	}

	/* Unlink all undo segment files in this tablespace. */
	UndoLogDirectory(tablespace, undo_path);

	dir = AllocateDir(undo_path);
	if (dir != NULL)
	{
		struct dirent *de;

		while ((de = ReadDirExtended(dir, undo_path, LOG)) != NULL)
		{
			char segment_path[MAXPGPATH];

			if (strcmp(de->d_name, ".") == 0 ||
				strcmp(de->d_name, "..") == 0)
				continue;
			snprintf(segment_path, sizeof(segment_path), "%s/%s",
					 undo_path, de->d_name);
			if (unlink(segment_path) < 0)
				elog(LOG, "couldn't unlink file \"%s\": %m", segment_path);
		}
		FreeDir(dir);
	}

	/* Remove all dropped undo logs from the free-lists. */
	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
	for (i = 0; i < UndoPersistenceLevels; ++i)
	{
		UndoLogControl *log;
		UndoLogNumber *place;

		place = &shared->free_lists[i];
		while (*place != InvalidUndoLogNumber)
		{
			log = get_undo_log(*place, true);
			if (!log)
				elog(ERROR,
					 "corrupted undo log freelist, unknown log %u", *place);
			if (log->meta.status == UNDO_LOG_STATUS_DISCARDED)
				*place = log->next_free;
			else
				place = &log->next_free;
		}
	}
	LWLockRelease(UndoLogLock);

	return true;
}

void
ResetUndoLogs(UndoPersistence persistence)
{
	UndoLogControl *log;

	for (log = UndoLogNext(NULL); log != NULL; log = UndoLogNext(log))
	{
		DIR	   *dir;
		struct dirent *de;
		char	undo_path[MAXPGPATH];
		char	segment_prefix[MAXPGPATH];
		size_t	segment_prefix_size;

		if (log->meta.persistence != persistence)
			continue;

		/* Scan the directory for files belonging to this undo log. */
		snprintf(segment_prefix, sizeof(segment_prefix), "%06X.", log->logno);
		segment_prefix_size = strlen(segment_prefix);
		UndoLogDirectory(log->meta.tablespace, undo_path);
		dir = AllocateDir(undo_path);
		if (dir == NULL)
			continue;
		while ((de = ReadDirExtended(dir, undo_path, LOG)) != NULL)
		{
			char segment_path[MAXPGPATH];

			if (strncmp(de->d_name, segment_prefix, segment_prefix_size) != 0)
				continue;
			snprintf(segment_path, sizeof(segment_path), "%s/%s",
					 undo_path, de->d_name);
			elog(LOG, "unlinked undo segment \"%s\"", segment_path); /* XXX: remove me */
			if (unlink(segment_path) < 0)
				elog(LOG, "couldn't unlink file \"%s\": %m", segment_path);
		}
		FreeDir(dir);

		/*
		 * We have no segment files.  Set the pointers to indicate that there
		 * is no data.  The discard and insert pointers point to the first
		 * usable byte in the segment we will create when we next try to
		 * allocate.  This is a bit strange, because it means that they are
		 * past the end pointer.  That's the same as when new undo logs are
		 * created.
		 *
		 * TODO: Should we rewind to zero instead, so we can reuse that (now)
		 * unreferenced address space?
		 */
		log->meta.unlogged.insert = log->meta.discard = log->meta.end +
			UndoLogBlockHeaderSize;
	}
}

Datum
pg_stat_get_undo_logs(PG_FUNCTION_ARGS)
{
#define PG_STAT_GET_UNDO_LOGS_COLS 10
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	UndoLogSharedData *shared = MyUndoLogState.shared;
	char *tablespace_name = NULL;
	Oid last_tablespace = InvalidOid;
	int			i;

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

	/* Scan all undo logs to build the results. */
	for (i = 0; i < shared->array_size; ++i)
	{
		UndoLogControl *log = &shared->logs[i];
		char buffer[17];
		Datum values[PG_STAT_GET_UNDO_LOGS_COLS];
		bool nulls[PG_STAT_GET_UNDO_LOGS_COLS] = { false };
		Oid tablespace;

		if (log == NULL)
			continue;

		/*
		 * This won't be a consistent result overall, but the values for each
		 * log will be consistent because we'll take the per-log lock while
		 * copying them.
		 */
		LWLockAcquire(&log->mutex, LW_SHARED);

		/* Skip unused slots and entirely discarded undo logs. */
		if (log->logno == InvalidUndoLogNumber ||
			log->meta.status == UNDO_LOG_STATUS_DISCARDED)
		{
			LWLockRelease(&log->mutex);
			continue;
		}

		values[0] = ObjectIdGetDatum((Oid) log->logno);
		values[1] = CStringGetTextDatum(
			log->meta.persistence == UNDO_PERMANENT ? "permanent" :
			log->meta.persistence == UNDO_UNLOGGED ? "unlogged" :
			log->meta.persistence == UNDO_TEMP ? "temporary" : "<uknown>");
		tablespace = log->meta.tablespace;

		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(log->logno, log->meta.discard));
		values[3] = CStringGetTextDatum(buffer);
		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(log->logno, log->meta.unlogged.insert));
		values[4] = CStringGetTextDatum(buffer);
		snprintf(buffer, sizeof(buffer), UndoRecPtrFormat,
				 MakeUndoRecPtr(log->logno, log->meta.end));
		values[5] = CStringGetTextDatum(buffer);
		if (log->meta.unlogged.xid == InvalidTransactionId)
			nulls[6] = true;
		else
			values[6] = TransactionIdGetDatum(log->meta.unlogged.xid);
		if (log->pid == InvalidPid)
			nulls[7] = true;
		else
			values[7] = Int32GetDatum((int64) log->pid);
		if (log->meta.unlogged.prevlogno == InvalidUndoLogNumber)
			nulls[8] = true;
		else
			values[8] = ObjectIdGetDatum((Oid) log->meta.unlogged.prevlogno);
		switch (log->meta.status)
		{
		case UNDO_LOG_STATUS_ACTIVE:
			values[9] = CStringGetTextDatum("ACTIVE"); break;
		case UNDO_LOG_STATUS_FULL:
			values[9] = CStringGetTextDatum("FULL"); break;
		default:
			nulls[9] = true;
		}
		LWLockRelease(&log->mutex);

		/*
		 * Deal with potentially slow tablespace name lookup without the lock.
		 * Avoid making multiple calls to that expensive function for the
		 * common case of repeating tablespace.
		 */
		if (tablespace != last_tablespace)
		{
			if (tablespace_name)
				pfree(tablespace_name);
			tablespace_name = get_tablespace_name(tablespace);
			last_tablespace = tablespace;
		}
		if (tablespace_name)
		{
			values[2] = CStringGetTextDatum(tablespace_name);
			nulls[2] = false;
		}
		else
			nulls[2] = true;

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	if (tablespace_name)
		pfree(tablespace_name);
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
	LWLockAcquire(UndoLogLock, LW_EXCLUSIVE);
	/* TODO: assert that it doesn't exist already? */
	log = allocate_undo_log();
	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	log->logno = xlrec->logno;
	log->meta.logno = xlrec->logno;
	log->meta.status = UNDO_LOG_STATUS_ACTIVE;
	log->meta.persistence = xlrec->persistence;
	log->meta.tablespace = xlrec->tablespace;
	log->meta.unlogged.insert = UndoLogBlockHeaderSize;
	log->meta.discard = UndoLogBlockHeaderSize;
	shared->next_logno = Max(xlrec->logno + 1, shared->next_logno);
	LWLockRelease(&log->mutex);
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
 * Drop all buffers for the given undo log, from the old_discard to up
 * new_discard.  If drop_tail is true, also drop the buffer that holds
 * new_discard; this is used when discarding undo logs completely, for example
 * via DROP TABLESPACE.  If it is false, then the final buffer is not dropped
 * because it may contain data.
 *
 */
static void
forget_undo_buffers(int logno, UndoLogOffset old_discard,
					UndoLogOffset new_discard, bool drop_tail)
{
	BlockNumber old_blockno;
	BlockNumber new_blockno;
	RelFileNode	rnode;

	UndoRecPtrAssignRelFileNode(rnode, MakeUndoRecPtr(logno, old_discard));
	old_blockno = old_discard / BLCKSZ;
	new_blockno = new_discard / BLCKSZ;
	if (drop_tail)
		++new_blockno;
	while (old_blockno < new_blockno)
	{
		ForgetBuffer(rnode, UndoLogForkNum, old_blockno);
		ForgetLocalBuffer(rnode, UndoLogForkNum, old_blockno++);
	}
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
	RelFileNode rnode = {0};
	char	dir[MAXPGPATH];

	log = get_undo_log(xlrec->logno, false);
	if (log == NULL)
		elog(ERROR, "unknown undo log %d", xlrec->logno);

	/*
	 * We're about to discard undologs. In Hot Standby mode, ensure that
	 * there's no queries running which need to get tuple from discarded undo.
	 *
	 * XXX we are passing empty rnode to the conflict function so that it can
	 * check conflict in all the backend regardless of which database the
	 * backend is connected.
	 */
	if (InHotStandby && TransactionIdIsValid(xlrec->latestxid))
		ResolveRecoveryConflictWithSnapshot(xlrec->latestxid, rnode);

	/*
	 * See if we need to unlink or rename any files, but don't consider it an
	 * error if we find that files are missing.  Since UndoLogDiscard()
	 * performs filesystem operations before WAL logging or updating shmem
	 * which could be checkpointed, a crash could have left files already
	 * deleted, but we could replay WAL that expects the files to be there.
	 */

	LWLockAcquire(&log->mutex, LW_EXCLUSIVE);
	Assert(log->logno == xlrec->logno);
	discard = log->meta.discard;
	end = log->meta.end;
	LWLockRelease(&log->mutex);

	/* Drop buffers before we remove/recycle any files. */
	forget_undo_buffers(xlrec->logno, discard, xlrec->discard,
						xlrec->entirely_discarded);

	/* Rewind to the start of the segment. */
	old_segment_begin = discard - discard % UndoLogSegmentSize;
	new_segment_begin = xlrec->discard - xlrec->discard % UndoLogSegmentSize;

	/* Unlink or rename segments that are no longer in range. */
	while (old_segment_begin < new_segment_begin)
	{
		RelFileNode rnode;
		char	discard_path[MAXPGPATH];

		/*
		 * Before removing the file, make sure that undofile_sync knows that
		 * it might be missing.
		 */
		rnode.dbNode = UndoLogDatabaseOid;
		rnode.spcNode = log->meta.tablespace;
		rnode.relNode = log->logno;
		ForgetSegmentFsyncRequests(rnode,
								   UndoLogForkNum,
								   old_segment_begin / UndoLogSegmentSize);
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
				elog(LOG, "recycled undo segment \"%s\" -> \"%s\"", discard_path, recycle_path); /* XXX: remove me */
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
				elog(LOG, "unlinked undo segment \"%s\"", discard_path); /* XXX: remove me */
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

	/* If we discarded everything, the slot can be given up. */
	if (xlrec->entirely_discarded)
		free_undo_log(log);
}

/*
 * replay the rewind of a undo log
 */
static void
undolog_xlog_rewind(XLogReaderState *record)
{
	xl_undolog_rewind *xlrec = (xl_undolog_rewind *) XLogRecGetData(record);
	UndoLogControl *log;

	log = get_undo_log(xlrec->logno, false);
	log->meta.unlogged.insert = xlrec->insert;
	log->meta.unlogged.prevlen = xlrec->prevlen;
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
		case XLOG_UNDOLOG_DISCARD:
			undolog_xlog_discard(record);
			break;
		case XLOG_UNDOLOG_REWIND:
			undolog_xlog_rewind(record);
			break;
		default:
			elog(PANIC, "undo_redo: unknown op code %u", info);
	}
}

/*
 * For assertions only.
 */
bool
AmAttachedToUndoLog(UndoLogControl *log)
{
	/*
	 * In general, we can't access log's members without locking.  But this
	 * function is intended only for asserting that you are attached, and
	 * while you're attached the slot can't be recycled, so don't bother
	 * locking.
	 */
	return MyUndoLogState.logs[log->meta.persistence] == log;
}

/*
 * For testing use only.  This function is only used by the test_undo module.
 */
void
UndoLogDetachFull(void)
{
	int		i;

	for (i = 0; i < UndoPersistenceLevels; ++i)
		if (MyUndoLogState.logs[i])
			detach_current_undo_log(i, true);
}

/*
 * Fetch database id from the undo log state
 */
Oid
UndoLogStateGetDatabaseId()
{
	Assert(InRecovery);
	return MyUndoLogState.dbid;
}
