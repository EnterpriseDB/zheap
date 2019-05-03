/*-------------------------------------------------------------------------
 *
 * undolog.h
 *
 * PostgreSQL undo log manager.  This module is responsible for life-cycle
 * management of undo logs and backing files, associating undo logs with
 * backends, allocating and managing space within undo logs.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undolog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOLOG_H
#define UNDOLOG_H

#include "access/xlogreader.h"
#include "catalog/pg_class.h"
#include "common/relpath.h"
#include "storage/bufpage.h"

#ifndef FRONTEND
#include "storage/lwlock.h"
#endif

/* The type used to identify an undo log and position within it. */
typedef uint64 UndoRecPtr;

/* The type used for undo record lengths. */
typedef uint16 UndoRecordSize;

/* Undo log statuses. */
typedef enum
{
	UNDO_LOG_STATUS_UNUSED = 0,
	UNDO_LOG_STATUS_ACTIVE,
	UNDO_LOG_STATUS_EXHAUSTED,
	UNDO_LOG_STATUS_DISCARDED
} UndoLogStatus;

/*
 * Undo log persistence levels.  These have a one-to-one correspondence with
 * relpersistence values, but are small integers so that we can use them as an
 * index into the "logs" and "lognos" arrays.
 */
typedef enum
{
	UNDO_PERMANENT = 0,
	UNDO_UNLOGGED = 1,
	UNDO_TEMP = 2
} UndoPersistence;

#define UndoPersistenceLevels 3

/*
 * Convert from relpersistence ('p', 'u', 't') to an UndoPersistence
 * enumerator.
 */
#define UndoPersistenceForRelPersistence(rp)						\
	((rp) == RELPERSISTENCE_PERMANENT ? UNDO_PERMANENT :			\
	 (rp) == RELPERSISTENCE_UNLOGGED ? UNDO_UNLOGGED : UNDO_TEMP)

/*
 * Convert from UndoPersistence to a relpersistence value.
 */
#define RelPersistenceForUndoPersistence(up)				\
	((up) == UNDO_PERMANENT ? RELPERSISTENCE_PERMANENT :	\
	 (up) == UNDO_UNLOGGED ? RELPERSISTENCE_UNLOGGED :		\
	 RELPERSISTENCE_TEMP)

/*
 * Get the appropriate UndoPersistence value from a Relation.
 */
#define UndoPersistenceForRelation(rel)									\
	(UndoPersistenceForRelPersistence((rel)->rd_rel->relpersistence))

/* Type for offsets within undo logs */
typedef uint64 UndoLogOffset;

/* printf-family format string for UndoRecPtr. */
#define UndoRecPtrFormat "%016" INT64_MODIFIER "X"

/* printf-family format string for UndoLogOffset. */
#define UndoLogOffsetFormat UINT64_FORMAT

/* Number of blocks of BLCKSZ in an undo log segment file.  128 = 1MB. */
#define UNDOSEG_SIZE 128

/* Size of an undo log segment file in bytes. */
#define UndoLogSegmentSize ((size_t) BLCKSZ * UNDOSEG_SIZE)

/* The width of an undo log number in bits.  24 allows for 16.7m logs. */
#define UndoLogNumberBits 24

/* The width of an undo log offset in bits.  40 allows for 1TB per log.*/
#define UndoLogOffsetBits (64 - UndoLogNumberBits)

/* Special value for undo record pointer which indicates that it is invalid. */
#define	InvalidUndoRecPtr	((UndoRecPtr) 0)

/* End-of-list value when building linked lists of undo logs. */
#define InvalidUndoLogNumber -1

/*
 * The maximum amount of data that can be stored in an undo log.  Can be set
 * artificially low to test full log behavior.
 */
#define UndoLogMaxSize ((UndoLogOffset) 1 << UndoLogOffsetBits)

/* Type for numbering undo logs. */
typedef int UndoLogNumber;

/* Extract the undo log number from an UndoRecPtr. */
#define UndoRecPtrGetLogNo(urp)					\
	((urp) >> UndoLogOffsetBits)

/* Extract the offset from an UndoRecPtr. */
#define UndoRecPtrGetOffset(urp)				\
	((urp) & ((UINT64CONST(1) << UndoLogOffsetBits) - 1))

/* Make an UndoRecPtr from an log number and offset. */
#define MakeUndoRecPtr(logno, offset)			\
	(((uint64) (logno) << UndoLogOffsetBits) | (offset))

/* The number of unusable bytes in the header of each block. */
#define UndoLogBlockHeaderSize SizeOfPageHeaderData

/* The number of usable bytes we can store per block. */
#define UndoLogUsableBytesPerPage (BLCKSZ - UndoLogBlockHeaderSize)

/* The pseudo-database OID used for undo logs. */
#define UndoLogDatabaseOid 9

/* Length of undo checkpoint filename */
#define UNDO_CHECKPOINT_FILENAME_LENGTH	16

/*
 * UndoRecPtrIsValid
 *		True iff undoRecPtr is valid.
 */
#define UndoRecPtrIsValid(undoRecPtr) \
	((bool) ((UndoRecPtr) (undoRecPtr) != InvalidUndoRecPtr))

/* Extract the relnode for an undo log. */
#define UndoRecPtrGetRelNode(urp)				\
	UndoRecPtrGetLogNo(urp)

/* The only valid fork number for undo log buffers. */
#define UndoLogForkNum MAIN_FORKNUM

/* Compute the block number that holds a given UndoRecPtr. */
#define UndoRecPtrGetBlockNum(urp)				\
	(UndoRecPtrGetOffset(urp) / BLCKSZ)

/* Compute the offset of a given UndoRecPtr in the page that holds it. */
#define UndoRecPtrGetPageOffset(urp)			\
	(UndoRecPtrGetOffset(urp) % BLCKSZ)

/* Compare two undo checkpoint files to find the oldest file. */
#define UndoCheckPointFilenamePrecedes(file1, file2)	\
	(strcmp(file1, file2) < 0)

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

/* Find out which tablespace the given undo log location is backed by. */
extern Oid	UndoRecPtrGetTablespace(UndoRecPtr insertion_point);

/* Populate a RelFileNode from an UndoRecPtr. */
#define UndoRecPtrAssignRelFileNode(rfn, urp)			\
	do													\
	{													\
		(rfn).spcNode = UndoRecPtrGetTablespace(urp);	\
		(rfn).dbNode = UndoLogDatabaseOid;				\
		(rfn).relNode = UndoRecPtrGetRelNode(urp);		\
	} while (false);

/*
 * Control metadata for an active undo log.  Lives in shared memory inside an
 * UndoLogControl object, but also written to disk during checkpoints.
 */
typedef struct UndoLogMetaData
{
	UndoLogStatus status;
	Oid			tablespace;
	UndoPersistence persistence;	/* permanent, unlogged, temp? */
	UndoLogOffset insert;		/* next insertion point (head) */
	UndoLogOffset end;			/* one past end of highest segment */
	UndoLogOffset discard;		/* oldest data needed (tail) */
	UndoLogOffset last_xact_start;	/* last transactions start undo offset */

	bool		is_first_rec;
} UndoLogMetaData;

/* Record the undo log number used for a transaction. */
typedef struct xl_undolog_meta
{
	UndoLogMetaData meta;
	UndoLogNumber logno;
	TransactionId xid;
} xl_undolog_meta;

#ifndef FRONTEND

/*
 * The in-memory control object for an undo log.  As well as the current
 * meta-data for the undo log, we also lazily maintain a snapshot of the
 * meta-data as it was at the redo point of a checkpoint that is in progress.
 *
 * The following two locks are used to manage the discard process
 * discard_lock - should be acquired for undo read to protect it from discard and
 * discard worker will acquire this lock to update oldest_data.
 *
 * discard_update_lock - This lock will be acquired in exclusive mode by discard
 * worker during the discard process and in shared mode to update the
 * next_urp in previous transaction's start header.
 *
 * Two different locks are used so that the readers are not blocked during the
 * actual discard but only during the update of shared memory variable which
 * influences the visibility decision but the updaters need to be blocked for
 * the entire discard process to ensure proper ordering of WAL records.
 *
 * Conceptually the set of UndoLogControl objects is arranged into a very
 * large array for access by log number, but because we typically need only a
 * smallish number of adjacent undo logs to be active at a time we arrange
 * them into smaller fragments called 'banks'.
 */
typedef struct UndoLogControl
{
	UndoLogNumber logno;
	UndoLogMetaData meta;		/* current meta-data */
	XLogRecPtr	lsn;
	bool		need_attach_wal_record; /* need_attach_wal_record */
	pid_t		pid;			/* InvalidPid for unattached */
	LWLock		mutex;			/* protects the above */
	TransactionId xid;
	/* State used by undo workers. */
	TransactionId oldest_xid;	/* cache of oldest transaction's xid */
	uint32		oldest_xidepoch;
	UndoRecPtr	oldest_data;
	LWLock		discard_update_lock;	/* block updaters during discard */
	LWLock		discard_lock;	/* prevents discarding while reading */
	LWLock		rewind_lock;	/* prevent rewinding while reading */

	UndoLogNumber next_free;	/* protected by UndoLogLock */
} UndoLogControl;

#endif

/* Space management. */
extern UndoRecPtr UndoLogAllocate(size_t size,
				UndoPersistence level);
extern UndoRecPtr UndoLogAllocateInRecovery(TransactionId xid,
						  size_t size,
						  UndoPersistence persistence);
extern void UndoLogAdvance(UndoRecPtr insertion_point,
			   size_t size,
			   UndoPersistence persistence);
extern void UndoLogDiscard(UndoRecPtr discard_point, TransactionId xid);
extern bool UndoLogIsDiscarded(UndoRecPtr point);

/* Initialization interfaces. */
extern void StartupUndoLogs(XLogRecPtr checkPointRedo);
extern void UndoLogShmemInit(void);
extern Size UndoLogShmemSize(void);
extern void UndoLogInit(void);
extern void UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace,
				   char *path);
extern void ResetUndoLogs(UndoPersistence persistence);

/* Interface use by tablespace.c. */
extern bool DropUndoLogsInTablespace(Oid tablespace);

/* GUC interfaces. */
extern void assign_undo_tablespaces(const char *newval, void *extra);

/* Checkpoint interfaces. */
extern void CheckPointUndoLogs(XLogRecPtr checkPointRedo,
				   XLogRecPtr priorCheckPointRedo);

#ifndef FRONTEND

extern UndoLogControl *UndoLogGet(UndoLogNumber logno);
extern UndoLogControl *UndoLogNext(UndoLogControl *log);
extern bool AmAttachedToUndoLog(UndoLogControl *log);

#endif

extern void UndoLogSetLastXactStartPoint(UndoRecPtr point);
extern UndoRecPtr UndoLogGetLastXactStartPoint(UndoLogNumber logno);
extern UndoRecPtr UndoLogGetCurrentLocation(UndoPersistence persistence);
extern UndoRecPtr UndoLogGetFirstValidRecord(UndoLogNumber logno);
extern UndoRecPtr UndoLogGetNextInsertPtr(UndoLogNumber logno,
						TransactionId xid);
extern void UndoLogRewind(UndoRecPtr insert_urp);
extern bool IsTransactionFirstRec(TransactionId xid);
extern void UndoLogSetPrevLen(UndoLogNumber logno, uint16 prevlen);
extern uint16 UndoLogGetPrevLen(UndoLogNumber logno);
extern bool NeedUndoMetaLog(XLogRecPtr redo_point);
extern void UndoLogSetLSN(XLogRecPtr lsn);
extern void LogUndoMetaData(xl_undolog_meta *xlrec);
void		UndoLogNewSegment(UndoLogNumber logno, Oid tablespace, int segno);

/* Redo interface. */
extern void undolog_redo(XLogReaderState *record);

/* Discard the undo logs for temp tables */
extern UndoRecPtr UndoLogStateGetAndClearPrevLogXactUrp(void);
extern UndoLogNumber UndoLogAmAttachedTo(UndoPersistence persistence);
extern Oid	UndoLogStateGetDatabaseId(void);

#endif							/* UNDOLOG_H */
