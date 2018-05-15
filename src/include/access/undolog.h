/*-------------------------------------------------------------------------
 *
 * undolog.h
 *
 * PostgreSQL undo log manager.  This module is responsible for lifecycle
 * management of undo logs and backing files, associating undo logs with
 * backends, allocating and managing space within undo logs.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
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
	UNDO_LOG_STATUS_DROPPED
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

/*
 * This undo record pointer will be used in the transaction header this special
 * value is the indication that currently we don't have the value of the the
 * next transactions start point but it will be updated with a valid value
 * in the future.
 */
#define SpecialUndoRecPtr	((UndoRecPtr) 0xFFFFFFFFFFFFFFFF)

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

/* Find out which tablespace the given undo log location is backed by. */
extern Oid UndoRecPtrGetTablespace(UndoRecPtr insertion_point);

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
	Oid		tablespace;
	UndoPersistence persistence;	/* permanent, unlogged, temp? */
	UndoLogOffset insert;			/* next insertion point (head) */
	UndoLogOffset end;				/* one past end of highest segment */
	UndoLogOffset discard;			/* oldest data needed (tail) */
	UndoLogOffset last_xact_start;	/* last transactions start undo offset */
	bool	is_first_rec;

	/*
	 * last undo record's length. We need to save this in undo meta and WAL
	 * log so that the value can be preserved across restart so that the first
	 * undo record after the restart can get this value properly.  This will be
	 * used going to the previous record of the transaction during rollback.
	 * In case the transaction have done some operation before checkpoint and
	 * remaining after checkpoint in such case if we can't get the previous
	 * record prevlen which which before checkpoint we can not properly
	 * rollback.  And, undo worker is also fetch this value when rolling back
	 * the last transaction in the undo log for locating the last undo record
	 * of the transaction.
	 */
	uint16	prevlen;
} UndoLogMetaData;

/* Record the undo log number used for a transaction. */
typedef struct xl_undolog_meta
{
	UndoLogMetaData	meta;
	UndoLogNumber	logno;
	TransactionId	xid;
} xl_undolog_meta;

#ifndef FRONTEND

/*
 * The in-memory control object for an undo log.  As well as the current
 * meta-data for the undo log, we also lazily maintain a snapshot of the
 * meta-data as it was at the redo point of a checkpoint that is in progress.
 *
 * Conceptually the set of UndoLogControl objects is arranged into a very
 * large array for access by log number, but because we typically need only a
 * smallish number of adjacent undo logs to be active at a time we arrange
 * them into smaller fragments called 'banks'.
 */
typedef struct UndoLogControl
{
	UndoLogNumber logno;
	UndoLogMetaData meta;			/* current meta-data */
	XLogRecPtr      lsn;
	bool	need_attach_wal_record;	/* need_attach_wal_record */
	pid_t		pid;				/* InvalidPid for unattached */
	LWLock	mutex;					/* protects the above */
	TransactionId xid;
	/* State used by undo workers. */
	TransactionId	oldest_xid;		/* cache of oldest transaction's xid */
	uint32		oldest_xidepoch;
	UndoRecPtr	oldest_data;
	LWLock		discard_lock;		/* prevents discarding while reading */

	UndoLogNumber next_free;		/* protected by UndoLogLock */
} UndoLogControl;

#endif

/* Space management. */
extern UndoRecPtr UndoLogAllocate(size_t size,
								  UndoPersistence level,
								  xl_undolog_meta *undometa);
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

/* Checkpointing interfaces. */
extern void CheckPointUndoLogs(XLogRecPtr checkPointRedo,
							   XLogRecPtr priorCheckPointRedo);

#ifndef FRONTEND

extern UndoLogControl *UndoLogGet(UndoLogNumber logno);
extern UndoLogControl *UndoLogNext(UndoLogControl *log);
extern bool AmAttachedToUndoLog(UndoLogControl *log);

#endif

extern void UndoLogGetDirtySegmentRange(UndoLogNumber logno,
										int *low_segno, int *high_segno);
extern void UndoLogSetHighestSyncedSegment(UndoLogNumber logno, int segno);
extern void UndoLogSetLastXactStartPoint(UndoRecPtr point);
extern UndoRecPtr UndoLogGetLastXactStartPoint(UndoLogNumber logno);
extern UndoRecPtr UndoLogGetCurrentLocation(UndoPersistence persistence);
extern UndoRecPtr UndoLogGetFirstValidRecord(UndoLogNumber logno);
extern UndoRecPtr UndoLogGetNextInsertPtr(UndoLogNumber logno,
										  TransactionId xid);
extern void UndoLogRewind(UndoRecPtr insert_urp, uint16 prevlen);
extern bool IsTransactionFirstRec(TransactionId xid);
extern void UndoLogSetPrevLen(UndoLogNumber logno, uint16 prevlen);
extern uint16 UndoLogGetPrevLen(UndoLogNumber logno);
extern bool NeedUndoMetaLog(XLogRecPtr redo_point);
extern void UndoLogSetLSN(XLogRecPtr lsn);
extern void LogUndoMetaData(xl_undolog_meta *xlrec);
/* Redo interface. */
extern void undolog_redo(XLogReaderState *record);

#endif
