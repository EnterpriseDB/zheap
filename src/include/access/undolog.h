/*-------------------------------------------------------------------------
 *
 * undolog.h
 *
 * PostgreSQL undo log manager.  This module is responsible for lifecycle
 * management of undo logs and backing files, associating undo logs with
 * backends, allocating and managing space within undo logs.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
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

/* The type used to identify an undo log and position within it. */
typedef uint64 UndoRecPtr;

/* The type used for undo record lengths. */
typedef uint16 UndoRecordSize;

/* Undo log persistence levels. */
typedef enum
{
	UNDO_PERSISTENT = RELPERSISTENCE_PERMANENT,
	UNDO_UNLOGGED = RELPERSISTENCE_UNLOGGED,
	UNDO_TEMP = RELPERSISTENCE_TEMP
} UndoPersistence;

/* Type for offsets within undo logs */
typedef uint64 UndoLogOffset;

/* Number of blocks of BLCKSZ in an undo log segment file.  2048 = 16MB. */
#define UNDOSEG_SIZE 2048

/* The width of an undo log number in bits.  24 allows for 16.7m logs. */
#define UndoLogNumberBits 24

/* The width of an undo log offset in bits.  40 allows for 1TB per log.*/
#define UndoLogOffsetBits (64 - UndoLogNumberBits)

/*
 * The maximum amount of data that can be stored in an undo log.  Can be set
 * artificially low to test full log behavior.
 */
#define UndoLogMaxSize ((size_t) 1 << UndoLogOffsetBits)

/* Type for numbering undo logs. */
typedef int UndoLogNumber;

/* Extract the undo log number from an UndoRecPtr. */
#define UndoRecPtrGetLogNo(urp)					\
	((urp) >> UndoLogOffsetBits)

/* Extract the offset from an UndoRecPtr. */
#define UndoRecPtrGetOffset(urp)				\
	((urp) & (1L << UndoLogOffsetBits) - 1)

/* Make an UndoRecPtr from an log number and offset. */
#define MakeUndoRecPtr(logno, offset)			\
	(((uint64) (logno) << UndoLogOffsetBits) | (offset))

/* The number of unusable bytes in the header of each block. */
#define UndoLogBlockHeaderSize SizeOfPageHeaderData

/* The number of usable bytes we can store per block. */
#define UndoLogUsableBytesPerPage (BLCKSZ - UndoLogBlockHeaderSize)

/* The pseudo-database OID used for undo logs. */
#define UndoLogDatabaseOid 9

/* Extract the relnode for an undo log. */
#define UndoRecPtrGetRelNode(urp)				\
	UndoRecPtrGetLogNo(urp)

/* The only valid fork number for undo log buffers. */
#define UndoLogForkNum MAIN_FORKNUM

/* Compute the block number that holds a given UndoRecPtr. */
#define UndoRecPtrGetBlockNum(urp)							\
	(UndoRecPtrGetOffset(urp) / UndoLogUsableBytesPerPage)

/* Compute the offset of a given UndoRecPtr in the page that holds it. */
#define UndoRecPtrGetPageOffset(urp)							\
	(UndoRecPtrGetOffset(urp) % UndoLogUsableBytesPerPage +		\
	 UndoLogBlockHeaderSize)

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
	Oid		tablespace;
	UndoRecordSize last_size;		/* size of last inserted record */
	UndoLogOffset insert;			/* next insertion point */
	UndoLogOffset capacity;			/* one past end of highest segment */
	UndoLogOffset mvcc;				/* oldest data needed for MVCC */
	UndoLogOffset rollback;			/* oldest data needed for rollback */
} UndoLogMetaData;

extern UndoRecPtr UndoLogAllocate(UndoRecordSize size, UndoPersistence level);
extern UndoRecPtr UndoLogAllocateInRecovery(TransactionId xid,
											UndoRecordSize size,
											UndoPersistence level);
extern void UndoLogAdvance(UndoRecPtr insertion_point, UndoRecordSize size);


extern void CheckPointUndoLogs(XLogRecPtr checkPointRedo);
extern void StartupUndoLogs(XLogRecPtr checkPointRedo);
extern void UndoLogShmemInit(void);
extern Size UndoLogShmemSize(void);
extern void UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace,
							   char *dir, char *path);
extern bool UndoLogNextActiveLog(UndoLogNumber *logno, Oid *spcNode);
extern void UndoLogGetDirtySegmentRange(UndoLogNumber logno,
										int *low_segno, int *high_segno);
extern void UndoLogSetHighestSyncedSegment(UndoLogNumber logno, int segno);

extern void undolog_redo(XLogReaderState *record);

#endif
