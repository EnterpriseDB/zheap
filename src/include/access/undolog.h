/*-------------------------------------------------------------------------
 *
 * undolog.h
 *	  management of undo logs
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

#include "postgres.h"

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

/* The width of an undo log number in bits.  24 allows for 16.7m logs. */
#define UndoLogNumberBits 24

/* The width of an undo log offset in bits.  40 allows for 1TB per log.*/
#define UndoLogOffsetBits (64 - UndoLogNumberBits)

/* Extract the undo log number from an UndoRecPtr. */
#define UndoRecPtrGetLogNo(urp)					\
	((urp) >> UndoLogOffsetBits)

/* Extract the offset from an UndoRecPtr. */
#define UndoRecPtrGetOffset(urp)				\
	((urp) & (1L << UndoLogOffsetBits) - 1)

/* The number of unusable bytes in the header of each block. */
#define UndoLogBlockHeaderSize SizeOfPageHeaderData

/* The number of usable bytes we can store per block. */
#define UndoLogUsableBytesPerPage (BLKSIZE - UndoLogBlockHeaderSize)

/* The pseudo-database OID used for undo logs. */
#define UndoLogDatabaseOid 9

/* Extract the relnode for an undo log. */
#define UndoRecPtrGetRelNode(urp)				\
	(0x10000 + UndoRecPtrGetLogNo(urp))

/* The only valid fork number for undo log buffers. */
#define UndoLogForkNum MAIN_FORKNUM

/* Compute the block number that holds a given UndoRecPtr. */
#define UndoRecPtrGetBlockNum(urp)							\
	(UndoRecPtrGetOffset(urp) / UndoLogUsableBytesPerPage)

/* Compute the offset of a given UndoRecPtr in the page that holds it. */
#define UndoRecPtrGetPageOffset(urp)							\
	(UndoRecPtrGetOffset(urp) % UndoLogUsableBytesPerPage +	\
	 UndoLogBlockHeaderSize)

/* Find out which tablespace the given undo log location is backed by. */
extern Oid UndoRecPtrGetTablespace(UndoRecPtr insertion_point);

/*
 * Get an insertion point guaranteed to be backed be enough buffers to hold
 * 'size' bytes available.
 */
extern UndoRecPtr GetUndoLogInsertionPoint(UndoRecordSize size,
										   UndoPersistence level);

/*
 * Set the new insertion point within a log.  'insertion_point' be a value
 * returned by GetUndoLogInsertionPoint.
 */
extern void AdvanceUndoLogInsertionPoint(UndoRecPtr insertion_point,
										 UndoRecordSize size);

extern void BootStrapUndoLog(void);
extern void UndoLogShmemInit(void);
extern Size UndoLogShmemSize(void);

#endif
