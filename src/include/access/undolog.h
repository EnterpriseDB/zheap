/*-------------------------------------------------------------------------
 *
 * undolog.h
 *
 * PostgreSQL undo log manager.  This module is responsible for lifecycle
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

#include "access/undodefs.h"
#include "access/xlogdefs.h"
#include "catalog/database_internal.h"
#include "lib/ilist.h"
#include "storage/bufpage.h"

#ifndef FRONTEND
#include "storage/lwlock.h"
#endif

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

/* The maximum valid undo log number. */
#define MaxUndoLogNumber ((1 << UndoLogNumberBits) - 1)

/* The width of an undo log offset in bits.  40 allows for 1TB per log.*/
#define UndoLogOffsetBits (64 - UndoLogNumberBits)

/* Special value for undo record pointer which indicates that it is invalid. */
#define	InvalidUndoRecPtr	((UndoRecPtr) 0)

/* End-of-list value when building linked lists of undo logs. */
#define InvalidUndoLogNumber -1

/*
 * UndoRecPtrIsValid
 *		True iff undoRecPtr is valid.
 */
#define UndoRecPtrIsValid(undoRecPtr) \
	((bool) ((UndoRecPtr) (undoRecPtr) != InvalidUndoRecPtr))

/*
 * The maximum amount of data that can be stored in an undo log.  Can be set
 * artificially low to test full log behavior.
 */
#define UndoLogMaxSize ((UndoLogOffset) 1 << UndoLogOffsetBits)

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

/* Length of undo checkpoint filename */
#define UNDO_CHECKPOINT_FILENAME_LENGTH	16

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

/* Add 'n' usable bytes to an UndoRecPtr, stepping over headers. */
#define UndoRecPtrPlusUsableBytes(ptr, n)							\
	UndoLogOffsetPlusUsableBytes(ptr, n)

/* Populate a RelFileNode from an UndoRecPtr. */
#define UndoRecPtrAssignRelFileNode(rfn, urp)								 \
	do																		 \
	{																		 \
		(rfn).spcNode = UndoLogNumberGetTablespace(UndoRecPtrGetLogNo(urp)); \
		(rfn).dbNode = UndoDbOid;											 \
		(rfn).relNode = UndoRecPtrGetRelNode(urp);							 \
	} while (false);

/*
 * Control metadata for an active undo log.  Lives in shared memory inside an
 * UndoLogSlot object, but also written to disk during checkpoints.
 */
typedef struct UndoLogMetaData
{
	UndoLogNumber logno;
	Oid			tablespace;
	char		persistence;

	UndoLogOffset discard;			/* oldest data needed (tail) */
	UndoLogOffset insert;			/* location of next insert (head) */
	UndoLogOffset full;				/* If insert == full, the log is full. */
} UndoLogMetaData;

#ifndef FRONTEND

/*
 * The in-memory control object for an undo log.  We have a fixed-sized array
 * of these.
 *
 * The following locks protect different aspects of UndoLogSlot objects, and
 * if more than one these is taken they must be taken in the order listed
 * here:
 *
 * * UndoLogLock -- protects undo log freelists, and prevents slot alloc/free
 * * file_lock -- used to prevent concurrent modification of begin, end
 * * meta_lock -- used to update or read meta, begin, end
 *
 * Note that begin and end can be read while holding only file_lock or
 * meta_lock, but can only be updated while holding both.
 */
typedef struct UndoLogSlot
{
	/*
	 * Protected by UndoLogLock, file_lock and meta_lock.  All must be held to
	 * steal this slot for another undolog.  Any one may be held to prevent
	 * that from happening.
	 */
	UndoLogNumber logno;			/* InvalidUndoLogNumber for unused slots */

	slist_node	next;				/* link node for freelists */

	LWLock		file_lock;			/* prevents concurrent file operations */

	LWLock		meta_lock;			/* protects following members */
	UndoLogMetaData meta;			/* current meta-data */
	bool		simulate_full;		/* for testing only */
	pid_t		pid;				/* InvalidPid for unattached */
	TransactionId xid;
	UndoLogOffset begin;			/* beginning of lowest segment file */
	UndoLogOffset end;				/* one past end of highest segment */
} UndoLogSlot;

extern UndoLogSlot *UndoLogGetSlot(UndoLogNumber logno, bool missing_ok);
extern UndoRecPtr UndoLogGetOldestRecord(UndoLogNumber logno, bool *full);

/*
 * Each backend maintains a small hash table mapping undo log numbers to
 * UndoLogSlot objects in shared memory.
 *
 * We also cache the tablespace, category and a recently observed discard
 * pointer here, since we need fast access to those.  We could also reach them
 * via slot->meta, but they can't be accessed without locking (since the
 * UndoLogSlot object might be recycled if the log is entirely discard).
 * Since tablespace and category are constant for lifetime of the undo log
 * number, and the discard pointer only travels in one direction, there is no
 * cache invalidation problem to worry about.
 */
typedef struct UndoLogTableEntry
{
	UndoLogNumber	number;
	UndoLogSlot	   *slot;
	Oid				tablespace;
	char			persistence;
	UndoRecPtr		recent_discard;
	char			status;			/* used by simplehash */
} UndoLogTableEntry;

/*
 * Instantiate fast inline hash table access functions.  We use an identity
 * hash function for speed, since we already have integers and don't expect
 * many collisions.
 */
#define SH_PREFIX undologtable
#define SH_ELEMENT_TYPE UndoLogTableEntry
#define SH_KEY_TYPE UndoLogNumber
#define SH_KEY number
#define SH_HASH_KEY(tb, key) (key)
#define SH_EQUAL(tb, a, b) ((a) == (b))
#define SH_SCOPE static inline
#define SH_DECLARE
#define SH_DEFINE
#include "lib/simplehash.h"

extern PGDLLIMPORT undologtable_hash *undologtable_cache;
extern UndoLogNumber undologtable_low_logno;

/*
 * Find or create an UndoLogTableGetEntry for this log number.  This is used
 * only for fast look-ups of tablespace and persistence.
 */
static pg_attribute_always_inline UndoLogTableEntry *
UndoLogGetTableEntry(UndoLogNumber logno)
{
	UndoLogTableEntry  *entry;

	/* Fast path. */
	entry = undologtable_lookup(undologtable_cache, logno);
	if (likely(entry))
		return entry;

	/* Avoid a slow look up for ancient discarded undo logs. */
	if (logno < undologtable_low_logno)
		return NULL;

	/* Slow path: force cache entry to be created. */
	UndoLogGetSlot(logno, false);
	entry = undologtable_lookup(undologtable_cache, logno);

	return entry;
}

/*
 * Look up the tablespace for an undo log in our cache.
 */
static inline Oid
UndoLogNumberGetTablespace(UndoLogNumber logno)
{
	return UndoLogGetTableEntry(logno)->tablespace;
}

static inline Oid
UndoRecPtrGetTablespace(UndoRecPtr urp)
{
	return UndoLogNumberGetTablespace(UndoRecPtrGetLogNo(urp));
}

/*
 * Look up the category for an undo log in our cache.
 */
static inline char
UndoLogNumberGetPersistence(UndoLogNumber logno)
{
	return UndoLogGetTableEntry(logno)->persistence;
}

static inline char
UndoRecPtrGetPersistence(UndoRecPtr urp)
{
	return UndoLogNumberGetPersistence(UndoRecPtrGetLogNo(urp));
}

#endif

/* Discarding data. */
extern void UndoDiscard(UndoRecPtr location);
extern bool UndoLogRecPtrIsDiscardedSlowPath(UndoRecPtr pointer);

#ifndef FRONTEND

/*
 * Check if an undo log pointer is discarded.
 */
static inline bool
UndoRecPtrIsDiscarded(UndoRecPtr pointer)
{
	UndoLogNumber	logno = UndoRecPtrGetLogNo(pointer);
	UndoRecPtr		recent_discard;

	/* See if we can answer the question without acquiring any locks. */
	recent_discard = UndoLogGetTableEntry(logno)->recent_discard;
	if (likely(recent_discard > pointer))
		return true;

	/*
	 * It might be discarded or not, but we'll need to do a bit more work to
	 * find out.
	 */
	return UndoLogRecPtrIsDiscardedSlowPath(pointer);
}

/* Interfaces used by undorecordset.c. */
extern UndoLogSlot *UndoLogGetForPersistence(char persistence);
extern void UndoLogPut(UndoLogSlot *slot);
extern void UndoLogAdjustPhysicalRange(UndoLogNumber logno,
									   UndoLogOffset new_discard,
									   UndoLogOffset new_isnert);
extern void UndoLogMarkFull(UndoLogSlot *uls);

extern UndoPersistenceLevel GetUndoPersistenceLevel(char persistence);

#endif

/* Initialization interfaces. */
extern void StartupUndoLogs(XLogRecPtr checkPointRedo);
extern void UndoLogShmemInit(void);
extern Size UndoLogShmemSize(void);
extern void AtProcExit_UndoLog(void);

/* Interfaces exported for undo_file.c. */
extern void UndoLogNewSegment(UndoLogNumber logno, Oid tablespace, int segno);
extern void UndoLogDirectory(Oid tablespace, char *path);
extern void UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace,
							   char *path);
extern void ResetUndoLogs(char persistence);

/* Interface use by tablespace.c. */
extern bool DropUndoLogsInTablespace(Oid tablespace);

/* GUC interfaces. */
extern void assign_undo_tablespaces(const char *newval, void *extra);

/* Checkpointing interfaces. */
extern void CheckPointUndoLogs(XLogRecPtr checkPointRedo);

extern void TempUndoDiscard(UndoLogNumber);

#endif
