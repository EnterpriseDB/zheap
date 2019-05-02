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

#include "access/transam.h"
#include "access/xlogreader.h"
#include "catalog/database_internal.h"
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
	UNDO_LOG_STATUS_FULL,
	UNDO_LOG_STATUS_DISCARDED
} UndoLogStatus;

/*
 * Undo log categories.  These correspond to the different persistence levels
 * of relations so that we can discard unlogged and temporary undo data
 * wholesale in some circumstance.  We also have a separate category for
 * 'shared' records that are not associated with a single transactions.  Since
 * they might live longer than the transaction that created them, and since we
 * prefer to avoid interleaving records that don't belong to the same
 * transaction, we keep them separate.
 */
typedef enum
{
	UNDO_PERMANENT = 0,
	UNDO_UNLOGGED = 1,
	UNDO_TEMP = 2,
	UNDO_SHARED = 3
} UndoLogCategory;

#define UndoLogCategories 4

/*
 * Convert from relpersistence ('p', 'u', 't') to an UndoLogCategory
 * enumerator.
 */
#define UndoLogCategoryForRelPersistence(rp)						\
	((rp) == RELPERSISTENCE_PERMANENT ? UNDO_PERMANENT :			\
	 (rp) == RELPERSISTENCE_UNLOGGED ? UNDO_UNLOGGED : UNDO_TEMP)

/*
 * Convert from UndoLogCategory to a relpersistence value.  There is no
 * relpersistence level for UNDO_SHARED, but the only use of this macro is to
 * pass a value to ReadBufferWithoutRelcache, which cares only about detecting
 * RELPERSISTENCE_TEMP.  XXX There must be a better way.
 */
#define RelPersistenceForUndoLogCategory(up)				\
	((up) == UNDO_PERMANENT ? RELPERSISTENCE_PERMANENT :	\
	 (up) == UNDO_UNLOGGED ? RELPERSISTENCE_UNLOGGED :		\
	 (up) == UNDO_SHARED ? RELPERSISTENCE_PERMANENT :		\
	 RELPERSISTENCE_TEMP)

/*
 * Get the appropriate UndoLogCategory value from a Relation.
 */
#define UndoLogCategoryForRelation(rel)									\
	(UndoLogCategoryForRelPersistence((rel)->rd_rel->relpersistence))

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

/* The maximum valid undo log number. */
#define MaxUndoLogNumber ((1 << UndoLogNumberBits) - 1)

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
#define UndoLogBlockHeaderSize SizeOfUndoPageHeaderData

/* The number of usable bytes we can store per block. */
#define UndoLogUsableBytesPerPage (BLCKSZ - UndoLogBlockHeaderSize)

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

/* Compute the undo record pointer offset given the undo rec page offset and the block number. */
#define UndoRecPageOffsetGetRecPtr(offset, blkno)             \
	((blkno * BLCKSZ) + offset)

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

/* Populate a RelFileNode from an UndoRecPtr. */
#define UndoRecPtrAssignRelFileNode(rfn, urp)								 \
	do																		 \
	{																		 \
		(rfn).spcNode = UndoLogNumberGetTablespace(UndoRecPtrGetLogNo(urp)); \
		(rfn).dbNode = UndoDbOid;											 \
		(rfn).relNode = UndoRecPtrGetRelNode(urp);							 \
	} while (false);

/*
 * Properties of an undo log that don't have explicit WAL records logging
 * their changes, to reduce WAL volume.  Instead, they change incrementally
 * whenever data is inserted as a result of other WAL records.  Since the
 * values recorded in an online checkpoint may be out of the sync (ie not the
 * correct values as at the redo LSN), these are backed up in buffer data on
 * first change after each checkpoint.
 */
typedef struct UndoLogUnloggedMetaData
{
	UndoLogOffset insert;		/* next insertion point (head) */
	UndoLogOffset last_xact_start;	/* last transaction's first byte in this log */
	UndoLogOffset this_xact_start;	/* this transaction's first byte in this log */
	TransactionId xid;				/* currently attached/writing xid */
} UndoLogUnloggedMetaData;

/*
 * Control metadata for an active undo log.  Lives in shared memory inside an
 * UndoLogSlot object, but also written to disk during checkpoints.
 */
typedef struct UndoLogMetaData
{
	/* Members that are not managed by explicit WAL logs. */
	UndoLogUnloggedMetaData unlogged;

	/* Members that are fixed for the lifetime of the undo log. */
	UndoLogNumber logno;
	Oid		tablespace;
	UndoLogCategory category;

	/* Members that are changed by explicit WAL records. */
	UndoLogStatus status;
	UndoLogOffset end;				/* one past end of highest segment */
	UndoLogOffset discard;			/* oldest data needed (tail) */

	/*
	 * Below two variable are used during recovery when transaction's undo
	 * records are split across undo logs.  Replay of switch will restore
	 * these two undo record pointers which will be reset on next allocation
	 * during recovery. */
	UndoRecPtr	prevlog_xact_start; /* Transaction's start undo record pointer
									 * in the previous log. */
	UndoRecPtr	prevlog_last_urp;	/* Transaction's last undo record pointer in
									 * the previous log. */
} UndoLogMetaData;

/*
 * Context used to hold undo log state across all the undo log insertions
 * corresponding to a single WAL record.
 */
typedef struct UndoLogAllocContext
{
	UndoLogCategory category;
	UndoRecPtr	try_location;
	XLogReaderState *xlog_record;
	UndoLogNumber recovery_logno;
	uint8 		recovery_block_id;
	bool		new_shared_record_set;

	/*
	 * The maximum number of undo logs that a single WAL record could insert
	 * into, modifying its unlogged meta data.  Typically the number is 1, but
	 * it might touch a couple or more in rare cases where space runs out.
	 */
#define MAX_META_DATA_IMAGES 4
	int			num_meta_data_images;
	struct
	{
		UndoLogNumber logno;
		UndoLogUnloggedMetaData data;
	} meta_data_images[MAX_META_DATA_IMAGES];
} UndoLogAllocContext;

#ifndef FRONTEND

/*
 * The in-memory control object for an undo log.  We have a fixed-sized array
 * of these.
 */
typedef struct UndoLogSlot
{
	/*
	 * Protected by UndoLogLock and 'mutex'.  Both must be held to steal this
	 * slot for another undolog.  Either may be held to prevent that from
	 * happening.
	 */
	UndoLogNumber logno;			/* InvalidUndoLogNumber for unused slots */

	/* Protected by UndoLogLock. */
	UndoLogNumber next_free;		/* link for active unattached undo logs */

	/* Protected by 'mutex'. */
	LWLock		mutex;
	UndoLogMetaData meta;			/* current meta-data */
	pid_t		pid;				/* InvalidPid for unattached */

	/* Protected by 'discard_lock'.  State used by undo workers. */
	FullTransactionId	wait_fxmin;		/* trigger for processing this log again */
	UndoRecPtr	oldest_data;
	LWLock		discard_lock;		/* prevents discarding while reading */
	LWLock      discard_update_lock;    /* block updaters during discard */
} UndoLogSlot;

extern UndoLogSlot *UndoLogGetSlot(UndoLogNumber logno, bool missing_ok);
extern UndoLogSlot *UndoLogNextSlot(UndoLogSlot *slot);
extern bool AmAttachedToUndoLogSlot(UndoLogSlot *slot);
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
	UndoLogCategory category;
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

/*
 * Find or create an UndoLogTableGetEntry for this log number.  This is used
 * only for fast look-ups of tablespace and persistence.
 */
static pg_attribute_always_inline UndoLogTableEntry *
UndoLogGetTableEntry(UndoLogNumber logno)
{
	UndoLogTableEntry *entry;

	/* Fast path. */
	entry = undologtable_lookup(undologtable_cache, logno);
	if (likely(entry))
		return entry;

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
static inline UndoLogCategory
UndoLogNumberGetCategory(UndoLogNumber logno)
{
	return UndoLogGetTableEntry(logno)->category;
}

static inline UndoLogCategory
UndoRecPtrGetCategory(UndoRecPtr urp)
{
	return UndoLogNumberGetCategory(UndoRecPtrGetLogNo(urp));
}

#endif

/* Space management. */
extern void UndoLogBeginInsert(UndoLogAllocContext *context,
							   UndoLogCategory category,
							   XLogReaderState *xlog_record);
extern void UndoLogRegister(UndoLogAllocContext *context,
							uint8 block_id,
							UndoLogNumber logno);
extern UndoRecPtr UndoLogAllocate(UndoLogAllocContext *context,
								  uint16 size,
								  bool *need_xact_header,
								  UndoRecPtr *last_xact_start,
								  UndoRecPtr *prevlog_xact_start,
								  UndoRecPtr *prevlog_insert_urp);
extern UndoRecPtr UndoLogAllocateInRecovery(UndoLogAllocContext *context,
											TransactionId xid,
											uint16 size,
											bool *need_xact_header,
											UndoRecPtr *last_xact_start,
											UndoRecPtr *prevlog_xact_start,
											UndoRecPtr *prevlog_last_urp);
extern void UndoLogAdvance(UndoLogAllocContext *context, size_t size);
extern void UndoLogAdvanceFinal(UndoRecPtr insertion_point, size_t size);
extern bool UndoLogDiscard(UndoRecPtr discard_point, TransactionId xid);
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

#endif

/* Initialization interfaces. */
extern void StartupUndoLogs(XLogRecPtr checkPointRedo);
extern void UndoLogShmemInit(void);
extern Size UndoLogShmemSize(void);
extern void UndoLogInit(void);
extern void UndoLogDirectory(Oid tablespace, char *path);
extern void UndoLogSegmentPath(UndoLogNumber logno, int segno, Oid tablespace,
							   char *path);
extern void ResetUndoLogs(UndoLogCategory category);

/* Interface use by tablespace.c. */
extern bool DropUndoLogsInTablespace(Oid tablespace);

/* GUC interfaces. */
extern void assign_undo_tablespaces(const char *newval, void *extra);

/* Checkpointing interfaces. */
extern void CheckPointUndoLogs(XLogRecPtr checkPointRedo,
							   XLogRecPtr priorCheckPointRedo);

/* File sync request management. */


extern UndoRecPtr UndoLogGetLastXactStartPoint(UndoLogNumber logno);
extern UndoRecPtr UndoLogGetNextInsertPtr(UndoLogNumber logno);
extern void UndoLogSwitchSetPrevLogInfo(UndoLogNumber logno,
										UndoRecPtr prevlog_last_urp,
										UndoRecPtr prevlog_xact_start);
extern void UndoLogSetLSN(XLogRecPtr lsn);
void UndoLogNewSegment(UndoLogNumber logno, Oid tablespace, int segno);
/* Redo interface. */
extern void undolog_redo(XLogReaderState *record);
/* Discard the undo logs for temp tables */
extern void TempUndoDiscard(UndoLogNumber);

/* Test-only interfacing. */
extern void UndoLogDetachFull(void);

#endif
