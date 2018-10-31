/*-------------------------------------------------------------------------
 *
 * genham.h
 *	  POSTGRES generalized heap access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/genham.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef GENHAM_H
#define GENHAM_H

#include "access/multixact.h"
#include "access/sdir.h"
#include "access/skey.h"
#include "nodes/lockoptions.h"
#include "storage/buf.h"
#include "storage/itemptr.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"

typedef struct BulkInsertStateData *BulkInsertState;

/* struct definitions appear in relscan.h */
typedef struct HeapScanDescData *HeapScanDesc;
typedef struct ParallelHeapScanDescData *ParallelHeapScanDesc;

/*
 * When heap_update, heap_delete, or heap_lock_tuple fail because the target
 * tuple is already outdated, they fill in this struct to provide information
 * to the caller about what happened.
 * ctid is the target's ctid link: it is the same as the target's TID if the
 * target was deleted, or the location of the replacement tuple if the target
 * was updated.
 * xmax is the outdating transaction's XID.  If the caller wants to visit the
 * replacement tuple, it must check that this matches before believing the
 * replacement is really a match.
 * cmax is the outdating command's CID, but only when the failure code is
 * HeapTupleSelfUpdated (i.e., something in the current transaction outdated
 * the tuple); otherwise cmax is zero.  (We make this restriction because
 * HeapTupleHeaderGetCmax doesn't work for tuples outdated in other
 * transactions.)
 * in_place_updated_or_locked indicates whether the tuple is updated or locked.
 * We need to re-verify the tuple even if it is just marked as locked, because
 * previously someone could have updated it in place.
 */
typedef struct HeapUpdateFailureData
{
	ItemPointerData ctid;
	TransactionId xmax;
	CommandId	cmax;
	bool		in_place_updated_or_locked;
} HeapUpdateFailureData;

/* Result codes for HeapTupleSatisfiesVacuum */
typedef enum
{
	HEAPTUPLE_DEAD,				/* tuple is dead and deletable */
	HEAPTUPLE_LIVE,				/* tuple is live (committed, no deleter) */
	HEAPTUPLE_RECENTLY_DEAD,	/* tuple is dead, but not deletable yet */
	HEAPTUPLE_INSERT_IN_PROGRESS,		/* inserting xact is still in progress */
	HEAPTUPLE_DELETE_IN_PROGRESS	/* deleting xact is still in progress */
} HTSV_Result;

/* Result codes for ZHeapTupleSatisfiesVacuum */
typedef enum
{
	ZHEAPTUPLE_DEAD,				/* tuple is dead and deletable */
	ZHEAPTUPLE_LIVE,				/* tuple is live (committed, no deleter) */
	ZHEAPTUPLE_RECENTLY_DEAD,	/* tuple is dead, but not deletable yet */
	ZHEAPTUPLE_INSERT_IN_PROGRESS,		/* inserting xact is still in progress */
	ZHEAPTUPLE_DELETE_IN_PROGRESS,	/* deleting xact is still in progress */
	ZHEAPTUPLE_ABORT_IN_PROGRESS		/* rollback is still pending */
} ZHTSV_Result;

/*
 * Possible lock modes for a tuple.
 */
typedef enum LockTupleMode
{
	/* SELECT FOR KEY SHARE */
	LockTupleKeyShare,
	/* SELECT FOR SHARE */
	LockTupleShare,
	/* SELECT FOR NO KEY UPDATE, and UPDATEs that don't modify key columns */
	LockTupleNoKeyExclusive,
	/* SELECT FOR UPDATE, UPDATEs that modify key columns, and DELETE */
	LockTupleExclusive
} LockTupleMode;

#define MaxLockTupleMode	LockTupleExclusive


static const struct
{
	LOCKMODE	hwlock;
	int			lockstatus;
	int			updstatus;
}

			tupleLockExtraInfo[MaxLockTupleMode + 1] =
{
	{							/* LockTupleKeyShare */
		AccessShareLock,
		MultiXactStatusForKeyShare,
		-1						/* KeyShare does not allow updating tuples */
	},
	{							/* LockTupleShare */
		RowShareLock,
		MultiXactStatusForShare,
		-1						/* Share does not allow updating tuples */
	},
	{							/* LockTupleNoKeyExclusive */
		ExclusiveLock,
		MultiXactStatusForNoKeyUpdate,
		MultiXactStatusNoKeyUpdate
	},
	{							/* LockTupleExclusive */
		AccessExclusiveLock,
		MultiXactStatusForUpdate,
		MultiXactStatusUpdate
	}
};

#define UnlockTupleTuplock(rel, tup, mode) \
	UnlockTuple((rel), (tup), tupleLockExtraInfo[mode].hwlock)

extern bool heap_acquire_tuplock(Relation relation, ItemPointer tid,
					 LockTupleMode mode, LockWaitPolicy wait_policy,
					 bool *have_tuple_lock);
extern void GetVisibilityMapPins(Relation relation, Buffer buffer1,
					Buffer buffer2, BlockNumber block1, BlockNumber block2,
					Buffer *vmbuffer1, Buffer *vmbuffer2);
extern void RelationAddExtraBlocks(Relation relation, BulkInsertState bistate);
extern Buffer ReadBufferBI(Relation relation, BlockNumber targetBlock,
					BulkInsertState bistate);

#endif   /* GENHAM_H */
