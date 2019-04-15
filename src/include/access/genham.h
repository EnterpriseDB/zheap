/*-------------------------------------------------------------------------
 *
 * genham.h
 *	  POSTGRES generalized heap access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/genham.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef GENHAM_H
#define GENHAM_H

#include "access/multixact.h"
#include "nodes/lockoptions.h"
#include "storage/bufmgr.h"
#include "storage/lockdefs.h"

typedef struct BulkInsertStateData *BulkInsertState;

/* struct definitions appear in relscan.h */
typedef struct HeapScanDescData *HeapScanDesc;
typedef struct ParallelTableScanDescData *ParallelTableScanDesc;

/* Result codes for HeapTupleSatisfiesVacuum */
typedef enum
{
	HEAPTUPLE_DEAD,				/* tuple is dead and deletable */
	HEAPTUPLE_LIVE,				/* tuple is live (committed, no deleter) */
	HEAPTUPLE_RECENTLY_DEAD,	/* tuple is dead, but not deletable yet */
	HEAPTUPLE_INSERT_IN_PROGRESS,	/* inserting xact is still in progress */
	HEAPTUPLE_DELETE_IN_PROGRESS	/* deleting xact is still in progress */
} HTSV_Result;

/* Result codes for ZHeapTupleSatisfiesVacuum */
typedef enum
{
	ZHEAPTUPLE_DEAD,			/* tuple is dead and deletable */
	ZHEAPTUPLE_LIVE,			/* tuple is live (committed, no deleter) */
	ZHEAPTUPLE_RECENTLY_DEAD,	/* tuple is dead, but not deletable yet */
	ZHEAPTUPLE_INSERT_IN_PROGRESS,	/* inserting xact is still in progress */
	ZHEAPTUPLE_DELETE_IN_PROGRESS,	/* deleting xact is still in progress */
	ZHEAPTUPLE_ABORT_IN_PROGRESS	/* rollback is still pending */
}			ZHTSV_Result;



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
			 ReadBufferMode mode, BulkInsertState bistate);

#endif							/* GENHAM_H */
