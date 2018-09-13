/*-------------------------------------------------------------------------
 *
 * tqual.h
 *	  POSTGRES "time qualification" definitions, ie, tuple visibility rules.
 *
 *	  Should be moved/renamed...    - vadim 07/28/98
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/tqual.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TQUAL_H
#define TQUAL_H

#include "utils/snapshot.h"
#include "access/xlogdefs.h"
#include "utils/ztqual.h"


/* Static variables representing various special snapshot semantics */
extern PGDLLIMPORT SnapshotData SnapshotSelfData;
extern PGDLLIMPORT SnapshotData SnapshotAnyData;
extern PGDLLIMPORT SnapshotData CatalogSnapshotData;

#define SnapshotSelf		(&SnapshotSelfData)
#define SnapshotAny			(&SnapshotAnyData)

/* This macro encodes the knowledge of which snapshots are MVCC-safe */
#define IsMVCCSnapshot(snapshot)  \
	((snapshot)->satisfies == HeapTupleSatisfiesMVCC || \
	 (snapshot)->satisfies == HeapTupleSatisfiesHistoricMVCC || \
	 (snapshot)->zsatisfies == ZHeapTupleSatisfiesMVCC)

/*
 * HeapTupleSatisfiesVisibility
 *		True iff heap tuple satisfies a time qual.
 *
 * Notes:
 *	Assumes heap tuple is valid.
 *	Beware of multiple evaluations of snapshot argument.
 *	Hint bits in the HeapTuple's t_infomask may be updated as a side effect;
 *	if so, the indicated buffer is marked dirty.
 */
#define HeapTupleSatisfiesVisibility(tuple, snapshot, buffer) \
	((*(snapshot)->satisfies) (tuple, snapshot, buffer))

/* These are the "satisfies" test routines for the various snapshot types */
extern bool HeapTupleSatisfiesMVCC(HeapTuple htup,
					   Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesSelf(HeapTuple htup,
					   Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesAny(HeapTuple htup,
					  Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesToast(HeapTuple htup,
						Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesDirty(HeapTuple htup,
						Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesNonVacuumable(HeapTuple htup,
								Snapshot snapshot, Buffer buffer);
extern bool HeapTupleSatisfiesHistoricMVCC(HeapTuple htup,
							   Snapshot snapshot, Buffer buffer);
extern bool	HeapTupleHasSerializableConflictOut(bool visible,
								HeapTuple htup, Buffer buffer,
								TransactionId *xid);
extern bool ZHeapTupleHasSerializableConflictOut(bool visible,
						Relation relation, ItemPointer tid, Buffer buffer,
						TransactionId *xid);

/* Special "satisfies" routines with different APIs */
extern HTSU_Result HeapTupleSatisfiesUpdate(HeapTuple htup,
						 CommandId curcid, Buffer buffer);
extern HTSV_Result HeapTupleSatisfiesVacuum(HeapTuple htup,
						 TransactionId OldestXmin, Buffer buffer);
extern bool HeapTupleIsSurelyDead(HeapTuple htup,
					  TransactionId OldestXmin);
extern bool XidInMVCCSnapshot(TransactionId xid, Snapshot snapshot);

extern void HeapTupleSetHintBits(HeapTupleHeader tuple, Buffer buffer,
					 uint16 infomask, TransactionId xid);
extern bool HeapTupleHeaderIsOnlyLocked(HeapTupleHeader tuple);

extern bool XidInMVCCSnapshot(TransactionId xid, Snapshot snapshot);

/*
 * To avoid leaking too much knowledge about reorderbuffer implementation
 * details this is implemented in reorderbuffer.c not tqual.c.
 */
struct HTAB;
extern bool ResolveCminCmaxDuringDecoding(struct HTAB *tuplecid_data,
							  Snapshot snapshot,
							  HeapTuple htup,
							  Buffer buffer,
							  CommandId *cmin, CommandId *cmax);

/*
 * We don't provide a static SnapshotDirty variable because it would be
 * non-reentrant.  Instead, users of that snapshot type should declare a
 * local variable of type SnapshotData, and initialize it with this macro.
 */
#define InitDirtySnapshot(snapshotdata)  \
	((snapshotdata).satisfies = HeapTupleSatisfiesDirty, \
	 (snapshotdata).zsatisfies = ZHeapTupleSatisfiesDirty)

/*
 * Similarly, some initialization is required for a NonVacuumable snapshot.
 * The caller must supply the xmin horizon to use (e.g., RecentGlobalXmin).
 */
#define InitNonVacuumableSnapshot(snapshotdata, xmin_horizon)  \
	((snapshotdata).satisfies = HeapTupleSatisfiesNonVacuumable, \
	 (snapshotdata).zsatisfies = ZHeapTupleSatisfiesNonVacuumable, \
	 (snapshotdata).xmin = (xmin_horizon))

/*
 * Similarly, some initialization is required for SnapshotToast.  We need
 * to set lsn and whenTaken correctly to support snapshot_too_old.
 */
#define InitToastSnapshot(snapshotdata, l, w)  \
	((snapshotdata).satisfies = HeapTupleSatisfiesToast, \
	 (snapshotdata).zsatisfies = ZHeapTupleSatisfiesToast, \
	 (snapshotdata).lsn = (l),					\
	 (snapshotdata).whenTaken = (w))

#endif							/* TQUAL_H */
