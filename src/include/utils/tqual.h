/*-------------------------------------------------------------------------
 *
 * tqual.h
 *	  POSTGRES "time qualification" definitions, ie, tuple visibility rules.
 *
 *	  Should be moved/renamed...    - vadim 07/28/98
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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
	((snapshot)->visibility_type == MVCC_VISIBILITY || \
	 (snapshot)->visibility_type == HISTORIC_MVCC_VISIBILITY)

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

extern bool HeapTupleHasSerializableConflictOut(bool visible,
									HeapTuple htup, Buffer buffer,
									TransactionId *xid);

extern bool ZHeapTupleHasSerializableConflictOut(bool visible,
									 Relation relation, ItemPointer tid, Buffer buffer,
									 TransactionId *xid);

/*
 * We don't provide a static SnapshotDirty variable because it would be
 * non-reentrant.  Instead, users of that snapshot type should declare a
 * local variable of type SnapshotData, and initialize it with this macro.
 */
#define InitDirtySnapshot(snapshotdata)  \
	((snapshotdata).visibility_type = DIRTY_VISIBILITY)

/*
 * Similarly, some initialization is required for a NonVacuumable snapshot.
 * The caller must supply the xmin horizon to use (e.g., RecentGlobalXmin).
 */
#define InitNonVacuumableSnapshot(snapshotdata, xmin_horizon)  \
	((snapshotdata).visibility_type = NON_VACUUMABLE_VISIBILTY, \
	 (snapshotdata).xmin = (xmin_horizon))

/*
 * Similarly, some initialization is required for SnapshotToast.  We need
 * to set lsn and whenTaken correctly to support snapshot_too_old.
 */
#define InitToastSnapshot(snapshotdata, l, w)  \
	((snapshotdata).visibility_type = TOAST_VISIBILITY, \
	 (snapshotdata).lsn = (l),					\
	 (snapshotdata).whenTaken = (w))

#endif							/* TQUAL_H */
