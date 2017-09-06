/*-------------------------------------------------------------------------
 *
 * ztqual.h
 *	  POSTGRES "time qualification" definitions, ie, ztuple visibility rules.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/ztqual.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZTQUAL_H
#define ZTQUAL_H

#include "access/genham.h"
#include "access/xlogdefs.h"
#include "access/zheap.h"

/*
 * ZHeapTupleSatisfiesVisibility
 *		True iff zheap tuple satisfies a time qual.
 */
#define ZHeapTupleSatisfiesVisibility(tuple, snapshot, buffer) \
	((*(snapshot)->zsatisfies) (tuple, snapshot, buffer))

/* These are the "satisfies" test routines for the zheap. */
extern ZHeapTuple ZHeapTupleSatisfiesMVCC(ZHeapTuple zhtup,
					   Snapshot snapshot, Buffer buffer);
extern HTSU_Result ZHeapTupleSatisfiesUpdate(ZHeapTuple zhtup,
						CommandId curcid, Buffer buffer, ItemPointer ctid,
						TransactionId *xid, CommandId *cid, bool free_zhtup,
						bool lock_allowed, Snapshot snapshot,
						bool *in_place_updated_or_locked);
extern bool ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, TransactionId OldestXmin,
								   Buffer buffer);
extern ZHeapTuple ZHeapTupleSatisfiesDirty(ZHeapTuple zhtup,
						Snapshot snapshot, Buffer buffer);
extern ZHeapTuple ZHeapTupleSatisfiesAny(ZHeapTuple zhtup,
					  Snapshot snapshot, Buffer buffer);
extern HTSV_Result ZHeapTupleSatisfiesOldestXmin(ZHeapTuple zhtup,
						TransactionId OldestXmin, Buffer buffer);

#endif   /* ZTQUAL_H */
