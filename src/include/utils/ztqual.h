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
#define ZHeapTupleSatisfiesVisibility(tuple, snapshot, buffer, ctid) \
	((*(snapshot)->zsatisfies) (tuple, snapshot, buffer, ctid))

extern void FetchTransInfoFromUndo(ZHeapTuple undo_tup, uint64 *epoch,
					   TransactionId *xid, CommandId *cid,
					   UndoRecPtr *urec_ptr, bool skip_lockers);
extern void ZHeapTupleGetTransInfo(ZHeapTuple zhtup, Buffer buf,
					   int *trans_slot, uint64 *epoch_xid_out,
					   TransactionId *xid_out, CommandId *cid_out,
					   UndoRecPtr *urec_ptr_out, bool nobuflock,
					   Snapshot snapshot);

/* Fetch CTID information stored in undo */
extern void ZHeapPageGetNewCtid(Buffer buffer, ItemPointer ctid,
					TransactionId *xid, CommandId *cid);

/* These are the "satisfies" test routines for the zheap. */
extern ZHeapTuple ZHeapTupleSatisfiesMVCC(ZHeapTuple zhtup,
										  Snapshot snapshot, Buffer buffer, ItemPointer ctid);
extern ZHeapTuple ZHeapGetVisibleTuple(OffsetNumber off, Snapshot snapshot,
									   Buffer buffer, bool *all_dead);
extern HTSU_Result ZHeapTupleSatisfiesUpdate(Relation rel, ZHeapTuple zhtup,
						  CommandId curcid, Buffer buffer, ItemPointer ctid,
						  int *trans_slot, TransactionId *xid,
						  SubTransactionId *subxid, CommandId *cid,
						  TransactionId *single_locker_xid, int *single_locker_trans_slot,
						  bool free_zhtup, bool lock_allowed, Snapshot snapshot,
						  bool *in_place_updated_or_locked);
extern bool ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, uint64 OldestXmin,
					   Buffer buffer);
extern ZHeapTuple ZHeapTupleSatisfiesSelf(ZHeapTuple zhtup, Snapshot snapshot,
										  Buffer buffer, ItemPointer ctid);
extern ZHeapTuple ZHeapTupleSatisfiesDirty(ZHeapTuple zhtup,
										   Snapshot snapshot, Buffer buffer, ItemPointer ctid);
extern ZHeapTuple ZHeapTupleSatisfiesAny(ZHeapTuple zhtup,
										 Snapshot snapshot, Buffer buffer, ItemPointer ctid);
extern HTSV_Result ZHeapTupleSatisfiesOldestXmin(ZHeapTuple *zhtup,
							  TransactionId OldestXmin, Buffer buffer,
							  TransactionId *xid, SubTransactionId *subxid);
extern ZHeapTuple ZHeapTupleSatisfiesNonVacuumable(ZHeapTuple ztup, Snapshot snapshot,
												   Buffer buffer, ItemPointer ctid);
extern ZHTSV_Result ZHeapTupleSatisfiesVacuum(ZHeapTuple zhtup, TransactionId OldestXmin,
											  Buffer buffer, TransactionId *xid);
extern ZHeapTuple ZHeapTupleSatisfiesToast(ZHeapTuple ztup, Snapshot snapshot,
										   Buffer buffer, ItemPointer ctid);

extern ZHeapTuple ZHeapTupleSatisfies(ZHeapTuple stup, Snapshot snapshot, Buffer buffer, ItemPointer ctid);

#endif							/* ZTQUAL_H */
