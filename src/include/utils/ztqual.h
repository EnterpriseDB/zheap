/*-------------------------------------------------------------------------
 *
 * ztqual.h
 *	  POSTGRES "time qualification" definitions, ie, ztuple visibility rules.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/ztqual.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZTQUAL_H
#define ZTQUAL_H

#include "access/xlogdefs.h"
#include "access/zheap.h"

typedef struct ZHeapTupleTransInfo
{
	int trans_slot;
	uint64 epoch_xid;
	TransactionId xid;
	CommandId cid;
	UndoRecPtr urec_ptr;
} ZHeapTupleTransInfo;

/* Result codes for ZHeapTupleSatisfiesVacuum */
typedef enum
{
	ZHEAPTUPLE_DEAD,			/* tuple is dead and deletable */
	ZHEAPTUPLE_LIVE,			/* tuple is live (committed, no deleter) */
	ZHEAPTUPLE_RECENTLY_DEAD,	/* tuple is dead, but not deletable yet */
	ZHEAPTUPLE_INSERT_IN_PROGRESS,	/* inserting xact is still in progress */
	ZHEAPTUPLE_DELETE_IN_PROGRESS,	/* deleting xact is still in progress */
	ZHEAPTUPLE_ABORT_IN_PROGRESS	/* rollback is still pending */
} ZHTSV_Result;

extern void FetchTransInfoFromUndo(BlockNumber blocknum, OffsetNumber offnum,
					   TransactionId xid, ZHeapTupleTransInfo *zinfo);
extern void ZHeapUpdateTransactionSlotInfo(int trans_slot, Buffer buffer,
							   OffsetNumber offnum,
							   ZHeapTupleTransInfo *zinfo);
extern void ZHeapTupleGetTransInfo(ZHeapTuple zhtup, Buffer buf,
					   bool fetch_cid, ZHeapTupleTransInfo *zinfo);
extern TransactionId ZHeapTupleGetTransXID(ZHeapTuple zhtup, Buffer buf,
					  bool nobuflock);

/* Fetch CTID information stored in undo */
extern void ZHeapPageGetNewCtid(Buffer buffer, ItemPointer ctid,
					TransactionId *xid, CommandId *cid);

/* These are the "satisfies" test routines for the zheap. */
extern ZHeapTuple ZHeapGetVisibleTuple(OffsetNumber off, Snapshot snapshot,
									   Buffer buffer, bool *all_dead);
extern TM_Result ZHeapTupleSatisfiesUpdate(Relation rel, ZHeapTuple zhtup,
						  CommandId curcid, Buffer buffer, ItemPointer ctid,
						  ZHeapTupleTransInfo *zinfo,
						  SubTransactionId *subxid,
						  TransactionId *single_locker_xid, int *single_locker_trans_slot,
						  bool lock_allowed, Snapshot snapshot,
						  bool *in_place_updated_or_locked);
extern bool ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, uint64 OldestXmin,
					   Buffer buffer);
extern ZHeapTuple ZHeapTupleSatisfiesAny(ZHeapTuple zhtup,
										 Snapshot snapshot, Buffer buffer, ItemPointer ctid);
extern ZHTSV_Result ZHeapTupleSatisfiesOldestXmin(ZHeapTuple * zhtup,
							  TransactionId OldestXmin, Buffer buffer,
							  TransactionId *xid, SubTransactionId *subxid);
extern ZHTSV_Result ZHeapTupleSatisfiesVacuum(ZHeapTuple zhtup, TransactionId OldestXmin,
											  Buffer buffer, TransactionId *xid);

extern ZHeapTuple ZHeapTupleSatisfies(ZHeapTuple stup, Snapshot snapshot, Buffer buffer, ItemPointer ctid);

extern bool ZHeapTupleHasSerializableConflictOut(bool visible, Relation relation,
									 ItemPointer tid, Buffer buffer,
									 TransactionId *xid);

#endif							/* ZTQUAL_H */
