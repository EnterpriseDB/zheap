/*-------------------------------------------------------------------------
 *
 * ztqual.c
 *	  POSTGRES "time qualification" code, ie, ztuple visibility rules.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/time/ztqual.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xact.h"
#include "access/zheap.h"
#include "storage/bufmgr.h"
#include "storage/procarray.h"
#include "utils/tqual.h"
#include "utils/ztqual.h"

/*
 * GetTupleFromUndo
 *
 *	Fetch the record from undo and determine if previous version of tuple
 *	is visible for the given snapshot.  If there exists a visible version
 *	of tuple in undo, then return the same, else return NULL.
 *
 *	During undo chain traversal, we need to ensure that we switch the undo
 *	chain if the current version of undo tuple is modified by a transaction
 *	that is different from transaction that has modified the previous version
 *	of undo tuple.  This is primarily done because undo chain for a particular
 *	tuple is formed based on the transaction id that has modified the tuple.
 *
 *	Also we don't need to process the chain if the latest xid that has changed
 *  the tuple precedes smallest xid that has undo.
 */
static ZHeapTuple
GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup, Snapshot snapshot,
				 Buffer buffer)
{
	UnpackedUndoRecord	*urec;
	ZHeapPageOpaque	opaque;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr = InvalidUndoRecPtr;
	TransactionId	xid;
	int	trans_slot_id = InvalidXactSlotId;
	int	prev_trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
	int	undo_oper = -1;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	/*
	 * deleted or updated after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self));

	undo_tup = CopyTupleFromUndoRecord(urec, zhtup, true);
	trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_xid;

	if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
	{
		undo_oper = ZHEAP_INPLACE_UPDATED;
	}
	else if (undo_tup->t_data->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		undo_oper = ZHEAP_XID_LOCK_ONLY;
	}
	else
	{
		/* we can't further operate on deleted tuple */
		Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
	}

	UndoRecordRelease(urec);

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdPrecedes(xid, RecentGlobalXmin))
		return undo_tup;

	if (undo_oper == ZHEAP_INPLACE_UPDATED ||
		undo_oper == ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * Change the undo chain if the undo tuple is stamped with the different
		 * transaction.
		 */
		if (trans_slot_id != prev_trans_slot_id)
			prev_urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(undo_tup->t_data, opaque);

		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (undo_oper == ZHEAP_XID_LOCK_ONLY)
				return undo_tup;
			if (ZHeapTupleGetCid(undo_tup, buffer) >= snapshot->curcid)
			{
				/* updated after scan started */
				return GetTupleFromUndo(prev_urec_ptr,
										undo_tup,
										snapshot,
										buffer);
			}
			else
				return undo_tup;	/* updated before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapPageGetRawXid(trans_slot_id, opaque), snapshot))
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return undo_tup;
		else
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer);
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapTupleGetCid(undo_tup, buffer) >= snapshot->curcid)
				return NULL;	/* inserted after scan started */
			else
				return undo_tup;	/* inserted before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapPageGetRawXid(trans_slot_id, opaque), snapshot))
			return NULL;
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return undo_tup;
		else
			return NULL;
	}
}

/*
 * UndoTupleSatisfiesUpdate
 *
 *	Returns true, if there exists a visible version of zhtup in undo,
 *	false otherwise.
 *
 *	This function returns ctid for the undo tuple which will be always
 *	same as the ctid of zhtup except for non-in-place update case.
 *
 *	The Undo chain traversal follows similar protocol as mentioned atop
 *	GetTupleFromUndo.
 */
static bool
UndoTupleSatisfiesUpdate(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
						 CommandId curcid, Buffer buffer,
						 ItemPointer ctid, bool free_zhtup,
						 bool *in_place_updated_or_locked)
{
	UnpackedUndoRecord	*urec;
	ZHeapPageOpaque	opaque;
	ZHeapTuple	undo_tup = NULL;
	UndoRecPtr	prev_urec_ptr = InvalidUndoRecPtr;
	TransactionId	xid;
	int	trans_slot_id = InvalidXactSlotId;
	int prev_trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
	int	undo_oper = -1;
	bool result = false;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	/*
	 * deleted or updated after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self));

	undo_tup = CopyTupleFromUndoRecord(urec, zhtup, free_zhtup);
	trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_xid;
	*ctid = undo_tup->t_self;

	if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
	{
		undo_oper = ZHEAP_INPLACE_UPDATED;
		*in_place_updated_or_locked = true;
	}
	else if (undo_tup->t_data->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		undo_oper = ZHEAP_XID_LOCK_ONLY;
		*in_place_updated_or_locked = true;
	}
	else
	{
		/* we can't further operate on deleted tuple */
		Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
	}

	UndoRecordRelease(urec);

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdPrecedes(xid, RecentGlobalXmin))
	{
		result = true;
		goto result_available;
	}

	if (undo_oper == ZHEAP_INPLACE_UPDATED ||
		undo_oper == ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * Change the undo chain if the undo tuple is stamped with the different
		 * transaction.
		 */
		if (trans_slot_id != prev_trans_slot_id)
			prev_urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(undo_tup->t_data, opaque);

		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (undo_oper == ZHEAP_XID_LOCK_ONLY)
			{
				result = true;
				goto result_available;
			}
			if (ZHeapTupleGetCid(undo_tup, buffer) >= curcid)
			{
				/* updated after scan started */
				return UndoTupleSatisfiesUpdate(prev_urec_ptr,
												undo_tup,
												curcid,
												buffer,
												ctid,
												true,
												in_place_updated_or_locked);
			}
			else
				result = true;	/* updated before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return UndoTupleSatisfiesUpdate(prev_urec_ptr,
											undo_tup,
											curcid,
											buffer,
											ctid,
											true,
											in_place_updated_or_locked);
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = true;
		else
			return UndoTupleSatisfiesUpdate(prev_urec_ptr,
											undo_tup,
											curcid,
											buffer,
											ctid,
											true,
											in_place_updated_or_locked);
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapTupleGetCid(undo_tup, buffer) >= curcid)
				result = false;	/* inserted after scan started */
			else
				result = true;	/* inserted before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = false;
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = true;
		else
			result = false;
	}

result_available:
	if (undo_tup)
		pfree(undo_tup);
	return result;
}

/*
 * ZHeapTupleSatisfiesMVCC
 *
 *	Returns the visible version of tuple if any, NULL otherwise. We need to
 *	traverse undo record chains to determine the visibility of tuple.  In
 *	this function we need to first the determine the visibility of modified
 *	tuple and if it is not visible, then we need to fetch the prior version
 *	of tuple from undo chain and decide based on its visibility.  The undo
 *	chain needs to be traversed till we reach root version of the tuple.
 *
 *	Here, we consider the effects of:
 *		all transactions committed as of the time of the given snapshot
 *		previous commands of this transaction
 *
 *	Does _not_ include:
 *		transactions shown as in-progress by the snapshot
 *		transactions started after the snapshot was taken
 *		changes made by the current command
 *
 *	The tuple will be considered visible iff latest operation on tuple is
 *	Insert, In-Place update or tuple is locked and the transaction that has
 *	performed operation is current transaction (and the operation is performed
 *	by some previous command) or is committed.
 *
 *	We traverse the undo chain to get the visible tuple if any, in case the
 *	the latest transaction that has operated on tuple is shown as in-progress
 *	by the snapshot or is started after the snapshot was taken or is current
 *	transaction and the changes are made by current command.
 */
ZHeapTuple
ZHeapTupleSatisfiesMVCC(ZHeapTuple zhtup, Snapshot snapshot,
						Buffer buffer)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return NULL;

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleGetCid(zhtup, buffer) >= snapshot->curcid)
			{
				/* deleted after scan started, get previous tuple from undo */
				return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
										zhtup,
										snapshot,
										buffer);
			}
			else
				return NULL;	/* deleted before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return NULL;	/* tuple is deleted */
		else	/* transaction is aborted */
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * The tuple is updated/locked and must be all visible if the
		 * transaction slot is cleared or latest xid that has changed the
		 * tuple precedes smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return zhtup;	/* tuple is updated */

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
				return zhtup;
			if (ZHeapTupleGetCid(zhtup, buffer) >= snapshot->curcid)
			{
				/* updated after scan started, get previous tuple from undo */
				return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
										zhtup,
										snapshot,
										buffer);
			}
			else
				return zhtup;	/* updated before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return zhtup;	/* tuple is updated */
		else	/* transaction is aborted */
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
	}

	/*
	 * The tuple must be all visible if the transaction slot
	 * is cleared or latest xid that has changed the tuple precedes
	 * smallest xid that has undo.
	 */
	if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
		TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
							  RecentGlobalXmin))
		return zhtup;

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		if (ZHeapTupleGetCid(zhtup, buffer) >= snapshot->curcid)
			return NULL;	/* inserted after scan started */
		else
			return zhtup;	/* inserted before scan started */
	}
	else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
		return NULL;
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return zhtup;
	else
		return NULL;

	return NULL;
}

/*
 * ZHeapTupleSatisfiesUpdate
 *
 *	The retrun values for this API are same as HeapTupleSatisfiesUpdate.
 *	However, there is a notable difference in the way to determine visibility
 *	of tuples.  We need to traverse undo record chains to determine the
 *	visibility of tuple.
 *
 *	ctid - returns the ctid of visible tuple if the tuple is either deleted or
 *	updated.  ctid needs to be retrieved from undo tuple.
 *	lock_allowed - allow caller to lock the tuple if it is in-place updated
 *	in_place_updated - returns whether the current visible version of tuple is
 *	updated in place.
 */
HTSU_Result
ZHeapTupleSatisfiesUpdate(ZHeapTuple zhtup, CommandId curcid,
						  Buffer buffer, ItemPointer ctid, bool free_zhtup,
						  bool lock_allowed, bool *in_place_updated_or_locked)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;
	bool	visible;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));
	*in_place_updated_or_locked = false;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return HeapTupleUpdated;

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleGetCid(zhtup, buffer) >= curcid)
			{
				/* deleted after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   free_zhtup,
												   in_place_updated_or_locked);
				if (visible)
					return HeapTupleSelfUpdated;
				else
					return HeapTupleInvisible;
			}
			else
				return HeapTupleInvisible;	/* deleted before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
				return HeapTupleBeingUpdated;
			else
				return HeapTupleInvisible;
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return HeapTupleUpdated;	/* tuple is deleted */
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - For aborted transactions, we should either wait for undo
			 * to be applied or apply undo by ourselves before modifying the
			 * the tuple.
			 */
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleInvisible;
		}
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		*in_place_updated_or_locked = true;

		/*
		 * The tuple is updated/locked and must be all visible if the
		 * transaction slot is cleared or latest xid that has touched the
		 * tuple precedes smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return HeapTupleMayBeUpdated;

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
				return HeapTupleBeingUpdated;

			if (ZHeapTupleGetCid(zhtup, buffer) >= curcid)
			{
				/* updated after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   free_zhtup,
												   in_place_updated_or_locked);
				if (visible)
					return HeapTupleSelfUpdated;
				else
					return HeapTupleInvisible;
			}
			else
				return HeapTupleMayBeUpdated;	/* updated before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
				return HeapTupleBeingUpdated;
			else
				return HeapTupleInvisible;
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			/* tuple is updated */
			if (lock_allowed)
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleUpdated;
		}
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - For aborted transactions, we should either wait for undo
			 * to be applied or apply undo by ourselves before modifying the
			 * the tuple.
			 */
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleInvisible;
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot
	 * is cleared or latest xid that has changed the tuple precedes
	 * smallest xid that has undo.
	 */
	if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
		TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
							  RecentGlobalXmin))
		return HeapTupleMayBeUpdated;

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		if (ZHeapTupleGetCid(zhtup, buffer) >= curcid)
			return HeapTupleInvisible;	/* inserted after scan started */
		else
			return HeapTupleMayBeUpdated;	/* inserted before scan started */
	}
	else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return HeapTupleInvisible;
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return HeapTupleMayBeUpdated;
	else
		return HeapTupleInvisible;

	return HeapTupleInvisible;
}

/*
 * ZHeapTupleIsSurelyDead
 *
 * Similar to HeapTupleIsSurelyDead, but for zheap tuples.
 */
bool
ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, TransactionId OldestXmin, Buffer buffer)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return true;
	}

	return false; /* Tuple is still alive */
}

/*
 * ZHeapTupleSatisfiesDirty
 *		Returns the visible version of tuple (including effects of open
 *		transactions) if any, NULL otherwise.
 *
 *	Here, we consider the effects of:
 *		all committed and in-progress transactions (as of the current instant)
 *		previous commands of this transaction
 *		changes made by the current command
 *
 *	The tuple will be considered visible iff:
 *	(a) Latest operation on tuple is Delete and the current transaction is in
 *		progress.
 *	(b) Latest operation on tuple is Insert, In-Place update or tuple is
 *		locked and the transaction that has performed operation is current
 *		transaction or is in-progress or is committed.
 */
ZHeapTuple
ZHeapTupleSatisfiesDirty(ZHeapTuple zhtup, Snapshot snapshot,
						 Buffer buffer)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	snapshot->xmin = snapshot->xmax = InvalidTransactionId;

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return NULL;

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return NULL;
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			snapshot->xmax = ZHeapTupleHeaderGetRawXid(tuple, opaque);
			return zhtup;		/* in deletion by other */
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return NULL;	/* tuple is deleted */
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - Here we need to fetch the tuple from undo, something similar
			 * to GetTupleFromUndo but for DirtySnapshots.
			 */
			Assert(false);
			return NULL;
		}
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * The tuple is updated/locked and must be all visible if the
		 * transaction slot is cleared or latest xid that has changed the
		 * tuple precedes smallest xid that has undo.
		 */
		if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
			TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
								  RecentGlobalXmin))
			return zhtup;	/* tuple is updated */

		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return zhtup;
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (!ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
				snapshot->xmax = ZHeapTupleHeaderGetRawXid(tuple, opaque);
			return zhtup;		/* being updated */
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return zhtup;	/* tuple is updated by someone else */
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - Here we need to fetch the tuple from undo, something similar
			 * to GetTupleFromUndo but for DirtySnapshots.
			 */
			Assert(false);
			return NULL;
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (ZHeapTupleHeaderGetXactSlot(tuple) == ZHTUP_SLOT_FROZEN ||
		TransactionIdPrecedes(ZHeapTupleHeaderGetRawXid(tuple, opaque),
							  RecentGlobalXmin))
		return zhtup;

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return zhtup;
	else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		snapshot->xmin = ZHeapTupleHeaderGetRawXid(tuple, opaque);
		return zhtup;		/* in insertion by other */
	}
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return zhtup;
	else
	{
		/*
		 * Fixme - Here we need to fetch the tuple from undo, something similar
		 * to GetTupleFromUndo but for DirtySnapshots.
		 */
		Assert(false);
		return NULL;
	}

	return NULL;
}
