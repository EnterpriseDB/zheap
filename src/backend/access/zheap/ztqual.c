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
 * The core idea to check if the tuple is all-visible is to see if it is
 * modified by transaction smaller than oldestXidWithEpochHavingUndo (aka
 * there is no undo pending for the transaction) or if the transaction slot
 * is frozen.  For undo tuples, we additionally check if the transaction id
 * of a transaction that has modified the tuple is FrozenTransactionId. The
 * idea is we will always check the visibility of latest tuple based on
 * epoch+xid and undo tuple's visibility based on xid.  If the heap tuple is
 * not all-visible (epoch+xid is not older than oldestXidWithEpochHavingUndo),
 * then the xid corresponding to undo tuple must be in the range of 2-billion
 * transactions with oldestXidHavingUndo (xid part in
 * oldestXidWithEpochHavingUndo).  This is true because we don't allow undo
 * records older than 2-billion transactions.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/xact.h"
#include "access/zheap.h"
#include "access/zheaputils.h"
#include "access/zmultilocker.h"
#include "storage/bufmgr.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "utils/ztqual.h"
#include "storage/proc.h"


static ZHeapTuple GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
				 Snapshot snapshot, Buffer buffer,
				 ItemPointer ctid, int trans_slot_id,
				 TransactionId prev_undo_xid);
static ZHeapTuple
GetTupleFromUndoForAbortedXact(UndoRecPtr urec_ptr, Buffer buffer, int trans_slot,
							   ZHeapTuple ztuple,TransactionId *xid);

/*
 * FetchTransInfoFromUndo - Retrieve transaction information of transaction
 *			that has modified the undo tuple.
 */
void
FetchTransInfoFromUndo(ZHeapTuple undo_tup, uint64 *epoch, TransactionId *xid,
					   CommandId *cid, UndoRecPtr *urec_ptr, bool skip_lockers)
{
	UnpackedUndoRecord	*urec;
	UndoRecPtr		urec_ptr_out = InvalidUndoRecPtr;
	TransactionId	undo_tup_xid;

fetch_prior_undo:
	undo_tup_xid = *xid;

	/*
	 * The transaction slot referred by the undo tuple could have been reused
	 * multiple times, so to ensure that we have fetched the right undo record
	 * we need to verify that the undo record contains xid same as the xid
	 * that has modified the tuple.
	 */
	urec = UndoFetchRecord(*urec_ptr,
						   ItemPointerGetBlockNumber(&undo_tup->t_self),
						   ItemPointerGetOffsetNumber(&undo_tup->t_self),
						   undo_tup_xid,
						   &urec_ptr_out,
						   ZHeapSatisfyUndoRecord);

	/*
	 * The undo tuple must be visible, if the undo record containing
	 * the information of the last transaction that has updated the
	 * tuple is discarded.
	 */
	if (urec == NULL)
	{
		if (epoch)
			*epoch = 0;
		if (xid)
			*xid = InvalidTransactionId;
		if (cid)
			*cid = InvalidCommandId;
		if (urec_ptr)
			*urec_ptr = InvalidUndoRecPtr;
		return;
	}

	/*
	 * If we reach here, this means the transaction id that has
	 * last modified this tuple must be in 2-billion xid range
	 * of oldestXidHavingUndo, so we can get compute its epoch
	 * as we do for current transaction.
	 */
	if (epoch)
		*epoch = GetEpochForXid(urec->uur_xid);
	*xid = urec->uur_xid;
	*cid = urec->uur_cid;
	*urec_ptr = urec_ptr_out;

	if (skip_lockers &&
		(urec->uur_type == UNDO_XID_LOCK_ONLY ||
		 urec->uur_type == UNDO_XID_LOCK_FOR_UPDATE ||
		 urec->uur_type == UNDO_XID_MULTI_LOCK_ONLY))
	{
		*xid = InvalidTransactionId;
		*urec_ptr = urec->uur_blkprev;
		UndoRecordRelease(urec);
		goto fetch_prior_undo;
	}

	UndoRecordRelease(urec);
}

/*
 * ZHeapPageGetNewCtid
 *
 * 	This should be called for ctid which is already set deleted to get the new
 * 	ctid, xid and cid which modified the given one.
 */
void
ZHeapPageGetNewCtid(Buffer buffer, ItemPointer ctid, TransactionId *xid,
					CommandId *cid)
{
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	int		trans_slot;
	int		vis_info;
	uint64		epoch;
	ItemId	lp;
	Page	page;
	OffsetNumber	offnum = ItemPointerGetOffsetNumber(ctid);
	int		out_slot_no PG_USED_FOR_ASSERTS_ONLY;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, offnum);

	Assert(ItemIdIsDeleted(lp));

	trans_slot = ItemIdGetTransactionSlot(lp);
	vis_info = ItemIdGetVisibilityInfo(lp);

	if (vis_info & ITEMID_XACT_INVALID)
	{
		ZHeapTupleData	undo_tup;
		ItemPointerSetBlockNumber(&undo_tup.t_self,
								  BufferGetBlockNumber(buffer));
		ItemPointerSetOffsetNumber(&undo_tup.t_self, offnum);

		/*
		 * We need undo record pointer to fetch the transaction information
		 * from undo.
		 */
		out_slot_no = GetTransactionSlotInfo(buffer, offnum, trans_slot,
											 (uint32 *) &epoch, xid, &urec_ptr,
											 true, false);
		*xid = InvalidTransactionId;
		FetchTransInfoFromUndo(&undo_tup, &epoch, xid, cid, &urec_ptr, false);
	}
	else
	{
		out_slot_no = GetTransactionSlotInfo(buffer, offnum, trans_slot,
											 (uint32 *) &epoch, xid, &urec_ptr,
											 true, false);
		*cid = ZHeapPageGetCid(buffer, trans_slot, (uint32) epoch, *xid,
							   urec_ptr, offnum);
	}

	/*
	 * We always expect non-frozen transaction slot here as the caller tries
	 * to fetch the ctid of tuples that are visible to the snapshot, so
	 * corresponding undo record can't be discarded.
	 */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

	ZHeapPageGetCtid(trans_slot, buffer, urec_ptr, ctid);
}

/*
 * GetVisibleTupleIfAny
 *
 * This is a helper function for GetTupleFromUndoWithOffset.
 */
static ZHeapTuple
GetVisibleTupleIfAny(UndoRecPtr prev_urec_ptr, ZHeapTuple undo_tup,
					 Snapshot snapshot, Buffer buffer, TransactionId xid,
					 int trans_slot_id, CommandId cid)
{
	int			undo_oper = -1;
	TransactionId	oldestXidHavingUndo;

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
		/* we can't further operate on deleted or non-inplace-updated tuple */
		Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED) ||
			   !(undo_tup->t_data->t_infomask & ZHEAP_UPDATED));
	}

	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if ((trans_slot_id != ZHTUP_SLOT_FROZEN) &&
		!TransactionIdEquals(xid, FrozenTransactionId) &&
		!TransactionIdPrecedes(xid, oldestXidHavingUndo))
	{
		if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
		{
			FetchTransInfoFromUndo(undo_tup, NULL, &xid, &cid, &prev_urec_ptr, false);
		}
		/*
		 * If we already have a valid cid then don't fetch it from the undo.
		 * This is the case when old locker got transferred to the newly
		 * inserted tuple of the non-in place update.  In such case undo chain
		 * will not have a separate undo-record for the locker so we have to
		 * use the cid we have got from the insert undo record because in this
		 * case the actual previous version of the locker is insert only and
		 * that is what we are interested in.
		 */
		/* 
		 * If we already have a valid cid then don't fetch it from the undo.
		 * For detailed comment refer GetVisibleTupleIfAny.
		 */
		/* 
		 * If we already have a valid cid then don't fetch it from the undo.
		 * For detailed comment refer GetVisibleTupleIfAny.
		 */		
		else if (cid == InvalidCommandId)
		{
			/*
 			 * we don't use prev_undo_xid to fetch the undo record for cid as it is
 			 * required only when transaction is current transaction in which case
 			 * there is no risk of transaction chain switching, so we are safe.  It
 			 * might be better to move this check near to it's usage, but that will
 			 * make code look ugly, so keeping it here.
 			 */
			cid = ZHeapTupleGetCid(undo_tup, buffer, prev_urec_ptr, trans_slot_id);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
		return undo_tup;

	if (undo_oper == ZHEAP_INPLACE_UPDATED ||
		undo_oper == ZHEAP_XID_LOCK_ONLY)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (IsMVCCSnapshot(snapshot) && cid >= snapshot->curcid)
			{
				/* updated/locked after scan started */
				return GetTupleFromUndo(prev_urec_ptr,
										undo_tup,
										snapshot,
										buffer,
										NULL,
										trans_slot_id,
										xid);
			}
			else
				return undo_tup;	/* updated before scan started */
		}
		else if (IsMVCCSnapshot(snapshot) && XidInMVCCSnapshot(xid, snapshot))
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer,
									NULL,
									trans_slot_id,
									xid);
		else if (!IsMVCCSnapshot(snapshot) && TransactionIdIsInProgress(xid))
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer,
									NULL,
									trans_slot_id,
									xid);
		else if (TransactionIdDidCommit(xid))
			return undo_tup;
		else
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer,
									NULL,
									trans_slot_id,
									xid);
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (IsMVCCSnapshot(snapshot) && cid >= snapshot->curcid)
				return NULL;	/* inserted after scan started */
			else
				return undo_tup;	/* inserted before scan started */
		}
		else if (IsMVCCSnapshot(snapshot) && XidInMVCCSnapshot(xid, snapshot))
			return NULL;
		else if (!IsMVCCSnapshot(snapshot) && TransactionIdIsInProgress(xid))
			return NULL;
		else if (TransactionIdDidCommit(xid))
			return undo_tup;
		else
			return NULL;
	}
}

/*
 * GetTupleFromUndoForAbortedXact
 *
 *	This is used to fetch the prior committed version of the tuple which is
 *	modified by an aborted xact.
 *
 *	It returns the prior committed version of the tuple, if available. Else,
 *	returns NULL.
 *
 *	The caller must send a palloc'ed tuple. This function can get a tuple
 *	from undo to return in which case it will free the memory passed by
 *	the caller.
 *
 *	xid is an output parameter. It is set to the latest committed xid that
 *	inserted/in-place-updated the tuple. If the aborted transaction inserted
 *	the tuple itself, we return the same transaction id. The caller *should*
 *	handle the same scenario.
 */
static ZHeapTuple
GetTupleFromUndoForAbortedXact(UndoRecPtr urec_ptr, Buffer buffer, int trans_slot,
							   ZHeapTuple ztuple,TransactionId *xid)
{
	ZHeapTuple  undo_tup = ztuple;
	UnpackedUndoRecord	*urec;
	UndoRecPtr  prev_urec_ptr;
	TransactionId	prev_undo_xid PG_USED_FOR_ASSERTS_ONLY;
	TransactionId	oldestXidHavingUndo = InvalidTransactionId;
	int				trans_slot_id;
	int				prev_trans_slot_id = trans_slot;

	prev_undo_xid = InvalidTransactionId;
fetch_prior_undo_record:
	prev_urec_ptr = InvalidUndoRecPtr;
	trans_slot_id = InvalidXactSlotId;

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&undo_tup->t_self),
						   ItemPointerGetOffsetNumber(&undo_tup->t_self),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/* If undo is discarded, then current tuple is visible. */
	if (urec == NULL)
		return undo_tup;

	/* Here, we free the previous version and palloc a new tuple from undo. */
	undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id, NULL,
									   true, BufferGetPage(buffer));

	prev_urec_ptr = urec->uur_blkprev;
	*xid = urec->uur_prevxid;

	UndoRecordRelease(urec);

	/* we can't further operate on deleted or non-inplace-updated tuple */
	Assert(!((undo_tup->t_data->t_infomask & ZHEAP_DELETED) ||
		   (undo_tup->t_data->t_infomask & ZHEAP_UPDATED)));

	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(*xid, FrozenTransactionId) ||
		TransactionIdPrecedes(*xid, oldestXidHavingUndo))
	{
		return undo_tup;
	}

	/*
	 * If we got a tuple modified by a committed transaction, return it.
	 */
	if (TransactionIdDidCommit(*xid))
		return undo_tup;

	/*
	 * If the tuple points to a slot that gets invalidated for reuse at some
	 * point of time, then undo_tup is the latest committed version of the tuple.
	 */
	if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
		return undo_tup;

	/*
	 * If the undo tuple is stamped with a different transaction, then either
	 * the previous transaction is committed or tuple must be locked only. In both
	 * cases, we can return the tuple fetched from undo.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		(void) GetTransactionSlotInfo(buffer,
									  ItemPointerGetOffsetNumber(&undo_tup->t_self),
									  trans_slot_id,
									  NULL,
									  NULL,
									  &prev_urec_ptr,
									  true,
									  true);
		FetchTransInfoFromUndo(undo_tup, NULL, xid, NULL, &prev_urec_ptr, false);

		Assert(TransactionIdDidCommit(*xid) ||
			   ZHEAP_XID_IS_LOCKED_ONLY(undo_tup->t_data->t_infomask));

		return undo_tup;
	}

	/* transaction must be aborted. */
	Assert(!TransactionIdIsCurrentTransactionId(*xid));
	Assert(!TransactionIdIsInProgress(*xid));
	Assert(TransactionIdDidAbort(*xid));
	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(*xid, FrozenTransactionId) ||
		TransactionIdPrecedes(*xid, oldestXidHavingUndo))
	{
		return undo_tup;
	}

	/*
	 * We can't have two aborted transaction with pending rollback state for
	 * the same tuple.
	 */
	Assert(!TransactionIdIsValid(prev_undo_xid) ||
		   TransactionIdEquals(prev_undo_xid, *xid));

	/*
	 * If undo tuple is the root tuple inserted by the aborted transaction,
	 * we don't have to process any further. The tuple is not visible to us.
	 */
	if (!IsZHeapTupleModified(undo_tup->t_data->t_infomask))
	{
		/* before leaving, free the allocated memory */
		pfree(undo_tup);
		return NULL;
	}

	urec_ptr = prev_urec_ptr;
	prev_undo_xid = *xid;
	prev_trans_slot_id = trans_slot_id;

	goto fetch_prior_undo_record;

	/* not reachable */
	Assert(0);
	return NULL;
}

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
GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
				 Snapshot snapshot, Buffer buffer,
				 ItemPointer ctid, int trans_slot,
				 TransactionId prev_undo_xid)
{
	UnpackedUndoRecord	*urec;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr;
	TransactionId	xid;
	CommandId	cid;
	int			undo_oper;
	TransactionId	oldestXidHavingUndo;
	int	trans_slot_id;
	int	prev_trans_slot_id = trans_slot;


	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
fetch_prior_undo_record:
	prev_urec_ptr = InvalidUndoRecPtr;
	cid = InvalidCommandId;
	undo_oper = -1;
	trans_slot_id = InvalidXactSlotId;

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   prev_undo_xid,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/* If undo is discarded, then current tuple is visible. */
	if (urec == NULL)
		return zhtup;

	undo_tup = CopyTupleFromUndoRecord(urec, zhtup, &trans_slot_id, &cid, true,
									   BufferGetPage(buffer));
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_prevxid;

	/*
	 * For non-inplace-updates, ctid needs to be retrieved from undo
	 * record if required.
	 */
	if (ctid)
	{
		if (urec->uur_type == UNDO_UPDATE)
			*ctid = *((ItemPointer) urec->uur_payload.data);
		else
			*ctid = undo_tup->t_self;
	}

	UndoRecordRelease(urec);

	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
		return undo_tup;

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		/*
		 * It is quite possible that the tuple is showing some valid
		 * transaction slot, but actual slot has been frozen.  This can happen
		 * when the slot belongs to TPD entry and the corresponding TPD entry
		 * is pruned.
		 */
		trans_slot_id = GetTransactionSlotInfo(buffer,
											   ItemPointerGetOffsetNumber(&undo_tup->t_self),
											   trans_slot_id,
											   NULL,
											   NULL,
											   &prev_urec_ptr,
											   true,
											   true);
	}

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
		/* we can't further operate on deleted or non-inplace-updated tuple */
		Assert(!((undo_tup->t_data->t_infomask & ZHEAP_DELETED) ||
			   (undo_tup->t_data->t_infomask & ZHEAP_UPDATED)));
	}

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
	{
		FetchTransInfoFromUndo(undo_tup, NULL, &xid, &cid, &prev_urec_ptr, false);
	}
	else if (cid == InvalidCommandId)
	{
		CommandId		cur_cid = GetCurrentCommandId(false);

		/*
		 * If the current command doesn't need to modify any tuple and the
		 * snapshot used is not of any previous command, then it can see all the
		 * modifications made by current transactions till now.  So, we don't even
		 * attempt to fetch CID from undo in such cases.
		 */
		if (!GetCurrentCommandIdUsed() && cur_cid == snapshot->curcid)
		{
			cid = InvalidCommandId;
		}
		else
		{
			/*
			 * we don't use prev_undo_xid to fetch the undo record for cid as it is
			 * required only when transaction is current transaction in which case
			 * there is no risk of transaction chain switching, so we are safe.  It
			 * might be better to move this check near to it's usage, but that will
			 * make code look ugly, so keeping it here.
			 */
			cid = ZHeapTupleGetCid(undo_tup, buffer, prev_urec_ptr, trans_slot_id);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
		return undo_tup;

	if (undo_oper == ZHEAP_INPLACE_UPDATED ||
		undo_oper == ZHEAP_XID_LOCK_ONLY)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (IsMVCCSnapshot(snapshot) && cid >= snapshot->curcid)
			{
				/*
				 * Updated after scan started, need to fetch prior tuple
				 * in undo chain.
				 */
				urec_ptr = prev_urec_ptr;
				zhtup = undo_tup;
				prev_undo_xid = xid;
				prev_trans_slot_id = trans_slot_id;

				goto fetch_prior_undo_record;
			}
			else
				return undo_tup;	/* updated before scan started */
		}
		else if (IsMVCCSnapshot(snapshot) && XidInMVCCSnapshot(xid, snapshot))
		{
			urec_ptr = prev_urec_ptr;
			zhtup = undo_tup;
			prev_undo_xid = xid;
			prev_trans_slot_id = trans_slot_id;

			goto fetch_prior_undo_record;
		}
		else if (!IsMVCCSnapshot(snapshot) && TransactionIdIsInProgress(xid))
		{
			urec_ptr = prev_urec_ptr;
			zhtup = undo_tup;
			prev_undo_xid = xid;
			prev_trans_slot_id = trans_slot_id;

			goto fetch_prior_undo_record;
		}
		else if (TransactionIdDidCommit(xid))
			return undo_tup;
		else
		{
			urec_ptr = prev_urec_ptr;
			zhtup = undo_tup;
			prev_undo_xid = xid;
			prev_trans_slot_id = trans_slot_id;

			goto fetch_prior_undo_record;
		}
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (IsMVCCSnapshot(snapshot) && cid >= snapshot->curcid)
				return NULL;	/* inserted after scan started */
			else
				return undo_tup;	/* inserted before scan started */
		}
		else if (IsMVCCSnapshot(snapshot) && XidInMVCCSnapshot(xid, snapshot))
			return NULL;
		else if (!IsMVCCSnapshot(snapshot) && TransactionIdIsInProgress(xid))
			return NULL;
		else if (TransactionIdDidCommit(xid))
			return undo_tup;
		else
			return NULL;
	}

	/* we should never reach here */
	return NULL;
}

/*
 * GetTupleFromUndoWithOffset
 *
 *	This is similar to GetTupleFromUndo with a difference that it takes
 *	line offset as an input.  This is a special purpose function that
 *	is written to fetch visible version of deleted tuple that has been
 *	pruned to a deleted line pointer.
 */
static ZHeapTuple
GetTupleFromUndoWithOffset(UndoRecPtr urec_ptr, Snapshot snapshot,
						   Buffer buffer, OffsetNumber off, int trans_slot)
{
	UnpackedUndoRecord	*urec;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr = InvalidUndoRecPtr;
	TransactionId	xid, oldestXidHavingUndo;
	CommandId	cid = InvalidCommandId;
	int	trans_slot_id = InvalidXactSlotId;
	int	prev_trans_slot_id = trans_slot;


	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
	urec = UndoFetchRecord(urec_ptr,
						   BufferGetBlockNumber(buffer),
						   off,
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/* need to ensure that undo record contains complete tuple */
	Assert(urec->uur_type == UNDO_DELETE || urec->uur_type == UNDO_UPDATE);
	undo_tup = CopyTupleFromUndoRecord(urec, NULL, &trans_slot_id, &cid, false,
									   BufferGetPage(buffer));
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_prevxid;

	UndoRecordRelease(urec);

	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
			return undo_tup;

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		trans_slot_id = GetTransactionSlotInfo(buffer,
											   ItemPointerGetOffsetNumber(&undo_tup->t_self),
											   trans_slot_id,
											   NULL,
											   NULL,
											   &prev_urec_ptr,
											   true,
											   true);
	}

	return GetVisibleTupleIfAny(prev_urec_ptr, undo_tup,
								snapshot, buffer, xid, trans_slot_id, cid);
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
						 ItemPointer ctid, int trans_slot,
						 TransactionId  prev_undo_xid, bool free_zhtup,
						 bool *in_place_updated_or_locked)
{
	UnpackedUndoRecord	*urec;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr;
	TransactionId	xid, oldestXidHavingUndo;
	CommandId	cid;
	int	trans_slot_id;
	int prev_trans_slot_id = trans_slot;
	int	undo_oper;
	bool result;

	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
fetch_prior_undo_record:
	undo_tup = NULL;
	prev_urec_ptr = InvalidUndoRecPtr;
	cid = InvalidCommandId;
	trans_slot_id = InvalidXactSlotId;
	undo_oper = -1;
	result = false;

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   prev_undo_xid,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/* If undo is discarded, then current tuple is visible. */
	if (urec == NULL)
	{
		result = true;
		goto result_available;
	}

	undo_tup = CopyTupleFromUndoRecord(urec, zhtup, &trans_slot_id, &cid,
									   free_zhtup, BufferGetPage(buffer));
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_prevxid;
	/*
	 * For non-inplace-updates, ctid needs to be retrieved from undo
	 * record if required.
	 */
	if (ctid)
	{
		if (urec->uur_type == UNDO_UPDATE)
			*ctid = *((ItemPointer) urec->uur_payload.data);
		else
			*ctid = undo_tup->t_self;
	}

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
		/* we can't further operate on deleted or non-inplace-updated tuple */
		Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED) ||
			   !(undo_tup->t_data->t_infomask & ZHEAP_UPDATED));
	}

	UndoRecordRelease(urec);

	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
	{
		result = true;
		goto result_available;
	}

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction slot.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		/*
		 * It is quite possible that the tuple is showing some valid
		 * transaction slot, but actual slot has been frozen.  This can happen
		 * when the slot belongs to TPD entry and the corresponding TPD entry
		 * is pruned.
		 */
		trans_slot_id =  GetTransactionSlotInfo(buffer,
												ItemPointerGetOffsetNumber(&undo_tup->t_self),
												trans_slot_id,
												NULL,
												NULL,
												&prev_urec_ptr,
												true,
												true);
	}

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
	{
		FetchTransInfoFromUndo(undo_tup, NULL, &xid, &cid, &prev_urec_ptr, false);
	}
	else if (cid == InvalidCommandId)
	{
		CommandId		cur_comm_cid = GetCurrentCommandId(false);

		/*
		 * If the current command doesn't need to modify any tuple and the
		 * snapshot used is not of any previous command, then it can see all the
		 * modifications made by current transactions till now.  So, we don't even
		 * attempt to fetch CID from undo in such cases.
		 */
		if (!GetCurrentCommandIdUsed() && cur_comm_cid == curcid)
		{
			cid = InvalidCommandId;
		}
		else
		{
			/*
			 * we don't use prev_undo_xid to fetch the undo record for cid as it is
			 * required only when transaction is current transaction in which case
			 * there is no risk of transaction chain switching, so we are safe.  It
			 * might be better to move this check near to it's usage, but that will
			 * make code look ugly, so keeping it here.
			 */
			cid = ZHeapTupleGetCid(undo_tup, buffer, prev_urec_ptr, trans_slot_id);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(xid, FrozenTransactionId) ||
		TransactionIdPrecedes(xid, oldestXidHavingUndo))
	{
		result = true;
		goto result_available;
	}

	if (undo_oper == ZHEAP_INPLACE_UPDATED ||
		undo_oper == ZHEAP_XID_LOCK_ONLY)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= curcid)
			{
				/*
				 * Updated after scan started, need to fetch prior tuple
				 * in undo chain.
				 */
				urec_ptr = prev_urec_ptr;
				zhtup = undo_tup;
				prev_undo_xid = xid;
				prev_trans_slot_id = trans_slot_id;
				free_zhtup = true;

				goto fetch_prior_undo_record;
			}
			else
				result = true;	/* updated before scan started */
		}
		else if (TransactionIdIsInProgress(xid))
		{
			/* Note the values required to fetch prior tuple in undo chain. */
			urec_ptr = prev_urec_ptr;
			zhtup = undo_tup;
			prev_undo_xid = xid;
			prev_trans_slot_id = trans_slot_id;
			free_zhtup = true;

			goto fetch_prior_undo_record;
		}
		else if (TransactionIdDidCommit(xid))
			result = true;
		else
		{
			/* Note the values required to fetch prior tuple in undo chain. */
			urec_ptr = prev_urec_ptr;
			zhtup = undo_tup;
			prev_undo_xid = xid;
			prev_trans_slot_id = trans_slot_id;
			free_zhtup = true;

			goto fetch_prior_undo_record;
		}
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= curcid)
				result = false;	/* inserted after scan started */
			else
				result = true;	/* inserted before scan started */
		}
		else if (TransactionIdIsInProgress(xid))
			result = false;
		else if (TransactionIdDidCommit(xid))
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
 *
 *  For aborted transactions, we need to fetch the visible tuple from undo.
 *	Now, it is possible that actions corresponding to aborted transaction
 *	has been applied, but still xid is present in slot, however we should
 *	never get such an xid.
 *
 *	For multilockers, the strongest locker information is always present on
 *	the tuple.  So for updaters, we don't need anything special as the tuple
 *	visibility will be determined based on the transaction information present
 *	on tuple.  For the lockers only case, we need to determine if the original
 *	inserter is visible to snapshot.
 */
ZHeapTuple
ZHeapTupleSatisfiesMVCC(ZHeapTuple zhtup, Snapshot snapshot,
						Buffer buffer, ItemPointer ctid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	TransactionId	xid;
	CommandId		*cid;
	CommandId		cur_cid = GetCurrentCommandId(false);
	CommandId		tmp_cid;
	uint64		epoch_xid;
	int			trans_slot;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/*
	 * If the current command doesn't need to modify any tuple and the
	 * snapshot used is not of any previous command, then it can see all the
	 * modifications made by current transactions till now.  So, we don't even
	 * attempt to fetch CID from undo in such cases.
	 */
	if (!GetCurrentCommandIdUsed() && cur_cid == snapshot->curcid)
	{
		cid = NULL;
	}
	else
	{
		cid = &tmp_cid;
		*cid = InvalidCommandId;
	}

	/* Get transaction info */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot, &epoch_xid, &xid, cid,
						   &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.  Transaction slot can also be considered
		 * frozen if it belongs to previous epoch.
		 */
		if (trans_slot == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return NULL;

		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid && *cid >= snapshot->curcid)
			{
				/* deleted after scan started, get previous tuple from undo */
				return GetTupleFromUndo(urec_ptr,
										zhtup,
										snapshot,
										buffer,
										ctid,
										trans_slot,
										InvalidTransactionId);
			}
			else
			{
				/*
				 * For non-inplace-updates, ctid needs to be retrieved from
				 * undo record if required.  If the tuple is moved to another
				 * partition, then we don't need ctid.
				 */
				if (ctid &&
					tuple->t_infomask & ZHEAP_UPDATED &&
					!ZHeapTupleIsMoved(tuple->t_infomask))
					ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);

				return NULL;	/* deleted before scan started */
			}
		}
		else if (XidInMVCCSnapshot(xid, snapshot))
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot,
									InvalidTransactionId);
		else if (TransactionIdDidCommit(xid))
		{
			/*
			 * For non-inplace-updates, ctid needs to be retrieved from undo
			 * record if required.  If the tuple is moved to another
			 * partition, then we don't need ctid.
			 */
			if (ctid &&
				!ZHeapTupleIsMoved(tuple->t_infomask) &&
				tuple->t_infomask & ZHEAP_UPDATED)
				ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);

			return NULL;	/* tuple is deleted */
		}
		else	/* transaction is aborted */
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot,
									InvalidTransactionId);
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * The tuple is updated/locked and must be all visible if the
		 * transaction slot is cleared or latest xid that has changed the
		 * tuple precedes smallest xid that has undo.
		 */
		if (trans_slot == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return zhtup;	/* tuple is updated */

		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid && *cid >= snapshot->curcid)
			{
				/*
				 * updated/locked after scan started, get previous tuple from
				 * undo.
				 */
				return GetTupleFromUndo(urec_ptr,
										zhtup,
										snapshot,
										buffer,
										ctid,
										trans_slot,
										InvalidTransactionId);
			}
			else
				return zhtup;	/* updated before scan started */
		}
		else if (XidInMVCCSnapshot(xid, snapshot))
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot,
									InvalidTransactionId);
		else if (TransactionIdDidCommit(xid))
			return zhtup;	/* tuple is updated */
		else	/* transaction is aborted */
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot,
									InvalidTransactionId);
	}

	/*
	 * The tuple must be all visible if the transaction slot
	 * is cleared or latest xid that has changed the tuple precedes
	 * smallest xid that has undo.
	 */
	if (trans_slot == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return zhtup;

	if (TransactionIdIsCurrentTransactionId(xid))
	{
		if (cid && *cid >= snapshot->curcid)
			return NULL;	/* inserted after scan started */
		else
			return zhtup;	/* inserted before scan started */
	}
	else if (XidInMVCCSnapshot(xid, snapshot))
		return NULL;
	else if (TransactionIdDidCommit(xid))
		return zhtup;
	else
		return NULL;

	return NULL;
}

/*
 * ZHeapGetVisibleTuple
 *
 *	This function is called for tuple that is deleted but not all-visible. It
 *	returns NULL, if the last transaction that has modified the tuple is
 *	visible to snapshot or if none of the versions of tuple is visible,
 *	otherwise visible version tuple if any.
 *
 *	The caller must ensure that it passes the line offset for a tuple that is
 *	marked as deleted.
 */
ZHeapTuple
ZHeapGetVisibleTuple(OffsetNumber off, Snapshot snapshot, Buffer buffer, bool *all_dead)
{
	Page	page;
	UndoRecPtr	urec_ptr;
	TransactionId	xid;
	CommandId		cid;
	ItemId	lp;
	uint64		epoch, epoch_xid;
	uint32	tmp_epoch;
	int		trans_slot;
	int		vis_info;

	if (all_dead)
		*all_dead = false;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, off);
	Assert(ItemIdIsDeleted(lp));

	trans_slot = ItemIdGetTransactionSlot(lp);
	vis_info = ItemIdGetVisibilityInfo(lp);

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
check_trans_slot:
	if (trans_slot != ZHTUP_SLOT_FROZEN)
	{
		if (vis_info & ITEMID_XACT_INVALID)
		{
			ZHeapTupleData	undo_tup;
			ItemPointerSetBlockNumber(&undo_tup.t_self,
									  BufferGetBlockNumber(buffer));
			ItemPointerSetOffsetNumber(&undo_tup.t_self, off);

			/*
			 * We need undo record pointer to fetch the transaction information
			 * from undo.
			 */
			trans_slot = GetTransactionSlotInfo(buffer, off, trans_slot,
												&tmp_epoch, &xid, &urec_ptr,
												true, false);
			/*
			 * It is quite possible that the tuple is showing some valid
			 * transaction slot, but actual slot has been frozen.  This can happen
			 * when the slot belongs to TPD entry and the corresponding TPD entry
			 * is pruned.
			 */
			if (trans_slot == ZHTUP_SLOT_FROZEN)
				goto check_trans_slot;

			xid = InvalidTransactionId;
			FetchTransInfoFromUndo(&undo_tup, &epoch, &xid, &cid, &urec_ptr, false);
		}
		else
		{
			trans_slot = GetTransactionSlotInfo(buffer, off, trans_slot,
												&tmp_epoch, &xid, &urec_ptr,
												true, false);
			if (trans_slot == ZHTUP_SLOT_FROZEN)
				goto check_trans_slot;

			epoch = (uint64) tmp_epoch;
			cid = ZHeapPageGetCid(buffer, trans_slot, tmp_epoch, xid, urec_ptr, off);
		}
	}
	else
	{
		epoch = 0;
		xid = InvalidTransactionId;
		cid = InvalidCommandId;
		urec_ptr = InvalidUndoRecPtr;
	}

	epoch_xid = MakeEpochXid(epoch, xid);

	/*
	 * The tuple is deleted and must be all visible if the transaction slot
	 * is cleared or latest xid that has changed the tuple precedes
	 * smallest xid that has undo.  Transaction slot can also be considered
	 * frozen if it belongs to previous epoch.
	 */
	if (trans_slot == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		if (all_dead)
			*all_dead = true;
		return NULL;
	}

	if (TransactionIdIsCurrentTransactionId(xid))
	{
		if (cid >= snapshot->curcid)
		{
			/* deleted after scan started, get previous tuple from undo */
			return GetTupleFromUndoWithOffset(urec_ptr,
											  snapshot,
											  buffer,
											  off,
											  trans_slot);
		}
		else
			return NULL;	/* deleted before scan started */
	}
	else if (IsMVCCSnapshot(snapshot) && XidInMVCCSnapshot(xid, snapshot))
		return GetTupleFromUndoWithOffset(urec_ptr,
										  snapshot,
										  buffer,
										  off,
										  trans_slot);
	else if (!IsMVCCSnapshot(snapshot) && TransactionIdIsInProgress(xid))
		return GetTupleFromUndoWithOffset(urec_ptr,
										  snapshot,
										  buffer,
										  off,
										  trans_slot);
	else if (TransactionIdDidCommit(xid))
		return NULL;	/* tuple is deleted */
	else	/* transaction is aborted */
		return GetTupleFromUndoWithOffset(urec_ptr,
										  snapshot,
										  buffer,
										  off,
										  trans_slot);

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
 *	For multilockers, the visibility can be determined by the information
 *	present on tuple.  See ZHeapTupleSatisfiesMVCC.  Also, this API returns
 *	TM_Ok, if the strongest locker is committed which means
 *	the caller need to take care of waiting for other lockers in such a case.
 *
 *	ctid - returns the ctid of visible tuple if the tuple is either deleted or
 *	updated.  ctid needs to be retrieved from undo tuple.
 *	trans_slot - returns the transaction slot of the transaction that has
 *	modified the visible tuple.
 *	xid - returns the xid that has modified the visible tuple.
 *	subxid - returns the subtransaction id, if any, that has modified the
 *	visible tuple.  We fetch the subxid from undo only when it is required,
 *	i.e when the caller would wait on it to finish.
 *	cid - returns the cid of visible tuple.
 *	single_locker_xid - returns the xid of a single in-progress locker, if any.
 *	single_locker_trans_slot - returns the transaction slot of a single
 *	in-progress locker, if any.
 *	lock_allowed - allow caller to lock the tuple if it is in-place updated
 *	in_place_updated - returns whether the current visible version of tuple is
 *	updated in place.
 */
TM_Result
ZHeapTupleSatisfiesUpdate(Relation rel, ZHeapTuple zhtup, CommandId curcid,
						  Buffer buffer, ItemPointer ctid, int *trans_slot,
						  TransactionId *xid, SubTransactionId *subxid,
						  CommandId *cid, TransactionId *single_locker_xid,
						  int *single_locker_trans_slot, bool free_zhtup,
						  bool lock_allowed, Snapshot snapshot,
						  bool *in_place_updated_or_locked)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	uint64	epoch_xid;
	CommandId	cur_comm_cid = GetCurrentCommandId(false);
	bool	visible;

	*single_locker_xid = InvalidTransactionId;
	*single_locker_trans_slot = InvalidXactSlotId;
	*in_place_updated_or_locked = false;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/*
	 * If the current command doesn't need to modify any tuple and the
	 * snapshot used is not of any previous command, then it can see all the
	 * modifications made by current transactions till now.  So, we don't even
	 * attempt to fetch CID from undo in such cases.
	 */
	if (!GetCurrentCommandIdUsed() && cur_comm_cid == curcid)
	{
		cid = NULL;
	}

	/* Get transaction info */
	ZHeapTupleGetTransInfo(zhtup, buffer, trans_slot, &epoch_xid, xid, cid,
						   &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted or non-inplace-updated and must be all visible
		 * if the transaction slot is cleared or latest xid that has changed
		 * the tuple precedes smallest xid that has undo.  However, that is
		 * not possible at this stage as the tuple has already passed snapshot
		 * check.
		 */
		Assert(!(*trans_slot == ZHTUP_SLOT_FROZEN &&
			   epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)));

		if (TransactionIdIsCurrentTransactionId(*xid))
		{
			if (cid && *cid >= curcid)
			{
				/* deleted after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(urec_ptr,
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   *trans_slot,
												   InvalidTransactionId,
												   free_zhtup,
												   in_place_updated_or_locked);
				if (visible)
					return TM_SelfModified;
				else
					return TM_Invisible;
			}
			else
				return TM_Invisible;	/* deleted before scan started */
		}
		else if (TransactionIdIsInProgress(*xid))
		{
			visible = UndoTupleSatisfiesUpdate(urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   *trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
			{
				if (subxid)
					ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, subxid);

				return TM_BeingModified;
			}
			else
				return TM_Invisible;
		}
		else if (TransactionIdDidCommit(*xid))
		{
			/*
			 * For non-inplace-updates, ctid needs to be retrieved from undo
			 * record if required.  If the tuple is moved to another
			 * partition, then we don't need ctid.
			 */
			if (ctid &&
				!ZHeapTupleIsMoved(tuple->t_infomask) &&
				tuple->t_infomask & ZHEAP_UPDATED)
				ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);

			/* tuple is deleted or non-inplace-updated */
			return TM_Updated;
		}
		else	/* transaction is aborted */
		{
			visible = UndoTupleSatisfiesUpdate(urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   *trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the
			 * undo before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			if (visible)
				return TM_BeingModified;
			else
				return TM_Invisible;
		}
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		*in_place_updated_or_locked = true;

		/*
		 * The tuple is updated/locked and must be all visible if the
		 * transaction slot is cleared or latest xid that has touched the
		 * tuple precedes smallest xid that has undo.  If there is a single
		 * locker on the tuple, then we fetch the lockers transaction info
		 * from undo as we never store lockers slot on tuple.  See
		 * compute_new_xid_infomask for more details about lockers.
		 */
		if (*trans_slot == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		{
			bool found = false;

			if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask) &&
				!ZHeapTupleHasMultiLockers(tuple->t_infomask))
				found = GetLockerTransInfo(rel, zhtup, buffer, single_locker_trans_slot,
										   NULL, single_locker_xid, NULL, NULL);
			if (!found)
				return TM_Ok;
			else
			{
				/*
				 * If there is a single locker in-progress/aborted locker,
				 * it's safe to return being updated so that the caller
				 * check for lock conflicts or perform rollback if necessary.
				 *
				 * If the single locker is our current transaction, then also
				 * we return beging updated.
				 */
				return TM_BeingModified;
			}
		}

		if (TransactionIdIsCurrentTransactionId(*xid))
		{
			if (cid && *cid >= curcid)
			{
				/*
				 * updated/locked after scan started, check previous tuple
				 * from undo
				 */
				visible = UndoTupleSatisfiesUpdate(urec_ptr,
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   *trans_slot,
												   InvalidTransactionId,
												   free_zhtup,
												   in_place_updated_or_locked);
				if (visible)
				{
					if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
						return TM_BeingModified;
					else
						return TM_SelfModified;
				}
			}
			else
			{
				if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
				{
					/*
					 * Locked before scan;  caller can check if it is locked
					 * in lock mode higher or equal to the required mode, then
					 * it can skip locking the tuple.
					 */
					return TM_BeingModified;
				}
				else
					return TM_Ok;	/* updated before scan started */
			}
		}
		else if (TransactionIdIsInProgress(*xid))
		{
			visible = UndoTupleSatisfiesUpdate(urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   *trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
			{
				if (subxid)
					ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, subxid);

				return TM_BeingModified;
			}
			else
				return TM_Invisible;
		}
		else if (TransactionIdDidCommit(*xid))
		{
			/* if tuple is updated and not in our snapshot, then allow to update it. */
			if (lock_allowed || !XidInMVCCSnapshot(*xid, snapshot))
				return TM_Ok;
			else
				return TM_Updated;
		}
		else	/* transaction is aborted */
		{
			visible = UndoTupleSatisfiesUpdate(urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   *trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the
			 * undo before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			if (visible)
				return TM_BeingModified;
			else
				return TM_Invisible;
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot
	 * is cleared or latest xid that has changed the tuple precedes
	 * smallest xid that has undo.
	 */
	if (*trans_slot == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return TM_Ok;

	if (TransactionIdIsCurrentTransactionId(*xid))
	{
		if (cid && *cid >= curcid)
			return TM_Invisible;	/* inserted after scan started */
		else
			return TM_Ok;	/* inserted before scan started */
	}
	else if (TransactionIdIsInProgress(*xid))
		return TM_Invisible;
	else if (TransactionIdDidCommit(*xid))
		return TM_Ok;
	else
		return TM_Invisible;

	return TM_Invisible;
}

/*
 * ZHeapTupleIsSurelyDead
 *
 * Similar to HeapTupleIsSurelyDead, but for zheap tuples.
 */
bool
ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, uint64 OldestXmin, Buffer buffer)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	TransactionId	xid;
	uint64			epoch_xid;
	int				trans_slot_id;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot_id, &epoch_xid, &xid, NULL,
						   NULL, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN || epoch_xid < OldestXmin)
			return true;
	}

	return false; /* Tuple is still alive */
}

/*
 * ZHeapTupleSatisfiesSelf
 *		Returns the visible version of tuple (including effects of previous
 *		commands in current transactions) if any, NULL otherwise.
 *
 *	Here, we consider the effects of:
 *		all committed transactions (as of the current instant)
 *		previous commands of this transaction
 *		changes made by the current command
 *
 *	The tuple will be considered visible iff:
 *		Latest operation on tuple is Insert, In-Place update or tuple is
 *		locked and the transaction that has performed operation is current
 *		transaction or is committed.
 *
 *	If the transaction is in progress, then we fetch the tuple from undo.
 */
ZHeapTuple
ZHeapTupleSatisfiesSelf(ZHeapTuple zhtup, Snapshot snapshot,
						Buffer buffer, ItemPointer ctid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	TransactionId	xid;
	UndoRecPtr  urec_ptr = InvalidUndoRecPtr;
	uint64			epoch_xid;
	int				trans_slot_id;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot_id, &epoch_xid, &xid,
						   NULL, &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return NULL;

		if (TransactionIdIsCurrentTransactionId(xid))
			return NULL;
		else if (TransactionIdIsInProgress(xid))
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot_id,
									InvalidTransactionId);
		else if (TransactionIdDidCommit(xid))
		{
			/* tuple is deleted or non-inplace-updated */
			return NULL;
		}
		else	/* transaction is aborted */
		{
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot_id,
									InvalidTransactionId);
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
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return zhtup;

		if (TransactionIdIsCurrentTransactionId(xid))
		{
			return zhtup;
		}
		else if (TransactionIdIsInProgress(xid))
		{
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot_id,
									InvalidTransactionId);
		}
		else if (TransactionIdDidCommit(xid))
		{
			return zhtup;
		}
		else	/* transaction is aborted */
		{
			return GetTupleFromUndo(urec_ptr,
									zhtup,
									snapshot,
									buffer,
									ctid,
									trans_slot_id,
									InvalidTransactionId);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return zhtup;

	if (TransactionIdIsCurrentTransactionId(xid))
		return zhtup;
	else if (TransactionIdIsInProgress(xid))
	{
		return NULL;
	}
	else if (TransactionIdDidCommit(xid))
		return zhtup;
	else
	{
		/* Inserting transaction is aborted. */
		return NULL;
	}

	return NULL;
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
 *	This is essentially like ZHeapTupleSatisfiesSelf as far as effects of
 *	the current transaction and committed/aborted xacts are concerned.
 *	However, we also include the effects of other xacts still in progress.
 *
 *	The tuple will be considered visible iff:
 *	(a) Latest operation on tuple is Delete or non-inplace-update and the
 *		current transaction is in progress.
 *	(b) Latest operation on tuple is Insert, In-Place update or tuple is
 *		locked and the transaction that has performed operation is current
 *		transaction or is in-progress or is committed.
 */
ZHeapTuple
ZHeapTupleSatisfiesDirty(ZHeapTuple zhtup, Snapshot snapshot,
						 Buffer buffer, ItemPointer ctid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	TransactionId	xid;
	uint64			epoch_xid;
	UndoRecPtr		urec_ptr;
	int				trans_slot_id;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	snapshot->xmin = snapshot->xmax = InvalidTransactionId;
	snapshot->subxid = InvalidSubTransactionId;
	snapshot->speculativeToken = 0;

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot_id, &epoch_xid, &xid, NULL,
						   &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return NULL;

		if (TransactionIdIsCurrentTransactionId(xid))
		{
			/*
			 * For non-inplace-updates, ctid needs to be retrieved from undo
			 * record if required.  If the tuple is moved to another
			 * partition, then we don't need ctid.
			 */
			if (ctid &&
				!ZHeapTupleIsMoved(tuple->t_infomask) &&
				tuple->t_infomask & ZHEAP_UPDATED)
				ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);
			return NULL;
		}
		else if (TransactionIdIsInProgress(xid))
		{
			snapshot->xmax = xid;
			if (UndoRecPtrIsValid(urec_ptr))
				ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, &snapshot->subxid);
			return zhtup;		/* in deletion by other */
		}
		else if (TransactionIdDidCommit(xid))
		{
			/*
			 * For non-inplace-updates, ctid needs to be retrieved from undo
			 * record if required.  If the tuple is moved to another
			 * partition, then we don't need ctid.
			 */
			if (ctid &&
				!ZHeapTupleIsMoved(tuple->t_infomask) &&
				tuple->t_infomask & ZHEAP_UPDATED)
				ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);

			/* tuple is deleted or non-inplace-updated */
			return NULL;
		}
		else	/* transaction is aborted */
		{
			return GetTupleFromUndo(urec_ptr, zhtup, snapshot, buffer, ctid,
									trans_slot_id, InvalidTransactionId);
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
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return zhtup;	/* tuple is updated */

		if (TransactionIdIsCurrentTransactionId(xid))
			return zhtup;
		else if (TransactionIdIsInProgress(xid))
		{
			if (!ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
			{
				snapshot->xmax = xid;
				if (UndoRecPtrIsValid(urec_ptr))
					ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, &snapshot->subxid);
			}
			return zhtup;		/* being updated */
		}
		else if (TransactionIdDidCommit(xid))
			return zhtup;	/* tuple is updated by someone else */
		else	/* transaction is aborted */
		{
			/* Here we need to fetch the tuple from undo. */
			return GetTupleFromUndo(urec_ptr, zhtup, snapshot, buffer, ctid,
									trans_slot_id, InvalidTransactionId);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return zhtup;

	if (TransactionIdIsCurrentTransactionId(xid))
		return zhtup;
	else if (TransactionIdIsInProgress(xid))
	{
		/* Return the speculative token to caller. */
		if (ZHeapTupleHeaderIsSpeculative(tuple))
		{
			ZHeapTupleGetSpecToken(zhtup, buffer, urec_ptr,
								   &snapshot->speculativeToken);

			Assert(snapshot->speculativeToken != 0);
		}

		snapshot->xmin = xid;
		if (UndoRecPtrIsValid(urec_ptr))
			ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, &snapshot->subxid);
		return zhtup;		/* in insertion by other */
	}
	else if (TransactionIdDidCommit(xid))
		return zhtup;
	else
	{
		/*
		 * Since the transaction that inserted the tuple is aborted. So, it's
		 * not visible to any transaction.
		 */
		return NULL;
	}

	return NULL;
}

/*
 * ZHeapTupleSatisfiesAny
 *		Dummy "satisfies" routine: any tuple satisfies SnapshotAny.
 */
ZHeapTuple
ZHeapTupleSatisfiesAny(ZHeapTuple zhtup, Snapshot snapshot, Buffer buffer,
					   ItemPointer ctid)
{
	/* Callers can expect ctid to be populated. */
	if (ctid &&
		!ZHeapTupleIsMoved(zhtup->t_data->t_infomask) &&
		ZHeapTupleIsUpdated(zhtup->t_data->t_infomask))
	{
		UndoRecPtr	urec_ptr;
		int		out_slot_no PG_USED_FOR_ASSERTS_ONLY;

		out_slot_no = GetTransactionSlotInfo(buffer,
											 ItemPointerGetOffsetNumber(&zhtup->t_self),
											 ZHeapTupleHeaderGetXactSlot(zhtup->t_data),
											 NULL,
											 NULL,
											 &urec_ptr,
											 true,
											 false);
		/*
		 * We always expect non-frozen transaction slot here as the caller tries
		 * to fetch the ctid of tuples that are visible to the snapshot, so
		 * corresponding undo record can't be discarded.
		 */
		Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

		ZHeapTupleGetCtid(zhtup, buffer, urec_ptr, ctid);
	}
	return zhtup;
}

/*
 * ZHeapTupleSatisfiesOldestXmin
 *	The tuple will be considered visible if it is visible to any open
 *	transaction.
 *
 *	ztuple is an input/output parameter.  The caller must send the palloc'ed
 *	data.  This function can get a tuple from undo to return in which case it
 *	will free the memory passed by the caller.
 *
 *	xid is an output parameter. It is set to the latest committed/in-progress
 *	xid that inserted/modified the tuple.
 *	If the latest transaction for the tuple aborted, we fetch a prior committed
 *	version of the tuple and return the prior comitted xid and status as
 *	HEAPTUPLE_LIVE.
 *	If the latest transaction for the tuple aborted and it also inserted
 *	the tuple, we return the aborted transaction id and status as
 *	HEAPTUPLE_DEAD. In this case, the caller *should* never mark the
 *	corresponding item id as dead. Because, when undo action for the same will
 *	be performed, we need the item pointer.
 */
HTSV_Result
ZHeapTupleSatisfiesOldestXmin(ZHeapTuple *ztuple, TransactionId OldestXmin,
							  Buffer buffer, TransactionId *xid,
							  SubTransactionId *subxid)
{
	ZHeapTuple	zhtup = *ztuple;
	ZHeapTupleHeader tuple = zhtup->t_data;
	UndoRecPtr	urec_ptr;
	uint64	epoch_xid;
	int		trans_slot_id;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot_id, &epoch_xid, xid, NULL,
						   &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return HEAPTUPLE_DEAD;

		if (TransactionIdIsCurrentTransactionId(*xid))
			return HEAPTUPLE_DELETE_IN_PROGRESS;
		else if (TransactionIdIsInProgress(*xid))
		{
			/* Get Sub transaction id */
			if (subxid)
				ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, subxid);

			return HEAPTUPLE_DELETE_IN_PROGRESS;
		}
		else if (TransactionIdDidCommit(*xid))
		{
			/*
			 * Deleter committed, but perhaps it was recent enough that some open
			 * transactions could still see the tuple.
			 */
			if (!TransactionIdPrecedes(*xid, OldestXmin))
				return HEAPTUPLE_RECENTLY_DEAD;

			/* Otherwise, it's dead and removable */
			return HEAPTUPLE_DEAD;
		}
		else	/* transaction is aborted */
		{
			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.
			 */
			*ztuple = GetTupleFromUndoForAbortedXact(urec_ptr, buffer,
													   trans_slot_id, zhtup, xid);
			if (*ztuple != NULL)
				return HEAPTUPLE_LIVE;
			else
			{
				/*
				 * If the transaction that inserted the tuple got aborted,
				 * we should return the aborted transaction id.
				 */
				return HEAPTUPLE_DEAD;
			}
		}
	}
	else if (tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * We can't take any decision if the tuple is marked as locked-only.
		 * It's possible that inserted transaction took a lock on the tuple
		 * Later, if it rolled back, we should return HEAPTUPLE_DEAD, or if
		 * it's still in progress, we should return HEAPTUPLE_INSERT_IN_PROGRESS.
		 * Similarly, if the inserted transaction got committed, we should return
		 * HEAPTUPLE_LIVE.
		 * The subsequent checks already takes care of all these possible
		 * scenarios, so we don't need any extra checks here.
		 */
	}

	/* The tuple is either a newly inserted tuple or is in-place updated. */

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return HEAPTUPLE_LIVE;

	if (TransactionIdIsCurrentTransactionId(*xid))
		return HEAPTUPLE_INSERT_IN_PROGRESS;
	else if (TransactionIdIsInProgress(*xid))
	{
		/* Get Sub transaction id */
		if (subxid)
			ZHeapTupleGetSubXid(zhtup, buffer, urec_ptr, subxid);
		return HEAPTUPLE_INSERT_IN_PROGRESS;		/* in insertion by other */
	}
	else if (TransactionIdDidCommit(*xid))
		return HEAPTUPLE_LIVE;
	else	/* transaction is aborted */
	{
		if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED)
		{
			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.
			 */
			*ztuple = GetTupleFromUndoForAbortedXact(urec_ptr, buffer,
													   trans_slot_id, zhtup, xid);
			if (*ztuple != NULL)
				return HEAPTUPLE_LIVE;
		}
		/*
		 * If the transaction that inserted the tuple got aborted, we should
		 * return the aborted transaction id.
		 */
		return HEAPTUPLE_DEAD;
	}

	return HEAPTUPLE_LIVE;
}

/*
 * ZHeapTupleSatisfiesNonVacuumable
 *
 *	True if tuple might be visible to some transaction; false if it's
 *	surely dead to everyone, ie, vacuumable.
 *
 *	This is an interface to ZHeapTupleSatisfiesOldestXmin that meets the
 *	SnapshotSatisfiesFunc API, so it can be used through a Snapshot.
 *	snapshot->xmin must have been set up with the xmin horizon to use.
 */
ZHeapTuple
ZHeapTupleSatisfiesNonVacuumable(ZHeapTuple ztup, Snapshot snapshot,
								Buffer buffer, ItemPointer	ctid)
{
	TransactionId	xid;

	return (ZHeapTupleSatisfiesOldestXmin(&ztup, snapshot->xmin, buffer, &xid, NULL)
		!= HEAPTUPLE_DEAD) ? ztup : NULL;
}

/*
 * ZHeapTupleSatisfiesVacuum
 * Similar to ZHeapTupleSatisfiesOldestXmin, but it behaves differently for
 * handling aborted transaction.
 *
 * For aborted transactions, we don't fetch any prior committed version of the
 * tuple. Instead, we return ZHEAPTUPLE_ABORT_IN_PROGRESS and return the aborted
 * xid. The caller should avoid such tuple for any kind of prunning/vacuuming.
 */
ZHTSV_Result
ZHeapTupleSatisfiesVacuum(ZHeapTuple zhtup, TransactionId OldestXmin,
						  Buffer buffer, TransactionId *xid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	UndoRecPtr	urec_ptr;
	uint64	epoch_xid;
	int		trans_slot_id;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, &trans_slot_id, &epoch_xid, xid, NULL,
						   &urec_ptr, false);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction slot
		 * is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
			epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return ZHEAPTUPLE_DEAD;

		if (TransactionIdIsCurrentTransactionId(*xid))
			return ZHEAPTUPLE_DELETE_IN_PROGRESS;
		else if (TransactionIdIsInProgress(*xid))
		{
			return ZHEAPTUPLE_DELETE_IN_PROGRESS;
		}
		else if (TransactionIdDidCommit(*xid))
		{
			/*
			 * Deleter committed, but perhaps it was recent enough that some open
			 * transactions could still see the tuple.
			 */
			if (!TransactionIdPrecedes(*xid, OldestXmin))
				return ZHEAPTUPLE_RECENTLY_DEAD;

			/* Otherwise, it's dead and removable */
			return ZHEAPTUPLE_DEAD;
		}
		else	/* transaction is aborted */
		{
			return ZHEAPTUPLE_ABORT_IN_PROGRESS;
		}
	}
	else if (tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		/*
		 * "Deleting" xact really only locked it, so the tuple is live in any
		 * case.
		 */
		return ZHEAPTUPLE_LIVE;
	}

	/* The tuple is either a newly inserted tuple or is in-place updated. */

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
		epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return ZHEAPTUPLE_LIVE;

	if (TransactionIdIsCurrentTransactionId(*xid))
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;
	else if (TransactionIdIsInProgress(*xid))
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;		/* in insertion by other */
	else if (TransactionIdDidCommit(*xid))
		return ZHEAPTUPLE_LIVE;
	else	/* transaction is aborted */
	{
		return ZHEAPTUPLE_ABORT_IN_PROGRESS;
	}

	return ZHEAPTUPLE_LIVE;
}

/*
 * ZHeapTupleSatisfiesToast
 *
 * True iff zheap tuple is valid as a TOAST row.
 *
 * Unlike heap, we don't need checks for VACUUM moving conditions as those are
 * for pre-9.0 and that doesn't apply for zheap.  For aborted speculative
 * inserts, we always marks row as dead, so we don't any check for that.  So,
 * here we can rely on the fact that if you can see the main table row that
 * contains a TOAST reference, you should be able to see the TOASTed value.
 */
ZHeapTuple
ZHeapTupleSatisfiesToast(ZHeapTuple zhtup, Snapshot snapshot,
						 Buffer buffer, ItemPointer ctid)
{
	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	return zhtup;
}


ZHeapTuple
ZHeapTupleSatisfies(ZHeapTuple stup, Snapshot snapshot, Buffer buffer, ItemPointer ctid)
{
	switch (snapshot->snapshot_type)
	{
		case SNAPSHOT_MVCC:
			return ZHeapTupleSatisfiesMVCC(stup, snapshot, buffer, ctid);
			break;
		case SNAPSHOT_SELF:
			return ZHeapTupleSatisfiesSelf(stup, snapshot, buffer, ctid);
			break;
		case SNAPSHOT_ANY:
			return ZHeapTupleSatisfiesAny(stup, snapshot, buffer, ctid);
			break;
		case SNAPSHOT_TOAST:
			return ZHeapTupleSatisfiesToast(stup, snapshot, buffer, ctid);
			break;
		case SNAPSHOT_DIRTY:
			return ZHeapTupleSatisfiesDirty(stup, snapshot, buffer, ctid);
			break;
		case SNAPSHOT_HISTORIC_MVCC:
			// ZBORKED: need a better error message
			elog(PANIC, "unimplemented");
			break;
		case SNAPSHOT_NON_VACUUMABLE:
			return ZHeapTupleSatisfiesNonVacuumable(stup, snapshot, buffer, ctid);
			break;
	}

	return NULL; /* silence compiler */
}

/*
 * This is a helper function for CheckForSerializableConflictOut.
 *
 * Check to see whether the tuple has been written to by a concurrent
 * transaction, either to create it not visible to us, or to delete it
 * while it is visible to us.  The "visible" bool indicates whether the
 * tuple is visible to us, while ZHeapTupleSatisfiesOldestXmin checks what
 * else is going on with it. The caller should have a share lock on the buffer.
 */
bool
ZHeapTupleHasSerializableConflictOut(bool visible, Relation relation,
									 ItemPointer tid, Buffer buffer,
									 TransactionId *xid)
{
	HTSV_Result		htsvResult;
	ItemId			lp;
	OffsetNumber	offnum;
	Page			dp;
	ZHeapTuple		tuple;
	Size			tuple_len;
	bool			tuple_inplace_updated = false;
	Snapshot		snap;

	Assert(ItemPointerGetBlockNumber(tid) == BufferGetBlockNumber(buffer));
	offnum = ItemPointerGetOffsetNumber(tid);
	dp = BufferGetPage(buffer);

	/* check for bogus TID */
	Assert (offnum >= FirstOffsetNumber &&
			offnum <= PageGetMaxOffsetNumber(dp));

	lp = PageGetItemId(dp, offnum);

	/* check for unused or dead items */
	Assert (ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If the record is deleted and pruned, its place in the page might have
	 * been taken by another of its kind.
	 */
	if (ItemIdIsDeleted(lp))
	{
		/*
		 * If the tuple is still visible to us, then we've a conflict. Becasue,
		 * the transaction that deleted the tuple already got committed.
		 */
		if (visible)
		{
			snap = GetTransactionSnapshot();
			tuple = ZHeapGetVisibleTuple(offnum, snap, buffer, NULL);
			ZHeapTupleGetTransInfo(tuple, buffer, NULL, NULL, xid,
								   NULL, NULL, false);
			pfree(tuple);
			return true;
		}
		else
			return false;
	}

	tuple_len = ItemIdGetLength(lp);
	tuple = palloc(ZHEAPTUPLESIZE + tuple_len);
	tuple->t_data = (ZHeapTupleHeader) ((char *) tuple + ZHEAPTUPLESIZE);
	tuple->t_tableOid = RelationGetRelid(relation);
	tuple->t_len = tuple_len;
	ItemPointerSet(&tuple->t_self, ItemPointerGetBlockNumber(tid), offnum);
	memcpy(tuple->t_data,
		   ((ZHeapTupleHeader) PageGetItem((Page) dp, lp)), tuple_len);

	if (tuple->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
				tuple_inplace_updated = true;

	htsvResult = ZHeapTupleSatisfiesOldestXmin(&tuple, TransactionXmin, buffer, xid, NULL);
	pfree(tuple);
	switch (htsvResult)
	{
		case HEAPTUPLE_LIVE:
			if (tuple_inplace_updated)
			{
				/*
				 * We can't rely on callers visibility information for
				 * in-place updated tuples because they consider the tuple as
				 * visible if any version of the tuple is visible whereas we
				 * want to know the status of current tuple.  In case of
				 * aborted transactions, it is quite possible that the rollback
				 * actions aren't yet applied and we need the status of last
				 * committed transaction; ZHeapTupleSatisfiesOldestXmin returns
				 * us that information.
				 */
				if (XidIsConcurrent(*xid))
					visible = false;
			}
			if (visible)
				return false;
			break;
		case HEAPTUPLE_RECENTLY_DEAD:
			if (!visible)
				return false;
			break;
		case HEAPTUPLE_DELETE_IN_PROGRESS:
			break;
		case HEAPTUPLE_INSERT_IN_PROGRESS:
			break;
		case HEAPTUPLE_DEAD:
			return false;
		default:

			/*
			 * The only way to get to this default clause is if a new value is
			 * added to the enum type without adding it to this switch
			 * statement.  That's a bug, so elog.
			 */
			elog(ERROR, "unrecognized return value from ZHeapTupleSatisfiesOldestXmin: %u", htsvResult);

			/*
			 * In spite of having all enum values covered and calling elog on
			 * this default, some compilers think this is a code path which
			 * allows xid to be used below without initialization. Silence
			 * that warning.
			 */
			*xid = InvalidTransactionId;
	}
	Assert(TransactionIdIsValid(*xid));
	Assert(TransactionIdFollowsOrEquals(*xid, TransactionXmin));

	/*
	 * Find top level xid.  Bail out if xid is too early to be a conflict, or
	 * if it's our own xid.
	 */
	if (TransactionIdEquals(*xid, GetTopTransactionIdIfAny()))
		return false;
	if (TransactionIdPrecedes(*xid, TransactionXmin))
		return false;
	if (TransactionIdEquals(*xid, GetTopTransactionIdIfAny()))
		return false;

	return true;
}
