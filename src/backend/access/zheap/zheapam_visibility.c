/*-------------------------------------------------------------------------
 *
 * zheapam_visibility.c
 *	  POSTGRES "time qualification" code, ie, ztuple visibility rules.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zheapam_visibility.c
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
#include "access/zmultilocker.h"
#include "storage/bufmgr.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "utils/ztqual.h"
#include "storage/proc.h"

typedef enum
{
	ZTUPLETID_NEW,				/* inserted */
	ZTUPLETID_MODIFIED,			/* in-place update or lock */
	ZTUPLETID_GONE				/* non-in-place update or delete */
} ZTupleTidOp;

typedef enum
{
	ZVERSION_NONE,
	ZVERSION_CURRENT,
	ZVERSION_OLDER
} ZVersionSelector;

static ZHeapTuple GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
								   Snapshot snapshot, Buffer buffer,
								   ItemPointer ctid, int trans_slot_id,
								   TransactionId prev_undo_xid);
static ZHeapTuple GetTupleFromUndoForAbortedXact(UndoRecPtr urec_ptr, Buffer buffer, int trans_slot,
												 ZHeapTuple ztuple, TransactionId *xid);
static ZTupleTidOp ZHeapTidOpFromInfomask(uint16 infomask);
static ZVersionSelector ZHeapSelectVersionMVCC(ZTupleTidOp op,
				   TransactionId xid, CommandId cid, Snapshot snapshot);
static ZVersionSelector ZHeapSelectVersionSelf(ZTupleTidOp op,
					   TransactionId xid, CommandId cid);

/*
 * FetchTransInfoFromUndo - Retrieve transaction information of transaction
 *			that has modified the undo tuple.
 */
void
FetchTransInfoFromUndo(ZHeapTuple undo_tup, uint32 *epoch, TransactionId *xid,
					   CommandId *cid, UndoRecPtr *urec_ptr, bool skip_lockers)
{
	UnpackedUndoRecord *urec;
	UndoRecPtr	urec_ptr_out = InvalidUndoRecPtr;
	TransactionId undo_tup_xid;

	Assert(xid != NULL);

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
	 * The undo tuple must be visible, if the undo record containing the
	 * information of the last transaction that has updated the tuple is
	 * discarded.
	 */
	if (urec == NULL)
	{
		if (epoch)
			*epoch = 0;
		*xid = InvalidTransactionId;
		if (cid)
			*cid = InvalidCommandId;
		if (urec_ptr)
			*urec_ptr = InvalidUndoRecPtr;
		return;
	}

	/*
	 * If we reach here, this means the transaction id that has last modified
	 * this tuple must be in 2-billion xid range of oldestXidHavingUndo, so we
	 * can get compute its epoch as we do for current transaction.
	 */
	if (epoch)
		*epoch = GetEpochForXid(urec->uur_xid);
	*xid = urec->uur_xid;
	if (cid)
		*cid = urec->uur_cid;
	if (urec_ptr)
		*urec_ptr = urec_ptr_out;

	if (skip_lockers &&
		(urec->uur_type == UNDO_XID_LOCK_ONLY ||
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
	int			trans_slot;
	int			vis_info;
	ItemId		lp;
	Page		page;
	OffsetNumber offnum = ItemPointerGetOffsetNumber(ctid);
	ZHeapTupleTransInfo	zinfo;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, offnum);

	Assert(ItemIdIsDeleted(lp));

	trans_slot = ItemIdGetTransactionSlot(lp);
	vis_info = ItemIdGetVisibilityInfo(lp);

	/*
	 * We need undo record pointer to fetch the transaction information
	 * from undo.
	 */
	GetTransactionSlotInfo(buffer, offnum, trans_slot, true, false, &zinfo);

	if (vis_info & ITEMID_XACT_INVALID)
	{
		ZHeapTupleData undo_tup;
		uint32		epoch;

		ItemPointerSetBlockNumber(&undo_tup.t_self,
								  BufferGetBlockNumber(buffer));
		ItemPointerSetOffsetNumber(&undo_tup.t_self, offnum);

		zinfo.xid = InvalidTransactionId;
		FetchTransInfoFromUndo(&undo_tup, &epoch, &zinfo.xid, &zinfo.cid,
							   &zinfo.urec_ptr, false);
		zinfo.epoch_xid =
			U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo.xid));
	}
	else
		zinfo.cid =
			ZHeapPageGetCid(buffer, zinfo.epoch_xid, zinfo.urec_ptr, offnum);

	/* Return results to caller. */
	*xid = zinfo.xid;
	*cid = zinfo.cid;

	/*
	 * We always expect non-frozen transaction slot here as the caller tries
	 * to fetch the ctid of tuples that are visible to the snapshot, so
	 * corresponding undo record can't be discarded.
	 */
	Assert(zinfo.trans_slot != ZHTUP_SLOT_FROZEN);

	ZHeapPageGetCtid(buffer, zinfo.urec_ptr, ctid);
}

/*
 * ZHeapTupleGetTransInfo - Retrieve transaction information of transaction
 *			that has modified the tuple.
 *
 * nobuflock indicates whether caller has lock on the buffer 'buf'. If nobuflock
 * is false, we rely on the supplied tuple zhtup to fetch the slot and undo
 * information. Otherwise, we take buffer lock and fetch the actual tuple.
 *
 * snapshot will be used to avoid fetching tuple transaction id from the
 * undo if the transaction slot is reused.  So caller should pass a valid
 * snapshot where it's just fetching the xid for the visibility purpose.
 * InvalidSnapshot indicates that we need the xid of reused transaction
 * slot even if it is not in the snapshot, this is required to store its
 * value in undo record, otherwise, that can break the visibility for
 * other concurrent session holding old snapshot.
 */
void
ZHeapTupleGetTransInfo(ZHeapTuple zhtup, Buffer buf,
					   bool nobuflock, bool fetch_cid, Snapshot snapshot,
					   ZHeapTupleTransInfo *zinfo)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	uint32		epoch;
	ItemId		lp;
	Page		page;
	ItemPointer tid = &(zhtup->t_self);
	OffsetNumber offnum = ItemPointerGetOffsetNumber(tid);
	bool		is_invalid_slot = false;

	/*
	 * We are going to access special space in the page to retrieve the
	 * transaction information and that requires share lock on buffer.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));
	if (!ItemIdIsDeleted(lp))
	{
		if (nobuflock)
		{
			/*
			 * If the tuple is updated such that its transaction slot has been
			 * changed, then we will never be able to get the correct tuple
			 * from undo. To avoid, that we get the latest tuple from page
			 * rather than relying on it's in-memory copy.
			 */
			zhtup->t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			zhtup->t_len = ItemIdGetLength(lp);
			tuple = zhtup->t_data;
		}
		zinfo->trans_slot = ZHeapTupleHeaderGetXactSlot(tuple);
		if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		if (ZHeapTupleHasInvalidXact(tuple->t_infomask))
			is_invalid_slot = true;
	}
	else
	{
		/*
		 * If it's deleted and pruned, we fetch the slot and undo information
		 * from the item pointer itself.
		 */
		zinfo->trans_slot = ItemIdGetTransactionSlot(lp);
		if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		if (ItemIdGetVisibilityInfo(lp) & ITEMID_XACT_INVALID)
			is_invalid_slot = true;
	}

	GetTransactionSlotInfo(buf, offnum, zinfo->trans_slot, true, false, zinfo);

	/*
	 * It is quite possible that the item is showing some valid
	 * transaction slot, but actual slot has been frozen. This can happen
	 * when the slot belongs to TPD entry and the corresponding TPD entry
	 * is pruned.
	 */
	if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN)
		goto slot_is_frozen;

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (is_invalid_slot)
	{
		Assert((snapshot == InvalidSnapshot) || IsMVCCSnapshot(snapshot));

		/*
		 * We are intentionally avoiding to fetch the transaction information
		 * from undo even when the tuple has invalid_xact_slot marking as if
		 * the slot's current xid is all-visible, then the xid prior to it
		 * must be all-visible.  The other case where we can avoid it when the
		 * current xid is visible to the snapshot for similar reasoning. But,
		 * in second can we can only avoid fetching the actual xid if we are
		 * just checking the visibility, but if we need to fetch xid for
		 * storing the xid in undo as previous xid then we can not avoid it
		 * (e.g zheap_update) because this xid is still not all visible and
		 * may be not visible to some of the concurrent session.  So if we
		 * store invalid xid in the undo as prevxid then that tuple version
		 * will be considered as all visible which is not true.
		 */
		if ((TransactionIdIsValid(zinfo->xid) &&
			 (TransactionIdPrecedes(zinfo->xid, pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)) ||
			  (snapshot != InvalidSnapshot && !XidInMVCCSnapshot(zinfo->xid, snapshot)))) ||
			UndoLogIsDiscarded(zinfo->urec_ptr))
			goto slot_is_frozen;

		zinfo->xid = InvalidTransactionId;
		FetchTransInfoFromUndo(zhtup, &epoch, &zinfo->xid, &zinfo->cid,
							   &zinfo->urec_ptr, true);
		zinfo->epoch_xid =
			U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo->xid));
	}
	else if (!ItemIdIsDeleted(lp) && ZHeapTupleHasMultiLockers(tuple->t_infomask))
	{
		/*
		 * When we take a lock on the tuple, we never set locker's slot on the
		 * tuple.  However, we use the newly computed infomask for the tuple
		 * and write its current infomask in undo due to which
		 * INVALID_XACT_SLOT bit of the tuple will move to undo.  In such
		 * cases, if we need the previous inserter/updater's transaction id,
		 * we've to skip locker's undo records.
		 */
		zinfo->xid = InvalidTransactionId;
		FetchTransInfoFromUndo(zhtup, &epoch, &zinfo->xid, &zinfo->cid,
							   &zinfo->urec_ptr, true);
		zinfo->epoch_xid =
			U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo->xid));
	}
	else
	{
		if (fetch_cid && TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			lp = PageGetItemId(page, offnum);
			if (!ItemIdIsDeleted(lp))
				zinfo->cid = ZHeapTupleGetCid(zhtup, buf, InvalidUndoRecPtr,
											  InvalidXactSlotId);
			else
				zinfo->cid =
					ZHeapPageGetCid(buf, zinfo->epoch_xid,
									zinfo->urec_ptr, offnum);
		}
		else
			zinfo->cid = InvalidCommandId;
	}

	goto done;

slot_is_frozen:
	zinfo->trans_slot = ZHTUP_SLOT_FROZEN;
	zinfo->epoch_xid = U64FromFullTransactionId(InvalidFullTransactionId);
	zinfo->xid = InvalidTransactionId;
	zinfo->cid = InvalidCommandId;
	zinfo->urec_ptr = InvalidUndoRecPtr;

done:
	/* Set the value of required parameters. */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
}

/*
 * ZHeapTupleGetTransXID - Retrieve just the XID that last modified the tuple.
 */
TransactionId
ZHeapTupleGetTransXID(ZHeapTuple zhtup, Buffer buf, bool nobuflock)
{
	ZHeapTupleTransInfo	zinfo;

	ZHeapTupleGetTransInfo(zhtup, buf, nobuflock, false, InvalidSnapshot,
						   &zinfo);
	return zinfo.xid;
}

/*
 * GetVisibleTupleIfAny
 *
 * This is a helper function for GetTupleFromUndoWithOffset.
 */
static ZHeapTuple
GetVisibleTupleIfAny(ZHeapTuple undo_tup, ZHeapTupleTransInfo *zinfo,
					 Snapshot snapshot, Buffer buffer)
{
	ZVersionSelector	zselect;
	ZTupleTidOp	op;
	TransactionId oldestXidHavingUndo;

	op = ZHeapTidOpFromInfomask(undo_tup->t_data->t_infomask);
	Assert(op != ZTUPLETID_GONE);	/* shouldn't find such tuples in undo */

	oldestXidHavingUndo = GetXidFromEpochXid(
											 pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if ((zinfo->trans_slot != ZHTUP_SLOT_FROZEN) &&
		!TransactionIdEquals(zinfo->xid, FrozenTransactionId) &&
		!TransactionIdPrecedes(zinfo->xid, oldestXidHavingUndo))
	{
		if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
		{
			uint32		epoch;

			FetchTransInfoFromUndo(undo_tup, &epoch, &zinfo->xid, &zinfo->cid,
								   &zinfo->urec_ptr, false);
			zinfo->epoch_xid =
				U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo->xid));
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

		else if (zinfo->cid == InvalidCommandId)
		{
			/*
			 * we don't use prev_undo_xid to fetch the undo record for cid as
			 * it is required only when transaction is current transaction in
			 * which case there is no risk of transaction chain switching, so
			 * we are safe.  It might be better to move this check near to
			 * it's usage, but that will make code look ugly, so keeping it
			 * here.
			 */
			zinfo->cid = ZHeapTupleGetCid(undo_tup, buffer, zinfo->urec_ptr,
										  zinfo->trans_slot);
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(zinfo->xid, FrozenTransactionId) ||
		TransactionIdPrecedes(zinfo->xid, oldestXidHavingUndo))
		return undo_tup;

	/* Check XID and CID against snapshot. */
	if (IsMVCCSnapshot(snapshot))
		zselect = ZHeapSelectVersionMVCC(op, zinfo->xid, zinfo->cid, snapshot);
	else
	{
		/* ZBORKED: Why do we always use SnapshotSelf rules here? */
		zselect = ZHeapSelectVersionSelf(op, zinfo->xid, zinfo->cid);
	}

	/* Return the current version, or nothing, if appropriate. */
	if (zselect == ZVERSION_CURRENT)
		return undo_tup;
	if (zselect == ZVERSION_NONE)
		return NULL;

	/* Need to check older versions, so delegate to GetTupleFromUndo. */
	return GetTupleFromUndo(zinfo->urec_ptr,
							undo_tup,
							snapshot,
							buffer,
							NULL,
							zinfo->trans_slot,
							zinfo->xid);
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
 *	The caller must send a palloc'd tuple. This function can get a tuple
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
							   ZHeapTuple ztuple, TransactionId *xid)
{
	ZHeapTuple	undo_tup = ztuple;
	UnpackedUndoRecord *urec;
	UndoRecPtr	prev_urec_ptr;
	TransactionId prev_undo_xid PG_USED_FOR_ASSERTS_ONLY;
	TransactionId oldestXidHavingUndo = InvalidTransactionId;
	int			trans_slot_id;
	int			prev_trans_slot_id = trans_slot;

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
	Assert(ZHeapTidOpFromInfomask(undo_tup->t_data->t_infomask)
				!= ZTUPLETID_GONE);

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
	 * point of time, then undo_tup is the latest committed version of the
	 * tuple.
	 */
	if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
		return undo_tup;

	/*
	 * If the undo tuple is stamped with a different transaction, then either
	 * the previous transaction is committed or tuple must be locked only. In
	 * both cases, we can return the tuple fetched from undo.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		ZHeapTupleTransInfo	zinfo;

		GetTransactionSlotInfo(buffer,
							   ItemPointerGetOffsetNumber(&undo_tup->t_self),
							   trans_slot_id,
							   true,
							   true,
							   &zinfo);
		prev_urec_ptr = zinfo.urec_ptr;
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
	 * If undo tuple is the root tuple inserted by the aborted transaction, we
	 * don't have to process any further. The tuple is not visible to us.
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
	UnpackedUndoRecord *urec;
	ZHeapTuple	undo_tup;
	TransactionId oldestXidHavingUndo;
	int			prev_trans_slot_id = trans_slot;
	ZHeapTupleTransInfo	zinfo;

	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible. loop until we find the visible
	 * version.
	 */
	while (1)
	{
		ZTupleTidOp			op = ZTUPLETID_NEW;
		ZVersionSelector	zselect;

		zinfo.urec_ptr = InvalidUndoRecPtr;
		zinfo.cid = InvalidCommandId;
		zinfo.trans_slot = InvalidXactSlotId;

		urec = UndoFetchRecord(urec_ptr,
							   ItemPointerGetBlockNumber(&zhtup->t_self),
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   prev_undo_xid,
							   NULL,
							   ZHeapSatisfyUndoRecord);

		/* If undo is discarded, then current tuple is visible. */
		if (urec == NULL)
			return zhtup;

		undo_tup = CopyTupleFromUndoRecord(urec, zhtup, &zinfo.trans_slot,
										   &zinfo.cid, true,
										   BufferGetPage(buffer));
		zinfo.urec_ptr = urec->uur_blkprev;
		zinfo.xid = urec->uur_prevxid;

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

		oldestXidHavingUndo =
			GetXidFromEpochXid(pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

		/*
		 * The tuple must be all visible if the transaction slot is cleared
		 * or latest xid that has changed the tuple is too old that it is
		 * all-visible or it precedes smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			TransactionIdEquals(zinfo.xid, FrozenTransactionId) ||
			TransactionIdPrecedes(zinfo.xid, oldestXidHavingUndo))
			return undo_tup;

		/*
		 * Change the undo chain if the undo tuple is stamped with the
		 * different transaction.
		 */
		if (zinfo.trans_slot != prev_trans_slot_id)
		{
			ZHeapTupleTransInfo	zinfo2;

			/*
			 * It is quite possible that the tuple is showing some valid
			 * transaction slot, but actual slot has been frozen.  This can
			 * happen when the slot belongs to TPD entry and the
			 * corresponding TPD entry is pruned.
			 */
			GetTransactionSlotInfo(buffer,
								   ItemPointerGetOffsetNumber(&undo_tup->t_self),
								   zinfo.trans_slot,
								   true,
								   true,
								   &zinfo2);
			zinfo.trans_slot = zinfo2.trans_slot;
			zinfo.urec_ptr = zinfo2.urec_ptr;
		}

		op = ZHeapTidOpFromInfomask(undo_tup->t_data->t_infomask);

		/* can't further operate on deleted or non-inplace-updated tuple */
		Assert(op != ZTUPLETID_GONE);

		/*
		 * We need to fetch all the transaction related information from
		 * undo record for the tuples that point to a slot that gets
		 * invalidated for reuse at some point of time.  See
		 * PageFreezeTransSlots.
		 */
		if (ZHeapTupleHasInvalidXact(undo_tup->t_data->t_infomask))
		{
			uint32		epoch;

			FetchTransInfoFromUndo(undo_tup, &epoch, &zinfo.xid, &zinfo.cid,
								   &zinfo.urec_ptr, false);
			zinfo.epoch_xid =
				U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo.xid));
		}
		else if (zinfo.cid == InvalidCommandId)
		{
			CommandId	cur_cid = GetCurrentCommandId(false);

			/*
			 * If the current command doesn't need to modify any tuple and
			 * the snapshot used is not of any previous command, then it can
			 * see all the modifications made by current transactions till
			 * now.  So, we don't even attempt to fetch CID from undo in
			 * such cases.
			 */
			if (!GetCurrentCommandIdUsed() && cur_cid == snapshot->curcid)
				zinfo.cid = InvalidCommandId;
			else
			{
				/*
				 * we don't use prev_undo_xid to fetch the undo record for
				 * cid as it is required only when transaction is current
				 * transaction in which case there is no risk of transaction
				 * chain switching, so we are safe.  It might be better to
				 * move this check near to it's usage, but that will make
				 * code look ugly, so keeping it here.
				 */
				zinfo.cid = ZHeapTupleGetCid(undo_tup, buffer, zinfo.urec_ptr,
											 zinfo.trans_slot);
			}
		}

		/*
		 * The tuple must be all visible if the transaction slot is cleared
		 * or latest xid that has changed the tuple is too old that it is
		 * all-visible or it precedes smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			TransactionIdEquals(zinfo.xid, FrozenTransactionId) ||
			TransactionIdPrecedes(zinfo.xid, oldestXidHavingUndo))
			return undo_tup;

		/* Check XID and CID against snapshot. */
		if (IsMVCCSnapshot(snapshot))
			zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, zinfo.cid,
											 snapshot);
		else
		{
			/* ZBORKED: Why do we always use SnapshotSelf rules here? */
			zselect = ZHeapSelectVersionSelf(op, zinfo.xid, zinfo.cid);
		}

		/* Return the current version, or nothing, if appropriate. */
		if (zselect == ZVERSION_CURRENT)
			return undo_tup;
		if (zselect == ZVERSION_NONE)
			return NULL;

		/* Need to check next older version, so loop around. */
		urec_ptr = zinfo.urec_ptr;
		zhtup = undo_tup;
		prev_undo_xid = zinfo.xid;
		prev_trans_slot_id = zinfo.trans_slot;
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
	UnpackedUndoRecord *urec;
	ZHeapTuple	undo_tup;
	TransactionId oldestXidHavingUndo;
	int			prev_trans_slot_id = trans_slot;
	ZHeapTupleTransInfo	zinfo;
	uint32		epoch;

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
	zinfo.trans_slot = InvalidXactSlotId;
	undo_tup =
		CopyTupleFromUndoRecord(urec, NULL, &zinfo.trans_slot, &zinfo.cid,
								false, BufferGetPage(buffer));
	zinfo.urec_ptr = urec->uur_blkprev;
	zinfo.xid = urec->uur_prevxid;

	/*
	 * We don't allow XIDs with an age of more than 2 billion in undo, so
	 * we can infer the epoch here.
	 */
	epoch = GetEpochForXid(urec->uur_xid);
	zinfo.epoch_xid = U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, urec->uur_xid));

	UndoRecordRelease(urec);

	oldestXidHavingUndo = GetXidFromEpochXid(
											 pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(zinfo.xid, FrozenTransactionId) ||
		TransactionIdPrecedes(zinfo.xid, oldestXidHavingUndo))
		return undo_tup;

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction.
	 */
	if (zinfo.trans_slot != prev_trans_slot_id)
	{
		ZHeapTupleTransInfo	zinfo2;

		GetTransactionSlotInfo(buffer,
							   ItemPointerGetOffsetNumber(&undo_tup->t_self),
							   zinfo.trans_slot,
							   true,
							   true,
							   &zinfo2);
		zinfo.trans_slot = zinfo2.trans_slot;
		zinfo.urec_ptr = zinfo2.urec_ptr;
	}

	return GetVisibleTupleIfAny(undo_tup, &zinfo, snapshot, buffer);
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
						 TransactionId prev_undo_xid, bool free_zhtup,
						 bool *in_place_updated_or_locked)
{
	UnpackedUndoRecord *urec;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr;
	TransactionId xid,
				oldestXidHavingUndo;
	CommandId	cid;
	int			trans_slot_id;
	int			prev_trans_slot_id = trans_slot;
	ZTupleTidOp	op;
	ZVersionSelector	zselect;

	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
fetch_prior_undo_record:
	undo_tup = NULL;
	prev_urec_ptr = InvalidUndoRecPtr;
	cid = InvalidCommandId;
	trans_slot_id = InvalidXactSlotId;

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   prev_undo_xid,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/* If undo is discarded, then current tuple is visible. */
	if (urec == NULL)
	{
		zselect = ZVERSION_CURRENT;
		goto result_available;
	}

	undo_tup = CopyTupleFromUndoRecord(urec, zhtup, &trans_slot_id, &cid,
									   free_zhtup, BufferGetPage(buffer));
	prev_urec_ptr = urec->uur_blkprev;
	xid = urec->uur_prevxid;

	/*
	 * For non-inplace-updates, ctid needs to be retrieved from undo record if
	 * required.
	 */
	if (ctid)
	{
		if (urec->uur_type == UNDO_UPDATE)
			*ctid = *((ItemPointer) urec->uur_payload.data);
		else
			*ctid = undo_tup->t_self;
	}

	op = ZHeapTidOpFromInfomask(undo_tup->t_data->t_infomask);
	Assert(op != ZTUPLETID_GONE);   /* shouldn't find such tuples in undo */

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
		zselect = ZVERSION_CURRENT;
		goto result_available;
	}

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction slot.
	 */
	if (trans_slot_id != prev_trans_slot_id)
	{
		ZHeapTupleTransInfo	zinfo;

		/*
		 * It is quite possible that the tuple is showing some valid
		 * transaction slot, but actual slot has been frozen.  This can happen
		 * when the slot belongs to TPD entry and the corresponding TPD entry
		 * is pruned.
		 */
		GetTransactionSlotInfo(buffer,
							   ItemPointerGetOffsetNumber(&undo_tup->t_self),
							   trans_slot_id,
							   true,
							   true,
							   &zinfo);
		trans_slot_id = zinfo.trans_slot;
		prev_urec_ptr = zinfo.urec_ptr;
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
		CommandId	cur_comm_cid = GetCurrentCommandId(false);

		/*
		 * If the current command doesn't need to modify any tuple and the
		 * snapshot used is not of any previous command, then it can see all
		 * the modifications made by current transactions till now.  So, we
		 * don't even attempt to fetch CID from undo in such cases.
		 */
		if (!GetCurrentCommandIdUsed() && cur_comm_cid == curcid)
		{
			cid = InvalidCommandId;
		}
		else
		{
			/*
			 * we don't use prev_undo_xid to fetch the undo record for cid as
			 * it is required only when transaction is current transaction in
			 * which case there is no risk of transaction chain switching, so
			 * we are safe.  It might be better to move this check near to
			 * it's usage, but that will make code look ugly, so keeping it
			 * here.
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
		zselect = ZVERSION_CURRENT;
		goto result_available;
	}

	if (op == ZTUPLETID_MODIFIED)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= curcid)
				zselect = ZVERSION_OLDER;	/* updated after scan started */
			else
				zselect = ZVERSION_CURRENT; /* updated before scan started */
		}
		else if (TransactionIdIsInProgress(xid))
			zselect = ZVERSION_OLDER;
		else if (TransactionIdDidCommit(xid))
			zselect = ZVERSION_CURRENT;
		else
			zselect = ZVERSION_OLDER;
	}
	else						/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= curcid)
				zselect = ZVERSION_NONE; /* inserted after scan started */
			else
				zselect = ZVERSION_CURRENT;	/* inserted before scan started */
		}
		else if (TransactionIdIsInProgress(xid))
			zselect = ZVERSION_NONE;
		else if (TransactionIdDidCommit(xid))
			zselect = ZVERSION_CURRENT;
		else
			zselect = ZVERSION_NONE;
	}

	if (zselect == ZVERSION_OLDER)
	{
		/* Note the values required to fetch prior tuple in undo chain. */
		urec_ptr = prev_urec_ptr;
		zhtup = undo_tup;
		prev_undo_xid = xid;
		prev_trans_slot_id = trans_slot_id;
		free_zhtup = true;

		/* And then go fetch it. */
		goto fetch_prior_undo_record;
	}

result_available:
	if (undo_tup)
		pfree(undo_tup);
	return (zselect == ZVERSION_CURRENT);
}

/*
 * ZHeapTidOpFromInfomask
 *
 * Determine the last operation performed on a tuple using the infomask.
 */
static ZTupleTidOp
ZHeapTidOpFromInfomask(uint16 infomask)
{
	if ((infomask & (ZHEAP_INPLACE_UPDATED|ZHEAP_XID_LOCK_ONLY)) != 0)
		return ZTUPLETID_MODIFIED;
	if ((infomask & (ZHEAP_UPDATED|ZHEAP_DELETED)) != 0)
		return ZTUPLETID_GONE;
	return ZTUPLETID_NEW;
}

/*
 * ZHeapSelectVersionMVCC
 *
 * Decide, for a given MVCC snapshot, whether we should return the current
 * version of a tuple, an older version, or no version at all.
 */
static ZVersionSelector
ZHeapSelectVersionMVCC(ZTupleTidOp op, TransactionId xid, CommandId cid,
					   Snapshot snapshot)
{
	Assert(IsMVCCSnapshot(snapshot));

	if (op == ZTUPLETID_GONE)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= snapshot->curcid)
				return ZVERSION_OLDER;	/* deleted after scan started */
			else
				return ZVERSION_NONE;	/* deleted before scan started */
		}
		else if (XidInMVCCSnapshot(xid, snapshot))
			return ZVERSION_OLDER;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_NONE;		/* tuple is deleted */
		else
			return ZVERSION_OLDER;		/* transaction is aborted */
	}
	else if (op == ZTUPLETID_MODIFIED)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= snapshot->curcid)
			{
				/* updated/locked after scan started */
				return ZVERSION_OLDER;
			}
			else
			{
				/* updated or locked before scan started */
				return ZVERSION_CURRENT;
			}
		}
		else if (XidInMVCCSnapshot(xid, snapshot))
			return ZVERSION_OLDER;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_CURRENT;
		else
			return ZVERSION_OLDER;
	}
	else						/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(xid))
		{
			if (cid >= snapshot->curcid)
				return ZVERSION_NONE; /* inserted after scan started */
			else
				return ZVERSION_CURRENT;	/* inserted before scan started */
		}
		else if (XidInMVCCSnapshot(xid, snapshot))
			return ZVERSION_NONE;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_CURRENT;
		else
			return ZVERSION_NONE;
	}

	/* should never get here */
	pg_unreachable();
}

/*
 * ZHeapSelectVersionSelf
 *
 * Decide, using SnapshotSelf visibility rules, whether we should return the
 * current version of a tuple, an older version, or no version at all.
 */
static ZVersionSelector
ZHeapSelectVersionSelf(ZTupleTidOp op, TransactionId xid, CommandId cid)
{
	if (op == ZTUPLETID_GONE)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
			return ZVERSION_NONE;
		else if (TransactionIdIsInProgress(xid))
			return ZVERSION_OLDER;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_NONE;
		else
			return ZVERSION_OLDER;		/* transaction is aborted */
	}
	else if (op == ZTUPLETID_MODIFIED)
	{
		if (TransactionIdIsCurrentTransactionId(xid))
			return ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(xid))
			return ZVERSION_OLDER;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_CURRENT;
		else
			return ZVERSION_OLDER;		/* transaction is aborted */
	}
	else
	{
		if (TransactionIdIsCurrentTransactionId(xid))
			return ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(xid))
			return ZVERSION_NONE;
		else if (TransactionIdDidCommit(xid))
			return ZVERSION_CURRENT;
		else
			return ZVERSION_NONE;		/* transaction is aborted */
	}

	/* should never get here */
	pg_unreachable();
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
	CommandId	cur_cid = GetCurrentCommandId(false);
	ZHeapTupleTransInfo	zinfo;
	bool		fetch_cid;
	ZTupleTidOp op;
	ZVersionSelector	zselect;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get last operation type */
	op = ZHeapTidOpFromInfomask(tuple->t_infomask);

	/*
	 * If the current command doesn't need to modify any tuple and the
	 * snapshot used is not of any previous command, then it can see all the
	 * modifications made by current transactions till now.  So, we don't even
	 * attempt to fetch CID from undo in such cases.
	 */
	if (!GetCurrentCommandIdUsed() && cur_cid == snapshot->curcid)
		fetch_cid = false;
	else
		fetch_cid = true;

	/* Get transaction info */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, fetch_cid, snapshot, &zinfo);

	/*
	 * If we decided not to fetch the CID, it's because we know that every
	 * tuple which has been stamped with our XID was also stamped with a CID
	 * less than snapshot->curcid. The exact value doesn't matter, so we can
	 * just use FirstCommandId.  This might seem to be a problem in the case
	 * where snapshot->curcid == FirstCommandId, but in that case there can't
	 * be any tuples stamped with our XID at all, so won't matter what value
	 * we pick here.
	 */
	if (!fetch_cid)
		zinfo.cid = FirstCommandId;

	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		/*
		 * The tuple is not associated with a transaction slot that is new
		 * enough to matter, so all changes previously made to the tuple are
		 * now all-visible.  If the last operation performed was a delete or
		 * a non-inplace update, the tuple is now effectively gone; if it was
		 * an insert or an inplace update, use the current version.
		 */
		if (op == ZTUPLETID_GONE)
			zselect = ZVERSION_NONE;
		else
			zselect = ZVERSION_CURRENT;
	}
	else
		zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, zinfo.cid, snapshot);

	/*
	 * If we decided that our snapshot can't see any version of the tuple,
	 * return NULL.
	 */
	if (zselect == ZVERSION_NONE)
	{
		/*
		 * For non-inplace-updates, ctid needs to be retrieved from undo
		 * record if required.  If the tuple is moved to another
		 * partition, then we don't need ctid.
		 */
		if (ctid && (tuple->t_infomask & ZHEAP_UPDATED) != 0 &&
			!ZHeapTupleIsMoved(tuple->t_infomask))
			ZHeapTupleGetCtid(zhtup, buffer, zinfo.urec_ptr, ctid);

		return NULL;
	}

	/*
	 * If we decided that we need to consult the undo log to figure out
	 * what version our snapshot can see, delegate to GetTupleFromUndo.
	 */
	if (zselect == ZVERSION_OLDER)
		return GetTupleFromUndo(zinfo.urec_ptr,
								zhtup,
								snapshot,
								buffer,
								ctid,
								zinfo.trans_slot,
								InvalidTransactionId);

	return zhtup;
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
	Page		page;
	ItemId		lp;
	int			vis_info;
	ZHeapTupleTransInfo	zinfo;
	ZVersionSelector	zselect;

	if (all_dead)
		*all_dead = false;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, off);
	Assert(ItemIdIsDeleted(lp));

	zinfo.trans_slot = ItemIdGetTransactionSlot(lp);
	vis_info = ItemIdGetVisibilityInfo(lp);

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
check_trans_slot:
	if (zinfo.trans_slot != ZHTUP_SLOT_FROZEN)
	{
		/*
		 * We need undo record pointer to fetch the transaction
		 * information from undo.
		 */
		GetTransactionSlotInfo(buffer, off, zinfo.trans_slot,
							   true, false, &zinfo);

		if (vis_info & ITEMID_XACT_INVALID)
		{
			ZHeapTupleData undo_tup;
			uint32		epoch;

			ItemPointerSetBlockNumber(&undo_tup.t_self,
									  BufferGetBlockNumber(buffer));
			ItemPointerSetOffsetNumber(&undo_tup.t_self, off);

			/*
			 * It is quite possible that the tuple is showing some valid
			 * transaction slot, but actual slot has been frozen.  This can
			 * happen when the slot belongs to TPD entry and the corresponding
			 * TPD entry is pruned.
			 */
			if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
				goto check_trans_slot;

			zinfo.xid = InvalidTransactionId;
			FetchTransInfoFromUndo(&undo_tup, &epoch, &zinfo.xid, &zinfo.cid,
								   &zinfo.urec_ptr, false);
			zinfo.epoch_xid =
				U64FromFullTransactionId(FullTransactionIdFromEpochAndXid(epoch, zinfo.xid));
		}
		else
		{
			if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
				goto check_trans_slot;

			zinfo.cid = ZHeapPageGetCid(buffer, zinfo.epoch_xid,
										zinfo.urec_ptr, off);
		}
	}
	else
	{
		zinfo.epoch_xid = U64FromFullTransactionId(InvalidFullTransactionId);
		zinfo.xid = InvalidTransactionId;
		zinfo.cid = InvalidCommandId;
		zinfo.urec_ptr = InvalidUndoRecPtr;
	}

	/*
	 * The tuple is deleted and must be all visible if the transaction slot is
	 * cleared or latest xid that has changed the tuple precedes smallest xid
	 * that has undo.  Transaction slot can also be considered frozen if it
	 * belongs to previous epoch.
	 */
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		if (all_dead)
			*all_dead = true;
		return NULL;
	}

	/* Check XID and CID against snapshot. */
	if (IsMVCCSnapshot(snapshot))
		zselect = ZHeapSelectVersionMVCC(ZTUPLETID_GONE, zinfo.xid,
										 zinfo.cid, snapshot);
	else
	{
		/* ZBORKED: Why do we always use SnapshotSelf rules here? */
		zselect = ZHeapSelectVersionSelf(ZTUPLETID_GONE, zinfo.xid,
										 zinfo.cid);
	}

	if (zselect == ZVERSION_OLDER)
		return GetTupleFromUndoWithOffset(zinfo.urec_ptr,
										  snapshot,
										  buffer,
										  off,
										  zinfo.trans_slot);

	/* ZVERSION_CURRENT should be impossible here */
	Assert(zselect == ZVERSION_NONE);

	return NULL;
}

/*
 * ZHeapTupleSatisfiesUpdate
 *
 *	The return value for this API are same as HeapTupleSatisfiesUpdate.
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
 *	i.e. when the caller would wait on it to finish.
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
						  Buffer buffer, ItemPointer ctid,
						  ZHeapTupleTransInfo *zinfo,
						  SubTransactionId *subxid,
						  TransactionId *single_locker_xid,
						  int *single_locker_trans_slot, bool free_zhtup,
						  bool lock_allowed, Snapshot snapshot,
						  bool *in_place_updated_or_locked)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	CommandId	cur_comm_cid = GetCurrentCommandId(false);
	bool		visible;
	bool		fetch_cid = true;

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
		fetch_cid = false;

	/* Get transaction info */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, fetch_cid,
						   InvalidSnapshot, zinfo);

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
		Assert(!(zinfo->trans_slot == ZHTUP_SLOT_FROZEN &&
				 zinfo->epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)));

		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			if (fetch_cid && zinfo->cid >= curcid)
			{
				/* deleted after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   zinfo->trans_slot,
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
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   zinfo->trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
			{
				if (subxid)
					ZHeapTupleGetSubXid(zhtup, buffer, zinfo->urec_ptr,
										subxid);

				return TM_BeingModified;
			}
			else
				return TM_Invisible;
		}
		else if (TransactionIdDidCommit(zinfo->xid))
		{
			/*
			 * For non-inplace-updates, ctid needs to be retrieved from undo
			 * record if required.  If the tuple is moved to another
			 * partition, then we don't need ctid.
			 */
			if (ctid &&
				!ZHeapTupleIsMoved(tuple->t_infomask) &&
				tuple->t_infomask & ZHEAP_UPDATED)
				ZHeapTupleGetCtid(zhtup, buffer, zinfo->urec_ptr, ctid);

			/* tuple is deleted or non-inplace-updated */
			return TM_Updated;
		}
		else					/* transaction is aborted */
		{
			visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   zinfo->trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the undo
			 * before modifying the page.  Here, we don't need to fetch
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
		if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
			zinfo->epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		{
			bool		found = false;

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
				 * it's safe to return being updated so that the caller check
				 * for lock conflicts or perform rollback if necessary.
				 *
				 * If the single locker is our current transaction, then also
				 * we return being updated.
				 */
				return TM_BeingModified;
			}
		}

		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			if (fetch_cid && zinfo->cid >= curcid)
			{
				/*
				 * updated/locked after scan started, check previous tuple
				 * from undo
				 */
				visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   zinfo->trans_slot,
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
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   zinfo->trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			if (visible)
			{
				if (subxid)
					ZHeapTupleGetSubXid(zhtup, buffer, zinfo->urec_ptr,
										subxid);

				return TM_BeingModified;
			}
			else
				return TM_Invisible;
		}
		else if (TransactionIdDidCommit(zinfo->xid))
		{
			/*
			 * if tuple is updated and not in our snapshot, then allow to
			 * update it.
			 */
			if (lock_allowed || !XidInMVCCSnapshot(zinfo->xid, snapshot))
				return TM_Ok;
			else
				return TM_Updated;
		}
		else					/* transaction is aborted */
		{
			visible = UndoTupleSatisfiesUpdate(zinfo->urec_ptr,
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   zinfo->trans_slot,
											   InvalidTransactionId,
											   free_zhtup,
											   in_place_updated_or_locked);

			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the undo
			 * before modifying the page.  Here, we don't need to fetch
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
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo->epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return TM_Ok;

	if (TransactionIdIsCurrentTransactionId(zinfo->xid))
	{
		if (fetch_cid && zinfo->cid >= curcid)
			return TM_Invisible;	/* inserted after scan started */
		else
			return TM_Ok;		/* inserted before scan started */
	}
	else if (TransactionIdIsInProgress(zinfo->xid))
		return TM_Invisible;
	else if (TransactionIdDidCommit(zinfo->xid))
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

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		ZHeapTupleTransInfo	zinfo;

		/* Get transaction id. */
		ZHeapTupleGetTransInfo(zhtup, buffer, false, false, InvalidSnapshot,
						   &zinfo);
		/*
		 * The tuple is deleted and must be all visible if the transaction
		 * slot is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			zinfo.epoch_xid < OldestXmin)
			return true;
	}

	return false;				/* Tuple is still alive */
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
	ZHeapTupleTransInfo	zinfo;
	ZTupleTidOp op;
	ZVersionSelector	zselect;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get last operation type */
	op = ZHeapTidOpFromInfomask(tuple->t_infomask);

	/* Get transaction information */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, false, InvalidSnapshot,
						   &zinfo);

	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		/*
		 * The tuple is not associated with a transaction slot that is new
		 * enough to matter, so all changes previously made to the tuple are
		 * now all-visible.  If the last operation performed was a delete or
		 * a non-inplace update, the tuple is now effectively gone; if it was
		 * an insert or an inplace update, use the current version.
		 */
		if (op == ZTUPLETID_GONE)
			zselect = ZVERSION_NONE;
		else
			zselect = ZVERSION_CURRENT;
	}
	else
		zselect = ZHeapSelectVersionSelf(op, zinfo.xid, zinfo.cid);

	/*
	 * If we decided that our snapshot can't see any version of the tuple,
	 * return NULL.
	 */
	if (zselect == ZVERSION_NONE)
		return NULL;

	/*
	 * If we decided that we need to consult the undo log to figure out
	 * what version our snapshot can see, delegate to GetTupleFromUndo.
	 */
	if (zselect == ZVERSION_OLDER)
		return GetTupleFromUndo(zinfo.urec_ptr,
								zhtup,
								snapshot,
								buffer,
								ctid,
								zinfo.trans_slot,
								InvalidTransactionId);

	return zhtup;
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
	ZHeapTupleTransInfo	zinfo;
	ZVersionSelector	zselect;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	snapshot->xmin = snapshot->xmax = InvalidTransactionId;
	snapshot->subxid = InvalidSubTransactionId;
	snapshot->speculativeToken = 0;

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, false, InvalidSnapshot,
						   &zinfo);

	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		/*
		 * The tuple is not associated with a transaction slot that is new
		 * enough to matter, so all changes previously made to the tuple are
		 * now all-visible.  If the last operation performed was a delete or
		 * a non-inplace update, the tuple is now effectively gone; if it was
		 * an insert or an inplace update, use the current version.
		 */
		if ((tuple->t_infomask & (ZHEAP_DELETED|ZHEAP_UPDATED)) != 0)
			zselect = ZVERSION_NONE;
		else
			zselect = ZVERSION_CURRENT;
	}
	else if ((tuple->t_infomask & (ZHEAP_DELETED|ZHEAP_UPDATED)) != 0)
	{
		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			zselect = ZVERSION_NONE;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			snapshot->xmax = zinfo.xid;
			if (UndoRecPtrIsValid(zinfo.urec_ptr))
				ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr,
									&snapshot->subxid);
			zselect = ZVERSION_CURRENT;
		}
		else if (TransactionIdDidCommit(zinfo.xid))
		{
			/* tuple is deleted or non-inplace-updated */
			zselect = ZVERSION_NONE;
		}
		else					/* transaction is aborted */
			zselect = ZVERSION_OLDER;
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED ||
			 tuple->t_infomask & ZHEAP_XID_LOCK_ONLY)
	{
		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			zselect = ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			if (!ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
			{
				snapshot->xmax = zinfo.xid;
				if (UndoRecPtrIsValid(zinfo.urec_ptr))
					ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr,
										&snapshot->subxid);
			}
			zselect = ZVERSION_CURRENT; /* being updated */
		}
		else if (TransactionIdDidCommit(zinfo.xid))
			zselect = ZVERSION_CURRENT;	/* tuple is updated by someone else */
		else					/* transaction is aborted */
			zselect = ZVERSION_OLDER;
	}
	else
	{
		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			zselect = ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			/* Return the speculative token to caller. */
			if (ZHeapTupleHeaderIsSpeculative(tuple))
			{
				ZHeapTupleGetSpecToken(zhtup, buffer, zinfo.urec_ptr,
									   &snapshot->speculativeToken);

				Assert(snapshot->speculativeToken != 0);
			}

			snapshot->xmin = zinfo.xid;
			if (UndoRecPtrIsValid(zinfo.urec_ptr))
				ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr,
									&snapshot->subxid);
			zselect = ZVERSION_CURRENT; /* in insertion by other */
		}
		else if (TransactionIdDidCommit(zinfo.xid))
			zselect = ZVERSION_CURRENT;
		else
		{
			/* inserting transaction aborted */
			zselect = ZVERSION_NONE;
		}
	}

	/*
	 * If we decided that our snapshot can't see any version of the tuple,
	 * return NULL.
	 */
	if (zselect == ZVERSION_NONE)
	{
		/*
		 * For non-inplace-updates, ctid needs to be retrieved from undo
		 * record if required.  If the tuple is moved to another
		 * partition, then we don't need ctid.
		 */
		if (ctid && (tuple->t_infomask & ZHEAP_UPDATED) != 0 &&
			!ZHeapTupleIsMoved(tuple->t_infomask))
			ZHeapTupleGetCtid(zhtup, buffer, zinfo.urec_ptr, ctid);

		return NULL;
	}

	/*
	 * If we decided that we need to consult the undo log to figure out
	 * what version our snapshot can see, delegate to GetTupleFromUndo.
	 */
	if (zselect == ZVERSION_OLDER)
		return GetTupleFromUndo(zinfo.urec_ptr,
								zhtup,
								snapshot,
								buffer,
								ctid,
								zinfo.trans_slot,
								InvalidTransactionId);

	return zhtup;
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
		ZHeapTupleTransInfo	zinfo;

		GetTransactionSlotInfo(buffer,
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   ZHeapTupleHeaderGetXactSlot(zhtup->t_data),
							   true,
							   false,
							   &zinfo);

		/*
		 * We always expect non-frozen transaction slot here as the caller
		 * tries to fetch the ctid of tuples that are visible to the snapshot,
		 * so corresponding undo record can't be discarded.
		 */
		Assert(zinfo.trans_slot != ZHTUP_SLOT_FROZEN);

		ZHeapTupleGetCtid(zhtup, buffer, zinfo.urec_ptr, ctid);
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
 *	version of the tuple and return the prior committed xid and status as
 *	HEAPTUPLE_LIVE.
 *	If the latest transaction for the tuple aborted and it also inserted
 *	the tuple, we return the aborted transaction id and status as
 *	HEAPTUPLE_DEAD. In this case, the caller *should* never mark the
 *	corresponding item id as dead. Because, when undo action for the same will
 *	be performed, we need the item pointer.
 */
HTSV_Result
ZHeapTupleSatisfiesOldestXmin(ZHeapTuple * ztuple, TransactionId OldestXmin,
							  Buffer buffer, TransactionId *xid,
							  SubTransactionId *subxid)
{
	ZHeapTuple	zhtup = *ztuple;
	ZHeapTupleHeader tuple = zhtup->t_data;
	ZHeapTupleTransInfo	zinfo;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, false, InvalidSnapshot,
						   &zinfo);
	*xid = zinfo.xid;

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction
		 * slot is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return HEAPTUPLE_DEAD;

		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			return HEAPTUPLE_DELETE_IN_PROGRESS;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			/* Get Sub transaction id */
			if (subxid)
				ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr, subxid);

			return HEAPTUPLE_DELETE_IN_PROGRESS;
		}
		else if (TransactionIdDidCommit(zinfo.xid))
		{
			/*
			 * Deleter committed, but perhaps it was recent enough that some
			 * open transactions could still see the tuple.
			 */
			if (!TransactionIdPrecedes(zinfo.xid, OldestXmin))
				return HEAPTUPLE_RECENTLY_DEAD;

			/* Otherwise, it's dead and removable */
			return HEAPTUPLE_DEAD;
		}
		else					/* transaction is aborted */
		{
			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.
			 */
			*ztuple = GetTupleFromUndoForAbortedXact(zinfo.urec_ptr, buffer,
													 zinfo.trans_slot, zhtup,
													 xid);
			if (*ztuple != NULL)
				return HEAPTUPLE_LIVE;
			else
			{
				/*
				 * If the transaction that inserted the tuple got aborted, we
				 * should return the aborted transaction id.
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
		 * it's still in progress, we should return
		 * HEAPTUPLE_INSERT_IN_PROGRESS. Similarly, if the inserted
		 * transaction got committed, we should return HEAPTUPLE_LIVE. The
		 * subsequent checks already takes care of all these possible
		 * scenarios, so we don't need any extra checks here.
		 */
	}

	/* The tuple is either a newly inserted tuple or is in-place updated. */

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return HEAPTUPLE_LIVE;

	if (TransactionIdIsCurrentTransactionId(zinfo.xid))
		return HEAPTUPLE_INSERT_IN_PROGRESS;
	else if (TransactionIdIsInProgress(zinfo.xid))
	{
		/* Get Sub transaction id */
		if (subxid)
			ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr, subxid);
		return HEAPTUPLE_INSERT_IN_PROGRESS;	/* in insertion by other */
	}
	else if (TransactionIdDidCommit(zinfo.xid))
		return HEAPTUPLE_LIVE;
	else						/* transaction is aborted */
	{
		if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED)
		{
			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.
			 */
			*ztuple = GetTupleFromUndoForAbortedXact(zinfo.urec_ptr,
													 buffer,
													 zinfo.trans_slot,
													 zhtup,
													 xid);
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
 *	surely dead to everyone, i.e. vacuumable.
 *
 *	This is an interface to ZHeapTupleSatisfiesOldestXmin that meets the
 *	SnapshotSatisfiesFunc API, so it can be used through a Snapshot.
 *	snapshot->xmin must have been set up with the xmin horizon to use.
 */
ZHeapTuple
ZHeapTupleSatisfiesNonVacuumable(ZHeapTuple ztup, Snapshot snapshot,
								 Buffer buffer, ItemPointer ctid)
{
	TransactionId xid;

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
 * xid. The caller should avoid such tuple for any kind of pruning/vacuuming.
 */
ZHTSV_Result
ZHeapTupleSatisfiesVacuum(ZHeapTuple zhtup, TransactionId OldestXmin,
						  Buffer buffer, TransactionId *xid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	ZHeapTupleTransInfo	zinfo;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, false, InvalidSnapshot,
						   &zinfo);
	*xid = zinfo.xid;

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		/*
		 * The tuple is deleted and must be all visible if the transaction
		 * slot is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return ZHEAPTUPLE_DEAD;

		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			return ZHEAPTUPLE_DELETE_IN_PROGRESS;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			return ZHEAPTUPLE_DELETE_IN_PROGRESS;
		}
		else if (TransactionIdDidCommit(zinfo.xid))
		{
			/*
			 * Deleter committed, but perhaps it was recent enough that some
			 * open transactions could still see the tuple.
			 */
			if (!TransactionIdPrecedes(zinfo.xid, OldestXmin))
				return ZHEAPTUPLE_RECENTLY_DEAD;

			/* Otherwise, it's dead and removable */
			return ZHEAPTUPLE_DEAD;
		}
		else					/* transaction is aborted */
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
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return ZHEAPTUPLE_LIVE;

	if (TransactionIdIsCurrentTransactionId(zinfo.xid))
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;
	else if (TransactionIdIsInProgress(zinfo.xid))
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;	/* in insertion by other */
	else if (TransactionIdDidCommit(zinfo.xid))
		return ZHEAPTUPLE_LIVE;
	else						/* transaction is aborted */
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
			elog(ERROR, "unsupported snapshot type");
			break;
		case SNAPSHOT_NON_VACUUMABLE:
			return ZHeapTupleSatisfiesNonVacuumable(stup, snapshot, buffer, ctid);
			break;
	}

	return NULL;				/* silence compiler */
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
	HTSV_Result htsvResult;
	ItemId		lp;
	OffsetNumber offnum;
	Page		dp;
	ZHeapTuple	tuple;
	Size		tuple_len;
	bool		tuple_inplace_updated = false;
	Snapshot	snap;

	Assert(ItemPointerGetBlockNumber(tid) == BufferGetBlockNumber(buffer));
	offnum = ItemPointerGetOffsetNumber(tid);
	dp = BufferGetPage(buffer);

	/* check for bogus TID */
	Assert(offnum >= FirstOffsetNumber &&
		   offnum <= PageGetMaxOffsetNumber(dp));

	lp = PageGetItemId(dp, offnum);

	/* check for unused or dead items */
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If the record is deleted and pruned, its place in the page might have
	 * been taken by another of its kind.
	 */
	if (ItemIdIsDeleted(lp))
	{
		/*
		 * If the tuple is still visible to us, then we've a conflict.
		 * Because, the transaction that deleted the tuple already got
		 * committed.
		 */
		if (visible)
		{
			snap = GetTransactionSnapshot();
			tuple = ZHeapGetVisibleTuple(offnum, snap, buffer, NULL);
			*xid = ZHeapTupleGetTransXID(tuple, buffer, false);
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
				 * If xid is invalid, then we know that slot is frozen and
				 * tuple will be visible so we can return false.
				 */
				if (*xid == InvalidTransactionId)
				{
					Assert(visible);
					return false;
				}

				/*
				 * We can't rely on callers visibility information for
				 * in-place updated tuples because they consider the tuple as
				 * visible if any version of the tuple is visible whereas we
				 * want to know the status of current tuple.  In case of
				 * aborted transactions, it is quite possible that the
				 * rollback actions aren't yet applied and we need the status
				 * of last committed transaction;
				 * ZHeapTupleSatisfiesOldestXmin returns us that information.
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
