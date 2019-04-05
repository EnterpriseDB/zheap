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
#include "utils/tqual.h"
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
	ZVERSION_OLDER,
	ZVERSION_CHECK_CID
} ZVersionSelector;

#define SNAPSHOT_REQUESTS_SPECTOKEN		0x0001
#define SNAPSHOT_REQUESTS_SUBXID		0x0002

static ZHeapTuple GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
				 Snapshot snapshot, Buffer buffer, OffsetNumber offnum,
				 ItemPointer ctid, int trans_slot);
static ZHeapTuple GetTupleFromUndoForAbortedXact(UndoRecPtr urec_ptr, Buffer buffer, int trans_slot,
												 ZHeapTuple ztuple, TransactionId *xid);
static ZTupleTidOp ZHeapTidOpFromInfomask(uint16 infomask);
static ZVersionSelector ZHeapSelectVersionMVCC(ZTupleTidOp op,
				   TransactionId xid, Snapshot snapshot);
static ZVersionSelector ZHeapSelectVersionUpdate(ZTupleTidOp op,
						 TransactionId xid, CommandId visibility_cid);
static ZVersionSelector ZHeapCheckCID(ZTupleTidOp op,
			  CommandId tuple_cid, CommandId visibility_cid);
static ZVersionSelector ZHeapSelectVersionSelf(ZTupleTidOp op,
					   TransactionId xid);
static ZVersionSelector ZHeapSelectVersionDirty(ZTupleTidOp op,
						uint16 infomask, ZHeapTupleTransInfo *zinfo,
						Snapshot snapshot, int *snapshot_requests);

/*
 * FetchTransInfoFromUndo
 *
 * Retrieve information about the transaction which has last operated on the
 * specified tuple.
 */
void
FetchTransInfoFromUndo(BlockNumber blocknum, OffsetNumber offnum,
					   TransactionId xid, ZHeapTupleTransInfo *zinfo)
{
	UnpackedUndoRecord *urec;
	uint32	epoch;

	while (1)
	{
		/*
		 * The transaction slot referred by the undo tuple could have been
		 * reused multiple times, so to ensure that we have fetched the right
		 * undo record we need to verify that the undo record contains xid same
		 * as the xid that has modified the tuple. (However, when the tuple
		 * is from the zheap itself rather than from undo, it's OK to pass
		 * InvalidTransactionId as the XID, because we must be looking for
		 * the latest version of the tuple in the undo rather than some
		 * earlier one.)
		 */
		urec = UndoFetchRecord(zinfo->urec_ptr, blocknum, offnum,
							   xid,
							   &zinfo->urec_ptr,
							   ZHeapSatisfyUndoRecord);

		/*
		 * If the undo record containing the information about the last
		 * transaction that has operated on the tuple has been discareded,
		 * this version of the tuple must be all-visible.
		 */
		if (urec == NULL)
		{
			zinfo->epoch_xid = InvalidFullTransactionId;
			zinfo->xid = InvalidTransactionId;
			zinfo->cid = InvalidCommandId;
			zinfo->urec_ptr = InvalidUndoRecPtr;
			return;
		}

		/*
		 * If this is a UNDO_XID_LOCK_ONLY or UNDO_XID_MULTI_LOCK_ONLY
		 * operation, it doesn't have any useful transaction information and
		 * should be skipped.  See compute_new_xid_infomask for more details.
		 * Otherwise, we've found the correct record.
		 */
		if (urec->uur_type != UNDO_XID_LOCK_ONLY &&
			 urec->uur_type != UNDO_XID_MULTI_LOCK_ONLY)
			break;

		/* We'll need to look further back into the undo log. */
		xid = InvalidTransactionId;
		zinfo->urec_ptr = urec->uur_blkprev;
		UndoRecordRelease(urec);
	}

	/*
	 * If we reach here, this means the transaction id that has last modified
	 * this tuple must be in 2-billion xid range of oldestXidHavingUndo, so we
	 * can get compute its epoch as we do for current transaction.
	 */
	epoch = GetEpochForXid(urec->uur_xid);
	zinfo->xid = urec->uur_xid;
	zinfo->epoch_xid = FullTransactionIdFromEpochAndXid(epoch, zinfo->xid);
	zinfo->cid = urec->uur_cid;
	UndoRecordRelease(urec);
}

/*
 * ZHeapUpdateTransactionSlotInfo
 *
 * Get the transaction slot information for the specified transaction slot,
 * and use it to update the trans_slot and urec_ptr values for the
 * ZHeapTupleTransInfo passed as an argument.
 */
void
ZHeapUpdateTransactionSlotInfo(int trans_slot, Buffer buffer,
							   OffsetNumber offnum, ZHeapTupleTransInfo *zinfo)
{
	ZHeapTupleTransInfo	zinfo2;

	/*
	 * It is quite possible that the tuple is showing some valid
	 * transaction slot, but actual slot has been frozen.  This can happen
	 * when the slot belongs to TPD entry and the corresponding TPD entry
	 * is pruned.
	 */
	GetTransactionSlotInfo(buffer,
						   offnum,
						   trans_slot,
						   true,
						   true,
						   &zinfo2);
	zinfo->trans_slot = zinfo2.trans_slot;
	zinfo->urec_ptr = zinfo2.urec_ptr;
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
		FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
							   InvalidTransactionId, &zinfo);
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
					   bool fetch_cid, Snapshot snapshot,
					   ZHeapTupleTransInfo *zinfo)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	ItemId		lp;
	Page		page;
	ItemPointer tid = &(zhtup->t_self);
	BlockNumber	blocknum = BufferGetBlockNumber(buf);
	OffsetNumber offnum = ItemPointerGetOffsetNumber(tid);
	bool		is_invalid_slot = false;

	page = BufferGetPage(buf);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));
	if (!ItemIdIsDeleted(lp))
	{
		zinfo->trans_slot = ZHeapTupleHeaderGetXactSlot(tuple);
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
	{
slot_is_frozen:
		zinfo->trans_slot = ZHTUP_SLOT_FROZEN;
		zinfo->epoch_xid = InvalidFullTransactionId;
		zinfo->xid = InvalidTransactionId;
		zinfo->cid = InvalidCommandId;
		zinfo->urec_ptr = InvalidUndoRecPtr;
		return;
	}

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
		 * (e.g. zheap_update) because this xid is still not all visible and
		 * may be not visible to some of the concurrent session.  So if we
		 * store invalid xid in the undo as prevxid then that tuple version
		 * will be considered as all visible which is not true.
		 */
		if ((TransactionIdIsValid(zinfo->xid) &&
			 (TransactionIdPrecedes(zinfo->xid, pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)) ||
			  (snapshot != InvalidSnapshot && !XidInMVCCSnapshot(zinfo->xid, snapshot)))) ||
			UndoLogIsDiscarded(zinfo->urec_ptr))
			goto slot_is_frozen;

		FetchTransInfoFromUndo(blocknum, offnum, InvalidTransactionId, zinfo);
	}
	else
	{
		if (fetch_cid && TransactionIdIsCurrentTransactionId(zinfo->xid))
			zinfo->cid = ZHeapPageGetCid(buf, zinfo->epoch_xid,
										 zinfo->urec_ptr, offnum);
		else
			zinfo->cid = InvalidCommandId;
	}
}

/*
 * ZHeapTupleGetTransXID - Retrieve just the XID that last modified the tuple.
 */
TransactionId
ZHeapTupleGetTransXID(ZHeapTuple zhtup, Buffer buf, bool nobuflock)
{
	ZHeapTupleTransInfo	zinfo;
	ZHeapTupleData	mytup;

	if (nobuflock)
	{
		ItemPointer tid = &(zhtup->t_self);
		OffsetNumber offnum = ItemPointerGetOffsetNumber(tid);
		Page		page;
		ItemId		lp;

		LockBuffer(buf, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buf);
		lp = PageGetItemId(page, offnum);

		/*
		 * ZBORKED: Why is there only handling here for the !ItemIdIsDeleted
		 * case?  Maybe we should have a completely separate function for the
		 * nbuflock case that does Assert(!ItemIdIsDeleted(lp)).
		 */
		if (!ItemIdIsDeleted(lp))
		{
			/*
			 * If the tuple is updated such that its transaction slot has been
			 * changed, then we will never be able to get the correct tuple
			 * from undo. To avoid, that we get the latest tuple from page
			 * rather than relying on it's in-memory copy.
			 *
			 * ZBORKED: It should probably be the caller's job to ensure that
			 * we are passed the correct tuple, rather than our job to go
			 * re-fetch it.
			 */
			memcpy(&mytup, zhtup, sizeof(ZHeapTupleData));
			mytup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			mytup.t_len = ItemIdGetLength(lp);
			zhtup = &mytup;
		}
	}

	ZHeapTupleGetTransInfo(zhtup, buf, false, InvalidSnapshot, &zinfo);

	/* Release any buffer lock we acquired. */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	return zinfo.xid;
}

/*
 * GetTupleFromUndoRecord
 *
 * Look up an undo record and copy a tuple from it, updating zinfo and ctid,
 * and freeing the old tuple if so requested.
 *
 * If the undo record cannot be looked up, the tuple passed in as ztuple is
 * returned and the function returns false.  If the undo record is looked up
 * and the tuple found there is known to be the root tuple, that tuple is
 * returned and the function still returns false.  Otherwise, the tuple
 * looked up is returned and the function returns true.
 */
static bool
GetTupleFromUndoRecord(UndoRecPtr urec_ptr, TransactionId xid,
					   Buffer buffer, OffsetNumber offnum,
					   ZHeapTuple *ztuple, bool free_ztuple,
					   ZHeapTupleTransInfo *zinfo, ItemPointer ctid)
{
	UnpackedUndoRecord *urec;
	uint32		epoch;
	uint64		oldestXidHavingUndo;

	urec = UndoFetchRecord(urec_ptr,
						   BufferGetBlockNumber(buffer),
						   offnum,
						   xid,
						   NULL,
						   ZHeapSatisfyUndoRecord);
	if (urec == NULL)
		return false;

	*ztuple =
		CopyTupleFromUndoRecord(urec, *ztuple, &zinfo->trans_slot, NULL,
								free_ztuple, BufferGetPage(buffer));

	zinfo->urec_ptr = urec->uur_blkprev;
	zinfo->xid = urec->uur_prevxid;

	/*
	 * We don't allow XIDs with an age of more than 2 billion in undo, so
	 * we can infer the epoch here. (XXX Is this a valid justification
	 * given that we're dealing with uur_prevxid, not uur_xid?)
	 */
	epoch = GetEpochForXid(urec->uur_prevxid);
	zinfo->epoch_xid =
		FullTransactionIdFromEpochAndXid(epoch, urec->uur_prevxid);

	/*
	 * For non-inplace-updates, ctid needs to be retrieved from undo
	 * record if required.
	 */
	if (ctid)
	{
		if (urec->uur_type == UNDO_UPDATE)
			*ctid = *((ItemPointer) urec->uur_payload.data);
		else
			*ctid = (*ztuple)->t_self;
	}

	UndoRecordRelease(urec);

	/*
	 * If slot is frozen or XID is FrozenTransactionId, there are no older
	 * versions.
	 */
	if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(zinfo->xid, FrozenTransactionId))
		return false;

	/*
	 * If the XID is older than any XID that has undo, there are no older
	 * versions.
	 */
	oldestXidHavingUndo =
		pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo);
	if (zinfo->epoch_xid < oldestXidHavingUndo)
		return false;

	return true;
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
	TransactionId prev_undo_xid PG_USED_FOR_ASSERTS_ONLY;
	int			prev_trans_slot_id = trans_slot;
	ZHeapTupleTransInfo	zinfo;
	OffsetNumber	offnum = ItemPointerGetOffsetNumber(&ztuple->t_self);

	prev_undo_xid = InvalidTransactionId;
fetch_prior_undo_record:
	zinfo.urec_ptr = InvalidUndoRecPtr;
	zinfo.trans_slot = InvalidXactSlotId;

	if (!GetTupleFromUndoRecord(urec_ptr, InvalidTransactionId,
								buffer, offnum, &ztuple,
								true, &zinfo, NULL))
		return ztuple;

	/* we can't further operate on deleted or non-inplace-updated tuple */
	Assert(ZHeapTidOpFromInfomask(ztuple->t_data->t_infomask)
				!= ZTUPLETID_GONE);

	/*
	 * We know that we have the latest version of the tuple if the latest XID
	 * committed or if the transaction slot has been reused (which is what
	 * ZHeapTupleHasInvalidXact tests).
	 */
	if (TransactionIdDidCommit(zinfo.xid) ||
		ZHeapTupleHasInvalidXact(ztuple->t_data->t_infomask))
	{
		*xid = zinfo.xid;
		return ztuple;
	}

	/*
	 * If the undo tuple is stamped with a different transaction, then either
	 * the previous transaction is committed or tuple must be locked only. In
	 * both cases, we can return the tuple fetched from undo.
	 */
	if (zinfo.trans_slot != prev_trans_slot_id)
	{
		GetTransactionSlotInfo(buffer,
							   offnum,
							   zinfo.trans_slot,
							   true,
							   true,
							   &zinfo);
		FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
							   zinfo.xid, &zinfo);

		Assert(TransactionIdDidCommit(zinfo.xid) ||
			   ZHEAP_XID_IS_LOCKED_ONLY(ztuple->t_data->t_infomask));

		*xid = zinfo.xid;
		return ztuple;
	}

	/* transaction must be aborted. */
	Assert(!TransactionIdIsCurrentTransactionId(zinfo.xid));
	Assert(!TransactionIdIsInProgress(zinfo.xid));
	Assert(TransactionIdDidAbort(zinfo.xid));

	/*
	 * We can't have two aborted transaction with pending rollback state for
	 * the same tuple.
	 */
	Assert(!TransactionIdIsValid(prev_undo_xid) ||
		   TransactionIdEquals(prev_undo_xid, zinfo.xid));

	/*
	 * If undo tuple is the root tuple inserted by the aborted transaction, we
	 * don't have to process any further. The tuple is not visible to us.
	 */
	if (!IsZHeapTupleModified(ztuple->t_data->t_infomask))
	{
		/* before leaving, free the allocated memory */
		pfree(ztuple);
		return NULL;
	}

	urec_ptr = zinfo.urec_ptr;
	prev_undo_xid = zinfo.xid;
	prev_trans_slot_id = zinfo.trans_slot;

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
GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple ztuple,
				 Snapshot snapshot, Buffer buffer, OffsetNumber offnum,
				 ItemPointer ctid, int trans_slot)
{
	TransactionId	prev_undo_xid = InvalidTransactionId;
	int			prev_trans_slot_id = trans_slot;
	ZHeapTupleTransInfo	zinfo;

	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible. loop until we find the visible
	 * version.
	 */
	while (1)
	{
		ZTupleTidOp			op;
		ZVersionSelector	zselect;
		bool		have_cid = false;

		zinfo.urec_ptr = InvalidUndoRecPtr;
		zinfo.cid = InvalidCommandId;
		zinfo.trans_slot = InvalidXactSlotId;

		Assert(ztuple == NULL ||
			   ItemPointerGetOffsetNumber(&ztuple->t_self) == offnum);

		if (!GetTupleFromUndoRecord(urec_ptr, prev_undo_xid, buffer,
									offnum, &ztuple,
									(ztuple != NULL), &zinfo, ctid))
			return ztuple;

		/*
		 * Change the undo chain if the undo tuple is stamped with the
		 * different transaction.
		 */
		if (zinfo.trans_slot != prev_trans_slot_id)
			ZHeapUpdateTransactionSlotInfo(zinfo.trans_slot, buffer, offnum,
										   &zinfo);

		op = ZHeapTidOpFromInfomask(ztuple->t_data->t_infomask);

		/* can't further operate on deleted or non-inplace-updated tuple */
		Assert(op != ZTUPLETID_GONE);

		/*
		 * We need to fetch all the transaction related information from
		 * undo record for the tuples that point to a slot that gets
		 * invalidated for reuse at some point of time.  See
		 * PageFreezeTransSlots.
		 */
		if (ZHeapTupleHasInvalidXact(ztuple->t_data->t_infomask))
		{
			FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
								   zinfo.xid, &zinfo);
			have_cid = true;
		}
		else if (zinfo.cid != InvalidCommandId)
			have_cid = true;

		/*
		 * The tuple must be all visible if the transaction slot is cleared
		 * or latest xid that has changed the tuple is too old that it is
		 * all-visible or it precedes smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			TransactionIdEquals(zinfo.xid, FrozenTransactionId) ||
			zinfo.epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			return ztuple;

		/* Check XID against snapshot. */
		if (IsMVCCSnapshot(snapshot))
			zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, snapshot);
		else
		{
			/* ZBORKED: Why do we always use SnapshotSelf rules here? */
			zselect = ZHeapSelectVersionSelf(op, zinfo.xid);
		}

		/* If necessary, check CID against snapshot. */
		if (zselect == ZVERSION_CHECK_CID)
		{
			if (!have_cid)
			{
				/*
				 * we don't use prev_undo_xid to fetch the undo record for
				 * cid as it is required only when transaction is current
				 * transaction in which case there is no risk of transaction
				 * chain switching, so we are safe.
				 */
				zinfo.cid = ZHeapTupleGetCid(ztuple, buffer, zinfo.urec_ptr,
											 zinfo.trans_slot);
				have_cid = true;
			}

			/* OK, now we can make a final visibility decision. */
			zselect = ZHeapCheckCID(op, zinfo.cid, snapshot->curcid);
		}

		/* Return the current version, or nothing, if appropriate. */
		if (zselect == ZVERSION_CURRENT)
			return ztuple;
		if (zselect == ZVERSION_NONE)
			return NULL;

		/* Need to check next older version, so loop around. */
		Assert(zselect == ZVERSION_OLDER);
		urec_ptr = zinfo.urec_ptr;
		prev_undo_xid = zinfo.xid;
		prev_trans_slot_id = zinfo.trans_slot;
	}

	/* we should never reach here */
	return NULL;
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
UndoTupleSatisfiesUpdate(UndoRecPtr urec_ptr, ZHeapTuple ztuple,
						 CommandId curcid, Buffer buffer,
						 ItemPointer ctid, int trans_slot,
						 TransactionId prev_undo_xid, bool free_zhtup,
						 bool *in_place_updated_or_locked)
{
	int			prev_trans_slot_id = trans_slot;
	ZTupleTidOp	op;
	ZVersionSelector	zselect;
	ZHeapTupleTransInfo	zinfo;
	OffsetNumber    offnum = ItemPointerGetOffsetNumber(&ztuple->t_self);
	bool		have_cid = false;

	/*
	 * tuple is modified after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
fetch_prior_undo_record:
	zinfo.urec_ptr = InvalidUndoRecPtr;
	zinfo.cid = InvalidCommandId;
	zinfo.trans_slot = InvalidXactSlotId;

	if (!GetTupleFromUndoRecord(urec_ptr, prev_undo_xid, buffer,
								offnum, &ztuple,
								free_zhtup, &zinfo, ctid))
	{
		/* If undo is discarded, then current tuple is visible. */
		zselect = ZVERSION_CURRENT;
		goto result_available;
	}

	op = ZHeapTidOpFromInfomask(ztuple->t_data->t_infomask);
	Assert(op != ZTUPLETID_GONE);   /* shouldn't find such tuples in undo */

	/*
	 * Change the undo chain if the undo tuple is stamped with the different
	 * transaction slot.
	 */
	if (zinfo.trans_slot != prev_trans_slot_id)
		ZHeapUpdateTransactionSlotInfo(zinfo.trans_slot, buffer,
									   ItemPointerGetOffsetNumber(&ztuple->t_self),
									   &zinfo);

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (ZHeapTupleHasInvalidXact(ztuple->t_data->t_infomask))
	{
		FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
							   zinfo.xid, &zinfo);
		have_cid = true;
	}
	else if (zinfo.cid != InvalidCommandId)
		have_cid = true;

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple is too old that it is all-visible
	 * or it precedes smallest xid that has undo.
	 */
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
		TransactionIdEquals(zinfo.xid, FrozenTransactionId) ||
		zinfo.xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
	{
		zselect = ZVERSION_CURRENT;
		goto result_available;
	}

	zselect = ZHeapSelectVersionUpdate(op, zinfo.xid, curcid);

	if (zselect == ZVERSION_CHECK_CID)
	{
		if (!have_cid)
		{
			/*
			 * we don't use prev_undo_xid to fetch the undo record for cid as
			 * it is required only when transaction is current transaction in
			 * which case there is no risk of transaction chain switching, so
			 * we are safe.
			 */
			zinfo.cid = ZHeapTupleGetCid(ztuple, buffer, zinfo.urec_ptr,
										 zinfo.trans_slot);
			have_cid = true;
		}
		zselect = ZHeapCheckCID(op, zinfo.cid, curcid);
	}

	if (zselect == ZVERSION_OLDER)
	{
		/* Note the values required to fetch prior tuple in undo chain. */
		urec_ptr = zinfo.urec_ptr;
		prev_undo_xid = zinfo.xid;
		prev_trans_slot_id = zinfo.trans_slot;
		free_zhtup = true;

		/* And then go fetch it. */
		goto fetch_prior_undo_record;
	}

result_available:
	if (ztuple)
		pfree(ztuple);
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
 * version of a tuple, an older version, or no version at all.  We only have
 * the XID available here, so if the CID turns out to be relevant, we must
 * return ZVERSION_CHECK_CID; caller is responsible for calling ZHeapCheckCID
 * with the appropriate CID to obtain a final answer.
 */
static ZVersionSelector
ZHeapSelectVersionMVCC(ZTupleTidOp op, TransactionId xid, Snapshot snapshot)
{
	Assert(IsMVCCSnapshot(snapshot));

	if (TransactionIdIsCurrentTransactionId(xid))
	{
		/*
		 * This transaction is still running and belongs to the current
		 * session.  If the current CID has been used to stamp a tuple or
		 * the snapshot belongs to an older CID, then we need the CID for
		 * this tuple to make a final visibility decision.
		 */
		if (GetCurrentCommandIdUsed() ||
			GetCurrentCommandId(false) != snapshot->curcid)
			return ZVERSION_CHECK_CID;

		/* Nothing has changed since our scan started. */
		return (op == ZTUPLETID_GONE ? ZVERSION_NONE : ZVERSION_CURRENT);
	}

	if (XidInMVCCSnapshot(xid, snapshot) || !TransactionIdDidCommit(xid))
	{
		/*
		 * The XID is not visible to us, either because it aborted or because
		 * it's in our MVCC snapshot.  If this is a new tuple, that means we
		 * can't see it at all; otherwise, we need to check older versions.
		 */
		return (op == ZTUPLETID_NEW ? ZVERSION_NONE : ZVERSION_OLDER);
	}

	/* The XID is visible to us. */
	return (op == ZTUPLETID_GONE ? ZVERSION_NONE : ZVERSION_CURRENT);
}

/*
 * ZHeapSelectVersionUpdate
 *
 * Decide whether we should try to update the current version of a tuple,
 * or an older version, or no version at all.
 *
 * Like ZHeapSelectVersionMVCC, we may return ZVERSION_CHECK_CID; the caller
 * will need to invoke ZHeapCheckCID to get a final answer.  The caller must
 * provide the CID of the update operation; if it's the latest CID, we can
 * make a decision without forcing the caller to fetch the tuple CID.
 */
static ZVersionSelector
ZHeapSelectVersionUpdate(ZTupleTidOp op, TransactionId xid,
						 CommandId visibility_cid)
{
	/* Shouldn't be looking at a delete or non-inplace update. */
	Assert(op != ZTUPLETID_GONE);

	if (TransactionIdIsCurrentTransactionId(xid))
	{
		/*
		 * This transaction is still running and belongs to the current
		 * session.  If the current CID has been used to stamp a tuple or
		 * the snapshot belongs to an older CID, then we need the CID for
		 * this tuple to make a final visibility decision.
		 */
		if (GetCurrentCommandIdUsed() ||
			GetCurrentCommandId(false) != visibility_cid)
			return ZVERSION_CHECK_CID;

		/* Nothing has changed since our scan started. */
		return ZVERSION_CURRENT;
	}

	if (TransactionIdIsInProgress(xid) || !TransactionIdDidCommit(xid))
	{
		/* The XID is still in progress, or aborted; we can't see it. */
		return (op == ZTUPLETID_NEW ? ZVERSION_NONE : ZVERSION_OLDER);
	}

	/* The XID is visible to us. */
	return ZVERSION_CURRENT;
}

/*
 * ZHeapCheckCID
 *
 * For a tuple whose xid satisfies TransactionIdIsCurrentTransactionId(xid),
 * this function makes a determination about tuple visibility based on CID.
 */
static ZVersionSelector
ZHeapCheckCID(ZTupleTidOp op, CommandId tuple_cid, CommandId visibility_cid)
{
	if (op == ZTUPLETID_GONE)
	{
		if (tuple_cid >= visibility_cid)
			return ZVERSION_OLDER;		/* deleted after scan started */
		else
			return ZVERSION_NONE;		/* deleted before scan started */
	}
	else if (op == ZTUPLETID_MODIFIED)
	{
		if (tuple_cid >= visibility_cid)
			return ZVERSION_OLDER;		/* updated/locked after scan started */
		else
			return ZVERSION_CURRENT;	/* updated/locked before scan started */
	}
	else
	{
		if (tuple_cid >= visibility_cid)
			return ZVERSION_NONE;		/* inserted after scan started */
		else
			return ZVERSION_CURRENT;	/* inserted before scan started */
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
ZHeapSelectVersionSelf(ZTupleTidOp op, TransactionId xid)
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
 * ZHeapTupleSatisfies
 *
 * Returns the visible version of tuple if any, NULL otherwise. We need to
 * traverse undo record chains to determine the visibility of tuple.  In
 * this function we need to first the determine the visibility of modified
 * tuple and if it is not visible, then we need to fetch the prior version
 * of tuple from undo chain and decide based on its visibility.  The undo
 * chain needs to be traversed till we reach correct version of the tuple.
 *
 * For aborted transactions, we may need to fetch the visible tuple from undo.
 * It is possible that actions corresponding to aborted transaction have
 * been applied, but still xid is present in slot, however we should never
 * get such an xid.
 *
 * For multilockers, the strongest locker information is always present on
 * the tuple.  So for updaters, we don't need anything special as the tuple
 * visibility will be determined based on the transaction information present
 * on tuple.  For the lockers only case, we need to determine if the original
 * inserter is visible to snapshot.
 */
ZHeapTuple
ZHeapTupleSatisfies(ZHeapTuple zhtup, Snapshot snapshot,
					Buffer buffer, ItemPointer ctid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	ZHeapTupleTransInfo	zinfo;
	bool		fetch_cid = false;
	Snapshot	transinfo_snapshot = InvalidSnapshot;
	ZTupleTidOp op;
	ZVersionSelector	zselect;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Special handling for particular snapshot types. */
	if (snapshot->visibility_type == MVCC_VISIBILITY)
	{
		CommandId	cur_cid = GetCurrentCommandId(false);

		/*
		 * If the current command doesn't need to modify any tuple and the
		 * snapshot used is not of any previous command, then it can see all
		 * the modifications made by current transactions till now.  So, we
		 * don't even attempt to fetch CID from undo in such cases.
		 */
		if (!GetCurrentCommandIdUsed() && cur_cid == snapshot->curcid)
			fetch_cid = false;
		else
			fetch_cid = true;

		/*
		 * For an MVCC snapshot only, ZHeapTupleGetTransInfo needs to see
		 * our snapshot; for any other type, we must pass InvalidSnapshot.
		 */
		transinfo_snapshot = snapshot;
	}
	else if (snapshot->visibility_type == DIRTY_VISIBILITY)
	{
		snapshot->xmin = snapshot->xmax = InvalidTransactionId;
		snapshot->subxid = InvalidSubTransactionId;
		snapshot->speculativeToken = 0;
	}
	else if (snapshot->visibility_type == TOAST_VISIBILITY)
	{
		/*
		 * Unlike heap, we don't need checks for VACUUM moving conditions as
		 * those are for pre-9.0 and that doesn't apply for zheap.  For aborted
		 * speculative inserts, we always marks row as dead, so we don't any
		 * check for that.  So, here we can rely on the fact that if you can
		 * see the main table row that contains a TOAST reference, you should
		 * be able to see the TOASTed value.
		 */
		return zhtup;
	}
	else if (snapshot->visibility_type == ANY_VISIBILITY)
		return ZHeapTupleSatisfiesAny(zhtup, snapshot, buffer, ctid);
	else if (snapshot->visibility_type == NON_VACUUMABLE_VISIBILTY)
	{
		TransactionId	xid;
		HTSV_Result	result;

		result =
			ZHeapTupleSatisfiesOldestXmin(&zhtup, snapshot->xmin, buffer,
										  &xid, NULL);

		return result == HEAPTUPLE_DEAD ? zhtup : NULL;
	}

	/* Get last operation type */
	op = ZHeapTidOpFromInfomask(tuple->t_infomask);

	/* Get transaction info */
	ZHeapTupleGetTransInfo(zhtup, buffer, fetch_cid, transinfo_snapshot,
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
	else if (snapshot->visibility_type == MVCC_VISIBILITY)
	{
		zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, snapshot);

		if (zselect == ZVERSION_CHECK_CID)
		{
			/*
			 * ZBORKED: We should really rejigger this logic so that we don't
			 * need to fetch the CID unless ZHeapSelectVersionMVCC actually
			 * returns ZVERSION_CHECK_CID.  Rather than calling
			 * ZHeapTupleGetTransInfo, We should probably call
			 * GetTransactionSlotInfo first and then only call
			 * FetchTransInfoFromUndo if necessary.  But ZHeapTupleGetTransInfo
			 * also does some other stuff; more study is needed.
			 */
			Assert(fetch_cid);
			zselect = ZHeapCheckCID(op, zinfo.cid, snapshot->curcid);
		}
	}
	else if (snapshot->visibility_type == SELF_VISIBILITY)
		zselect = ZHeapSelectVersionSelf(op, zinfo.xid);
	else if (snapshot->visibility_type == DIRTY_VISIBILITY)
	{
		int		requests = 0;

		zselect = ZHeapSelectVersionDirty(op, tuple->t_infomask, &zinfo,
										  snapshot, &requests);
		if ((requests & SNAPSHOT_REQUESTS_SPECTOKEN) != 0 &&
			ZHeapTupleHeaderIsSpeculative(tuple))
		{
			ZHeapTupleGetSpecToken(zhtup, buffer, zinfo.urec_ptr,
								   &snapshot->speculativeToken);

			Assert(snapshot->speculativeToken != 0);
		}
		if ((requests & SNAPSHOT_REQUESTS_SUBXID) != 0)
			ZHeapTupleGetSubXid(zhtup, buffer, zinfo.urec_ptr,
								&snapshot->subxid);
	}
	else
		elog(ERROR, "unsupported snapshot type %d",
			 (int) snapshot->visibility_type);

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
		 *
		 * ZBORKED: Is it correct that we skip this for SELF_VISIBILITY?
		 * That's inherited from an older code structure, but it could be
		 * an arbitrary inconsistency.
		 */
		if (ctid && (tuple->t_infomask & ZHEAP_UPDATED) != 0 &&
			!ZHeapTupleIsMoved(tuple->t_infomask) &&
			snapshot->visibility_type != SELF_VISIBILITY)
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
								ItemPointerGetOffsetNumber(&zhtup->t_self),
								ctid,
								zinfo.trans_slot);

	Assert(zselect == ZVERSION_CURRENT);
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
	ZHeapTupleTransInfo	zinfo;
	ZVersionSelector	zselect;
	bool		have_cid;

	if (all_dead)
		*all_dead = false;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, off);
	Assert(ItemIdIsDeleted(lp));

	zinfo.trans_slot = ItemIdGetTransactionSlot(lp);

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	GetTransactionSlotInfo(buffer, off, zinfo.trans_slot, true, false, &zinfo);

	/*
	 * Even if zinfo.trans_slot was not ZHTUP_SLOT_FROZEN before we called
	 * GetTransactionSlotInfo, it might have that value now.  This can
	 * happen when the slot belongs to a TPD entry and the corresponding
	 * TPD entry is pruned.
	 */
	if (zinfo.trans_slot != ZHTUP_SLOT_FROZEN)
	{
		int		vis_info = ItemIdGetVisibilityInfo(lp);

		if (vis_info & ITEMID_XACT_INVALID)
		{
			FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), off,
								   InvalidTransactionId, &zinfo);
			have_cid = true;
		}
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

	/* Check XID against snapshot. */
	if (IsMVCCSnapshot(snapshot))
		zselect = ZHeapSelectVersionMVCC(ZTUPLETID_GONE, zinfo.xid, snapshot);
	else
	{
		/* ZBORKED: Why do we always use SnapshotSelf rules here? */
		zselect = ZHeapSelectVersionSelf(ZTUPLETID_GONE, zinfo.xid);
	}

	/* If necessary, check CID against snapshot. */
	if (zselect == ZVERSION_CHECK_CID)
	{
		if (!have_cid)
			zinfo.cid = ZHeapPageGetCid(buffer, zinfo.epoch_xid,
										zinfo.urec_ptr, off);

		/* OK, now we can make a final visibility decision. */
		zselect = ZHeapCheckCID(ZTUPLETID_GONE, zinfo.cid, snapshot->curcid);
	}

	if (zselect == ZVERSION_OLDER)
		return GetTupleFromUndo(zinfo.urec_ptr,
								NULL,
								snapshot,
								buffer,
								off,
								NULL,
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
 *	HeapTupleMayBeUpdated, if the strongest locker is committed which means
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
HTSU_Result
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
	ZHeapTupleGetTransInfo(zhtup, buffer, fetch_cid, InvalidSnapshot, zinfo);

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
					return HeapTupleSelfUpdated;
				else
					return HeapTupleInvisible;
			}
			else
				return HeapTupleInvisible;	/* deleted before scan started */
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

				return HeapTupleBeingUpdated;
			}
			else
				return HeapTupleInvisible;
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
			return HeapTupleUpdated;
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
			 * then return HeapTupleBeingUpdated, so that caller can apply the
			 * undo before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			if (visible)
				return HeapTupleBeingUpdated;
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
				return HeapTupleMayBeUpdated;
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
				return HeapTupleBeingUpdated;
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
						return HeapTupleBeingUpdated;
					else
						return HeapTupleSelfUpdated;
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
					return HeapTupleBeingUpdated;
				}
				else
					/* updated before scan is started */
					return HeapTupleMayBeUpdated;
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

				return HeapTupleBeingUpdated;
			}
			else
				return HeapTupleInvisible;
		}
		else if (TransactionIdDidCommit(zinfo->xid))
		{
			/*
			 * If tuple is updated and not in our snapshot, then allow to
			 * update it.
			 */
			if (lock_allowed || !XidInMVCCSnapshot(zinfo->xid, snapshot))
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleUpdated;
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
			 * then return HeapTupleBeingUpdated, so that caller can apply the
			 * undo before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			if (visible)
				return HeapTupleBeingUpdated;
			else
				return HeapTupleInvisible;
		}
	}

	/*
	 * The tuple must be all visible if the transaction slot is cleared or
	 * latest xid that has changed the tuple precedes smallest xid that has
	 * undo.
	 */
	if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
		zinfo->epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return HeapTupleMayBeUpdated;

	if (TransactionIdIsCurrentTransactionId(zinfo->xid))
	{
		if (fetch_cid && zinfo->cid >= curcid)
			return HeapTupleInvisible;	/* inserted after scan started */
		else
			return HeapTupleMayBeUpdated;	/* inserted before scan started */
	}
	else if (TransactionIdIsInProgress(zinfo->xid))
		return HeapTupleInvisible;
	else if (TransactionIdDidCommit(zinfo->xid))
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
		ZHeapTupleGetTransInfo(zhtup, buffer, false, InvalidSnapshot, &zinfo);
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
static ZVersionSelector
ZHeapSelectVersionDirty(ZTupleTidOp op, uint16 infomask,
						ZHeapTupleTransInfo *zinfo,
						Snapshot snapshot, int *snapshot_requests)
{
	if (op == ZTUPLETID_GONE)
	{
		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
			return ZVERSION_NONE;
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			snapshot->xmax = zinfo->xid;
			if (UndoRecPtrIsValid(zinfo->urec_ptr))
				*snapshot_requests |= SNAPSHOT_REQUESTS_SUBXID;
			return ZVERSION_CURRENT;
		}
		else if (TransactionIdDidCommit(zinfo->xid))
		{
			/* tuple is deleted or non-inplace-updated */
			return ZVERSION_NONE;
		}
		else					/* transaction is aborted */
			return ZVERSION_OLDER;
	}
	else if (op == ZTUPLETID_MODIFIED)
	{
		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
			return ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			if (!ZHEAP_XID_IS_LOCKED_ONLY(infomask))
			{
				snapshot->xmax = zinfo->xid;
				if (UndoRecPtrIsValid(zinfo->urec_ptr))
					*snapshot_requests |= SNAPSHOT_REQUESTS_SUBXID;
			}
			return ZVERSION_CURRENT; /* being updated */
		}
		else if (TransactionIdDidCommit(zinfo->xid))
			return ZVERSION_CURRENT;	/* tuple is updated by someone else */
		else					/* transaction is aborted */
			return ZVERSION_OLDER;
	}
	else
	{
		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
			return ZVERSION_CURRENT;
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			/* Return any speculative token to caller. */
			*snapshot_requests |= SNAPSHOT_REQUESTS_SPECTOKEN;

			snapshot->xmin = zinfo->xid;
			if (UndoRecPtrIsValid(zinfo->urec_ptr))
				*snapshot_requests |= SNAPSHOT_REQUESTS_SUBXID;
			return ZVERSION_CURRENT; /* in insertion by other */
		}
		else if (TransactionIdDidCommit(zinfo->xid))
			return ZVERSION_CURRENT;
		else
		{
			/* inserting transaction aborted */
			return ZVERSION_NONE;
		}
	}

	/* should never get here */
	pg_unreachable();
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
 *	ztuple is an input/output parameter.  The caller must send the palloc'd
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
ZHeapTupleSatisfiesOldestXmin(ZHeapTuple *ztuple, TransactionId OldestXmin,
							  Buffer buffer, TransactionId *xid,
							  SubTransactionId *subxid)
{
	ZHeapTuple	zhtup = *ztuple;
	ZHeapTupleHeader tuple = zhtup->t_data;
	ZHeapTupleTransInfo	zinfo;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(zhtup, buffer, false, InvalidSnapshot, &zinfo);
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
	ZHeapTupleGetTransInfo(zhtup, buffer, false, InvalidSnapshot, &zinfo);
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
		 * If the tuple is still visible to us, then we've a conflict because
		 * the transaction that deleted the tuple already got committed.
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
