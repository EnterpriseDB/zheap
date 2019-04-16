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
	ZVERSION_OLDER,
	ZVERSION_CHECK_CID
} ZVersionSelector;

#define SNAPSHOT_REQUESTS_SPECTOKEN		0x0001
#define SNAPSHOT_REQUESTS_SUBXID		0x0002

static bool GetTupleFromUndo(UndoRecPtr urec_ptr,
				 ZHeapTuple current_tuple, ZHeapTuple *visible_tuple,
				 Snapshot snapshot, CommandId curcid, Buffer buffer,
				 OffsetNumber offnum, ItemPointer ctid, int trans_slot);
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
static ZHeapTuple ZHeapGetVisibleTuple(OffsetNumber off, Snapshot snapshot,
									   Buffer buffer, bool *all_dead);
static ZHeapTuple ZHeapTupleSatisfies(ZHeapTuple stup,
					Snapshot snapshot, Buffer buffer, ItemPointer ctid);

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
	zinfo->epoch_xid =
		FullTransactionIdFromEpochAndXid(epoch, zinfo->xid);
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
	ItemId		lp;
	Page		page;
	OffsetNumber offnum = ItemPointerGetOffsetNumber(ctid);
	ZHeapTupleTransInfo	zinfo;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, offnum);

	Assert(ItemIdIsDeleted(lp));

	trans_slot = ItemIdGetTransactionSlot(lp);

	/*
	 * We need undo record pointer to fetch the transaction information
	 * from undo.
	 */
	GetTransactionSlotInfo(buffer, offnum, trans_slot, true, false, &zinfo);
	FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
						   InvalidTransactionId, &zinfo);

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
ZHeapTupleGetTransInfo(Buffer buf, OffsetNumber offnum, bool fetch_cid,
					   ZHeapTupleTransInfo *zinfo)
{
	ItemId		lp;
	Page		page;
	BlockNumber	blocknum = BufferGetBlockNumber(buf);
	bool		is_invalid_slot = false;

	page = BufferGetPage(buf);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));
	if (!ItemIdIsDeleted(lp))
	{
		ZHeapTupleHeaderData hdr;

		memcpy(&hdr, PageGetItem(page, lp), SizeofZHeapTupleHeader);
		zinfo->trans_slot = ZHeapTupleHeaderGetXactSlot(&hdr);
		if (ZHeapTupleHasInvalidXact(hdr.t_infomask))
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
		return;

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (is_invalid_slot)
	{
		/*
		 * We are intentionally avoiding to fetch the transaction information
		 * from undo even when the tuple has invalid_xact_slot marking as if
		 * the slot's current xid is all-visible, then the xid prior to it
		 * must be all-visible.
		 */
		if ((TransactionIdIsValid(zinfo->xid) &&
			 (TransactionIdPrecedes(zinfo->xid, pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)))) ||
			UndoLogIsDiscarded(zinfo->urec_ptr))
		{
			zinfo->trans_slot = ZHTUP_SLOT_FROZEN;
			zinfo->epoch_xid = InvalidFullTransactionId;
			zinfo->xid = InvalidTransactionId;
			zinfo->cid = InvalidCommandId;
			zinfo->urec_ptr = InvalidUndoRecPtr;
			return;
		}

		FetchTransInfoFromUndo(blocknum, offnum, InvalidTransactionId, zinfo);
	}
	else
	{
		if (fetch_cid && TransactionIdIsCurrentTransactionId(zinfo->xid))
			FetchTransInfoFromUndo(blocknum, offnum, InvalidTransactionId,
								   zinfo);
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
	ItemPointer		tid = &(zhtup->t_self);
	OffsetNumber	offnum = ItemPointerGetOffsetNumber(tid);

	if (nobuflock)
	{
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

	ZHeapTupleGetTransInfo(buf, offnum, false, &zinfo);

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
GetTupleFromUndoRecord(UndoRecPtr urec_ptr, TransactionId xid, Buffer buffer,
					   OffsetNumber offnum, ZHeapTupleHeader hdr,
					   ZHeapTuple *ztuple, bool *free_ztuple,
					   ZHeapTupleTransInfo *zinfo, ItemPointer ctid)
{
	UnpackedUndoRecord *urec;
	uint32		epoch;

	urec = UndoFetchRecord(urec_ptr,
						   BufferGetBlockNumber(buffer),
						   offnum,
						   xid,
						   NULL,
						   ZHeapSatisfyUndoRecord);
	if (urec == NULL)
		return false;

	zinfo->trans_slot =
		UpdateTupleHeaderFromUndoRecord(urec, hdr, BufferGetPage(buffer));

	/*
	 * If the tuple is being updated or deleted, the payload contains a whole
	 * new tuple.  If the caller wants it, extract it.
	 */
	if (ztuple != NULL &&
		(urec->uur_type == UNDO_UPDATE ||
		 urec->uur_type == UNDO_INPLACE_UPDATE ||
		 urec->uur_type == UNDO_DELETE))
	{
		ZHeapTuple	zhtup;

		zhtup = palloc(ZHEAPTUPLESIZE + urec->uur_tuple.len);
		zhtup->t_len = urec->uur_tuple.len;
		ItemPointerSet(&zhtup->t_self, urec->uur_block, urec->uur_offset);
		zhtup->t_tableOid = urec->uur_reloid;
		zhtup->t_data = (ZHeapTupleHeader) ((char *) zhtup + ZHEAPTUPLESIZE);
		memcpy(zhtup->t_data, urec->uur_tuple.data, urec->uur_tuple.len);

		if (*free_ztuple)
			pfree(*ztuple);
		*ztuple = zhtup;
		*free_ztuple = true;
	}

	zinfo->urec_ptr = urec->uur_blkprev;
	zinfo->xid = urec->uur_prevxid;
	zinfo->cid = InvalidCommandId;

	/*
	 * We don't allow XIDs with an age of more than 2 billion in undo, so
	 * we can infer the epoch here. (XXX Is this a valid justification
	 * given that we're dealing with uur_prevxid, not uur_xid?)
	 */
	epoch = GetEpochForXid(urec->uur_prevxid);
	zinfo->epoch_xid =
		FullTransactionIdFromEpochAndXid(epoch, urec->uur_prevxid);

	/* If this is a non-in-place update, update ctid if requested. */
	if (ctid && urec->uur_type == UNDO_UPDATE)
		*ctid = *((ItemPointer) urec->uur_payload.data);

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
	if (FullTransactionIdOlderThanAllUndo(zinfo->epoch_xid))
		return false;

	return true;
}

/*
 * GetTupleFromUndo
 *
 * Fetch the record from undo and determine if previous version of tuple
 * is visible for the given snapshot.  If there exists a visible version
 * of the tuple, return true, otherwise false.
 *
 * current_tuple should point to the current version of the tuple on input,
 * or NULL if the current version is deleted.  visible_tuple, if not NULL,
 * will be set to the visible version of the tuple on return. This may be
 * current_tuple, an older version of the tuple retrieved from the undo log,
 * or NULL.
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
static bool
GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple current_tuple,
				 ZHeapTuple *visible_tuple, Snapshot snapshot,
				 CommandId curcid, Buffer buffer, OffsetNumber offnum,
				 ItemPointer ctid, int trans_slot)
{
	TransactionId	prev_undo_xid = InvalidTransactionId;
	int			prev_trans_slot_id = trans_slot;
	ZHeapTupleTransInfo	zinfo;
	bool		free_ztuple = false;
	BlockNumber	blkno = BufferGetBlockNumber(buffer);
	ZHeapTupleHeaderData hdr;

	if (current_tuple != NULL)
	{
		/* Sanity check. */
		Assert(ItemPointerGetOffsetNumber(&current_tuple->t_self) == offnum);

		/*
		 * We must set up 'hdr' to point to be a copy of the header bytes from
		 * the most recent version of the tuple.  This is because in the
		 * special case where the undo record we find is an UNDO_INSERT record,
		 * we modify the existing bytes rather than overwriting them
		 * completely.  If current_tuple == NULL, then the current version of
		 * the tuple has been deleted or subjected to a non-in-place update, so
		 * the first record we find won't be UNDO_INSERT.
		 *
		 * ZBORKED: We should really change this to get rid of the special case
		 * for UNDO_INSERT, either by making it so that this function doesn't
		 * get called in that case, or by making it so that it doesn't need the
		 * newer tuple header bytes, or some other clever trick.  That would
		 * eliminate a substantial amount of complexity and ugliness here.
		 */
		memcpy(&hdr, current_tuple->t_data, SizeofZHeapTupleHeader);

		/* Initially, result tuple is same as input tuple. */
		if (visible_tuple != NULL)
			*visible_tuple = current_tuple;
	}

	/*
	 * If caller wants the CTID of the latest version of the tuple, set it
	 * to that of the tuple we're looking up for starters.  If it's been
	 * the subject of a non-in-place update, GetTupleFromUndoRecord will
	 * adjust the value later.
	 */
	if (ctid)
		ItemPointerSet(ctid, blkno, offnum);

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

		if (!GetTupleFromUndoRecord(urec_ptr, prev_undo_xid, buffer,
									offnum, &hdr, visible_tuple,
									&free_ztuple, &zinfo, ctid))
			break;

		/*
		 * Change the undo chain if the undo tuple is stamped with the
		 * different transaction.
		 */
		if (zinfo.trans_slot != prev_trans_slot_id)
			ZHeapUpdateTransactionSlotInfo(zinfo.trans_slot, buffer, offnum,
										   &zinfo);

		op = ZHeapTidOpFromInfomask(hdr.t_infomask);

		/* can't further operate on deleted or non-inplace-updated tuple */
		Assert(op != ZTUPLETID_GONE);

		/*
		 * We need to fetch all the transaction related information from
		 * undo record for the tuples that point to a slot that gets
		 * invalidated for reuse at some point of time.  See
		 * PageFreezeTransSlots.
		 */
		if (ZHeapTupleHasInvalidXact(hdr.t_infomask))
		{
			FetchTransInfoFromUndo(blkno, offnum, zinfo.xid, &zinfo);
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
			FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
			break;

		/* Preliminary visibility check, without relying on the CID. */
		if (snapshot == NULL)
			zselect = ZHeapSelectVersionUpdate(op, zinfo.xid, curcid);
		else if (IsMVCCSnapshot(snapshot))
			zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, snapshot);
		else
		{
			/* ZBORKED: Why do we always use SnapshotSelf rules here? */
			zselect = ZHeapSelectVersionSelf(op, zinfo.xid);
		}

		/* If necessary, get and check CID. */
		if (zselect == ZVERSION_CHECK_CID)
		{
			if (!have_cid)
			{
				FetchTransInfoFromUndo(blkno, offnum, zinfo.xid, &zinfo);
				have_cid = true;
			}

			/* OK, now we can make a final visibility decision. */
			zselect = ZHeapCheckCID(op, zinfo.cid, curcid);
		}

		/* Return the current version, or nothing, if appropriate. */
		if (zselect == ZVERSION_CURRENT)
			break;
		if (zselect == ZVERSION_NONE)
		{
			if (visible_tuple != NULL)
			{
				if (free_ztuple)
					pfree(*visible_tuple);
				*visible_tuple = NULL;
			}
			return false;
		}

		/* Need to check next older version, so loop around. */
		Assert(zselect == ZVERSION_OLDER);
		urec_ptr = zinfo.urec_ptr;
		prev_undo_xid = zinfo.xid;
		prev_trans_slot_id = zinfo.trans_slot;
	}

	/* Copy latest header reconstructed from undo back into ztuple. */
	if (visible_tuple != NULL && *visible_tuple != NULL)
		memcpy((*visible_tuple)->t_data, &hdr, SizeofZHeapTupleHeader);
	return true;
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
 * ZHeapTupleFetch
 *
 * Look for a tuple within a given buffer by offset.  If there is a version
 * of that tuple that is visible to the given snapshot, return true, else
 * return false.
 *
 * If visible_tuple != NULL, then set *visible_tuple to the visible version
 * of the tuple, if there is one, or otherwise to NULL.
 */
bool
ZHeapTupleFetch(Relation rel, Buffer buffer, OffsetNumber offnum,
				Snapshot snapshot, ZHeapTuple *visible_tuple,
				ItemPointer new_ctid)
{
	ZHeapTuple	tuple;
	Page		dp;
	ItemId		lp;

	dp = BufferGetPage(buffer);
	lp = PageGetItemId(dp, offnum);

	if (ItemIdIsDeleted(lp))
	{
		TransactionId	tup_xid;
		CommandId	tup_cid;

		tuple = ZHeapGetVisibleTuple(offnum, snapshot, buffer, NULL);
		if (new_ctid)
			ZHeapPageGetNewCtid(buffer, new_ctid, &tup_xid, &tup_cid);
	}
	else if (ItemIdIsNormal(lp))
	{
		tuple = zheap_gettuple(rel, buffer, offnum);
		tuple = ZHeapTupleSatisfies(tuple, snapshot, buffer, new_ctid);
	}
	else
	{
		Assert(!ItemIdIsUsed(lp));
		tuple = NULL;
	}

	if (visible_tuple)
		*visible_tuple = tuple;
	else if (tuple)
		pfree(tuple);

	return (tuple != NULL);
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
static ZHeapTuple
ZHeapTupleSatisfies(ZHeapTuple zhtup, Snapshot snapshot,
					Buffer buffer, ItemPointer ctid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	ItemPointer tid = &(zhtup->t_self);
	OffsetNumber offnum = ItemPointerGetOffsetNumber(tid);
	ZHeapTupleTransInfo	zinfo;
	ZTupleTidOp op;
	ZVersionSelector	zselect;
	bool have_cid = false;

	Assert(ItemPointerIsValid(tid));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Special handling for particular snapshot types. */
	if (snapshot->snapshot_type == SNAPSHOT_DIRTY)
	{
		snapshot->xmin = snapshot->xmax = InvalidTransactionId;
		snapshot->subxid = InvalidSubTransactionId;
		snapshot->speculativeToken = 0;
	}
	else if (snapshot->snapshot_type == SNAPSHOT_TOAST)
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
	else if (snapshot->snapshot_type == SNAPSHOT_ANY)
		return ZHeapTupleSatisfiesAny(zhtup, snapshot, buffer, ctid);
	else if (snapshot->snapshot_type == SNAPSHOT_NON_VACUUMABLE)
	{
		TransactionId	xid;
		ZHTSV_Result	result;

		result =
			ZHeapTupleSatisfiesOldestXmin(zhtup, snapshot->xmin, buffer, true,
										  NULL, &xid, NULL);

		return result == ZHEAPTUPLE_DEAD ? zhtup : NULL;
	}

	/* Get last operation type */
	op = ZHeapTidOpFromInfomask(tuple->t_infomask);

	/* Get basic transaction information from transaction slot. */
	GetTransactionSlotInfo(buffer, offnum, ZHeapTupleHeaderGetXactSlot(tuple),
						   true, false, &zinfo);
	if (zinfo.trans_slot != ZHTUP_SLOT_FROZEN)
	{
		uint64	oldestXidHavingUndo;

		oldestXidHavingUndo =
			pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo);
		if (U64FromFullTransactionId(zinfo.epoch_xid) < oldestXidHavingUndo)
		{
			/* The slot is old enough that we can treat it as frozen. */
			zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
		}
		else if (ZHeapTupleHasInvalidXact(tuple->t_infomask))
		{
			/*
			 * The slot has been reused, but we can still skip reading the
			 * undo if the XID we got from the transaction slot is visible
			 * to our snapshot.  The real XID has to have committed before
			 * that one, so it will be visible to our snapshot as well.
			 */
			if (IsMVCCSnapshot(snapshot) &&
				!XidInMVCCSnapshot(zinfo.xid, snapshot))
				zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
			else
			{
				FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
									   InvalidTransactionId, &zinfo);
				have_cid = true;
				if (U64FromFullTransactionId(zinfo.epoch_xid) < oldestXidHavingUndo)
					zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
			}
		}
	}

	/* Attempt to make a visibility determination. */
	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
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
	else if (snapshot->snapshot_type == SNAPSHOT_MVCC)
	{
		zselect = ZHeapSelectVersionMVCC(op, zinfo.xid, snapshot);

		if (zselect == ZVERSION_CHECK_CID)
		{
			if (!have_cid)
			{
				FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), offnum,
									   InvalidTransactionId, &zinfo);
				have_cid = true;
			}
			zselect = ZHeapCheckCID(op, zinfo.cid, snapshot->curcid);
		}
	}
	else if (snapshot->snapshot_type == SNAPSHOT_SELF)
		zselect = ZHeapSelectVersionSelf(op, zinfo.xid);
	else if (snapshot->snapshot_type == SNAPSHOT_DIRTY)
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
			ZHeapTupleGetSubXid(buffer, offnum, zinfo.urec_ptr,
								&snapshot->subxid);
	}
	else
		elog(ERROR, "unsupported snapshot type %d",
			 (int) snapshot->snapshot_type);

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
			snapshot->snapshot_type != SNAPSHOT_SELF)
			ZHeapTupleGetCtid(zhtup, buffer, zinfo.urec_ptr, ctid);

		return NULL;
	}

	/*
	 * If we decided that we need to consult the undo log to figure out
	 * what version our snapshot can see, call GetTupleFromUndo.  That
	 * function will set zhtup; it also returns a Boolean, but we don't
	 * care about that here.
	 */
	if (zselect == ZVERSION_OLDER)
	{
		ZHeapTuple	result;

		GetTupleFromUndo(zinfo.urec_ptr, zhtup, &result, snapshot,
						 snapshot->curcid, buffer,
						 offnum, ctid, zinfo.trans_slot);
		if (result != zhtup)
			pfree(zhtup);
		return result;
	}

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
static ZHeapTuple
ZHeapGetVisibleTuple(OffsetNumber off, Snapshot snapshot, Buffer buffer, bool *all_dead)
{
	Page		page;
	ItemId		lp;
	ZHeapTupleTransInfo	zinfo;
	ZVersionSelector	zselect;
	bool		have_cid;
	ZHeapTuple	tuple = NULL;

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
		FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
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
			FetchTransInfoFromUndo(BufferGetBlockNumber(buffer), off,
								   InvalidTransactionId, &zinfo);

		/* OK, now we can make a final visibility decision. */
		zselect = ZHeapCheckCID(ZTUPLETID_GONE, zinfo.cid, snapshot->curcid);
	}

	/* Can't select the current version when it's deleted. */
	Assert(zselect != ZVERSION_CURRENT);

	/*
	 * If the delete/non-in-place update is not yet all-visible, look for
	 * a tuple in the undo log.  We don't care about the return value of
	 * GetTupleFromUndo, just the side effect of updating 'tuple'.
	 */
	if (zselect == ZVERSION_OLDER)
		GetTupleFromUndo(zinfo.urec_ptr, NULL, &tuple, snapshot,
						 snapshot->curcid, buffer, off, NULL,
						 zinfo.trans_slot);

	return tuple;
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
						  int *single_locker_trans_slot,
						  bool lock_allowed, Snapshot snapshot,
						  bool *in_place_updated_or_locked)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	CommandId	cur_comm_cid = GetCurrentCommandId(false);
	bool		fetch_cid = true;
	OffsetNumber offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
	ZTupleTidOp	op;
	TM_Result	result = TM_Invisible;
	bool		needs_recheck = false;
	bool		needs_subxid = false;

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

	/* Get last operation type */
	op = ZHeapTidOpFromInfomask(tuple->t_infomask);

	/* Get transaction info */
	ZHeapTupleGetTransInfo(buffer, offnum, fetch_cid, zinfo);

	if (op == ZTUPLETID_GONE)
	{
		/*
		 * The tuple is deleted or non-inplace-updated and must be all visible
		 * if the transaction slot is cleared or latest xid that has changed
		 * the tuple precedes smallest xid that has undo.  However, that is
		 * not possible at this stage as the tuple has already passed snapshot
		 * check.
		 */
		Assert(!(zinfo->trans_slot == ZHTUP_SLOT_FROZEN &&
				 FullTransactionIdOlderThanAllUndo(zinfo->epoch_xid)));

		if (TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			if (fetch_cid && zinfo->cid >= curcid)
			{
				/* deleted after scan started, check previous tuple from undo */
				result = TM_SelfModified;
				needs_recheck = true;
			}
		}
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			result = TM_BeingModified;
			needs_recheck = true;
			needs_subxid = true;
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
			result = TM_Updated;
		}
		else					/* transaction is aborted */
		{
			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the undo
			 * before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			result = TM_BeingModified;
			needs_recheck = true;
		}
	}
	else if (op == ZTUPLETID_MODIFIED)
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
			FullTransactionIdOlderThanAllUndo(zinfo->epoch_xid))
		{
			bool		found = false;

			if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask) &&
				!ZHeapTupleHasMultiLockers(tuple->t_infomask))
				found = GetLockerTransInfo(rel, zhtup, buffer, single_locker_trans_slot,
										   NULL, single_locker_xid, NULL, NULL);
			if (!found)
				result = TM_Ok;
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
				result = TM_BeingModified;
			}
		}
		else if (TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			if (fetch_cid && zinfo->cid >= curcid)
			{
				/*
				 * updated/locked after scan started, check previous tuple
				 * from undo
				 */
				if (ZHEAP_XID_IS_LOCKED_ONLY(tuple->t_infomask))
					result = TM_BeingModified;
				else
					result = TM_SelfModified;
				needs_recheck = true;
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
					result = TM_BeingModified;
				}
				else
					/* updated before scan is started */
					result = TM_Ok;
			}
		}
		else if (TransactionIdIsInProgress(zinfo->xid))
		{
			result = TM_BeingModified;
			needs_recheck = true;
			needs_subxid = true;
		}
		else if (TransactionIdDidCommit(zinfo->xid))
		{
			/*
			 * if tuple is updated and not in our snapshot, then allow to
			 * update it.
			 */
			if (lock_allowed || !XidInMVCCSnapshot(zinfo->xid, snapshot))
				result = TM_Ok;
			else
				result = TM_Updated;
		}
		else					/* transaction is aborted */
		{
			/*
			 * If updating transaction id is aborted and the tuple is visible
			 * then return TM_BeingModified, so that caller can apply the undo
			 * before modifying the page.  Here, we don't need to fetch
			 * subtransaction id as it is only possible for top-level xid to
			 * have pending undo actions.
			 */
			result = TM_BeingModified;
			needs_recheck = true;
		}
	}
	else
	{
		/*
		 * The tuple must be all visible if the transaction slot is cleared or
		 * latest xid that has changed the tuple precedes smallest xid that has
		 * undo.
		 */
		if (zinfo->trans_slot == ZHTUP_SLOT_FROZEN ||
			FullTransactionIdOlderThanAllUndo(zinfo->epoch_xid))
			result = TM_Ok;
		else if (TransactionIdIsCurrentTransactionId(zinfo->xid))
		{
			if (fetch_cid && zinfo->cid >= curcid)
				result = TM_Invisible;	/* inserted after scan started */
			else
				result = TM_Ok;	/* inserted before scan started */
		}
		else if (TransactionIdIsInProgress(zinfo->xid))
			result = TM_Invisible;
		else if (TransactionIdDidCommit(zinfo->xid))
			result = TM_Ok;
	}

	/*
	 * If a recheck was requested, we must consult the undo log to determine
	 * the final answer.
	 */
	if (needs_recheck &&
		!GetTupleFromUndo(zinfo->urec_ptr, zhtup, NULL, NULL, curcid, buffer,
						  offnum, ctid, zinfo->trans_slot))
	{
		result = TM_Invisible;
		needs_subxid = false;
	}

	if (needs_subxid)
		ZHeapTupleGetSubXid(buffer, offnum, zinfo->urec_ptr, subxid);

	return result;
}

/*
 * ZHeapTupleIsSurelyDead
 *
 * Similar to HeapTupleIsSurelyDead, but for zheap tuples.
 */
bool
ZHeapTupleIsSurelyDead(ZHeapTuple zhtup, Buffer buffer)
{
	ZHeapTupleHeader tuple = zhtup->t_data;

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED)
	{
		ItemPointer		tid = &(zhtup->t_self);
		OffsetNumber	offnum = ItemPointerGetOffsetNumber(tid);
		ZHeapTupleTransInfo	zinfo;

		/* Get transaction id. */
		ZHeapTupleGetTransInfo(buffer, offnum, false, &zinfo);

		/*
		 * The tuple is deleted and must be all visible if the transaction
		 * slot is cleared or latest xid that has changed the tuple precedes
		 * smallest xid that has undo.
		 */
		if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
			FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
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
ZHTSV_Result
ZHeapTupleSatisfiesOldestXmin(ZHeapTuple zhtup, TransactionId OldestXmin,
							  Buffer buffer, bool resolve_abort_in_progress,
							  ZHeapTuple *preabort_tuple,
							  TransactionId *xid, SubTransactionId *subxid)
{
	ZHeapTupleHeader tuple = zhtup->t_data;
	ZHeapTupleTransInfo	zinfo;
	OffsetNumber offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	/* Get transaction id */
	ZHeapTupleGetTransInfo(buffer, offnum, false, &zinfo);
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
			FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
			return ZHEAPTUPLE_DEAD;

		if (TransactionIdIsCurrentTransactionId(zinfo.xid))
			return ZHEAPTUPLE_DELETE_IN_PROGRESS;
		else if (TransactionIdIsInProgress(zinfo.xid))
		{
			/* Get Sub transaction id */
			if (subxid)
				ZHeapTupleGetSubXid(buffer, offnum, zinfo.urec_ptr, subxid);

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
			ZHeapTuple	undo_tuple;

			if (!resolve_abort_in_progress)
				return ZHEAPTUPLE_ABORT_IN_PROGRESS;

			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.  It should be OK to use SnapshotSelf semantics because
			 * we know that the latest transaction is aborted; the previous
			 * transaction therefore can't be current or in-progress or for
			 * that matter aborted.  It seems like even SnapshotAny semantics
			 * would be OK here, but GetTupleFromUndo doesn't know about
			 * those.
			 *
			 * ZBORKED: This code path needs tests.  I was not able to hit it
			 * in either automated or manual testing.
			 */
			GetTupleFromUndo(zinfo.urec_ptr, zhtup, &undo_tuple,
							 SnapshotSelf,
							 InvalidCommandId, buffer, offnum, NULL,
							 zinfo.trans_slot);

			if (preabort_tuple)
				*preabort_tuple = undo_tuple;
			else if (undo_tuple != zhtup)
				pfree(undo_tuple);

			if (undo_tuple != NULL)
				return ZHEAPTUPLE_LIVE;
			else
			{
				/*
				 * If the transaction that inserted the tuple got aborted, we
				 * should return the aborted transaction id.
				 */
				return ZHEAPTUPLE_DEAD;
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
		FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
		return ZHEAPTUPLE_LIVE;

	if (TransactionIdIsCurrentTransactionId(zinfo.xid))
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;
	else if (TransactionIdIsInProgress(zinfo.xid))
	{
		/* Get Sub transaction id */
		if (subxid)
			ZHeapTupleGetSubXid(buffer, offnum, zinfo.urec_ptr, subxid);
		return ZHEAPTUPLE_INSERT_IN_PROGRESS;	/* in insertion by other */
	}
	else if (TransactionIdDidCommit(zinfo.xid))
		return ZHEAPTUPLE_LIVE;
	else						/* transaction is aborted */
	{
		if (!resolve_abort_in_progress)
			return ZHEAPTUPLE_ABORT_IN_PROGRESS;

		if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED)
		{
			ZHeapTuple	undo_tuple;

			/*
			 * For aborted transactions, we need to fetch the tuple from undo
			 * chain.  It should be OK to use SnapshotSelf semantics because
			 * we know that the latest transaction is aborted; the previous
			 * transaction therefore can't be current or in-progress or for
			 * that matter aborted.  It seems like even SnapshotAny semantics
			 * would be OK here, but GetTupleFromUndo doesn't know about
			 * those.
			 *
			 * ZBORKED: This code path needs tests.  I was not able to hit it
			 * in either automated or manual testing.
			 */
			GetTupleFromUndo(zinfo.urec_ptr, zhtup, &undo_tuple, SnapshotSelf,
							 InvalidCommandId, buffer, offnum, NULL,
							 zinfo.trans_slot);

			if (preabort_tuple)
				*preabort_tuple = undo_tuple;
			else if (undo_tuple != zhtup)
				pfree(undo_tuple);

			if (undo_tuple != NULL)
				return ZHEAPTUPLE_LIVE;
		}

		/*
		 * If the transaction that inserted the tuple got aborted, we should
		 * return the aborted transaction id.
		 */
		return ZHEAPTUPLE_DEAD;
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
	ZHTSV_Result htsvResult;
	ItemId		lp;
	OffsetNumber offnum;
	Page		dp;
	ZHeapTuple	tuple;
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

	tuple = zheap_gettuple(relation, buffer, offnum);

	if (tuple->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
		tuple_inplace_updated = true;

	htsvResult =
		ZHeapTupleSatisfiesOldestXmin(tuple, TransactionXmin, buffer, true,
									  NULL, xid, NULL);
	pfree(tuple);
	switch (htsvResult)
	{
		case ZHEAPTUPLE_LIVE:
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
		case ZHEAPTUPLE_RECENTLY_DEAD:
			if (!visible)
				return false;
			break;
		case ZHEAPTUPLE_DELETE_IN_PROGRESS:
			break;
		case ZHEAPTUPLE_INSERT_IN_PROGRESS:
			break;
		case ZHEAPTUPLE_DEAD:
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
