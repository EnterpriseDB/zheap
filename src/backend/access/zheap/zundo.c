/*-------------------------------------------------------------------------
 *
 * zundo.c
 *	  Routines to process undo records.
 *
 * Each operation in zheap generates an undo record which later can be used
 * for visibility and or rollback purpose.  This file provides set of API's
 * that can be used to process undo records.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zundo.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/tpd.h"
#include "access/xact.h"
#include "access/zheapscan.h"
#include "postmaster/undoloop.h"
#include "utils/ztqual.h"

/*
 * zheap_fetch_undo_guts
 *
 * Main function for fetching the previous version of the tuple from the undo
 * storage.
 */
ZHeapTuple
zheap_fetch_undo_guts(ZHeapTuple ztuple, Buffer buffer, ItemPointer tid)
{
	UnpackedUndoRecord *urec;
	UndoRecPtr	urec_ptr;
	ZHeapTuple	undo_tup;
	int			out_slot_no PG_USED_FOR_ASSERTS_ONLY;

	out_slot_no = GetTransactionSlotInfo(buffer,
										 ItemPointerGetOffsetNumber(tid),
										 ZHeapTupleHeaderGetXactSlot(ztuple->t_data),
										 NULL,
										 NULL,
										 &urec_ptr,
										 true,
										 false);

	/*
	 * See the Asserts below to know why the transaction slot can't be frozen.
	 */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(tid),
						   ItemPointerGetOffsetNumber(tid),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/*
	 * This function is used for trigger to retrieve previous version of the
	 * tuple from undolog. Since, the transaction that is updating the tuple
	 * is still in progress, neither undo record can be discarded nor it's
	 * transaction slot can be reused.
	 */
	Assert(urec != NULL);
	Assert(urec->uur_type == UNDO_INPLACE_UPDATE);

	undo_tup = CopyTupleFromUndoRecord(urec, NULL, NULL, NULL, false, NULL);
	UndoRecordRelease(urec);

	return undo_tup;
}

/*
 * zheap_fetch_undo
 *
 * Fetch the previous version of the tuple from the undo. In case of IN_PLACE
 * update old tuple and new tuple has the same TID. And, trigger just
 * stores the tid for fetching the old and new tuple so for fetching the older
 * tuple this function should be called.
 */
bool
zheap_fetch_undo(Relation relation,
				 Snapshot snapshot,
				 ItemPointer tid,
				 ZHeapTuple * tuple,
				 Buffer *userbuf,
				 Relation stats_relation)
{
	ZHeapTuple	undo_tup;
	Buffer		buffer;

	if (!zheap_fetch(relation, snapshot, tid, tuple, &buffer, true))
		return false;

	undo_tup = zheap_fetch_undo_guts(*tuple, buffer, tid);
	zheap_freetuple(*tuple);
	*tuple = undo_tup;

	ReleaseBuffer(buffer);

	return true;
}

/*
 * Per-undorecord callback from UndoFetchRecord to check whether
 * an undorecord satisfies the given conditions.
 */
bool
ZHeapSatisfyUndoRecord(UnpackedUndoRecord * urec, BlockNumber blkno,
					   OffsetNumber offset, TransactionId xid)
{
	Assert(urec != NULL);
	Assert(blkno != InvalidBlockNumber);

	if ((urec->uur_block != blkno ||
		 (TransactionIdIsValid(xid) && !TransactionIdEquals(xid, urec->uur_xid))))
		return false;

	switch (urec->uur_type)
	{
		case UNDO_MULTI_INSERT:
			{
				OffsetNumber start_offset;
				OffsetNumber end_offset;

				start_offset = ((OffsetNumber *) urec->uur_payload.data)[0];
				end_offset = ((OffsetNumber *) urec->uur_payload.data)[1];

				if (offset >= start_offset && offset <= end_offset)
					return true;
			}
			break;
		case UNDO_ITEMID_UNUSED:
			{
				/*
				 * We don't expect to check the visibility of any unused item,
				 * but the undo record of same can be present in chain which
				 * we need to ignore.
				 */
			}
			break;
		default:
			{
				Assert(offset != InvalidOffsetNumber);
				if (urec->uur_offset == offset)
					return true;
			}
			break;
	}

	return false;
}

/*
 * CopyTupleFromUndoRecord
 *	Extract the tuple from undo record.  Deallocate the previous version
 *	of tuple and form the new version.
 *
 *	trans_slot_id - If non-NULL, then populate it with the transaction slot of
 *			transaction that has modified the tuple.
 *  cid - output command id
 *	free_zhtup - if true, free the previous version of tuple.
 */
ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord * urec, ZHeapTuple zhtup,
						int *trans_slot_id, CommandId *cid, bool free_zhtup,
						Page page)
{
	ZHeapTuple	undo_tup;

	switch (urec->uur_type)
	{
		case UNDO_INSERT:
			{
				Assert(zhtup != NULL);

				/*
				 * We need to deal with undo of root tuple only for a special
				 * case where during non-inplace update operation, we
				 * propagate the lockers information to the freshly inserted
				 * tuple. But, we've to make sure the inserted tuple is locked
				 * only.
				 */
				Assert(ZHEAP_XID_IS_LOCKED_ONLY(zhtup->t_data->t_infomask));

				undo_tup = palloc(ZHEAPTUPLESIZE + zhtup->t_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				undo_tup->t_tableOid = zhtup->t_tableOid;
				undo_tup->t_len = zhtup->t_len;
				undo_tup->t_self = zhtup->t_self;
				memcpy(undo_tup->t_data, zhtup->t_data, zhtup->t_len);

				/*
				 * Ensure to clear the visibility related information from the
				 * tuple.  This is required for the cases where the passed in
				 * tuple has lock only flags set on it.
				 */
				undo_tup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;

				/*
				 * Free the previous version of tuple, see comments in
				 * UNDO_INPLACE_UPDATE case.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
						*trans_slot_id = *(int *) urec->uur_payload.data;
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}
				if (cid)
					*cid = urec->uur_cid;
			}
			break;
		case UNDO_XID_LOCK_ONLY:
		case UNDO_XID_LOCK_FOR_UPDATE:
		case UNDO_XID_MULTI_LOCK_ONLY:
			{
				ZHeapTupleHeader undo_tup_hdr;

				Assert(zhtup != NULL);

				undo_tup_hdr = (ZHeapTupleHeader) urec->uur_tuple.data;

				/*
				 * For locked tuples, undo tuple data is always same as prior
				 * tuple's data as we don't modify it.
				 */
				undo_tup = palloc(ZHEAPTUPLESIZE + zhtup->t_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				undo_tup->t_tableOid = zhtup->t_tableOid;
				undo_tup->t_len = zhtup->t_len;
				undo_tup->t_self = zhtup->t_self;
				memcpy(undo_tup->t_data, zhtup->t_data, zhtup->t_len);

				/*
				 * Free the previous version of tuple, see comments in
				 * UNDO_INPLACE_UPDATE case.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);

				/*
				 * override the tuple header values with values fetched from
				 * undo record
				 */
				undo_tup->t_data->t_infomask2 = undo_tup_hdr->t_infomask2;
				undo_tup->t_data->t_infomask = undo_tup_hdr->t_infomask;
				undo_tup->t_data->t_hoff = undo_tup_hdr->t_hoff;

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						/*
						 * We first store the Lockmode and then transaction
						 * slot in payload, so retrieve it accordingly.
						 */
						*trans_slot_id = *(int *) ((char *) urec->uur_payload.data + sizeof(LockTupleMode));
					}
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}
			}
			break;
		case UNDO_DELETE:
		case UNDO_UPDATE:
		case UNDO_INPLACE_UPDATE:
			{
				Size		offset = 0;
				uint32		undo_tup_len;

				/*
				 * After this point, the previous version of tuple won't be
				 * used. If we don't free the previous version, then we might
				 * accumulate lot of memory when many prior versions needs to
				 * be traversed.
				 *
				 * XXX One way to save deallocation and allocation of memory
				 * is to only make a copy of prior version of tuple when it is
				 * determined that the version is visible to current snapshot.
				 * In practise, we don't need to traverse many prior versions,
				 * so let's be tidy.
				 */
				undo_tup_len = *((uint32 *) &urec->uur_tuple.data[offset]);

				undo_tup = palloc(ZHEAPTUPLESIZE + undo_tup_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				memcpy(&undo_tup->t_len, &urec->uur_tuple.data[offset], sizeof(uint32));
				offset += sizeof(uint32);

				memcpy(&undo_tup->t_self, &urec->uur_tuple.data[offset], sizeof(ItemPointerData));
				offset += sizeof(ItemPointerData);

				memcpy(&undo_tup->t_tableOid, &urec->uur_tuple.data[offset], sizeof(Oid));
				offset += sizeof(Oid);

				memcpy(undo_tup->t_data, (ZHeapTupleHeader) & urec->uur_tuple.data[offset], undo_tup_len);

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						/*
						 * For UNDO_UPDATE, we first store the CTID and then
						 * transaction slot, so retrieve it accordingly.
						 */
						if (urec->uur_type == UNDO_UPDATE)
							*trans_slot_id = *(int *) ((char *) urec->uur_payload.data + sizeof(ItemPointerData));
						else
							*trans_slot_id = *(int *) urec->uur_payload.data;
					}
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}

				if (free_zhtup)
					zheap_freetuple(zhtup);
			}
			break;
		default:
			elog(ERROR, "unsupported undo record type");

			/*
			 * During tests, we take down the server to notice the error
			 * easily. This can be removed later.
			 */
			Assert(0);
	}

	/*
	 * If the undo tuple is pointing to the last slot of the page and the page
	 * has TPD slots that means the last slot information must move to the
	 * first slot of the TPD page so change the slot number as per that.
	 */
	if (page && (*trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS) &&
		ZHeapPageHasTPDSlot((PageHeader) page))
		*trans_slot_id = ZHEAP_PAGE_TRANS_SLOTS + 1;

	return undo_tup;
}

/*
 * ValidateTuplesXact - Check if the tuple is modified by priorXmax.
 *
 *	We need to traverse the undo chain of tuple to see if any of its
 *	prior version is modified by priorXmax.
 *
 *  nobuflock indicates whether caller has lock on the buffer 'buf'.
 */
bool
ValidateTuplesXact(ZHeapTuple tuple, Snapshot snapshot, Buffer buf,
				   TransactionId priorXmax, bool nobuflock)
{
	ZHeapTupleData zhtup;
	UnpackedUndoRecord *urec = NULL;
	UndoRecPtr	urec_ptr;
	ZHeapTuple	undo_tup = NULL;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	Page		page;
	TransactionId xid;
	TransactionId prev_undo_xid = InvalidTransactionId;
	uint32		epoch;
	int			trans_slot_id = InvalidXactSlotId;
	int			prev_trans_slot_id;
	OffsetNumber offnum;
	bool		valid = false;

	/*
	 * As we are going to access special space in the page to retrieve the
	 * transaction information share lock on buffer is required.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);

	zhtup.t_tableOid = tuple->t_tableOid;
	zhtup.t_self = *tid;

	if (ItemIdIsDead(lp) || !ItemIdHasStorage(lp))
	{
		/*
		 * If the tuple is already removed by Rollbacks/pruning, then we don't
		 * need to proceed further.
		 */
		if (nobuflock)
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		return false;
	}
	else if (!ItemIdIsDeleted(lp))
	{
		/*
		 * If the tuple is updated such that its transaction slot has been
		 * changed, then we will never be able to get the correct tuple from
		 * undo. To avoid, that we get the latest tuple from page rather than
		 * relying on it's in-memory copy.
		 */
		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup.t_data);
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &epoch, &xid, &urec_ptr, true,
											   false);
	}
	else
	{
		ZHeapTuple	vis_tuple;

		trans_slot_id = ItemIdGetTransactionSlot(lp);
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &epoch, &xid, &urec_ptr, true,
											   false);

		/*
		 * XXX for now we shall get a visible undo tuple for the given dirty
		 * snapshot. The tuple data is needed below in CopyTupleFromUndoRecord
		 * and some undo records will not have tuple data and mask info with
		 * them.
		 */
		vis_tuple = ZHeapGetVisibleTuple(ItemPointerGetOffsetNumber(tid),
										 snapshot, buf, NULL);
		Assert(vis_tuple != NULL);
		zhtup.t_data = vis_tuple->t_data;
		zhtup.t_len = vis_tuple->t_len;
	}

	/*
	 * Current xid on tuple must not precede oldestXidHavingUndo as it will be
	 * greater than priorXmax which was not visible to our snapshot.
	 */
	Assert(trans_slot_id != ZHTUP_SLOT_FROZEN);

	if (TransactionIdEquals(xid, priorXmax))
	{
		valid = true;
		goto tuple_is_valid;
	}

	undo_tup = &zhtup;

	/*
	 * Current xid on tuple must not precede RecentGlobalXmin as it will be
	 * greater than priorXmax which was not visible to our snapshot.
	 */
	Assert(TransactionIdEquals(xid, InvalidTransactionId) ||
		   !TransactionIdPrecedes(xid, RecentGlobalXmin));

	do
	{
		prev_trans_slot_id = trans_slot_id;
		Assert(prev_trans_slot_id != ZHTUP_SLOT_FROZEN);

		urec = UndoFetchRecord(urec_ptr,
							   ItemPointerGetBlockNumber(&undo_tup->t_self),
							   ItemPointerGetOffsetNumber(&undo_tup->t_self),
							   prev_undo_xid,
							   NULL,
							   ZHeapSatisfyUndoRecord);

		/*
		 * As we still hold a snapshot to which priorXmax is not visible,
		 * neither the transaction slot on tuple can be marked as frozen nor
		 * the corresponding undo be discarded.
		 */
		Assert(urec != NULL);

		if (TransactionIdEquals(urec->uur_xid, priorXmax))
		{
			valid = true;
			goto tuple_is_valid;
		}

		/* don't free the tuple passed by caller */
		undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id, NULL,
										   (undo_tup) == (&zhtup) ? false : true,
										   page);

		Assert(!TransactionIdPrecedes(urec->uur_prevxid, RecentGlobalXmin));

		prev_undo_xid = urec->uur_prevxid;

		/*
		 * Change the undo chain if the undo tuple is stamped with the
		 * different transaction slot.
		 */
		if (prev_trans_slot_id != trans_slot_id)
		{
			trans_slot_id = GetTransactionSlotInfo(buf,
												   ItemPointerGetOffsetNumber(&undo_tup->t_self),
												   trans_slot_id,
												   NULL,
												   NULL,
												   &urec_ptr,
												   true,
												   true);
		}
		else
			urec_ptr = urec->uur_blkprev;

		UndoRecordRelease(urec);
		urec = NULL;
	} while (UndoRecPtrIsValid(urec_ptr));

tuple_is_valid:
	if (urec)
		UndoRecordRelease(urec);
	if (undo_tup && undo_tup != &zhtup)
		pfree(undo_tup);

	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	return valid;
}

/*
 * zheap_exec_pending_rollback - Execute pending rollback actions for the
 *	given buffer (page).
 *
 * This function expects that the input buffer is locked.  We will release and
 * reacquire the buffer lock in this function, the same can be done in all the
 * callers of this function, but that is just a code duplication, so we instead
 * do it here.
 */
bool
zheap_exec_pending_rollback(Relation rel, Buffer buffer, int slot_no,
							TransactionId xwait)
{
	UndoRecPtr	urec_ptr;
	TransactionId xid;
	uint32		epoch;
	int			out_slot_no PG_USED_FOR_ASSERTS_ONLY;

	out_slot_no = GetTransactionSlotInfo(buffer,
										 InvalidOffsetNumber,
										 slot_no,
										 &epoch,
										 &xid,
										 &urec_ptr,
										 true,
										 true);

	/* As the rollback is pending, the slot can't be frozen. */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

	if (xwait != xid)
		return false;

	/*
	 * Release buffer lock before applying undo actions.
	 */
	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	process_and_execute_undo_actions_page(urec_ptr, rel, buffer, epoch, xid, slot_no);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	return true;
}

/*
 * zbuffer_exec_pending_rollback - apply any pending rollback on the input buffer
 *
 * This method traverses all the transaction slots of the current page including
 * tpd slots and applies any pending aborts on the page.
 *
 * It expects the caller has an exclusive lock on the relation. It also returns
 * the corresponding TPD block number in case it has rolled back any transactions
 * from the corresponding TPD page, if any.
 */
void
zbuffer_exec_pending_rollback(Relation rel, Buffer buf, BlockNumber *tpd_blkno)
{
	int			slot_no;
	int			total_trans_slots = 0;
	uint64		epoch;
	TransactionId xid;
	UndoRecPtr	urec_ptr;
	TransInfo  *trans_slots = NULL;
	bool		any_tpd_slot_rolled_back = false;

	Assert(tpd_blkno != NULL);

	/*
	 * Fetch all the transaction information from the page and its
	 * corresponding TPD page.
	 */
	LockBuffer(buf, BUFFER_LOCK_SHARE);
	trans_slots = GetTransactionsSlotsForPage(rel, buf, &total_trans_slots,
											  tpd_blkno);
	LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		epoch = trans_slots[slot_no].xid_epoch;
		xid = trans_slots[slot_no].xid;
		urec_ptr = trans_slots[slot_no].urec_ptr;

		/*
		 * There shouldn't be any other in-progress transaction as we hold an
		 * exclusive lock on the relation.
		 */
		Assert(TransactionIdIsCurrentTransactionId(xid) ||
			   !TransactionIdIsInProgress(xid));

		/* If the transaction is aborted, apply undo actions */
		if (TransactionIdIsValid(xid) && TransactionIdDidAbort(xid))
		{
			/* Remember if we've rolled back a transactio from a TPD-slot. */
			if ((slot_no >= ZHEAP_PAGE_TRANS_SLOTS - 1) &&
				BlockNumberIsValid(*tpd_blkno))
				any_tpd_slot_rolled_back = true;
			process_and_execute_undo_actions_page(urec_ptr, rel, buf, epoch,
												  xid, slot_no);
		}
	}

	/*
	 * If we've not rolled back anything from TPD slot, there is no need set
	 * the TPD buffer.
	 */
	if (!any_tpd_slot_rolled_back)
		*tpd_blkno = InvalidBlockNumber;

	/* be tidy */
	pfree(trans_slots);
}
