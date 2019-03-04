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
#include "access/undoaction_xlog.h"
#include "access/undorecord.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "access/zheapscan.h"
#include "miscadmin.h"
#include "postmaster/undoloop.h"
#include "utils/syscache.h"
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

	if (!zheap_fetch(relation, snapshot, tid, tuple, &buffer, true, NULL))
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
ZHeapSatisfyUndoRecord(UnpackedUndoRecord *urec, BlockNumber blkno,
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
CopyTupleFromUndoRecord(UnpackedUndoRecord *urec, ZHeapTuple zhtup,
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
	Page		page;
	PageHeader	phdr;
	int			out_slot_no PG_USED_FOR_ASSERTS_ONLY;


	page = BufferGetPage(buffer);
	phdr = (PageHeader) page;

	/*
	 * If the caller reaquired the lock before calling this function, rollback
	 * could have been performed by some other backend or the undo-worker.  In
	 * that case, the TPD entry can be pruned away.
	 */
	if (slot_no >= ZHEAP_PAGE_TRANS_SLOTS && !ZHeapPageHasTPDSlot(phdr))
		return false;

	out_slot_no = GetTransactionSlotInfo(buffer,
										 InvalidOffsetNumber,
										 slot_no,
										 &epoch,
										 &xid,
										 &urec_ptr,
										 true,
										 true);

	/*
	 * If the caller reaquired the lock before calling this function, rollback
	 * could have been performed by some other backend or the undo-worker.  In
	 * that case, the TPD slot can be frozen since the TPD entry can be pruned
	 * away.
	 */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN ||
		   (ZHeapPageHasTPDSlot(phdr) && slot_no >= ZHEAP_PAGE_TRANS_SLOTS));

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

/*
 * undo_action_insert - perform the undo action for insert
 *
 *	This will mark the tuple as dead so that the future access to it can't see
 *	this tuple.  We mark it as unused if there is no other index pointing to
 *	it, otherwise mark it as dead.
 */
static inline void
undo_action_insert(Relation rel, Page page, OffsetNumber off,
				   TransactionId xid)
{
	ItemId		lp;
	bool		relhasindex;

	/*
	 * This will mark the tuple as dead so that the future access to it can't
	 * see this tuple.  We mark it as unused if there is no other index
	 * pointing to it, otherwise mark it as dead.
	 */
	relhasindex = RelationGetForm(rel)->relhasindex;
	lp = PageGetItemId(page, off);
	if (relhasindex)
	{
		ItemIdSetDead(lp);
	}
	else
	{
		ItemIdSetUnused(lp);
		/* Set hint bit for ZPageAddItem */
		PageSetHasFreeLinePointers(page);
	}

	ZPageSetPrunable(page, xid);
}

/*
 * zheap_undo_actions - Execute the undo actions for a zheap page
 *
 *	After applying all the undo actions for a page, we clear the transaction
 *	slot on a page if the undo chain for block is complete, otherwise just
 *	rewind the undo pointer to the last record for that block that precedes
 *	the last undo record for which action is replayed.
 *
 *	luinfo - list of undo records (along with their location) for which undo
 *			 action needs to be replayed.
 *	urec_ptr - undo record pointer to which we need to rewind.
 *	reloid	- OID of relation on which undo actions needs to be applied.
 *	blkno	- block number on which undo actions needs to be applied.
 *	blk_chain_complete - indicates whether the undo chain for block is
 *						 complete.
 *	nopartial - true if rollback is for complete transaction. If we are not
 *				rolling back the complete transaction then we need to apply the
 *				undo action for UNDO_INVALID_XACT_SLOT also because in such
 *				case we will rewind the insert undo location.
 *	rellock	  -	if the caller already has the lock on the required relation,
 *				then this flag is false, i.e. we do not need to acquire any
 *				lock here. If the flag is true then we need to acquire lock
 *				here itself, because caller will not be having any lock.
 *				When we are performing undo actions for prepared transactions,
 *				or for rollback to savepoint, we need not to lock as we already
 *				have the lock on the table. In cases like error or when
 *				rollbacking from the undo worker we need to have proper locks.
 *
 *	returns true, if successfully applied the undo actions, otherwise, false.
 */
bool
zheap_undo_actions(List *luinfo, UndoRecPtr urec_ptr, Oid reloid,
				   TransactionId xid, BlockNumber blkno,
				   bool blk_chain_complete, bool rellock)
{
	ListCell   *l_iter;
	Relation	rel;
	Buffer		buffer;
	Page		page;
	UndoRecPtr	slot_urec_ptr;
	uint32		epoch;
	int			slot_no = 0;
	int			tpd_map_size = 0;
	char	   *tpd_offset_map = NULL;
	UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);
	Buffer		vmbuffer = InvalidBuffer;
	bool		need_init = false;
	bool		tpd_page_locked = false;
	bool		is_tpd_map_updated = false;

	/*
	 * FIXME: If reloid is not valid then we have nothing to do. In future, we
	 * might want to do it differently for transactions that perform both DDL
	 * and DML operations.
	 */
	if (!OidIsValid(reloid))
	{
		elog(LOG, "ignoring undo for invalid reloid");
		return false;
	}

	if (!SearchSysCacheExists1(RELOID, ObjectIdGetDatum(reloid)))
		return false;

	/*
	 * If the action is executed by backend as a result of rollback, we must
	 * already have an appropriate lock on relation.
	 */
	if (rellock)
		rel = heap_open(reloid, RowExclusiveLock);
	else
		rel = heap_open(reloid, NoLock);

	if (RelationGetNumberOfBlocks(rel) <= blkno)
	{
		/*
		 * This is possible if the underlying relation is truncated just
		 * before taking the relation lock above.
		 */
		heap_close(rel, NoLock);
		return false;
	}

	buffer = ReadBuffer(rel, blkno);

	/*
	 * If there is a undo action of type UNDO_ITEMID_UNUSED then might need to
	 * clear visibility_map. Since we cannot call visibilitymap_pin or
	 * visibilitymap_status within a critical section it shall be called here
	 * and let it be before taking the buffer lock on page.
	 */
	foreach(l_iter, luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) lfirst(l_iter);
		UnpackedUndoRecord *uur = urec_info->uur;

		if (uur->uur_type == UNDO_ITEMID_UNUSED)
		{
			visibilitymap_pin(rel, blkno, &vmbuffer);
			break;
		}
	}

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	page = BufferGetPage(buffer);

	/*
	 * Identify the slot number for this transaction.  As we never allow undo
	 * more than 2-billion transactions, we can compute epoch from xid.
	 *
	 * Here, we will always take a lock on the tpd_page, if there is a tpd
	 * slot on the page.  This is required because sometimes we only come to
	 * know that we need to update the tpd page after applying the undo
	 * record. Now, the case where this can happen is when during DO operation
	 * the slot of previous updater is a non-TPD slot, but by the time we came
	 * for rollback it became a TPD slot which means this information won't be
	 * even recorded in undo.
	 */
	epoch = GetEpochForXid(xid);
	slot_no = PageGetTransactionSlotId(rel, buffer, epoch, xid,
									   &slot_urec_ptr, true, true,
									   &tpd_page_locked);

	/*
	 * If undo action has been already applied for this page then skip the
	 * process altogether.  If we didn't find a slot corresponding to xid, we
	 * consider the transaction is already rolledback.
	 *
	 * The logno of slot's undo record pointer must be same as the logno of
	 * undo record to be applied.
	 */
	if (slot_no == InvalidXactSlotId ||
		(UndoRecPtrGetLogNo(slot_urec_ptr) !=
		 UndoRecPtrGetLogNo(urec_info->urp)) ||
		(UndoRecPtrGetLogNo(slot_urec_ptr) == UndoRecPtrGetLogNo(urec_ptr) &&
		 slot_urec_ptr <= urec_ptr))
	{
		UnlockReleaseBuffer(buffer);
		heap_close(rel, NoLock);

		UnlockReleaseTPDBuffers();

		return false;
	}

	/*
	 * We might need to update the TPD offset map while applying undo actions,
	 * so get the size of the TPD offset map and allocate the memory to fetch
	 * that outside the critical section.  It is quite possible that the TPD
	 * entry is already pruned by this time, in which case, we will mark the
	 * slot as frozen.
	 *
	 * XXX It would have been better if we fetch the tpd map only when
	 * required, but that won't be possible in all cases.  Sometimes we will
	 * come to know only during processing particular undo record. Now, we can
	 * process the undo records partially outside critical section such that
	 * we know whether we need TPD map or not, but that seems to be overkill.
	 */
	if (tpd_page_locked)
	{
		tpd_map_size = TPDPageGetOffsetMapSize(buffer);
		if (tpd_map_size > 0)
			tpd_offset_map = palloc(tpd_map_size);
	}

	START_CRIT_SECTION();

	foreach(l_iter, luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) lfirst(l_iter);
		UnpackedUndoRecord *uur = urec_info->uur;

		/* Skip already applied undo. */
		if (slot_urec_ptr < urec_info->urp)
			continue;

		switch (uur->uur_type)
		{
			case UNDO_INSERT:
				{
					int			i,
								nline;
					ItemId		lp;
					uint32		specToken = 0;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);

					/*
					 * If a dead item is found, ensure that it is from
					 * specualtive abort case only.
					 */
					if (ItemIdIsDead(lp))
					{
						/* Fetch if this is a speculative insert case */
						specToken = *(uint32 *) uur->uur_payload.data;

						if (specToken)
						{
							ItemIdSetDead(lp);
							break;
						}
					}

					undo_action_insert(rel, page, uur->uur_offset, xid);

					nline = PageGetMaxOffsetNumber(page);
					need_init = true;
					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}
				}
				break;
			case UNDO_MULTI_INSERT:
				{
					OffsetNumber start_offset;
					OffsetNumber end_offset;
					OffsetNumber iter_offset;
					int			i,
								nline;
					ItemId		lp;

					start_offset = ((OffsetNumber *) uur->uur_payload.data)[0];
					end_offset = ((OffsetNumber *) uur->uur_payload.data)[1];

					for (iter_offset = start_offset;
						 iter_offset <= end_offset;
						 iter_offset++)
					{
						undo_action_insert(rel, page, iter_offset, xid);
					}

					nline = PageGetMaxOffsetNumber(page);
					need_init = true;
					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}
				}
				break;
			case UNDO_DELETE:
			case UNDO_UPDATE:
			case UNDO_INPLACE_UPDATE:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup;
					TransactionId slot_xid;
					Size		offset = 0;
					uint32		undo_tup_len;
					int			trans_slot;
					uint16		infomask;
					int			prev_trans_slot;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);
					infomask = zhtup->t_infomask;
					trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

					undo_tup_len = *((uint32 *) &uur->uur_tuple.data[offset]);
					ItemIdChangeLen(lp, undo_tup_len);
					/* skip ctid and tableoid stored in undo tuple */
					offset += sizeof(uint32) + sizeof(ItemPointerData) +
						sizeof(Oid);
					memcpy(zhtup,
						   (ZHeapTupleHeader) & uur->uur_tuple.data[offset],
						   undo_tup_len);

					/*
					 * Fetch previous transaction slot on tuple formed from
					 * undo record.
					 */
					prev_trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

					/*
					 * If the previous version of the tuple points to a TPD
					 * slot then we need to update the slot in the offset map
					 * of the TPD entry.  But, only if we still have a valid
					 * TPD entry for the page otherwise the old tuple version
					 * must be all visible and we can mark the slot as frozen.
					 */
					if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT &&
						tpd_offset_map)
					{
						TransactionId prev_slot_xid;

						/* Fetch TPD slot from the undo. */
						if (uur->uur_type == UNDO_UPDATE)
							prev_trans_slot =
								*(int *) ((char *) uur->uur_payload.data +
										  sizeof(ItemPointerData));
						else
							prev_trans_slot = *(int *) uur->uur_payload.data;

						/*
						 * If the previous transaction slot points to a TPD
						 * slot then we need to update the slot in the offset
						 * map of the TPD entry.
						 *
						 * This is the case where during DO operation the
						 * previous updater belongs to a non-TPD slot whereas
						 * now the same slot has become a TPD slot.  In such
						 * cases, we need to update offset-map.
						 */
						GetTransactionSlotInfo(buffer,
											   InvalidOffsetNumber,
											   prev_trans_slot,
											   NULL,
											   &prev_slot_xid,
											   NULL,
											   false,
											   true);

						TPDPageSetOffsetMapSlot(buffer, prev_trans_slot,
												uur->uur_offset);

						/* Here, we updated TPD offset map, so need to log. */
						if (!is_tpd_map_updated)
							is_tpd_map_updated = true;

						/*
						 * If transaction slot to which tuple point is not
						 * same as the previous transaction slot, so that we
						 * need to mark the tuple with a special flag.
						 */
						if (uur->uur_prevxid != prev_slot_xid)
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
					}
					else if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						ZHeapTupleHeaderSetXactSlot(zhtup, ZHTUP_SLOT_FROZEN);
					}
					else if (prev_trans_slot == ZHEAP_PAGE_TRANS_SLOTS &&
							 ZHeapPageHasTPDSlot((PageHeader) page))
					{
						TransactionId prev_slot_xid;

						if (tpd_offset_map == NULL)
						{
							/*
							 * If the previous slot is in tpd but tpd is
							 * pruned away then set the slot as frozen.
							 */
							ZHeapTupleHeaderSetXactSlot(zhtup,
														ZHTUP_SLOT_FROZEN);
						}
						else
						{
							/* TPD page must be locked by now. */
							Assert(tpd_page_locked);

							/*
							 * If the previous transaction slot points to a
							 * TPD slot then we need to update the slot in the
							 * offset map of the TPD entry.
							 *
							 * This is the case where during DO operation the
							 * previous updater belongs to a non-TPD slot
							 * whereas now the same slot has become a TPD
							 * slot. In such cases, we need to update
							 * offset-map.
							 */
							GetTransactionSlotInfo(buffer,
												   InvalidOffsetNumber,
												   prev_trans_slot,
												   NULL,
												   &prev_slot_xid,
												   NULL,
												   false,
												   true);
							TPDPageSetOffsetMapSlot(buffer,
													ZHEAP_PAGE_TRANS_SLOTS + 1,
													uur->uur_offset);

							/*
							 * Here, we updated TPD offset map, so need to
							 * log.
							 */
							if (!is_tpd_map_updated)
								is_tpd_map_updated = true;

							/*
							 * If transaction slot to which tuple point is not
							 * same as the previous transaction slot, so that
							 * we need to mark the tuple with a special flag.
							 */
							if (uur->uur_prevxid != prev_slot_xid)
								zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
						}
					}
					else
					{
						trans_slot = GetTransactionSlotInfo(buffer,
															uur->uur_offset,
															trans_slot,
															NULL,
															&slot_xid,
															NULL,
															false,
															false);

						if (TransactionIdEquals(uur->uur_prevxid,
												FrozenTransactionId))
						{
							/*
							 * If the previous xid is frozen, then we can
							 * safely mark the tuple as frozen.
							 */
							ZHeapTupleHeaderSetXactSlot(zhtup,
														ZHTUP_SLOT_FROZEN);
						}
						else if (trans_slot != ZHTUP_SLOT_FROZEN &&
								 uur->uur_prevxid != slot_xid)
						{
							/*
							 * If the transaction slot to which tuple point
							 * got reused by this time, then we need to mark
							 * the tuple with a special flag.  See comments
							 * atop PageFreezeTransSlots.
							 */
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
						}
					}

					/*
					 * We always need to retain the strongest locker
					 * information on the the tuple (as part of infomask and
					 * infomask2), if there are multiple lockers on a tuple.
					 * This is because the conflict detection mechanism works
					 * based on strongest locker.  See
					 * zheap_update/zheap_delete.  We have allowed to override
					 * the transaction slot information with whatever is
					 * present in undo as we have taken care during DO
					 * operation that it contains previous strongest locker
					 * information.  See compute_new_xid_infomask.
					 */
					if (ZHeapTupleHasMultiLockers(infomask))
					{
						/* ZHeapTupleHeaderSetXactSlot(zhtup, trans_slot); */
						zhtup->t_infomask |= ZHEAP_MULTI_LOCKERS;
						zhtup->t_infomask &= ~(zhtup->t_infomask &
											   ZHEAP_LOCK_MASK);
						zhtup->t_infomask |= infomask & ZHEAP_LOCK_MASK;

						/*
						 * If the tuple originally has INVALID_XACT_SLOT set,
						 * then we need to retain it as that must be the
						 * information of strongest locker.
						 */
						if (ZHeapTupleHasInvalidXact(infomask))
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
					}
				}
				break;
			case UNDO_XID_LOCK_ONLY:
			case UNDO_XID_LOCK_FOR_UPDATE:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup,
								undo_tup_hdr;
					uint16		infomask;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);
					infomask = zhtup->t_infomask;

					/*
					 * Override the tuple header values with values retrieved
					 * from undo record except when there are multiple
					 * lockers.  In such cases, we want to retain the
					 * strongest locker information present in infomask and
					 * infomask2.
					 */
					undo_tup_hdr = (ZHeapTupleHeader) uur->uur_tuple.data;

					if (!(ZHeapTupleHasMultiLockers(infomask)))
					{
						int			trans_slot;
						int			prev_trans_slot PG_USED_FOR_ASSERTS_ONLY;
						TransactionId slot_xid;

						/*
						 * We need to set the previous slot for tuples that
						 * are locked for update as such tuples changed the
						 * slot while acquiring the lock.
						 */
						if (uur->uur_type == UNDO_XID_LOCK_ONLY)
						{

							trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);
							trans_slot = GetTransactionSlotInfo(buffer,
																uur->uur_offset,
																trans_slot,
																NULL,
																&slot_xid,
																NULL,
																false,
																false);

							zhtup->t_infomask2 = undo_tup_hdr->t_infomask2;
							zhtup->t_infomask = undo_tup_hdr->t_infomask;
							zhtup->t_hoff = undo_tup_hdr->t_hoff;

							/*
							 * If the previous version of the tuple points to
							 * a TPD slot then we need to update the slot in
							 * the offset map of the TPD entry.  But, only if
							 * we still have a valid TPD entry for the page
							 * otherwise the old tuple version must be all
							 * visible and we can mark the slot as frozen.
							 */
							if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
							{
								prev_trans_slot =
									*(int *) ((char *) uur->uur_payload.data +
											  sizeof(LockTupleMode));

								/*
								 * For a non multi locker case, the slot in
								 * undo (hence on tuple) must be either a
								 * frozen slot or the previous slot.
								 */
								Assert(trans_slot == ZHTUP_SLOT_FROZEN ||
									   trans_slot == prev_trans_slot);
							}
							else
							{
								/*
								 * For a non multi locker case, the slot in
								 * undo (hence on tuple) must be either a
								 * frozen slot or the previous slot. It is
								 * quite possible that previous slot may moved
								 * in TPD. Generally, we always set the
								 * multi-locker bit on the tuple whenever the
								 * tuple slot is not frozen. But, if the tuple
								 * is inserted/modified by the same
								 * transaction that later takes a lock on it,
								 * we keep the transaction slot as it is. See
								 * compute_new_xid_infomask for details.
								 */
								prev_trans_slot =
									ZHeapTupleHeaderGetXactSlot(zhtup);
								Assert(trans_slot == ZHTUP_SLOT_FROZEN ||
									   trans_slot == prev_trans_slot ||
									   (ZHeapPageHasTPDSlot((PageHeader) page) &&
										trans_slot == prev_trans_slot + 1));
							}
						}
						else
						{
							zhtup->t_infomask2 = undo_tup_hdr->t_infomask2;
							zhtup->t_infomask = undo_tup_hdr->t_infomask;
							zhtup->t_hoff = undo_tup_hdr->t_hoff;

							/*
							 * Fetch previous transaction slot on tuple formed
							 * from undo record.
							 */
							prev_trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

							/*
							 * If the previous version of the tuple points to
							 * a TPD slot then we need to update the slot in
							 * the offset map of the TPD entry.  But, only if
							 * we still have a valid TPD entry for the page
							 * otherwise the old tuple version must be all
							 * visible and we can mark the slot as frozen.
							 */
							if (uur->uur_info &
								UREC_INFO_PAYLOAD_CONTAINS_SLOT &&
								tpd_offset_map)
							{
								TransactionId prev_slot_xid;

								prev_trans_slot =
									*(int *) ((char *) uur->uur_payload.data +
											  sizeof(LockTupleMode));

								/*
								 * If the previous transaction slot points to
								 * a TPD slot then we need to update the slot
								 * in the offset map of the TPD entry.
								 *
								 * This is the case where during DO operation
								 * the previous updater belongs to a non-TPD
								 * slot whereas now the same slot has become a
								 * TPD slot.  In such cases, we need to update
								 * offset-map.
								 */
								GetTransactionSlotInfo(buffer,
													   InvalidOffsetNumber,
													   prev_trans_slot,
													   NULL,
													   &prev_slot_xid,
													   NULL,
													   false,
													   true);

								TPDPageSetOffsetMapSlot(buffer, prev_trans_slot,
														uur->uur_offset);

								/*
								 * Here, we updated TPD offset map, so need to
								 * log.
								 */
								if (!is_tpd_map_updated)
									is_tpd_map_updated = true;

								/*
								 * If transaction slot to which tuple point is
								 * not same as the previous transaction slot,
								 * so that we need to mark the tuple with a
								 * special flag.
								 */
								if (prev_slot_xid != uur->uur_prevxid)
									zhtup->t_infomask |=
										ZHEAP_INVALID_XACT_SLOT;
							}
							else if (uur->uur_info &
									 UREC_INFO_PAYLOAD_CONTAINS_SLOT)
							{
								ZHeapTupleHeaderSetXactSlot(zhtup,
															ZHTUP_SLOT_FROZEN);
							}
							else if (prev_trans_slot ==
									 ZHEAP_PAGE_TRANS_SLOTS &&
									 ZHeapPageHasTPDSlot((PageHeader) page))
							{
								TransactionId prev_slot_xid;

								if (tpd_offset_map == NULL)
								{
									/*
									 * If the previous slot is in tpd but tpd
									 * is pruned away then set the slot as
									 * frozen.
									 */
									ZHeapTupleHeaderSetXactSlot(zhtup,
																ZHTUP_SLOT_FROZEN);
								}
								else
								{
									/* TPD page must be locked by now. */
									Assert(tpd_page_locked);

									/*
									 * If the previous transaction slot points
									 * to a TPD slot then we need to update
									 * the slot in the offset map of the TPD
									 * entry.
									 *
									 * This is the case where during DO
									 * operation the previous updater belongs
									 * to a non-TPD slot whereas now the same
									 * slot has become a TPD slot.  In such
									 * cases, we need to update offset-map.
									 */
									GetTransactionSlotInfo(buffer,
														   InvalidOffsetNumber,
														   prev_trans_slot,
														   NULL,
														   &prev_slot_xid,
														   NULL,
														   false,
														   true);

									TPDPageSetOffsetMapSlot(buffer,
															ZHEAP_PAGE_TRANS_SLOTS + 1,
															uur->uur_offset);

									/*
									 * Here, we updated TPD offset map, so
									 * need to log.
									 */
									if (!is_tpd_map_updated)
										is_tpd_map_updated = true;

									if (prev_slot_xid != uur->uur_prevxid)
									{
										/*
										 * Here, transaction slot to which
										 * tuple point is not same as the
										 * previous transaction slot, so that
										 * we need to mark the tuple with a
										 * special flag.
										 */
										zhtup->t_infomask |=
											ZHEAP_INVALID_XACT_SLOT;
									}
								}
							}
							else
							{
								trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);
								trans_slot = GetTransactionSlotInfo(buffer,
																	uur->uur_offset,
																	trans_slot,
																	NULL,
																	&slot_xid,
																	NULL,
																	false,
																	false);

								if (TransactionIdEquals(uur->uur_prevxid,
														FrozenTransactionId))
								{
									/*
									 * If the previous xid is frozen, then we
									 * can safely mark the tuple as frozen.
									 */
									ZHeapTupleHeaderSetXactSlot(zhtup,
																ZHTUP_SLOT_FROZEN);
								}
								else if (trans_slot != ZHTUP_SLOT_FROZEN &&
										 uur->uur_prevxid != slot_xid)
								{
									/*
									 * If the transaction slot to which tuple
									 * point got reused by this time, then we
									 * need to mark the tuple with a special
									 * flag.  See comments atop
									 * PageFreezeTransSlots.
									 */
									zhtup->t_infomask |=
										ZHEAP_INVALID_XACT_SLOT;
								}
							}
						}
					}
				}
				break;
			case UNDO_XID_MULTI_LOCK_ONLY:
				break;
			case UNDO_ITEMID_UNUSED:
				{
					int			item_count,
								i;
					OffsetNumber *unused;

					unused = ((OffsetNumber *) uur->uur_payload.data);
					item_count = (uur->uur_payload.len / sizeof(OffsetNumber));

					/*
					 * We need to preserve all the unused items in zheap so
					 * that they can't be reused till the corresponding index
					 * entries are removed.  So, marking them dead is a
					 * sufficient indication for the index to remove the entry
					 * in index.
					 */
					for (i = 0; i < item_count; i++)
					{
						ItemId		itemid;

						itemid = PageGetItemId(page, unused[i]);
						ItemIdSetDead(itemid);
					}

					/* clear visibility map */
					Assert(BufferIsValid(vmbuffer));
					visibilitymap_clear(rel, blkno, vmbuffer,
										VISIBILITYMAP_VALID_BITS);

				}
				break;
			default:
				elog(ERROR, "unsupported undo record type");
		}
	}

	/*
	 * If the undo chain for the block is complete then set the xid in the
	 * slot as InvalidTransactionId.  But, rewind the slot urec_ptr to the
	 * previous urec_ptr in the slot.  This is to make sure if any transaction
	 * reuse the transaction slot and rollback then put back the previous
	 * transaction's urec_ptr.
	 */
	if (blk_chain_complete)
	{
		epoch = 0;
		xid = InvalidTransactionId;
	}

	PageSetTransactionSlotInfo(buffer, slot_no, epoch, xid, urec_ptr);

	MarkBufferDirty(buffer);

	/*
	 * We are logging the complete page for undo actions, so we don't need to
	 * record the data for individual operations.  We can optimize it by
	 * recording the data for individual operations, but again if there are
	 * multiple operations, then it might be better to log the complete page.
	 * So we can have some threshold above which we always log the complete
	 * page.
	 */
	if (RelationNeedsWAL(rel))
	{
		XLogRecPtr	recptr;
		uint8		flags = 0;

		if (slot_no > ZHEAP_PAGE_TRANS_SLOTS)
			flags |= XLU_PAGE_CONTAINS_TPD_SLOT;
		if (BufferIsValid(vmbuffer))
			flags |= XLU_PAGE_CLEAR_VISIBILITY_MAP;
		if (is_tpd_map_updated)
		{
			/* TPD page must be locked. */
			Assert(tpd_page_locked);
			/* tpd_offset_map must be non-null. */
			Assert(tpd_offset_map);
			flags |= XLU_CONTAINS_TPD_OFFSET_MAP;
		}
		if (need_init)
			flags |= XLU_INIT_PAGE;

		XLogBeginInsert();

		XLogRegisterData((char *) &flags, sizeof(uint8));
		XLogRegisterBuffer(0, buffer, REGBUF_FORCE_IMAGE | REGBUF_STANDARD);

		/* Log the TPD details, if the transaction slot belongs to TPD. */
		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT)
		{
			xl_undoaction_page xlrec;

			xlrec.urec_ptr = urec_ptr;
			xlrec.xid = xid;
			xlrec.trans_slot_id = slot_no;
			XLogRegisterData((char *) &xlrec, SizeOfUndoActionPage);
		}

		/*
		 * Log the TPD offset map if we have modified it.
		 *
		 * XXX Another option could be that we track all the offset map
		 * entries of TPD which got modified while applying the undo and only
		 * log those information into the WAL.
		 */
		if (is_tpd_map_updated)
		{
			/* Fetch the TPD offset map and write into the WAL record. */
			TPDPageGetOffsetMap(buffer, tpd_offset_map, tpd_map_size);
			XLogRegisterData((char *) tpd_offset_map, tpd_map_size);
		}

		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
			flags & XLU_CONTAINS_TPD_OFFSET_MAP)
		{
			RegisterTPDBuffer(page, 1);
		}

		recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_PAGE);

		PageSetLSN(page, recptr);
		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
			flags & XLU_CONTAINS_TPD_OFFSET_MAP)
			TPDPageSetLSN(page, recptr);
	}

	/*
	 * During rollback, if all the itemids are marked as unused, we need to
	 * initialize the page, so that the next insertion can see the page as
	 * initialized.  This serves two purposes (a) On next insertion, we can
	 * safely set the XLOG_ZHEAP_INIT_PAGE flag in WAL (OTOH, if we don't
	 * initialize the page here and set the flag, wal consistency checker can
	 * complain), (b) we don't accumulate the dead space in the page.
	 *
	 * Note that we initialize the page after writing WAL because the TPD
	 * routines use last slot in page to determine TPD block number.
	 */
	if (need_init)
		ZheapInitPage(page, (Size) BLCKSZ);

	END_CRIT_SECTION();

	/* Free TPD offset map memory. */
	if (tpd_offset_map)
		pfree(tpd_offset_map);

	/*
	 * Release any remaining pin on visibility map page.
	 */
	if (BufferIsValid(vmbuffer))
		ReleaseBuffer(vmbuffer);

	UnlockReleaseBuffer(buffer);
	UnlockReleaseTPDBuffers();

	heap_close(rel, NoLock);

	return true;
}
