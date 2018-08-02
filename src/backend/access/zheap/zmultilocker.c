/*-------------------------------------------------------------------------
 *
 * zmultilocker.c
 *	  zheap multi locker code
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zmultilocker.c
 *
 * NOTES
 *	  This file contains functions for the multi locker facility of zheap.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tpd.h"
#include "access/xact.h"
#include "access/zmultilocker.h"
#include "storage/bufmgr.h"
#include "storage/buf_internals.h"
#include "storage/proc.h"

static bool IsZMultiLockListMember(List *members, ZMultiLockMember *mlmember);

/*
 * ZGetMultiLockMembersForCurrentXact - Return the strongest lock mode held by
 *			the current transaction on a given tuple.
 */
List *
ZGetMultiLockMembersForCurrentXact(ZHeapTuple zhtup, int trans_slot,
								   UndoRecPtr urec_ptr)
{
	ZHeapTuple		undo_tup;
	UnpackedUndoRecord	*urec = NULL;
	ZMultiLockMember		*mlmember;
	List	*multilockmembers = NIL;
	int trans_slot_id = -1;
	uint8	uur_type;

	undo_tup = zhtup;
	do
	{
		urec = UndoFetchRecord(urec_ptr,
							   ItemPointerGetBlockNumber(&zhtup->t_self),
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   InvalidTransactionId,
							   NULL,
							   ZHeapSatisfyUndoRecord);

		/* If undo is discarded, we can't proceed further. */
		if (!urec)
			break;

		/* If we encounter a different transaction, we shouldn't go ahead. */
		if (!TransactionIdIsCurrentTransactionId(urec->uur_xid))
			break;


		uur_type = urec->uur_type;

		if (uur_type == UNDO_INSERT || uur_type == UNDO_MULTI_INSERT)
		{
			/*
			 * We are done, once we are at the end of current chain.  We
			 * consider the chain has ended when we reach the root tuple.
			 */
			break;
		}

		/* don't free the tuple passed by caller */
		undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id,
										   (undo_tup) == (zhtup) ? false : true);

		if (uur_type == UNDO_XID_LOCK_ONLY ||
			uur_type == UNDO_XID_MULTI_LOCK_ONLY)
		{
			mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
			mlmember->xid = urec->uur_xid;
			mlmember->trans_slot_id = trans_slot;
			mlmember->mode = *((LockTupleMode *) urec->uur_payload.data);
			multilockmembers = lappend(multilockmembers, mlmember);
		}
		else if (uur_type == UNDO_UPDATE ||
					 uur_type == UNDO_INPLACE_UPDATE)
		{
			mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
			mlmember->xid = urec->uur_xid;
			mlmember->trans_slot_id = trans_slot;

			if (ZHEAP_XID_IS_EXCL_LOCKED(undo_tup->t_data->t_infomask))
				mlmember->mode = LockTupleExclusive;
			else
				mlmember->mode = LockTupleNoKeyExclusive;

			multilockmembers = lappend(multilockmembers, mlmember);
		}
		else if (uur_type == UNDO_DELETE)
		{
			mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
			mlmember->xid = urec->uur_xid;
			mlmember->trans_slot_id = trans_slot;
			mlmember->mode = LockTupleExclusive;
			multilockmembers = lappend(multilockmembers, mlmember);
		}
		else
		{
			/* Should not reach here */
			Assert(0);
		}

		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
		{
			/*
			 * We are done, once the the undo record suggests that prior
			 * record is already discarded.
			 *
			 * Note that we record the lock mode for all these cases because
			 * the lock mode stored in undo tuple is for the current
			 * transaction.
			 */
			break;
		}
		urec_ptr = urec->uur_blkprev;

		UndoRecordRelease(urec);
		urec = NULL;
	} while (UndoRecPtrIsValid(urec_ptr));

	if (urec)
	{
		UndoRecordRelease(urec);
		urec = NULL;
	}
	if (undo_tup && undo_tup != zhtup)
		pfree(undo_tup);

	return multilockmembers;
}

/*
 * ZGetMultiLockMembers - Return the list of members that have locked a
 *		particular tuple.
 *
 * This function returns the list of in-progress, committed or aborted
 * transactions.  The purpose of returning committed or aborted transactions
 * is that some of the callers want to take some specific action for
 * such transactions if they have updated the tuple.
 */
List *
ZGetMultiLockMembers(Relation rel, ZHeapTuple zhtup, Buffer buf,
					 bool nobuflock)
{
	Page	page;
	PageHeader	phdr;
	ZHeapTuple		undo_tup;
	UnpackedUndoRecord	*urec = NULL;
	UndoRecPtr		urec_ptr;
	ZMultiLockMember		*mlmember;
	List	*multilockmembers = NIL;
	TransInfo *tpd_trans_slots;
	TransInfo *trans_slots = NULL;
	TransactionId	xid;
	uint64	epoch_xid;
	uint64	epoch;
	int		prev_trans_slot_id,
			trans_slot_id;
	uint8	uur_type;
	int		slot_no;
	int		total_trans_slots = 0;
	bool	tpd_e_pruned;

	if (nobuflock)
	{
		ItemId	lp;

		LockBuffer(buf, BUFFER_LOCK_SHARE);
		lp = PageGetItemId(BufferGetPage(buf),
						   ItemPointerGetOffsetNumber(&zhtup->t_self));
		/*
		 * It is quite possible that once we reacquire the lock on buffer,
		 * some other backend would have deleted the tuple and in such case,
		 * we don't need to do anything.  However, the tuple can't be pruned
		 * because the current snapshot must predates the transaction that
		 * removes the tuple.
		 */
		Assert(!ItemIdIsDead(lp));
		if (ItemIdIsDeleted(lp))
		{
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
			return NIL;
		}
	}

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;

	if (ZHeapPageHasTPDSlot(phdr))
	{
		int		num_tpd_trans_slots;

		tpd_trans_slots = TPDPageGetTransactionSlots(rel,
													 buf,
													 InvalidOffsetNumber,
													 false,
													 false,
													 &num_tpd_trans_slots,
													 NULL,
													 &tpd_e_pruned);
		if (!tpd_e_pruned)
		{
			/*
			 * The last slot in page contains TPD information, so we don't need to
			 * include it.
			 */
			total_trans_slots = num_tpd_trans_slots + ZHEAP_PAGE_TRANS_SLOTS - 1;
			trans_slots = (TransInfo *)
					palloc(total_trans_slots * sizeof(TransInfo));
			/* Copy the transaction slots from the page. */
			memcpy(trans_slots, page + phdr->pd_special,
				   (ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo));
			/* Copy the transaction slots from the tpd entry. */
			memcpy((char *) trans_slots + ((ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo)),
				   tpd_trans_slots, num_tpd_trans_slots * sizeof(TransInfo));

			pfree(tpd_trans_slots);
		}
	}

	if (!ZHeapPageHasTPDSlot(phdr) || tpd_e_pruned)
	{
		Assert (trans_slots == NULL);

		total_trans_slots = ZHEAP_PAGE_TRANS_SLOTS;
		trans_slots = (TransInfo *)
				palloc(total_trans_slots * sizeof(TransInfo));
		memcpy(trans_slots, page + phdr->pd_special,
			   total_trans_slots * sizeof(TransInfo));
	}

	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		epoch = trans_slots[slot_no].xid_epoch;
		xid = trans_slots[slot_no].xid;

		epoch_xid = MakeEpochXid(epoch, xid);

		/*
		 * We need to process the undo chain only for in-progress
		 * transactions.
		 */
		if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
			continue;

		urec_ptr = trans_slots[slot_no].urec_ptr;
		trans_slot_id = slot_no + 1;
		undo_tup = zhtup;

		do
		{
			prev_trans_slot_id = trans_slot_id;
			urec = UndoFetchRecord(urec_ptr,
								   ItemPointerGetBlockNumber(&undo_tup->t_self),
								   ItemPointerGetOffsetNumber(&undo_tup->t_self),
								   InvalidTransactionId,
								   NULL,
								   ZHeapSatisfyUndoRecord);

			/* If undo is discarded, we can't proceed further. */
			if (!urec)
				break;
			/*
			 * Exclude undo records inserted by my own transaction.  We neither
			 * need to check conflicts with them nor need to wait for them.
			 */
			if (TransactionIdEquals(urec->uur_xid, GetTopTransactionIdIfAny()))
			{
				urec_ptr = urec->uur_blkprev;
				UndoRecordRelease(urec);
				urec = NULL;
				continue;
			}

			uur_type = urec->uur_type;

			if (uur_type == UNDO_INSERT || uur_type == UNDO_MULTI_INSERT)
			{
				/*
				 * We are done, once we are at the end of current chain.  We
				 * consider the chain has ended when we reach the root tuple.
				 */
				break;
			}

			/* don't free the tuple passed by caller */
			undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id,
											   (undo_tup) == (zhtup) ? false : true);

			if (uur_type == UNDO_XID_LOCK_ONLY ||
				uur_type == UNDO_XID_MULTI_LOCK_ONLY)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = urec->uur_xid;
				mlmember->trans_slot_id = prev_trans_slot_id;
				mlmember->mode = *((LockTupleMode *) urec->uur_payload.data);
				multilockmembers = lappend(multilockmembers, mlmember);
			}
			else if (uur_type == UNDO_UPDATE ||
					 uur_type == UNDO_INPLACE_UPDATE)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = urec->uur_xid;
				mlmember->trans_slot_id = prev_trans_slot_id;

				if (ZHEAP_XID_IS_EXCL_LOCKED(undo_tup->t_data->t_infomask))
					mlmember->mode = LockTupleExclusive;
				else
					mlmember->mode = LockTupleNoKeyExclusive;

				multilockmembers = lappend(multilockmembers, mlmember);
			}
			else if (uur_type == UNDO_DELETE)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = urec->uur_xid;
				mlmember->trans_slot_id = prev_trans_slot_id;
				mlmember->mode = LockTupleExclusive;
				multilockmembers = lappend(multilockmembers, mlmember);
			}
			else
			{
				/* Should not reach here */
				Assert(0);
			}

			if (trans_slot_id == ZHTUP_SLOT_FROZEN ||
				trans_slot_id != prev_trans_slot_id)
			{
				/*
				 * We are done, once the the undo record suggests that prior
				 * record is already discarded or the prior record belongs to
				 * a different transaction slot chain.
				 */
				break;
			}

			/*
			 * We allow to move backwards in the chain even when we
			 * encountered undo record of committed transaction
			 * (ZHeapTupleHasInvalidXact(undo_tup->t_data)).
			 */
			urec_ptr = urec->uur_blkprev;

			UndoRecordRelease(urec);
			urec = NULL;
		} while (UndoRecPtrIsValid(urec_ptr));

		if (urec)
		{
			UndoRecordRelease(urec);
			urec = NULL;
		}

		if (undo_tup && undo_tup != zhtup)
			pfree(undo_tup);
	}

	/* be tidy */
	pfree(trans_slots);

	return multilockmembers;
}

/*
 * ZMultiLockMembersWait - Wait for all the members to end.
 *
 * This function also applies the undo actions for aborted transactions.
 */
bool
ZMultiLockMembersWait(Relation rel, List *mlmembers, ZHeapTuple zhtup,
					  Buffer buf, TransactionId update_xact,
					  LockTupleMode required_mode, bool nowait,
					  XLTW_Oper oper, int *remaining, bool *upd_xact_aborted)
{
	bool		result = true;
	ListCell   *lc;
	BufferDesc *bufhdr PG_USED_FOR_ASSERTS_ONLY;
	int			remain = 0;

	bufhdr = GetBufferDescriptor(buf - 1);
	/* buffer must be unlocked */
	Assert(!LWLockHeldByMe(BufferDescriptorGetContentLock(bufhdr)));

	*upd_xact_aborted = false;

	foreach(lc, mlmembers)
	{
		ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);
		TransactionId	memxid = mlmember->xid;
		LockTupleMode	memmode = mlmember->mode;

		if (TransactionIdIsCurrentTransactionId(memxid))
		{
			remain++;
			continue;
		}

		if (!DoLockModesConflict(HWLOCKMODE_from_locktupmode(memmode),
								 HWLOCKMODE_from_locktupmode(required_mode)))
		{
			if (remaining && TransactionIdIsInProgress(memxid))
				remain++;
			continue;
		}

		/*
		 * This member conflicts with our multi, so we have to sleep (or
		 * return failure, if asked to avoid waiting.)
		 */
		if (nowait)
		{
			result = ConditionalXactLockTableWait(memxid);
			if (!result)
				break;
		}
		else
			XactLockTableWait(memxid, rel, &zhtup->t_self, oper);

		/*
		 * For aborted transaction, if the undo actions are not applied yet,
		 * then apply them before modifying the page.
		 */
		if (TransactionIdDidAbort(memxid))
		{
			LockBuffer(buf, BUFFER_LOCK_SHARE);
			zheap_exec_pending_rollback(rel, buf, mlmember->trans_slot_id, memxid);
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);

			if (TransactionIdIsValid(update_xact) && memxid == update_xact)
				*upd_xact_aborted = true;
		}
	}

	if (remaining)
		*remaining = remain;

	return result;
}

/*
 * ConditionalZMultiLockMembersWait
 *		As above, but only lock if we can get the lock without blocking.
 */
bool
ConditionalZMultiLockMembersWait(Relation rel, List *mlmembers,
								 Buffer buf, TransactionId update_xact,
								 LockTupleMode required_mode, int *remaining,
								 bool *upd_xact_aborted)
{
	return ZMultiLockMembersWait(rel, mlmembers, NULL, buf, update_xact,
								 required_mode, true, XLTW_None, remaining,
								 upd_xact_aborted);
}

/*
 * ZIsAnyMultiLockMemberRunning - Check if any multi lock member is running.
 *
 * Returns true, if any member of the multi lock is running, false otherwise.
 *
 * Unlike heap, we don't consider current transaction's lockers to decide
 * if the lockers of multi lock are running. In heap, any lock taken by
 * subtransaction is recorded separetly in the multixact, so that it can
 * detect if the subtransaction is rolled back. Now as the lock information
 * is tracked at subtransaction level, we can't ignore the lockers for
 * subtransactions of current top-level transaction. For zheap, rollback to
 * subtransaction will rewind the undo and the lockers information will
 * be automatically removed, so we don't need to track subtransaction lockers
 * separately and hence we can ignore lockers of current top-level
 * transaction.
 */
bool
ZIsAnyMultiLockMemberRunning(List *mlmembers, ZHeapTuple zhtup, Buffer buf)
{
	ListCell   *lc;
	BufferDesc *bufhdr PG_USED_FOR_ASSERTS_ONLY;

	bufhdr = GetBufferDescriptor(buf - 1);

	/*
	 * Local buffers can't be accesed by other sessions.
	 */
	if (BufferIsLocal(buf))
		return false;

	/* buffer must be locked by caller */
	Assert(LWLockHeldByMe(BufferDescriptorGetContentLock(bufhdr)));

	if (list_length(mlmembers) <= 0)
	{
		elog(DEBUG2, "ZIsRunning: no members");
		return false;
	}

	foreach(lc, mlmembers)
	{
		ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);
		TransactionId	memxid = mlmember->xid;

		if (TransactionIdIsInProgress(memxid))
		{
			elog(DEBUG2, "ZIsRunning: member %d is running", memxid);
			return true;
		}
	}

	elog(DEBUG2, "ZIsRunning: no members are running");

	return false;
}

/*
 * IsZMultiLockListMember - Returns true iff mlmember is a member of list
 *	mlmembers.  Equality is determined by comparing all the variables of
 *	member.
 */
static bool
IsZMultiLockListMember(List *members, ZMultiLockMember *mlmember)
{
	ListCell   *lc;

	foreach(lc, members)
	{
		ZMultiLockMember *lc_member = (ZMultiLockMember *) lfirst(lc);

		if (lc_member->xid == mlmember->xid &&
			lc_member->trans_slot_id == mlmember->trans_slot_id &&
			lc_member->mode == mlmember->mode)
			return true;
	}

	return false;
}

/*
 * ZMultiLockMembersSame -  Returns true, iff all the members in list2 list
 *	are present in list1 list
 */
bool
ZMultiLockMembersSame(List *list1, List	*list2)
{
	ListCell   *lc;

	if (list_length(list2) > list_length(list1))
		return false;

	foreach(lc, list2)
	{
		ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

		if (!IsZMultiLockListMember(list1, mlmember))
			return false;
	}

	return true;
}

/*
 * ZGetMultiLockInfo - Helper function for compute_new_xid_infomask to
 *	get the multi lockers information.
 */
void
ZGetMultiLockInfo(uint16 old_infomask, TransactionId tup_xid,
				  int tup_trans_slot, TransactionId add_to_xid,
				  uint16 *new_infomask, int *new_trans_slot,
				  LockTupleMode *mode, bool *old_tuple_has_update,
				  bool is_update)
{
	LockTupleMode old_mode;

	old_mode = get_old_lock_mode(old_infomask);

	if (IsZHeapTupleModified(old_infomask) &&
		!ZHEAP_XID_IS_LOCKED_ONLY(old_infomask))
	{
		*old_tuple_has_update = true;

		if (ZHeapTupleIsInPlaceUpdated(old_infomask))
		{
			*new_infomask |= ZHEAP_INPLACE_UPDATED;
		}
		else
		{
			Assert(ZHeapTupleIsUpdated(old_infomask));
			*new_infomask |= ZHEAP_UPDATED;
		}
	}

	if (tup_xid == add_to_xid)
	{
		if (ZHeapTupleHasMultiLockers(old_infomask))
			*new_infomask |= ZHEAP_MULTI_LOCKERS;

		/* acquire the strongest of both */
		if (*mode < old_mode)
			*mode = old_mode;
	}
	else
	{
		*new_infomask |= ZHEAP_MULTI_LOCKERS;

		/*
		 * Acquire the strongest of both and keep the transaction slot of
		 * the stronger lock.
		 */
		if (*mode < old_mode)
		{
			*mode = old_mode;
		}

		/* For lockers, we want to store the updater's transaction slot. */
		if (!is_update)
			*new_trans_slot = tup_trans_slot;
	}
}

/*
 * GetLockerTransInfo - Retrieve the transaction information of single locker
 * from undo.
 *
 * If the locker is already committed or too-old, we consider as if it didn't
 * exist at all.
 *
 * The caller must have a lock on the buffer (buf).
 */
bool
GetLockerTransInfo(Relation rel, ZHeapTuple zhtup, Buffer buf,
				   int *trans_slot, uint64 *epoch_xid_out,
				   TransactionId *xid_out, CommandId *cid_out,
				   UndoRecPtr *urec_ptr_out)
{
	Page	page;
	PageHeader	phdr;
	UnpackedUndoRecord	*urec = NULL;
	UndoRecPtr		urec_ptr;
	UndoRecPtr		save_urec_ptr = InvalidUndoRecPtr;
	TransInfo *tpd_trans_slots;
	TransInfo *trans_slots = NULL;
	TransactionId	xid;
	CommandId	cid = InvalidCommandId;
	uint64	epoch;
	uint64	epoch_xid;
	int		trans_slot_id;
	uint8	uur_type;
	int		slot_no;
	int		total_trans_slots = 0;
	bool	found = false;
	bool	tpd_e_pruned;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;

	if (ZHeapPageHasTPDSlot(phdr))
	{
		int		num_tpd_trans_slots;

		tpd_trans_slots = TPDPageGetTransactionSlots(rel,
													 buf,
													 InvalidOffsetNumber,
													 false,
													 false,
													 &num_tpd_trans_slots,
													 NULL,
													 &tpd_e_pruned);
		if (!tpd_e_pruned)
		{
			/*
			 * The last slot in page contains TPD information, so we don't need to
			 * include it.
			 */
			total_trans_slots = num_tpd_trans_slots + ZHEAP_PAGE_TRANS_SLOTS - 1;
			trans_slots = (TransInfo *)
					palloc(total_trans_slots * sizeof(TransInfo));
			/* Copy the transaction slots from the page. */
			memcpy(trans_slots, page + phdr->pd_special,
				   (ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo));
			/* Copy the transaction slots from the tpd entry. */
			memcpy((char *) trans_slots + ((ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo)),
				   tpd_trans_slots, num_tpd_trans_slots * sizeof(TransInfo));

			pfree(tpd_trans_slots);
		}
	}

	if (!ZHeapPageHasTPDSlot(phdr) || tpd_e_pruned)
	{
		Assert (trans_slots == NULL);

		total_trans_slots = ZHEAP_PAGE_TRANS_SLOTS;
		trans_slots = (TransInfo *)
				palloc(total_trans_slots * sizeof(TransInfo));
		memcpy(trans_slots, page + phdr->pd_special,
			   total_trans_slots * sizeof(TransInfo));
	}

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		epoch = trans_slots[slot_no].xid_epoch;
		xid = trans_slots[slot_no].xid;

		epoch_xid = MakeEpochXid(epoch, xid);

		/*
		 * We need to process the undo chain only for in-progress
		 * transactions.
		 */
		if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo) ||
			(!TransactionIdIsInProgress(xid) && TransactionIdDidCommit(xid)))
			continue;

		save_urec_ptr = urec_ptr = trans_slots[slot_no].urec_ptr;

		do
		{
			UndoRecPtr out_urec_ptr PG_USED_FOR_ASSERTS_ONLY;

			out_urec_ptr = InvalidUndoRecPtr;
			urec = UndoFetchRecord(urec_ptr,
								   ItemPointerGetBlockNumber(&zhtup->t_self),
								   ItemPointerGetOffsetNumber(&zhtup->t_self),
								   InvalidTransactionId,
								   &out_urec_ptr,
								   ZHeapSatisfyUndoRecord);

			/*
			 * We couldn't find any undo record for the tuple corresponding
			 * to current slot.
			 */
			if (urec == NULL)
			{
				/* Make sure we've reached the end of current undo chain. */
				Assert(!out_urec_ptr);
				break;
			}

			cid = urec->uur_cid;

			/*
			 * If the current transaction has locked the tuple, then we don't need
			 * to process the undo records.
			 */
			if (TransactionIdEquals(urec->uur_xid, GetTopTransactionIdIfAny()))
			{
				found = true;
				break;
			}

			uur_type = urec->uur_type;

			if (uur_type == UNDO_INSERT || uur_type == UNDO_MULTI_INSERT)
			{
				/*
				 * We are done, once we are at the end of current chain.  We
				 * consider the chain has ended when we reach the root tuple.
				 */
				break;
			}

			if (uur_type == UNDO_XID_LOCK_ONLY)
			{
				found = true;
				break;
			}

			if (xid != urec->uur_xid)
			{
				/*
				 * We are done, once the the undo record suggests that prior
				 * tuple version is modified by a different transaction.
				 */
				break;
			}

			urec_ptr = urec->uur_blkprev;

			UndoRecordRelease(urec);
			urec = NULL;
		} while (UndoRecPtrIsValid(urec_ptr));

		if (urec)
		{
			UndoRecordRelease(urec);
			urec = NULL;
		}

		if (found)
		{
			/* Transaction slots in the page start from 1. */
			trans_slot_id = slot_no + 1;
			break;
		}
	}

	/* be tidy */
	pfree(trans_slots);

	/*
	 * If found, we return the corresponding transaction information. Else, we
	 * return the same information as passed as arguments.
	 */
	if (found)
	{
		/* Set the value of required parameters. */
		if (trans_slot)
			*trans_slot = trans_slot_id;
		if (epoch_xid_out)
			*epoch_xid_out = MakeEpochXid(epoch, xid);
		if (xid_out)
			*xid_out = xid;
		if (cid_out)
			*cid_out = cid;
		if (urec_ptr_out)
			*urec_ptr_out = save_urec_ptr;
	}

	return found;
}
