/*-------------------------------------------------------------------------
 *
 * zmultilocker.c
 *	  zheap multi locker code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
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
#include "utils/ztqual.h"

static bool IsZMultiLockListMember(List *members, ZMultiLockMember *mlmember);

/*
 * ZCurrentXactHasTupleLockMode
 *
 * Returns true if the current transaction has a lock in the given mode or
 * higher on the current tuple.
 */
bool
ZCurrentXactHasTupleLockMode(ZHeapTuple zhtup, UndoRecPtr urec_ptr,
							 LockTupleMode required_mode)
{
	ZHeapTupleHeaderData hdr;
	UnpackedUndoRecord *urec = NULL;
	int			trans_slot_id = -1;
	uint8		uur_type;
	bool		result = false;
	LockTupleMode current_mode;

	memcpy(&hdr, zhtup->t_data, SizeofZHeapTupleHeader);
	do
	{
		urec = ZHeapUndoFetchRecord(urec_ptr,
							   ItemPointerGetBlockNumber(&zhtup->t_self),
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   InvalidTransactionId,
							   NULL);

		/* If undo is discarded, we can't proceed further. */
		if (!urec)
			break;

		/* If we encounter a different transaction, we shouldn't go ahead. */
		if (!TransactionIdIsCurrentTransactionId(XidFromFullTransactionId(urec->uur_fxid)))
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

		trans_slot_id = UpdateTupleHeaderFromUndoRecord(urec, &hdr, NULL);

		if (uur_type == UNDO_XID_LOCK_ONLY ||
			uur_type == UNDO_XID_LOCK_FOR_UPDATE ||
			uur_type == UNDO_XID_MULTI_LOCK_ONLY)
			current_mode = *((LockTupleMode *) urec->uur_payload.data);
		else if (uur_type == UNDO_UPDATE ||
				 uur_type == UNDO_INPLACE_UPDATE)
		{
			if (ZHEAP_XID_IS_EXCL_LOCKED(hdr.t_infomask))
				current_mode = LockTupleExclusive;
			else
				current_mode = LockTupleNoKeyExclusive;
		}
		else if (uur_type == UNDO_DELETE)
			current_mode = LockTupleExclusive;
		else
		{
			/* Should not reach here */
			Assert(0);
		}

		if (current_mode >= required_mode)
		{
			result = true;
			break;
		}

		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
		{
			/*
			 * We are done, once the undo record suggests that prior record is
			 * already discarded.
			 *
			 * Note that we record the lock mode for all these cases because
			 * the lock mode stored in undo tuple is for the current
			 * transaction.
			 */
			break;
		}
		urec_ptr = urec->uur_prevundo;

		UndoRecordRelease(urec);
		urec = NULL;
	} while (UndoRecPtrIsValid(urec_ptr));

	if (urec)
	{
		UndoRecordRelease(urec);
		urec = NULL;
	}

	return result;
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
	ZHeapTupleHeaderData hdr;
	UnpackedUndoRecord *urec = NULL;
	UndoRecPtr	urec_ptr;
	ZMultiLockMember *mlmember;
	List	   *multilockmembers = NIL;
	TransInfo  *trans_slots = NULL;
	SubTransactionId subxid = InvalidSubTransactionId;
	int			prev_trans_slot_id,
				trans_slot_id;
	uint8		uur_type;
	int			slot_no;
	int			total_trans_slots = 0;
	BlockNumber tpd_blkno = InvalidBlockNumber;
	BlockNumber blkno = ItemPointerGetBlockNumber(&zhtup->t_self);
	OffsetNumber offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);

	if (nobuflock)
	{
		ItemId		lp;

		LockBuffer(buf, BUFFER_LOCK_SHARE);
		lp = PageGetItemId(BufferGetPage(buf), offnum);

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

	trans_slots = GetTransactionsSlotsForPage(rel, buf, &total_trans_slots,
											  &tpd_blkno);

	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		FullTransactionId epoch_xid = trans_slots[slot_no].fxid;

		/*
		 * We need to process the undo chain only for in-progress
		 * transactions.
		 */
		if (FullTransactionIdOlderThanAllUndo(epoch_xid))
			continue;

		urec_ptr = trans_slots[slot_no].urec_ptr;
		trans_slot_id = slot_no + 1;
		memcpy(&hdr, zhtup->t_data, SizeofZHeapTupleHeader);

		/*
		 * If the page contains TPD slots and it's not pruned, the last slot
		 * contains the information about the corresponding TPD entry. Hence,
		 * if current slot refers to some TPD slot, we should skip the last
		 * slot in the page by increasing the slot index by 1.
		 */
		if ((trans_slot_id >= ZHEAP_PAGE_TRANS_SLOTS) &&
			BlockNumberIsValid(tpd_blkno))
			trans_slot_id += 1;

		do
		{
			prev_trans_slot_id = trans_slot_id;
			urec = ZHeapUndoFetchRecord(urec_ptr,
								   blkno,
								   offnum,
								   InvalidTransactionId,
								   NULL);

			/* If undo is discarded, we can't proceed further. */
			if (!urec)
				break;

			ZHeapTupleGetSubXid(buf, offnum, urec_ptr, &subxid);

			/*
			 * Exclude undo records inserted by my own transaction.  We
			 * neither need to check conflicts with them nor need to wait for
			 * them.
			 */
			if (TransactionIdEquals(XidFromFullTransactionId(urec->uur_fxid), GetTopTransactionIdIfAny()))
			{
				urec_ptr = urec->uur_prevundo;
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

			trans_slot_id =
				UpdateTupleHeaderFromUndoRecord(urec, &hdr,
												BufferGetPage(buf));

			if (uur_type == UNDO_XID_LOCK_ONLY ||
				uur_type == UNDO_XID_LOCK_FOR_UPDATE ||
				uur_type == UNDO_XID_MULTI_LOCK_ONLY)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = XidFromFullTransactionId(urec->uur_fxid);
				mlmember->subxid = subxid;
				mlmember->trans_slot_id = prev_trans_slot_id;
				mlmember->mode = *((LockTupleMode *) urec->uur_payload.data);
				multilockmembers = lappend(multilockmembers, mlmember);
			}
			else if (uur_type == UNDO_UPDATE ||
					 uur_type == UNDO_INPLACE_UPDATE)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = XidFromFullTransactionId(urec->uur_fxid);
				mlmember->subxid = subxid;
				mlmember->trans_slot_id = prev_trans_slot_id;

				if (ZHEAP_XID_IS_EXCL_LOCKED(hdr.t_infomask))
					mlmember->mode = LockTupleExclusive;
				else
					mlmember->mode = LockTupleNoKeyExclusive;

				multilockmembers = lappend(multilockmembers, mlmember);
			}
			else if (uur_type == UNDO_DELETE)
			{
				mlmember = (ZMultiLockMember *) palloc(sizeof(ZMultiLockMember));
				mlmember->xid = XidFromFullTransactionId(urec->uur_fxid);
				mlmember->subxid = subxid;
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
				 * We are done, once the undo record suggests that prior
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
			urec_ptr = urec->uur_prevundo;

			UndoRecordRelease(urec);
			urec = NULL;
		} while (UndoRecPtrIsValid(urec_ptr));

		if (urec)
		{
			UndoRecordRelease(urec);
			urec = NULL;
		}
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
		TransactionId memxid = mlmember->xid;
		SubTransactionId memsubxid = mlmember->subxid;
		LockTupleMode memmode = mlmember->mode;

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
		if (memsubxid != InvalidSubTransactionId)
		{
			if (nowait)
			{
				result = ConditionalSubXactLockTableWait(memxid, memsubxid);
				if (!result)
					break;
			}
			else
				SubXactLockTableWait(memxid, memsubxid, rel, &zhtup->t_self,
									 oper);
		}
		else if (nowait)
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
		 * To check abort, we can call TransactionIdDidAbort but always this
		 * will not give proper status because if this transaction was running
		 * at the time of crash, and after restart, status of this transaction
		 * will be as aborted but still we should consider this transaction as
		 * aborted and should apply the actions. So here, to identify all types
		 * of aborted transaction, we will check that if this transaction is
		 * not committed and not in-progress, it means this is aborted and we
		 * can apply actions here.
		 */
		if (!TransactionIdDidCommit(memxid) && !TransactionIdIsInProgress(memxid))
		{
			LockBuffer(buf, BUFFER_LOCK_SHARE);
			zheap_exec_pending_rollback(rel, buf, mlmember->trans_slot_id,
										memxid, NULL);
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
 * subtransaction is recorded separately in the multixact, so that it can
 * detect if the subtransaction is rolled back. Now as the lock information
 * is tracked at subtransaction level, we can't ignore the lockers for
 * subtransactions of current top-level transaction. For zheap, rollback to
 * subtransaction will rewind the undo and the lockers information will
 * be automatically removed, so we don't need to track subtransaction lockers
 * separately and hence we can ignore lockers of current top-level
 * transaction.
 */
bool
ZIsAnyMultiLockMemberRunning(Relation rel,
							 List *mlmembers, ZHeapTuple zhtup, Buffer buf,
							 bool *pending_actions_applied)
{
	ListCell   *lc;
	BufferDesc *bufhdr PG_USED_FOR_ASSERTS_ONLY;

	bufhdr = GetBufferDescriptor(buf - 1);

	/*
	 * Local buffers can't be accessed by other sessions.
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
		TransactionId memxid = mlmember->xid;

		if (TransactionIdIsInProgress(memxid))
		{
			elog(DEBUG2, "ZIsRunning: member %d is running", memxid);
			return true;
		}
		else if (TransactionIdDidAbort(memxid))
		{
			bool		action_applied;

			/* Slot must be valid. */
			Assert(mlmember->trans_slot_id != InvalidXactSlotId);

			/* Apply the actions. */
			action_applied = zheap_exec_pending_rollback(rel, buf,
													mlmember->trans_slot_id,
													memxid,
													NULL);

			/*
			 * If actions are applied, then set pending_actions_applied flag
			 * so that the caller can identify that buffer lock is reacquired.
			 */
			if (action_applied && !*pending_actions_applied)
				*pending_actions_applied = true;
		}
	}

	elog(DEBUG2, "ZIsRunning: no members are running");

	return false;
}

/*
 * IsZMultiLockListMember - Returns true iff mlmember is a member of list
 *	members.  Equality is determined by comparing all the variables of
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
ZMultiLockMembersSame(List *list1, List *list2)
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
				  LockOper lockoper)
{
	LockTupleMode old_mode;

	old_mode = get_old_lock_mode(old_infomask);

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
		 * Acquire the strongest of both and keep the transaction slot of the
		 * stronger lock.
		 */
		if (*mode < old_mode)
		{
			*mode = old_mode;
		}

		/* For lockers, we want to store the updater's transaction slot. */
		if (lockoper != ForUpdate)
			*new_trans_slot = tup_trans_slot;
	}

	/*
	 * We want to propagate the updaters information for lockers only provided
	 * the tuple is already locked by others (aka it has its multi-locker bit
	 * set).
	 */
	if (lockoper != ForUpdate &&
		ZHeapTupleHasMultiLockers(*new_infomask) &&
		IsZHeapTupleModified(old_infomask) &&
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
GetLockerTransInfo(Relation rel, ItemPointer tid, Buffer buf,
				   int *trans_slot, FullTransactionId *fxid_out)
{
	UnpackedUndoRecord *urec = NULL;
	UndoRecPtr	urec_ptr;
	TransInfo  *trans_slots = NULL;
	FullTransactionId fxid;
	FullTransactionId oldestXidWithEpochHavingUndo;
	int			trans_slot_id = InvalidXactSlotId;
	uint8		uur_type;
	int			slot_no;
	int			total_trans_slots = 0;
	bool		found = false;
	BlockNumber tpd_blkno;

	/* Set the default values. */
	if (fxid_out)
		*fxid_out = InvalidFullTransactionId;
	if (trans_slot)
		*trans_slot = InvalidXactSlotId;

	oldestXidWithEpochHavingUndo = FullTransactionIdFromU64(
															pg_atomic_read_u64(&ProcGlobal->oldestFullXidHavingUnappliedUndo));
	trans_slots = GetTransactionsSlotsForPage(rel, buf, &total_trans_slots,
											  &tpd_blkno);

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		TransactionId xid;

		fxid = trans_slots[slot_no].fxid;
		xid = XidFromFullTransactionId(fxid);

		/*
		 * We need to process the undo chain only for in-progress
		 * transactions.
		 */
		if (FullTransactionIdPrecedes(fxid, oldestXidWithEpochHavingUndo) ||
			(!TransactionIdIsInProgress(xid) && TransactionIdDidCommit(xid)))
			continue;

		urec_ptr = trans_slots[slot_no].urec_ptr;

		do
		{
			UndoRecPtr	out_urec_ptr PG_USED_FOR_ASSERTS_ONLY;

			out_urec_ptr = InvalidUndoRecPtr;
			urec = ZHeapUndoFetchRecord(urec_ptr,
								   ItemPointerGetBlockNumber(tid),
								   ItemPointerGetOffsetNumber(tid),
								   InvalidTransactionId,
								   &out_urec_ptr);

			/*
			 * We couldn't find any undo record for the tuple corresponding to
			 * current slot.
			 */
			if (urec == NULL)
			{
				/* Make sure we've reached the end of current undo chain. */
				Assert(!out_urec_ptr);
				break;
			}

			/*
			 * If the current transaction has locked the tuple, then we don't
			 * need to process the undo records.
			 */
			if (TransactionIdEquals(XidFromFullTransactionId(urec->uur_fxid), GetTopTransactionIdIfAny()))
			{
				found = true;
				break;
			}

			if (xid != XidFromFullTransactionId(urec->uur_fxid))
			{
				/*
				 * We are done, once the undo record suggests that prior tuple
				 * version is modified by a different transaction.
				 */
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

			if (uur_type == UNDO_XID_LOCK_ONLY ||
				uur_type == UNDO_XID_LOCK_FOR_UPDATE)
			{
				found = true;
				break;
			}

			urec_ptr = urec->uur_prevundo;

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

			/*
			 * If the page contains TPD slots and it's not pruned, the last
			 * slot contains the information about the corresponding TPD
			 * entry. Hence, if current slot refers to some TPD slot, we
			 * should skip the last slot in the page by increasing the slot
			 * index by 1.
			 */
			if ((trans_slot_id >= ZHEAP_PAGE_TRANS_SLOTS) &&
				BlockNumberIsValid(tpd_blkno))
				trans_slot_id += 1;

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
		if (fxid_out)
			*fxid_out = fxid;
	}

	return found;
}
