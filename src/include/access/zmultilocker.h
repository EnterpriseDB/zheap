/*-------------------------------------------------------------------------
 *
 * zmultilocker.h
 *	  POSTGRES zheap multi locker function definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zmultilocker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZMULTILOCKER_H
#define ZMULTILOCKER_H

#include "postgres.h"

#include "access/zhtup.h"
#include "storage/lmgr.h"
#include "utils/rel.h"

/* Get the LOCKMODE for a given LockTupleMode */
#define HWLOCKMODE_from_locktupmode(lockmode) \
				(GetHWLockModeFromMode(lockmode))

extern bool ZCurrentXactHasTupleLockMode(ZHeapTuple zhtup,
										 UndoRecPtr urec_ptr, LockTupleMode required_mode);
extern List *ZGetMultiLockMembers(Relation rel, ZHeapTuple zhtup, Buffer buf,
								  bool nobuflock);
extern bool ZMultiLockMembersWait(Relation rel, List *mlmembers,
								  ZHeapTuple zhtup, Buffer buf, TransactionId update_xact,
								  LockTupleMode required_mode, bool nowait, XLTW_Oper oper,
								  int *remaining, bool *upd_xact_aborted);
extern bool ConditionalZMultiLockMembersWait(Relation rel, List *mlmembers,
											 Buffer buf, TransactionId update_xact,
											 LockTupleMode required_mode, int *remaining,
											 bool *upd_xact_aborted);
extern bool ZIsAnyMultiLockMemberRunning(Relation rel,
										 List *mlmembers, ZHeapTuple zhtup,
										 Buffer buf, bool *pending_actions_applied);
extern bool ZMultiLockMembersSame(List *old_members, List *new_members);
extern void ZGetMultiLockInfo(uint16 old_infomask, TransactionId tup_xid,
							  int tup_trans_slot, TransactionId add_to_xid,
							  uint16 *new_infomask, int *new_trans_slot,
							  LockTupleMode *mode, bool *old_tuple_has_update,
							  LockOper lockoper);
extern bool GetLockerTransInfo(Relation rel, ItemPointer tid, Buffer buf,
							   int *trans_slot, FullTransactionId *fxid_out);

static inline LockTupleMode
get_old_lock_mode(uint16 infomask)
{
	LockTupleMode old_lock_mode;

	/*
	 * Normally, if the tuple is not marked as locked only, it should not
	 * contain any locker information. But, during rollback of
	 * (in-)update/delete, we retain the multilocker information. See
	 * execute_undo_actions_page for details.
	 */
	if (ZHEAP_XID_IS_LOCKED_ONLY(infomask) || !IsZHeapTupleModified(infomask))
	{
		if (ZHEAP_XID_IS_KEYSHR_LOCKED(infomask))
			old_lock_mode = LockTupleKeyShare;
		else if (ZHEAP_XID_IS_SHR_LOCKED(infomask))
			old_lock_mode = LockTupleShare;
		else if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask))
			old_lock_mode = LockTupleNoKeyExclusive;
		else if (ZHEAP_XID_IS_EXCL_LOCKED(infomask))
			old_lock_mode = LockTupleExclusive;
		else
		{
			/* LOCK_ONLY can't be present alone */
			pg_unreachable();
		}
	}
	else
	{
		/* it's an update, but which kind? */
		if (infomask & ZHEAP_XID_EXCL_LOCK)
			old_lock_mode = LockTupleExclusive;
		else
			old_lock_mode = LockTupleNoKeyExclusive;
	}

	return old_lock_mode;
}

#endif							/* ZMULTILOCKER_H */
