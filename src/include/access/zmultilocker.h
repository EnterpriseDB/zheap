/*-------------------------------------------------------------------------
 *
 * zmultilocker.h
 *	  POSTGRES zheap multi locker function definitions.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
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
			(tupleLockExtraInfo[lockmode].hwlock)

extern List *ZGetMultiLockMembersForCurrentXact(ZHeapTuple zhtup, Buffer buf,
							int trans_slot, UndoRecPtr urec_ptr);
extern List *ZGetMultiLockMembers(ZHeapTuple zhtup, Buffer buf, bool nobuflock);
extern bool ZMultiLockMembersWait(Relation rel, List *mlmembers, ZHeapTuple zhtup,
				  Buffer buf, LockTupleMode required_mode, bool nowait,
				  XLTW_Oper oper, int *remaining);
extern bool ConditionalZMultiLockMembersWait(Relation rel, List *mlmembers,
								 Buffer buf, LockTupleMode required_mode,
								 int *remaining);
extern bool ZIsAnyMultiLockMemberRunning(List *mlmembers, ZHeapTuple zhtup,
					Buffer buf);
extern bool ZMultiLockMembersSame(List *old_members, List* new_members);
extern void ZGetMultiLockInfo(uint16 old_infomask, TransactionId tup_xid,
				  int tup_trans_slot, TransactionId add_to_xid,
				  uint16 *new_infomask, int *new_trans_slot,
				  LockTupleMode *mode, bool *old_tuple_has_update);
extern inline LockTupleMode get_old_lock_mode(uint16 infomask);

#endif   /* ZMULTILOCKER_H */
