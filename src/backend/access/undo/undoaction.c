/*-------------------------------------------------------------------------
 *
 * undoaction.c
 *	  execute undo actions
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoaction.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "utils/syscache.h"
#include "access/tpd.h"
#include "access/undoaction_xlog.h"
#include "access/undolog.h"
#include "access/xact.h"
#include "access/xlog_internal.h"
#include "access/zheap.h"
#include "nodes/pg_list.h"
#include "pgstat.h"
#include "postmaster/undoloop.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "miscadmin.h"
#include "storage/shmem.h"
#include "access/undodiscard.h"

#define ROLLBACK_HT_SIZE	1024

static bool execute_undo_actions_page(List *luinfo, UndoRecPtr urec_ptr,
						  Oid reloid, TransactionId xid, BlockNumber blkno,
						  bool blk_chain_complete, bool norellock);
static void RollbackHTRemoveEntry(UndoRecPtr start_urec_ptr);

/* This is the hash table to store all the rollabck requests. */
static HTAB *RollbackHT;

/*
 * execute_undo_actions - Execute the undo actions
 *
 * from_urecptr - undo record pointer from where to start applying undo action.
 * to_urecptr	- undo record pointer upto which point apply undo action.
 * nopartial	- true if rollback is for complete transaction.
 * rewind		- whether to rewind the insert location of the undo log or not.
 *				  Only the backend executed the transaction can rewind, but
 *				  any other process e.g. undo worker should not rewind it.
 *				  Because, if the backend have already inserted new undo records
 *				  for the next transaction and if we rewind then we will loose
 *				  the undo record inserted for the new transaction.
 * 	rellock	  -	  if the caller already has the lock on the required relation,
 *				  then this flag is false, i.e. we do not need to acquire any
 *				  lock here. If the flag is true then we need to acquire lock
 *				  here itself, because caller will not be having any lock.
 *				  When we are performing undo actions for prepared transactions,
 *			      or for rollback to savepoint, we need not to lock as we already
 *				  have the lock on the table. In cases like error or when
 *				  rollbacking from the undo worker we need to have proper locks.
 */
void
execute_undo_actions(UndoRecPtr from_urecptr, UndoRecPtr to_urecptr,
					 bool nopartial, bool rewind, bool rellock)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr,
				prev_urec_ptr,
				prev_blkprev;
	UndoRecPtr	save_urec_ptr;
	Oid			prev_reloid = InvalidOid;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber prev_block = InvalidBlockNumber;
	List	   *luinfo = NIL;
	bool		more_undo;
	TransactionId xid = InvalidTransactionId;
	UndoRecInfo *urec_info;
	bool		has_truncated = false;

	Assert(from_urecptr != InvalidUndoRecPtr);

	/*
	 * If the location upto which rollback need to be done is not provided,
	 * then rollback the complete transaction. FIXME: this won't work if
	 * undolog crossed the limit of 1TB, because then from_urecptr and
	 * to_urecptr will be from different lognos.
	 */
	if (to_urecptr == InvalidUndoRecPtr)
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(from_urecptr);

		to_urecptr = UndoLogGetLastXactStartPoint(logno);
	}

	prev_blkprev = save_urec_ptr = urec_ptr = from_urecptr;

	if (nopartial)
	{
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber, InvalidOffsetNumber,
							  InvalidTransactionId, NULL, NULL);
		if (uur == NULL)
			return;

		xid = uur->uur_xid;
		UndoRecordRelease(uur);
		uur = NULL;

		/*
		 * Grab the undo action apply lock before start applying the undo
		 * action this will prevent applying undo actions concurrently.  If we
		 * do not get the lock that mean its already being applied
		 * concurrently or the discard worker might be pushing its request to
		 * the rollback hash table
		 */
		if (!ConditionTransactionUndoActionLock(xid))
			return;
	}

	prev_urec_ptr = InvalidUndoRecPtr;
	while (prev_urec_ptr != to_urecptr)
	{
		Oid			reloid = InvalidOid;
		uint16		urec_prevlen;
		UndoRecPtr	urec_prevurp;

		more_undo = true;

		prev_urec_ptr = urec_ptr;

		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId, NULL, NULL);

		if (uur != NULL)
			reloid = uur->uur_reloid;

		/*
		 * If the record is already discarded by undo worker or if the
		 * relation is dropped or truncated, then we cannot fetch record
		 * successfully. Hence, exit quietly.
		 *
		 * Note: reloid remains InvalidOid for a discarded record.
		 */

		if (OidIsValid(reloid))
		{
			Relation	rel;

			if (!SearchSysCacheExists1(RELOID, ObjectIdGetDatum(reloid)))
				reloid = InvalidOid;
			else
			{
				/*
				 * If the action is executed by backend as a result of
				 * rollback, we must already have an appropriate lock on
				 * relation.
				 */
				if (rellock)
					rel = heap_open(reloid, RowExclusiveLock);
				else
					rel = heap_open(reloid, NoLock);

				if (RelationGetNumberOfBlocks(rel) <= uur->uur_block)
				{
					/*
					 * This is possible if the underlying relation is
					 * truncated just before taking the relation lock above.
					 */
					has_truncated = true;
				}

				heap_close(rel, NoLock);
			}
		}

		/*
		 * FIXME:  Currently, we are ignoring the undo for the truncated table
		 * but this is not the best way to handle the undo for the truncated
		 * table, we might need to try to apply the undo actions for the
		 * truncated table i.e. we might call execute undo action in later
		 * stages where we can apply the undo action if the truncate is done
		 * in the same transaction and the transaction is rolledback.  We
		 * might want to do it differently once we fix the similar problem in
		 * 'cleaning up the orphan files' patch.
		 */
		if (!OidIsValid(reloid) || has_truncated)
		{
			/* release the undo records for which action has been replayed */
			while (luinfo)
			{
				UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

				UndoRecordRelease(urec_info->uur);
				pfree(urec_info);
				luinfo = list_delete_first(luinfo);
			}

			/* Release the undo action lock before returning. */
			if (nopartial)
				TransactionUndoActionLockRelease(xid);

			/* Release the just-fetched record */
			if (uur != NULL)
				UndoRecordRelease(uur);

			return;
		}

		xid = uur->uur_xid;

		/* Collect the undo records that belong to the same page. */
		if (!OidIsValid(prev_reloid) ||
			(prev_reloid == reloid &&
			 prev_fork == uur->uur_fork &&
			 prev_block == uur->uur_block &&
			 prev_blkprev == urec_ptr))
		{
			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;

			/* Prepare an undo record information element. */
			urec_info = palloc(sizeof(UndoRecInfo));
			urec_info->urp = urec_ptr;
			urec_info->uur = uur;

			luinfo = lappend(luinfo, urec_info);
			urec_prevlen = uur->uur_prevlen;
			urec_prevurp = uur->uur_prevurp;
			save_urec_ptr = uur->uur_blkprev;

			/* The undo chain must continue till we reach to_urecptr */
			if (urec_ptr != to_urecptr &&
				(urec_prevlen > 0 || UndoRecPtrIsValid(urec_prevurp)))
			{
				urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen,
												 urec_prevurp);
				prev_blkprev = uur->uur_blkprev;
				continue;
			}
			else
				more_undo = false;
		}
		else
		{
			more_undo = true;
		}

		/*
		 * If no more undo is left to be processed and we are rolling back the
		 * complete transaction, then we can consider that the undo chain for
		 * a block is complete. If the previous undo pointer in the page is
		 * invalid, then also the undo chain for the current block is
		 * completed.
		 */
		if ((!more_undo && nopartial) || !UndoRecPtrIsValid(save_urec_ptr))
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, true, rellock);
		}
		else
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, false, rellock);
		}

		/* release the undo records for which action has been replayed */
		while (luinfo)
		{
			UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

			UndoRecordRelease(urec_info->uur);
			pfree(urec_info);
			luinfo = list_delete_first(luinfo);
		}

		/*
		 * There are still more records to process, so keep moving backwards
		 * in the chain.
		 */
		if (more_undo)
		{
			/* Prepare an undo record information element. */
			urec_info = palloc(sizeof(UndoRecInfo));
			urec_info->urp = urec_ptr;
			urec_info->uur = uur;
			luinfo = lappend(luinfo, urec_info);

			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;
			save_urec_ptr = uur->uur_blkprev;
			prev_blkprev = uur->uur_blkprev;

			/*
			 * Continue to process the records if this is not the last undo
			 * record in chain.
			 */
			urec_prevlen = uur->uur_prevlen;
			urec_prevurp = uur->uur_prevurp;
			if (urec_ptr != to_urecptr &&
				(urec_prevlen > 0 || UndoRecPtrIsValid(urec_prevurp)))
				urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen, urec_prevurp);
			else
				break;
		}
		else
			break;
	}

	/* Apply the undo actions for the remaining records. */
	if (list_length(luinfo))
	{
		execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
								  xid, prev_block, nopartial ? true : false,
								  rellock);

		/* release the undo records for which action has been replayed */
		while (luinfo)
		{
			UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

			UndoRecordRelease(urec_info->uur);
			pfree(urec_info);
			luinfo = list_delete_first(luinfo);
		}
	}

	if (rewind)
	{
		/* Read the current log from undo */
		UndoLogControl *log = UndoLogGet(UndoRecPtrGetLogNo(to_urecptr));

		/* Read the prevlen from the first record of this transaction. */
		uur = UndoFetchRecord(to_urecptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId,
							  NULL, NULL);

		/*
		 * If undo is already discarded before we rewind, then do nothing.
		 */
		if (uur == NULL)
			return;


		/*
		 * In ZGetMultiLockMembers we fetch the undo record without a buffer
		 * lock so it's possible that a transaction in the slot can rollback
		 * and rewind the undo record pointer.  To prevent that we acquire the
		 * rewind lock before rewinding the undo record pointer and the same
		 * lock will be acquire by ZGetMultiLockMembers in shared mode.  Other
		 * places where we fetch the undo record we don't need this lock as we
		 * are doing that under the buffer lock. So remember to acquire the
		 * rewind lock in shared mode wherever we are fetching the undo record
		 * of non commited transaction without buffer lock.
		 */
		LWLockAcquire(&log->rewind_lock, LW_EXCLUSIVE);
		UndoLogRewind(to_urecptr, uur->uur_prevlen);
		LWLockRelease(&log->rewind_lock);

		UndoRecordRelease(uur);
	}

	if (nopartial)
	{
		/*
		 * Set undo action apply completed in the transaction header if this
		 * is a main transaction and we have not rewound its undo.
		 */
		if (!rewind)
		{
			/*
			 * Undo action is applied so delete the hash table entry and
			 * release the undo action lock.
			 */
			RollbackHTRemoveEntry(from_urecptr);

			/*
			 * Prepare and update the progress of the undo action apply in the
			 * transaction header.
			 */
			PrepareUpdateUndoActionProgress(NULL, to_urecptr, 1);

			START_CRIT_SECTION();

			/* Update the progress in the transaction header. */
			UndoRecordUpdateTransInfo(0);

			/* WAL log the undo apply progress. */
			{
				xl_undoapply_progress xlrec;

				xlrec.urec_ptr = to_urecptr;
				xlrec.progress = 1;

				/*
				 * FIXME : We need to register undo buffers and set LSN for
				 * them that will be required for FPW of the undo buffers.
				 */
				XLogBeginInsert();
				XLogRegisterData((char *) &xlrec, sizeof(xlrec));

				RegisterUndoLogBuffers(2);
				(void) XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_APPLY_PROGRESS);
			}

			END_CRIT_SECTION();
			UnlockReleaseUndoBuffers();
		}

		TransactionUndoActionLockRelease(xid);
	}
}

/*
 * process_and_execute_undo_actions_page
 *
 * Collect all the undo for the input buffer and execute.  Here, we don't know
 * the to_urecptr and we can not collect from undo meta data also like we do in
 * execute_undo_actions, because we might be applying undo of some old
 * transaction and may be from different undo log as well.
 *
 * from_urecptr - undo record pointer from where to start applying the undo.
 * rel			- relation descriptor for which undo to be applied.
 * buffer		- buffer for which unto to be processed.
 * epoch		- epoch of the xid passed.
 * xid			- aborted transaction id whose effects needs to be reverted.
 * slot_no		- transaction slot number of xid.
 */
void
process_and_execute_undo_actions_page(UndoRecPtr from_urecptr, Relation rel,
									  Buffer buffer, uint32 epoch,
									  TransactionId xid, int slot_no)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr = from_urecptr;
	List	   *luinfo = NIL;
	Page		page;
	UndoRecInfo *urec_info;
	bool		actions_applied = false;

	/*
	 * Process and collect the undo for the block until we reach the first
	 * record of the transaction.
	 *
	 * Fixme: This can lead to unbounded use of memory, so we should collect
	 * the undo in chunks based on work_mem or some other memory unit.
	 */
	do
	{
		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId,
							  NULL, NULL);

		/*
		 * If the record is already discarded by undo worker, or the xid we
		 * want to rollback has already applied its undo actions then just
		 * cleanup the slot and exit.
		 */
		if (uur == NULL || uur->uur_xid != xid)
		{
			if (uur != NULL)
				UndoRecordRelease(uur);
			break;
		}

		/* Prepare an undo element. */
		urec_info = palloc(sizeof(UndoRecInfo));
		urec_info->urp = urec_ptr;
		urec_info->uur = uur;

		/* Collect the undo records. */
		luinfo = lappend(luinfo, urec_info);
		urec_ptr = uur->uur_blkprev;

		/*
		 * If we have exhausted the undo chain for the slot, then we are done.
		 */
		if (!UndoRecPtrIsValid(urec_ptr))
			break;
	} while (true);

	if (list_length(luinfo))
		actions_applied = execute_undo_actions_page(luinfo, urec_ptr,
													rel->rd_id, xid,
													BufferGetBlockNumber(buffer),
													true,
													false);
	/* Release undo records and undo elements */
	while (luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

		UndoRecordRelease(urec_info->uur);
		pfree(urec_info);
		luinfo = list_delete_first(luinfo);
	}

	/*
	 * Clear the transaction id from the slot.  We expect that if the undo
	 * actions are applied by execute_undo_actions_page then it would have
	 * cleared the xid, otherwise we will clear it here.
	 */
	if (!actions_applied)
	{
		int			slot_no;

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);
		slot_no = PageGetTransactionSlotId(rel, buffer, epoch, xid, &urec_ptr,
										   true, false, NULL);

		/*
		 * If someone has already cleared the transaction info, then we don't
		 * need to do anything.
		 */
		if (slot_no != InvalidXactSlotId)
		{
			START_CRIT_SECTION();

			/* Clear the epoch and xid from the slot. */
			PageSetTransactionSlotInfo(buffer, slot_no, 0,
									   InvalidTransactionId, urec_ptr);
			MarkBufferDirty(buffer);

			/* XLOG stuff */
			if (RelationNeedsWAL(rel))
			{
				XLogRecPtr	recptr;
				xl_undoaction_reset_slot xlrec;

				xlrec.flags = 0;
				xlrec.urec_ptr = urec_ptr;
				xlrec.trans_slot_id = slot_no;

				XLogBeginInsert();

				XLogRegisterData((char *) &xlrec, SizeOfUndoActionResetSlot);
				XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

				/* Register tpd buffer if the slot belongs to tpd page. */
				if (slot_no > ZHEAP_PAGE_TRANS_SLOTS)
				{
					xlrec.flags |= XLU_RESET_CONTAINS_TPD_SLOT;
					RegisterTPDBuffer(page, 1);
				}

				recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_RESET_SLOT);

				PageSetLSN(page, recptr);
				if (xlrec.flags & XLU_RESET_CONTAINS_TPD_SLOT)
					TPDPageSetLSN(page, recptr);
			}

			END_CRIT_SECTION();
		}

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		UnlockReleaseTPDBuffers();
	}
}

/*
 * execute_undo_actions_page - Execute the undo actions for a page
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
static bool
execute_undo_actions_page(List *luinfo, UndoRecPtr urec_ptr, Oid reloid,
						  TransactionId xid, BlockNumber blkno,
						  bool blk_chain_complete, bool norellock)
{
	UndoRecInfo *first;

	/*
	 * All records passed to us are for the same RMGR, so we just use the
	 * first record to dispatch.
	 */
	Assert(luinfo != NIL);
	first = (UndoRecInfo *) linitial(luinfo);

	return RmgrTable[first->uur->uur_rmid].rm_undo(luinfo, urec_ptr, reloid,
												   xid, blkno,
												   blk_chain_complete,
												   norellock);
}

/*
 * To return the size of the hash-table for rollbacks.
 */
int
RollbackHTSize(void)
{
	return hash_estimate_size(ROLLBACK_HT_SIZE, sizeof(RollbackHashEntry));
}

/*
 * To initialize the hash-table for rollbacks in shared memory
 * for the given size.
 */
void
InitRollbackHashTable(void)
{
	HASHCTL		info;

	MemSet(&info, 0, sizeof(info));

	info.keysize = sizeof(UndoRecPtr);
	info.entrysize = sizeof(RollbackHashEntry);
	info.hash = tag_hash;

	RollbackHT = ShmemInitHash("Undo actions Lookup Table",
							   ROLLBACK_HT_SIZE, ROLLBACK_HT_SIZE, &info,
							   HASH_ELEM | HASH_FUNCTION | HASH_FIXED_SIZE);
}

/*
 * To push the rollback requests from backend to the hash-table.
 * Return true if the request is successfully added, else false
 * and the caller may execute undo actions itself.
 */
bool
PushRollbackReq(UndoRecPtr start_urec_ptr, UndoRecPtr end_urec_ptr, Oid dbid)
{
	bool		found = false;
	RollbackHashEntry *rh;

	/* Do not push any rollback request if working in single user-mode */
	if (!IsUnderPostmaster)
		return false;

	/*
	 * If the location upto which rollback need to be done is not provided,
	 * then rollback the complete transaction.
	 */
	if (start_urec_ptr == InvalidUndoRecPtr)
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(end_urec_ptr);

		start_urec_ptr = UndoLogGetLastXactStartPoint(logno);
	}

	Assert(UndoRecPtrIsValid(start_urec_ptr));

	/* If there is no space to accomodate new request, then we can't proceed. */
	if (RollbackHTIsFull())
		return false;

	if (!UndoRecPtrIsValid(end_urec_ptr))
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(start_urec_ptr);

		end_urec_ptr = UndoLogGetLastXactStartPoint(logno);
	}

	LWLockAcquire(RollbackHTLock, LW_EXCLUSIVE);

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &start_urec_ptr,
										   HASH_ENTER_NULL, &found);
	if (!rh)
	{
		LWLockRelease(RollbackHTLock);
		return false;
	}
	/* We shouldn't try to push the same rollback request again. */
	if (!found)
	{
		rh->start_urec_ptr = start_urec_ptr;
		rh->end_urec_ptr = end_urec_ptr;
		rh->dbid = (dbid == InvalidOid) ? MyDatabaseId : dbid;
	}
	LWLockRelease(RollbackHTLock);

	return true;
}

/*
 * To perform the undo actions for the transactions whose rollback
 * requests are in hash table. Sequentially, scan the hash-table
 * and perform the undo-actions for the respective transactions.
 * Once, the undo-actions are applied, remove the entry from the
 * hash table.
 */
void
RollbackFromHT(Oid dbid)
{
	UndoRecPtr	start[ROLLBACK_HT_SIZE];
	UndoRecPtr	end[ROLLBACK_HT_SIZE];
	RollbackHashEntry *rh;
	HASH_SEQ_STATUS status;
	int			i = 0;

	/* Fetch the rollback requests */
	LWLockAcquire(RollbackHTLock, LW_SHARED);

	Assert(hash_get_num_entries(RollbackHT) <= ROLLBACK_HT_SIZE);
	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		   (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
	{
		if (rh->dbid == dbid)
		{
			start[i] = rh->start_urec_ptr;
			end[i] = rh->end_urec_ptr;
			i++;
		}
	}

	LWLockRelease(RollbackHTLock);

	/* Execute the rollback requests */
	while (--i >= 0)
	{
		Assert(UndoRecPtrIsValid(start[i]));
		Assert(UndoRecPtrIsValid(end[i]));

		StartTransactionCommand();
		execute_undo_actions(start[i], end[i], true, false, true);
		CommitTransactionCommand();
	}
}

/*
 * Remove the rollback request entry from the rollback hash table.
 */
static void
RollbackHTRemoveEntry(UndoRecPtr start_urec_ptr)
{
	LWLockAcquire(RollbackHTLock, LW_EXCLUSIVE);

	hash_search(RollbackHT, &start_urec_ptr, HASH_REMOVE, NULL);

	LWLockRelease(RollbackHTLock);
}

/*
 * To check if the rollback requests in the hash table are all
 * completed or not. This is required because we don't not want to
 * expose RollbackHT in xact.c, where it is required to ensure
 * that we push the resuests only when there is some space in
 * the hash-table.
 */
bool
RollbackHTIsFull(void)
{
	bool		result = false;

	LWLockAcquire(RollbackHTLock, LW_SHARED);

	if (hash_get_num_entries(RollbackHT) >= ROLLBACK_HT_SIZE)
		result = true;

	LWLockRelease(RollbackHTLock);

	return result;
}

/*
 * Get database list from the rollback hash table.
 */
List *
RollbackHTGetDBList()
{
	HASH_SEQ_STATUS status;
	RollbackHashEntry *rh;
	List	   *dblist = NIL;

	/* Fetch the rollback requests */
	LWLockAcquire(RollbackHTLock, LW_SHARED);

	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		   (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
		dblist = list_append_unique_oid(dblist, rh->dbid);

	LWLockRelease(RollbackHTLock);

	return dblist;
}

/*
 * Remove all the entries for the given dbid. This is required in cases when
 * the database is dropped and there were rollback requests pushed to the
 * hash-table.
 */
void
RollbackHTCleanup(Oid dbid)
{
	RollbackHashEntry *rh;
	HASH_SEQ_STATUS status;
	UndoRecPtr	start_urec_ptr;

	/* Fetch the rollback requests */
	LWLockAcquire(RollbackHTLock, LW_SHARED);

	Assert(hash_get_num_entries(RollbackHT) <= ROLLBACK_HT_SIZE);
	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		   (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
	{
		if (rh->dbid == dbid)
		{
			start_urec_ptr = rh->start_urec_ptr;
			hash_search(RollbackHT, &start_urec_ptr, HASH_REMOVE, NULL);
		}
	}

	LWLockRelease(RollbackHTLock);
}

/*
 *		ConditionTransactionUndoActionLock
 *
 * Insert a lock showing that the undo action for given transaction is in
 * progress. This is only done for the main transaction not for the
 * sub-transaction.
 */
bool
ConditionTransactionUndoActionLock(TransactionId xid)
{
	LOCKTAG		tag;

	SET_LOCKTAG_TRANSACTION_UNDOACTION(tag, xid);

	if (LOCKACQUIRE_NOT_AVAIL == LockAcquire(&tag, ExclusiveLock, false, true))
		return false;
	else
		return true;
}

/*
 *		TransactionUndoActionLockRelease
 *
 * Delete the lock showing that the undo action given transaction ID is in
 * progress.
 */
void
TransactionUndoActionLockRelease(TransactionId xid)
{
	LOCKTAG		tag;

	SET_LOCKTAG_TRANSACTION_UNDOACTION(tag, xid);

	LockRelease(&tag, ExclusiveLock, false);
}
