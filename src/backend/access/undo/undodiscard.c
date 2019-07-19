/*-------------------------------------------------------------------------
 *
 * undodiscard.c
 *	  discard undo records
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undodiscard.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xact.h"
#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "access/undolog.h"
#include "access/undodiscard.h"
#include "access/undorequest.h"
#include "catalog/pg_tablespace.h"
#include "miscadmin.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "utils/resowner.h"

/*
 * Discard as many record sets as we can from the undo log occupying a given
 * slot, considering the given xmin horizon.  If we encounter a record set
 * that needs to be rolled back, register a rollback request.  Set *hibernate
 * to false if work was done.
 */
static void
UndoDiscardOneLog(UndoLogSlot *slot, TransactionId xmin, bool *hibernate)
{
	UndoRecPtr	undo_recptr, next_insert;
	UndoRecPtr	next_urecptr = InvalidUndoRecPtr;
	UnpackedUndoRecord	*uur = NULL;
	bool	need_discard = false;
	FullTransactionId	undofxid = InvalidFullTransactionId;
	TransactionId	latest_discardxid = InvalidTransactionId;
	UndoLogNumber logno;

	/*
	 * Currently we expect only one discard worker to be active at any time,
	 * but in future we might have more than one, and superuser maintenance
	 * functions might also discard data concurrently.  So we we have to
	 * assume that the given slot could be recycled underneath us any time we
	 * don't hold one of the locks that prevents that.  We'll detect that by
	 * the log number changing.
	 */
	LWLockAcquire(&slot->discard_lock, LW_SHARED);
	logno = slot->logno;
	if (UndoRecPtrIsValid(slot->oldest_data))
	{
		undo_recptr = slot->oldest_data;
		LWLockRelease(&slot->discard_lock);
	}
	else
	{
		LWLockRelease(&slot->discard_lock);
		undo_recptr = UndoLogGetOldestRecord(logno, NULL);
	}

	/* There might not be any undo log and hibernation might be needed. */
	*hibernate = true;

	StartTransactionCommand();

	/* Loop until we run out of discardable transactions in the given log. */
	do
	{
		TransactionId wait_xid = InvalidTransactionId;
		bool pending_abort = false;
		bool request_rollback = false;
		UndoStatus status;
		UndoRecordFetchContext	context;

		next_insert = UndoLogGetNextInsertPtr(logno);

		/* There must be some undo data for a transaction. */
		Assert(next_insert != undo_recptr);

		/* Fetch the undo record for the given undo_recptr. */
		BeginUndoFetch(&context);
		uur = UndoFetchRecord(&context, undo_recptr);
		FinishUndoFetch(&context);

		if (uur != NULL)
		{
			if (UndoRecPtrGetCategory(undo_recptr) == UNDO_SHARED)
			{
				/*
				 * For the "shared" category, we only discard when the
				 * rm_undo_status callback tells us we can.
				 */
				status = RmgrTable[uur->uur_rmid].rm_undo_status(uur, &wait_xid);

				Assert((status == UNDO_STATUS_WAIT_XMIN &&
						TransactionIdIsValid(wait_xid)) ^
						(status == UNDO_STATUS_DISCARD &&
						!TransactionIdIsValid(wait_xid)));
			}
			else
			{
				TransactionId xid = XidFromFullTransactionId(uur->uur_fxid);

				/*
				 * Otherwise we use the CLOG and xmin to decide whether to
				 * wait, discard or roll back.
				 *
				 * XXX: We've added the transaction-in-progress check to
				 * avoid xids of in-progress autovacuum as those are not
				 * computed for oldestxmin calculation.  See
				 * DiscardWorkerMain.
				 */
				if (TransactionIdDidCommit(xid))
				{
					/*
					 * If this record set's xid isn't before the xmin
					 * horizon, we'll have to wait before we can discard
					 * it.
					 */
					if (TransactionIdFollowsOrEquals(xid, xmin))
						wait_xid = xid;

				}
				else if (!TransactionIdIsInProgress(xid))
				{
					/*
					 * If it hasn't been applied already, then we'll ask
					 * for it to be applied now.  Otherwise it'll be
					 * discarded.
					 */
					if (!IsXactApplyProgressCompleted(uur->uur_txn->urec_progress))
						request_rollback = true;
				}
				else
				{
					/*
					 * It's either in progress or isn't yet before the
					 * xmin horizon, so we'll have to wait.
					 */
					wait_xid = XidFromFullTransactionId(uur->uur_fxid);
				}
			}

			/*
			 * Add the aborted transaction to the rollback request queues.
			 *
			 * We can ignore the abort for transactions whose corresponding
			 * database doesn't exist.
			 */
			if (request_rollback && dbid_exists(uur->uur_txn->urec_dbid))
			{
				(void) RegisterRollbackReq(InvalidUndoRecPtr,
										   undo_recptr,
										   uur->uur_txn->urec_dbid,
										   uur->uur_fxid);

				pending_abort = true;
			}

			next_urecptr = uur->uur_txn->urec_next;
			undofxid = uur->uur_fxid;

			UndoRecordRelease(uur);
			uur = NULL;
		}

		/*
		 * We can discard upto this point when one of following conditions is
		 * met: (a) we need to wait for a transaction first. (b) there is no
		 * more log to process. (c) the transaction undo in current log is
		 * finished. (d) there is a pending abort.
		 */
		if (TransactionIdIsValid(wait_xid) ||
			next_urecptr == InvalidUndoRecPtr ||
			UndoRecPtrGetLogNo(next_urecptr) != logno ||
			pending_abort)
		{
			/* Hey, I got some undo log to discard, can not hibernate now. */
			*hibernate = false;

			/*
			 * If we don't need to wait for this transaction and this is not
			 * an aborted transaction, then we can discard it as well.
			 */
			if (!TransactionIdIsValid(wait_xid) && !pending_abort)
			{
				/*
				 * It is safe to use next_insert as the location till which we
				 * want to discard in this case.  If something new has been
				 * added after we have fetched this transaction's record, it
				 * won't be considered in this pass of discard.
				 */
				undo_recptr = next_insert;
				latest_discardxid = XidFromFullTransactionId(undofxid);
				need_discard = true;

				/* We don't have anything more to discard. */
				undofxid = InvalidFullTransactionId;
			}

			/* Update the shared memory state. */
			LWLockAcquire(&slot->discard_lock, LW_EXCLUSIVE);

			/*
			 * If the slot has been recycling while we were thinking about it,
			 * we have to abandon the operation.
			 */
			if (slot->logno != logno)
			{
				LWLockRelease(&slot->discard_lock);
				break;
			}

			/* Update the slot information for the next pass of discard. */
			slot->wait_fxmin = undofxid;
			slot->oldest_data = undo_recptr;

			LWLockRelease(&slot->discard_lock);

			if (need_discard)
			{
				LWLockAcquire(&slot->discard_update_lock, LW_EXCLUSIVE);
				UndoLogDiscard(undo_recptr, latest_discardxid);
				LWLockRelease(&slot->discard_update_lock);
			}

			break;
		}

		/*
		 * This transaction is smaller than the xmin so lets jump to the next
		 * transaction.
		 */
		undo_recptr = next_urecptr;
		latest_discardxid = XidFromFullTransactionId(undofxid);

		Assert(uur == NULL);

		/* If we reach here, this means there is something to discard. */
		need_discard = true;
	} while (true);

	CommitTransactionCommand();
}

/*
 * Scan all the undo logs and register the aborted transactions.  This is
 * called as a first function from the discard worker and only after this pass
 * over undo logs is complete, new undo can is allowed to be written in the
 * system.  This is required because after crash recovery we don't know the
 * exact number of aborted transactions whose rollback request is pending and
 * we can not allow new undo request if we already have the request equal to
 * hash table size.  So before start allowing any new transaction to write the
 * undo we need to make sure that we know exact number of pending requests.
 */
void
UndoLogProcess()
{
	UndoLogSlot *slot = NULL;

	/*
	 * We need to perform this in a transaction because (a) we need resource
	 * owner to scan the logs and (b) TransactionIdIsInProgress requires us to
	 * be in transaction.
	 */
	StartTransactionCommand();

	/*
	 * Loop through all the valid undo logs and scan them transaction by
	 * transaction to find non-commited transactions if any and register them
	 * in the rollback hash table.
	 */
	while ((slot = UndoLogNextSlot(slot)))
	{
		UndoRecPtr	undo_recptr;
		UnpackedUndoRecord	*uur = NULL;

		/* We do not execute shared (non-transactional) undo records. */
		if (slot->meta.category == UNDO_SHARED)
			continue;

		/* Start scanning the log from the last discard point. */
		undo_recptr = UndoLogGetOldestRecord(slot->logno, NULL);

		/* Loop until we scan complete log. */
		while (1)
		{
			TransactionId xid;
			UndoRecordFetchContext	context;

			/* Done with this log. */
			if (!UndoRecPtrIsValid(undo_recptr))
				break;

			/* Fetch the undo record for the given undo_recptr. */
			BeginUndoFetch(&context);
			uur = UndoFetchRecord(&context, undo_recptr);
			FinishUndoFetch(&context);

			Assert(uur != NULL);

			xid = XidFromFullTransactionId(uur->uur_fxid);

			/*
			 * Register the rollback request for all uncommitted and not in
			 * progress transactions whose undo apply progress is still not
			 * completed.  Even though we don't allow any new transactions to
			 * write undo until this first pass is completed, there might be
			 * some prepared transactions which are still in progress, so we
			 * don't include such transactions.
			 */
			if (!TransactionIdDidCommit(xid) &&
				!TransactionIdIsInProgress(xid) &&
				!IsXactApplyProgressCompleted(uur->uur_txn->urec_progress))
			{
				(void) RegisterRollbackReq(InvalidUndoRecPtr, undo_recptr,
										uur->uur_txn->urec_dbid, uur->uur_fxid);
			}

			/*
			 * Go to the next transaction in the same log.  If uur_next is
			 * point to the undo record pointer in the different log then we are
			 * done with this log so just set undo_recptr to InvalidUndoRecPtr.
			 */
			if (UndoRecPtrGetLogNo(undo_recptr) ==
				UndoRecPtrGetLogNo(uur->uur_txn->urec_next))
				undo_recptr = uur->uur_txn->urec_next;
			else
				undo_recptr = InvalidUndoRecPtr;

			/* Release memory for the current record. */
			UndoRecordRelease(uur);
		}
	}

	CommitTransactionCommand();

	/* Allow the transactions to start writting undo. */
	ProcGlobal->rollbackHTInitialized = true;
}

/*
 * Discard the undo for all the transactions whose xid is smaller than
 * oldestXmin
 */
void
UndoDiscard(TransactionId oldestXmin, bool *hibernate)
{
	FullTransactionId oldestXidHavingUndo;
	UndoLogSlot *slot = NULL;
	uint32	epoch;

	/*
	 * If all the undo logs are discarded, then oldestXidHavingUndo should be
	 * oldestXmin.  As of now, we don't allow more than 2 billion xids in the
	 * system, so we can rely on the epoch retrieved with GetEpochForXid.
	 */
	epoch = GetEpochForXid(oldestXmin);
	oldestXidHavingUndo = FullTransactionIdFromEpochAndXid(epoch, oldestXmin);

	/*
	 * Iterate through all the active logs and one-by-one try to discard the
	 * transactions that are old enough to matter.
	 *
	 * XXX Ideally we can arrange undo logs so that we can efficiently find
	 * those with oldest_xid < oldestXmin, but for now we'll just scan all of
	 * them.
	 */
	while ((slot = UndoLogNextSlot(slot)))
	{
		/*
		 * If the log is already discarded, then we are done.  It is important
		 * to first check this to ensure that tablespace containing this log
		 * doesn't get dropped concurrently.
		 */
		LWLockAcquire(&slot->mutex, LW_SHARED);
		/*
		 * We don't have to worry about slot recycling and check the logno
		 * here, since we don't care about the identity of this slot, we're
		 * visiting all of them.
		 */
		if (slot->meta.discard == slot->meta.unlogged.insert)
		{
			LWLockRelease(&slot->mutex);
			continue;
		}
		LWLockRelease(&slot->mutex);

		/* We can't process temporary undo logs. */
		if (slot->meta.category == UNDO_TEMP)
			continue;

		/*
		 * If the first xid of the undo log is smaller than the xmin then try
		 * to discard the undo log.
		 */
		if (!FullTransactionIdIsValid(slot->wait_fxmin) ||
			FullTransactionIdPrecedes(slot->wait_fxmin, oldestXidHavingUndo))
		{
			/* Process the undo log. */
			UndoDiscardOneLog(slot, oldestXmin, hibernate);
		}
	}

	/* Get the smallest of 'xid having pending undo' and 'oldestXmin' */
	oldestXidHavingUndo = RollbackHTGetOldestFullXid(oldestXidHavingUndo);

	/*
	 * Update the oldestFullXidHavingUnappliedUndo in the shared memory.
	 *
	 * XXX: In future, if multiple workers can perform discard then we may
	 * need to use compare and swap for updating the shared memory value.
	 */
	if (FullTransactionIdIsValid(oldestXidHavingUndo))
		pg_atomic_write_u64(&ProcGlobal->oldestFullXidHavingUnappliedUndo,
							U64FromFullTransactionId(oldestXidHavingUndo));
}

/*
 * Discard all the logs.  This is particularly required in single user mode
 * where at the commit time we discard all the undo logs.
 */
void
UndoLogDiscardAll(void)
{
	UndoLogSlot *slot = NULL;

	Assert(!IsUnderPostmaster);

	/*
	 * No locks are required for discard, since this called only in single
	 * user mode.
	 */
	while ((slot = UndoLogNextSlot(slot)))
	{
		/* If the log is already discarded, then we are done. */
		if (slot->meta.discard == slot->meta.unlogged.insert)
			continue;

		/*
		 * Process the undo log.
		 */
		UndoLogDiscard(MakeUndoRecPtr(slot->logno, slot->meta.unlogged.insert),
					   InvalidTransactionId);
	}

}

/*
 * Discard the undo logs for temp tables.
 */
void
TempUndoDiscard(UndoLogNumber logno)
{
	UndoLogSlot *slot = UndoLogGetSlot(logno, false);

	/*
	 * Discard the undo log for temp table only. Ensure that there is
	 * something to be discarded there.
	 */
	Assert (slot->meta.category == UNDO_TEMP);

	/*
	 * If the log is already discarded, then we are done.  It is important
	 * to first check this to ensure that tablespace containing this log
	 * doesn't get dropped concurrently.
	 */
	LWLockAcquire(&slot->mutex, LW_SHARED);
	if (slot->meta.discard == slot->meta.unlogged.insert)
	{
		LWLockRelease(&slot->mutex);
		return;
	}
	LWLockRelease(&slot->mutex);

	/* Process the undo log. */
	UndoLogDiscard(MakeUndoRecPtr(slot->logno, slot->meta.unlogged.insert),
				   InvalidTransactionId);
}
