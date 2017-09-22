/*-------------------------------------------------------------------------
 *
 * undodiscard.c
 *	  discard undo records
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undodiscard.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xact.h"
#include "access/undolog.h"
#include "access/undodiscard.h"
#include "catalog/pg_tablespace.h"
#include "miscadmin.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"
#include "storage/proc.h"

DiscardXact	*UndoDiscardInfo = NULL;

/*
 * UndoDiscardShmemSize
 *		Compute shared memory space needed for undolog discard information.
 */
Size
UndoDiscardShmemSize(void)
{
	Size		size = 0;

	size = add_size(size, mul_size(MaxBackends, sizeof(DiscardXact)));

	return size;
}

/*
 * Initialize the undo discard shared memory structure.
 */
void
UndoDiscardShmemInit(void)
{
	bool	found;
	int		i;

	UndoDiscardInfo = (DiscardXact *)
		ShmemInitStruct("UndoDiscardInfo", UndoDiscardShmemSize(), &found);

	for (i = 0; i < MaxBackends; i++)
	{
		UndoDiscardInfo[i].xid = InvalidTransactionId;
		UndoDiscardInfo[i].undo_recptr = InvalidUndoRecPtr;

		/* Initialize. */
		LWLockInitialize(&UndoDiscardInfo[i].mutex, LWTRANCHE_UNDODISCARD);
	}
}

/*
 * Discard the undo for the log
 *
 * Search the undo log, get the start record for each transaction until we get
 * the transaction with xid >= xmin or an invalid xid.  Then call undolog
 * routine to discard upto that point and update the memory structure for the
 * log slot.
 */
static void 
UndoDiscardOneLog(DiscardXact *discard, TransactionId xmin)
{
	UndoRecPtr	undo_recptr = discard->undo_recptr;
	UnpackedUndoRecord	*uur;
	bool	need_discard = false;

	do
	{
		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(undo_recptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId);

		Assert(uur != NULL);

		/* we can discard upto this point. */
		if (TransactionIdFollowsOrEquals(uur->uur_xid, xmin) ||
			uur->uur_next == SpecialUndoRecPtr ||
			uur->uur_next == InvalidUndoRecPtr)
		{
			TransactionId	undoxid = uur->uur_xid;

			UndoRecordRelease(uur);

			/*
			 * If Transaction id is smaller than the xmin that means this must
			 * be the last transaction in this undo log, so we need to get the
			 * last insert point in this undo log and discard till that point.
			 */
			if (TransactionIdPrecedes(undoxid, xmin))
			{
				UndoLogNumber logno = UndoRecPtrGetLogNo(discard->undo_recptr);
				UndoRecPtr	next_insert = InvalidUndoRecPtr;

				/*
				 * Get the last insert location for this transaction Id, if it
				 * returns invalid pointer that means there is new transaction
				 * has started for this undolog.
				 */
				next_insert = UndoLogGetNextInsertPtr(logno, undoxid);

				if (!UndoRecPtrIsValid(next_insert))
					continue;

				undo_recptr = next_insert;
				need_discard = true;
				undoxid = InvalidTransactionId;
			}

			LWLockAcquire(&discard->mutex, LW_EXCLUSIVE);

			discard->xid = undoxid;
			discard->undo_recptr = undo_recptr;

			LWLockRelease(&discard->mutex);

			if (need_discard)
				UndoLogDiscard(undo_recptr);

			break;
		}

		/*
		 * This transaction is smaller than the xmin so lets jump to the next
		 * transaction.
		 */
		undo_recptr = uur->uur_next;
		UndoRecordRelease(uur);
		need_discard = true;
	} while (true);
}

/*
 * Discard the undo for all the transaction whose xid is smaller than xmin
 *
 *	Check the DiscardInfo memory array for each slot (every undo log) , process
 *	the undo log for all the slot which have xid smaller than xmin or invalid
 *	xid. Fetch the record from the undo log transaction by transaction until we
 *	find the xid which is not smaller than xmin.
 */
void 
UndoDiscard(TransactionId oldestXid)
{
	int		i;
	TransactionId	oldestXidHavingUndo = oldestXid;

	for (i = 0; i < MaxBackends; i++)
	{
		UndoRecPtr	urp;

		/*
		 * If the first xid of the undo log is smaller than the xmin the try
		 * to discard the undo log.
		 */
		if (TransactionIdPrecedes(UndoDiscardInfo[i].xid, oldestXid))
		{
			/*
			 * If the XID in the discard entry is invalid then start scanning from
			 * the first valid undorecord in the log.
			 */
			if (!TransactionIdIsValid(UndoDiscardInfo[i].xid))
			{
				urp = UndoLogGetFirstValidRecord(i);

				if (!UndoRecPtrIsValid(urp))
					continue;

				UndoDiscardInfo[i].undo_recptr = urp;
			}

			/* Process the undo log. */
			UndoDiscardOneLog(&UndoDiscardInfo[i], oldestXid);
		}

		/* Update the correct value for oldestXidHavingUndo. */
		if (TransactionIdIsValid(UndoDiscardInfo[i].xid) &&
			TransactionIdPrecedes(UndoDiscardInfo[i].xid, oldestXidHavingUndo))
			oldestXidHavingUndo = UndoDiscardInfo[i].xid;
	}

	/*
	 * Update the oldestXidHavingUndo in the shared memory.
	 *
	 * XXX In future if multiple worker can perform discard then we may need
	 * to use compare and swap for updating the shared memory value.
	 */
	pg_atomic_write_u32(&ProcGlobal->oldestXidHavingUndo,
						oldestXidHavingUndo);
}
