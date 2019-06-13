/*-------------------------------------------------------------------------
 *
 * undoaction.c
 *	  execute undo actions
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoaction.c
 *
 * To apply the undo actions, we collect the undo records in bulk and try to
 * process them together.  We ensure to update the transaction's progress at
 * regular intervals so that after a crash we can skip already applied undo.
 * The undo apply progress is updated in terms of the number of blocks
 * processed.  Undo apply progress value XACT_APPLY_PROGRESS_COMPLETED
 * indicates that all the undo is applied, XACT_APPLY_PROGRESS_NOT_STARTED
 * indicates that no undo action has been applied yet and any other value
 * indicates that we have applied undo partially and after crash recovery, we
 * need to start processing the undo from the same location.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/table.h"
#include "access/undoaction_xlog.h"
#include "access/undolog.h"
#include "access/undorequest.h"
#include "access/xact.h"
#include "access/xloginsert.h"
#include "access/xlog_internal.h"
#include "nodes/pg_list.h"
#include "pgstat.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "utils/syscache.h"
#include "miscadmin.h"
#include "storage/shmem.h"

static void UpdateUndoApplyProgress(UndoRecPtr last_log_start_urec_ptr,
						  BlockNumber block_num);
static bool UndoAlreadyApplied(FullTransactionId full_xid,
						UndoRecPtr to_urecptr);
static void ApplyUndo(UndoRecInfo *urecinfo, int nrecords);
static void ProcessAndApplyUndo(FullTransactionId full_xid,
				UndoRecPtr from_urecptr, UndoRecPtr to_urecptr,
				UndoRecPtr last_log_start_urec_ptr, bool complete_xact);

/*
 * undo_record_comparator - qsort comparator for undo records.
 *
 * This is used to sort undo records for applying undo actions of the
 * transaction.
 */
static int
undo_record_comparator(const void *left, const void *right)
{
	UnpackedUndoRecord *luur = ((UndoRecInfo *) left)->uur;
	UnpackedUndoRecord *ruur = ((UndoRecInfo *) right)->uur;

	if (luur->uur_rmid < ruur->uur_rmid)
		return -1;
	else if (luur->uur_rmid > ruur->uur_rmid)
		return 1;
	else if (luur->uur_reloid < ruur->uur_reloid)
		return -1;
	else if (luur->uur_reloid > ruur->uur_reloid)
		return 1;
	else if (luur->uur_block < ruur->uur_block)
		return -1;
	else if (luur->uur_block > ruur->uur_block)
		return 1;
	else if (luur->uur_offset < ruur->uur_offset)
		return -1;
	else if (luur->uur_offset > ruur->uur_offset)
		return 1;
	else if (((UndoRecInfo *) left)->index < ((UndoRecInfo *) right)->index)
	{
		/*
		 * If records are for the same block and offset, then maintain their
		 * existing order by comparing their index in the array.
		 */
		return -1;
	}
	else
		return 1;
}

/*
 * UpdateUndoApplyProgress - Updates how far undo actions from a particular
 * log have been applied while rolling back a transaction.  This progress is
 * measured in terms of undo block number of the undo log till which the
 * undo actions have been applied.
 */
static void
UpdateUndoApplyProgress(UndoRecPtr progress_urec_ptr,
						BlockNumber block_num)
{
	UndoLogCategory category;
	UndoRecordInsertContext context = {{0}};

	category =
		UndoLogNumberGetCategory(UndoRecPtrGetLogNo(progress_urec_ptr));

	/*
	 * We don't need to update the progress for temp tables as they get
	 * discraded after startup.
	 */
	if (category == UNDO_TEMP)
		return;

	BeginUndoRecordInsert(&context, category, 1, NULL);

	/*
	 * Prepare and update the undo apply progress in the transaction header.
	 */
	PrepareUndoRecordApplyProgress(&context, progress_urec_ptr, block_num);

	START_CRIT_SECTION();

	/* Update the progress in the transaction header. */
	UndoRecordUpdate(&context, 0);

	/* WAL log the undo apply progress. */
	{
		XLogRecPtr	lsn;
		xl_undoapply_progress xlrec;

		xlrec.urec_ptr = progress_urec_ptr;
		xlrec.progress = block_num;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(xlrec));

		RegisterUndoLogBuffers(&context, 1);
		lsn = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_APPLY_PROGRESS);
		UndoLogBuffersSetLSN(&context, lsn);
	}

	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);
}

/*
 * UndoAlreadyApplied - Retruns true, if the actions are already applied,
 *	false, otherwise.
 */
static bool
UndoAlreadyApplied(FullTransactionId full_xid, UndoRecPtr to_urecptr)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecordFetchContext	context;

	/* Fetch the undo record. */
	BeginUndoFetch(&context);
	uur = UndoFetchRecord(&context, to_urecptr);
	FinishUndoFetch(&context);

	/* already processed and discarded */
	if (uur == NULL)
	{
		/*
		 * Undo action is already applied, so delete the hash table entry
		 * if exists.
		 */
		RollbackHTRemoveEntry(full_xid, to_urecptr, false);
		return true;
	}

	/* already processed */
	if (IsXactApplyProgressCompleted(uur->uur_group->urec_progress))
	{
		/*
		 * Undo action is already applied, so delete the hash table entry
		 * if exists.
		 */
		RollbackHTRemoveEntry(full_xid, to_urecptr, false);
		UndoRecordRelease(uur);
		return true;
	}

	Assert(FullTransactionIdEquals(full_xid, uur->uur_fxid));

	UndoRecordRelease(uur);

	return false;
}

/*
 * ApplyUndo - Invode rmgr specific undo apply functions.
 *
 * urecinfo - An array of undo records sorted in the rmgr order.
 * nrecords - number of records in this array.
 */
static void
ApplyUndo(UndoRecInfo *urecinfo, int nrecords)
{
	int			rmgr_start_idx = 0;
	int			rmgr_nrecords = 0;
	int			prev_rmid = -1;
	int			i;

	/* Apply the undo action for each rmgr. */
	for (i = 0; i < nrecords; i++)
	{
		UnpackedUndoRecord *uur = urecinfo[i].uur;

		Assert(uur->uur_rmid >= 0);

		/*
		 * If this undo is not for the same rmgr then apply all undo
		 * actions for the previous rmgr.
		 */
		if (prev_rmid >= 0 &&
			prev_rmid != uur->uur_rmid)
		{
			Assert(urecinfo[rmgr_start_idx].uur->uur_rmid == prev_rmid);
			RmgrTable[prev_rmid].rm_undo(rmgr_nrecords,
										 &urecinfo[rmgr_start_idx]);

			rmgr_start_idx = i;
			rmgr_nrecords = 0;
		}

		rmgr_nrecords++;
		prev_rmid = uur->uur_rmid;
	}

	/* Apply the last set of the actions. */
	Assert(urecinfo[rmgr_start_idx].uur->uur_rmid == prev_rmid);
	RmgrTable[prev_rmid].rm_undo(rmgr_nrecords, &urecinfo[rmgr_start_idx]);
}

/*
 * ProcessAndApplyUndo - Fetch undo records and apply actions.
 *
 * We always process the undo of the last log when the undo for a transaction
 * spans across multiple logs.  Then from there onwards the previous undo logs
 * for the same transaction are processed.
 *
 * We also update the undo apply progress in the transaction header so that
 * after recovery we don't need to process the records that are already
 * processed.  As we update the progress only after one batch of records,
 * the crash in-between can cause us to read/apply part of undo records
 * again but this will never be more than one-batch.  We can further optimize
 * it by marking the progress in each record, but that has its own downsides
 * like it will generate more WAL and I/O corresponding to dirty undo buffers.
 */
static void
ProcessAndApplyUndo(FullTransactionId full_xid, UndoRecPtr from_urecptr,
					UndoRecPtr to_urecptr, UndoRecPtr last_log_start_urec_ptr,
					bool complete_xact)
{
	UndoRecInfo *urecinfo;
	UndoRecPtr	urec_ptr = from_urecptr;
	int			undo_apply_size;

	/*
	 * We choose maintenance_work_mem to collect the undo records for
	 * rollbacks as most of the large rollback requests are done by
	 * background worker which can be considered as maintainence operation.
	 * However, we can introduce a new guc for this as well.
	 */
	undo_apply_size = maintenance_work_mem * 1024L;

	/*
	 * Fetch the multiple undo records that can fit into undo_apply_size; sort
	 * them and then rmgr specific callback to process them.  Repeat this
	 * until we process all the records for the transaction being rolled back.
	 */
	while (true)
	{
		BlockNumber	progress_block_num = InvalidBlockNumber;
		int			i;
		int			nrecords;
		bool		log_switched = false;
		bool		rollback_completed = false;
		bool		update_progress = false;
		UndoRecPtr	progress_urec_ptr = InvalidUndoRecPtr;
		UndoRecInfo	*first_urecinfo;
		UndoRecInfo	*last_urecinfo;

		CHECK_FOR_INTERRUPTS();

		/*
		 * Fetch multiple undo records at once.
		 *
		 * At a time, we only fetch the undo records from a single undo log.
		 * Once, we process all the undo records from one undo log, we update
		 * the last_log_start_urec_ptr and proceed to the previous undo log.
		 */
		urecinfo = UndoBulkFetchRecord(&urec_ptr, last_log_start_urec_ptr,
									   undo_apply_size, &nrecords);

		/*
		 * Since the rollback of this transaction is in-progress, there will be
		 * at least one undo record which is not yet discarded.
		 */
		Assert(nrecords > 0);

		/*
		 * Get the required information from first and last undo record before
		 * we sort all the records.
		 */
		first_urecinfo = &urecinfo[0];
		last_urecinfo = &urecinfo[nrecords - 1];
		if (IsUndoLogSwitched(last_urecinfo->uur))
		{
			UndoRecordLogSwitch *logswitch = last_urecinfo->uur->uur_logswitch;

			/*
			 * We have crossed the log boundary.  The rest of the undo for
			 * this transaction is in some other log, the location of which
			 * can be found from this record.  See commets atop undoaccess.c.
			 */
			log_switched = true;

			/*
			 * The last fetched undo record corresponds to the first undo
			 * record of the current log.  Once, the undo actions are performed
			 * from this log, we've to mark the progress as completed.
			 */
			progress_urec_ptr = last_urecinfo->urp;

			/*
			 * We also need to save the start location of this transaction in
			 * previous log.  This will be used in the next iteration of bulk
			 * fetch and updating progress location.
			 */
			if (complete_xact)
			{
				Assert(UndoRecPtrIsValid(logswitch->urec_prevlogstart));
				last_log_start_urec_ptr = logswitch->urec_prevlogstart;
			}

			/* We've to update the progress for the current log as completed. */
			update_progress = true;
		}
		else if (complete_xact)
		{
			if (UndoRecPtrIsValid(urec_ptr))
			{
				/*
				 * There are still some undo actions pending in this log.  So,
				 * just update the progress block number.
				 */
				progress_block_num = UndoRecPtrGetBlockNum(last_urecinfo->urp);

				/*
				 * If we've not fetched undo records for more than one undo
				 * block, we can't update the progress block number.  Because,
				 * there can still be undo records in this block that needs to
				 * be applied for rolling back this transaction.
				 */
				if (UndoRecPtrGetBlockNum(first_urecinfo->urp) > progress_block_num)
				{
					update_progress = true;
					progress_urec_ptr = last_log_start_urec_ptr;
				}
			}
			else
			{
				/*
				 * Invalid urec_ptr indicates that we have executed all the undo
				 * actions for this transaction.  So, mark current log header
				 * as complete.
				 */
				Assert(last_log_start_urec_ptr == to_urecptr);
				rollback_completed = true;
				update_progress = true;
				progress_urec_ptr = last_log_start_urec_ptr;
			}
		}

		/*
		 * The undo records must belong to the transaction that is being
		 * rolled back.
		 */
		Assert(FullTransactionIdEquals(full_xid, urecinfo[0].uur->uur_fxid));

		/* Sort the undo record array in order of target blocks. */
		qsort((void *) urecinfo, nrecords, sizeof(UndoRecInfo),
			  undo_record_comparator);

		/* Call resource manager specific callbacks to apply actions. */
		ApplyUndo(urecinfo, nrecords);

		/* Set undo action apply progress if required. */
		if (update_progress)
		{
			Assert(UndoRecPtrIsValid(progress_urec_ptr));

			if (log_switched || rollback_completed)
			{
				/*
				 * We have crossed the log boundary or executed all the undo
				 * actions for the main transaction.  So, mark current log
				 * header as complete and set the next progress location in
				 * the previous log.
				 */
				UpdateUndoApplyProgress(progress_urec_ptr,
										XACT_APPLY_PROGRESS_COMPLETED);
			}
			else
			{
				/*
				 * Update the progress block number.  We increase the block
				 * number by one since the current block might have some undo
				 * records that are yet to be applied.  But, all undo records
				 * from the next block must have been applied.
				 */
				UpdateUndoApplyProgress(progress_urec_ptr,
										progress_block_num + 1);
			}
		}

		/* Free all undo records. */
		for (i = 0; i < nrecords; i++)
			UndoRecordRelease(urecinfo[i].uur);

		/* Free urp array for the current batch of undo records. */
		pfree(urecinfo);

		/*
		 * Invalid urec_ptr indicates that we have executed all the undo
		 * actions for this transaction.
		 */
		if (!UndoRecPtrIsValid(urec_ptr))
			break;
	}
}

/*
 * execute_undo_actions - Execute the undo actions
 *
 * full_xid - Transaction id that is getting rolled back.
 * from_urecptr - undo record pointer from where to start applying undo
 *				actions.
 * to_urecptr	- undo record pointer up to which the undo actions need to be
 *				applied.
 * complete_xact	- true if rollback is for complete transaction.
 */
void
execute_undo_actions(FullTransactionId full_xid, UndoRecPtr from_urecptr,
					 UndoRecPtr to_urecptr, bool complete_xact)
{
	UndoRecPtr last_log_start_urec_ptr = to_urecptr;
	UndoLogCategory		logcat = UndoRecPtrGetCategory(to_urecptr);

	/* 'from' and 'to' pointers must be valid. */
	Assert(UndoRecPtrIsValid(from_urecptr));
	Assert(UndoRecPtrIsValid(to_urecptr));

	/*
	 * We need to execute the undo actions in a semi-critical section for
	 *
	 * (a) Subtransactions.  We can't proceed without applying
	 * subtransaction's undo as the modifications made in that case must not
	 * be visible even if the main transaction commits.  The reason why that
	 * can happen is because for undo-based AM's we don't need to have a
	 * separate transaction id for subtransactions and once the main
	 * transaction commits the tuples modified by subtransactions will become
	 * visible.
	 *
	 * (b) Temp tables.  We don't expect background workers to process undo of
	 * temporary tables as the same won't be accessible.
	 */
	if (!complete_xact || logcat == UNDO_TEMP)
		START_SEMI_CRIT_SECTION();

	/*
	 * Here we compute the last log start urp which is used for fetching the
	 * undo records and updating the undo action progress.
	 *
	 * For rollbacks of subtransaction, we won't be able to calculate the last
	 * log start urp since we don't have the start urp of the top xid and hence
	 * we won't be able to follow the transaction chains to find the last log.
	 */
	if (complete_xact)
	{
		if (logcat == UNDO_TEMP)
		{
			UndoRecPtr end_urec_ptr = from_urecptr;

			/*
			 * For temporary tables, we don't push the rollback request in the
			 * rollback hash table so we can't directly get the last log start
			 * urp from there.  Instead, we need to compute it now.
			 */
			(void) FindUndoEndLocationAndSize(to_urecptr, &end_urec_ptr,
											  &last_log_start_urec_ptr,
											  full_xid);
		}
		else
		{
			/*
			 * It is important here to fetch the latest undo record and validate if
			 * the actions are already executed.  The reason is that it is possible
			 * that discard worker or backend might try to execute the rollback
			 * request which is already executed.  For ex., after discard worker
			 * fetches the record and found that this transaction need to be
			 * rolledback, backend might concurrently execute the actions and
			 * remove the request from rollback hash table.
			 *
			 * The other case where this will be required is when the transactions
			 * records span across multiple logs.  Say, we register the
			 * transaction from the first log and then we encounter the same
			 * transaction in the second log where its status is still not marked
			 * as done.  Now, before we try to register the request for the second
			 * log, the undo worker came along rolled back the previous request
			 * and removed its hash entry.  In this case, we will successfully
			 * register the request from the second log and it should be detected
			 * here.
			 */
			if (UndoAlreadyApplied(full_xid, to_urecptr))
				return;

			last_log_start_urec_ptr =
				RollbackHTGetLastLogStartUrp(full_xid, to_urecptr);
		}
	}

	ProcessAndApplyUndo(full_xid, from_urecptr, to_urecptr,
						last_log_start_urec_ptr, complete_xact);

	/*
	 * Undo actions are applied so delete the hash table entry.
	 */
	RollbackHTRemoveEntry(full_xid, to_urecptr, false);

	if (!complete_xact || logcat == UNDO_TEMP)
		END_SEMI_CRIT_SECTION();
}
