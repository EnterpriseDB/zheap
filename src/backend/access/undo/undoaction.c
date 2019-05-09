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
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/table.h"
#include "access/tpd.h"
#include "access/undoaction_xlog.h"
#include "access/undolog.h"
#include "access/undorequest.h"
#include "access/xact.h"
#include "access/xlog_internal.h"
#include "access/zheap.h"
#include "nodes/pg_list.h"
#include "pgstat.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "utils/syscache.h"
#include "miscadmin.h"
#include "storage/shmem.h"
#include "access/undodiscard.h"

/*
 * PrefetchUndoPages - Prefetch undo pages
 *
 * Prefetch undo pages, if prefetch_pages are behind prefetch_target
 */
static void
PrefetchUndoPages(RelFileNode rnode, int prefetch_target, int *prefetch_pages,
				  BlockNumber to_blkno, BlockNumber from_blkno,
				  char persistence)
{
	int			nprefetch;
	BlockNumber startblock;
	BlockNumber lastprefetched;

	/* Calculate last prefetched page in the previous iteration. */
	lastprefetched = from_blkno - *prefetch_pages;

	/* We have already prefetched all the pages of the transaction's undo. */
	if (lastprefetched <= to_blkno)
		return;

	/* Calculate number of blocks to be prefetched. */
	nprefetch =
		Min(prefetch_target - *prefetch_pages, lastprefetched - to_blkno);

	/* Where to start prefetch. */
	startblock = lastprefetched - nprefetch;

	while (nprefetch--)
	{
		PrefetchBufferWithoutRelcache(rnode, MAIN_FORKNUM, startblock++,
									  RelPersistenceForUndoPersistence(persistence));
		(*prefetch_pages)++;
	}
}

/*
 * UndoRecordBulkFetch  - Read undo records in bulk
 *
 * Read undo records between from_urecptr and to_urecptr until we exhaust the
 * the memory size specified by undo_apply_size.  If we could not read all the
 * records till to_urecptr then the caller should consume current set of records
 * and call this function again.
 *
 * from_urecptr		- Where to start fetching the undo records.  If we can not
 *					  read all the records because of memory limit then this
 *					  will be set to the previous undo record pointer from where
 *					  we need to start fetching on next call. Otherwise it will
 *					  be set to InvalidUndoRecPtr.
 * to_urecptr		- Last undo record pointer to be fetched.
 * undo_apply_size	- Memory segment limit to collect undo records.
 * nrecords			- Number of undo records read.
 * one_page			- Caller is applying undo only for one block not for
 *					  complete transaction.  If this is set true then instead of
 *					  following transaction undo chain using prevlen we will
 *					  follow the block prev chain of the block so that we can
 *					  avoid reading many unnecessary undo records of the
 *					  transaction.
 */
UndoRecInfo *
UndoRecordBulkFetch(UndoRecPtr *from_urecptr, UndoRecPtr to_urecptr,
					int undo_apply_size, int *nrecords, bool one_page)
{
	RelFileNode rnode;
	UndoRecPtr	urecptr,
				prev_urec_ptr;
	BlockNumber blkno;
	BlockNumber to_blkno;
	Buffer		buffer = InvalidBuffer;
	UnpackedUndoRecord *uur = NULL;
	UndoRecInfo *urp_array;
	int			urp_array_size = 1024;
	int			urp_index = 0;
	int			prefetch_target = 0;
	int			prefetch_pages = 0;
	Size		total_size = 0;
	TransactionId xid = InvalidTransactionId;

	/*
	 * In one_page mode we are fetching undo only for one page instead of
	 * fetching all the undo of the transaction.  Basically, we are fetching
	 * interleaved undo records.  So it does not make sense to do any prefetch
	 * in that case.
	 */
	if (!one_page)
		prefetch_target = target_prefetch_pages;

	/*
	 * Allocate initial memory to hold the undo record info, we can expand it
	 * if needed.
	 */
	urp_array = (UndoRecInfo *) palloc(sizeof(UndoRecInfo) * urp_array_size);
	urecptr = *from_urecptr;

	prev_urec_ptr = InvalidUndoRecPtr;
	*from_urecptr = InvalidUndoRecPtr;

	/* Read undo chain backward until we reach to the first undo record.  */
	do
	{
		BlockNumber from_blkno;
		UndoLogControl *log;
		UndoPersistence persistence;
		int			size;
		int			logno;

		logno = UndoRecPtrGetLogNo(urecptr);
		log = UndoLogGet(logno);
		persistence = log->meta.persistence;

		UndoRecPtrAssignRelFileNode(rnode, urecptr);
		to_blkno = UndoRecPtrGetBlockNum(to_urecptr);
		from_blkno = UndoRecPtrGetBlockNum(urecptr);

		/* Allocate memory for next undo record. */
		uur = palloc0(sizeof(UnpackedUndoRecord));

		/*
		 * If next undo record pointer to be fetched is not on the same block
		 * then release the old buffer and reduce the prefetch_pages count by
		 * one as we have consumed one page. Otherwise, just set the old
		 * buffer into the new undo record so that UndoGetOneRecord don't read
		 * the buffer again.
		 */
		blkno = UndoRecPtrGetBlockNum(urecptr);
		if (!UndoRecPtrIsValid(prev_urec_ptr) ||
			UndoRecPtrGetLogNo(prev_urec_ptr) != logno ||
			UndoRecPtrGetBlockNum(prev_urec_ptr) != blkno)
		{
			/* Release the previous buffer */
			if (BufferIsValid(buffer))
			{
				UnlockReleaseBuffer(buffer);
				buffer = InvalidBuffer;
			}

			if (prefetch_pages > 0)
				prefetch_pages--;
		}
		else
			uur->uur_buffer = buffer;

		/*
		 * If prefetch_pages are half of the prefetch_target then it's time to
		 * prefetch again.
		 */
		if (prefetch_pages < prefetch_target / 2)
			PrefetchUndoPages(rnode, prefetch_target, &prefetch_pages, to_blkno,
							  from_blkno, persistence);

		/*
		 * In one_page mode it's possible that the undo of the transaction might
		 * have been applied by worker and undo got discarded. Prevent discard
		 * worker from discarding undo data while we are reading it.  See detail
		 * comment in UndoFetchRecord.  In normal mode we are holding
		 * transaction undo action lock so it can not be discarded.
		 */
		if (one_page)
		{
			LWLockAcquire(&log->discard_lock, LW_SHARED);

			if (!UndoRecordIsValid(urecptr))
				break;

			/* Read the undo record. */
			UndoGetOneRecord(uur, urecptr, rnode, persistence, true);
			LWLockRelease(&log->discard_lock);
		}
		else
			UndoGetOneRecord(uur, urecptr, rnode, persistence, true);

		/*
		 * Remember the buffer, so that next time we can call UndoGetOneRecord
		 * with the same buffer if we are reading the undo from the same
		 * buffer.
		 */
		buffer = uur->uur_buffer;
		uur->uur_buffer = InvalidBuffer;

		/*
		 * As soon as the transaction id is changed we can stop fetching the
		 * undo record.  Ideally, to_urecptr should control this but while
		 * reading undo only for a page we don't know what is the end undo
		 * record pointer for the transaction.
		 */
		if (one_page)
		{
			if (!TransactionIdIsValid(xid))
				xid = uur->uur_xid;
			else if (xid != uur->uur_xid)
				break;
		}

		/* Remember the previous undo record pointer. */
		prev_urec_ptr = urecptr;

		/*
		 * Calculate the previous undo record pointer of the transaction.  If
		 * we are reading undo only for a page then follow the blkprev chain
		 * of the page.  Otherwise, calculate the previous undo record pointer
		 * using transaction's current undo record pointer and the prevlen.
		 */
		if (one_page)
			urecptr = uur->uur_blkprev;
		else if (prev_urec_ptr == to_urecptr || uur->uur_info & UREC_INFO_TRANSACTION)
			urecptr = InvalidUndoRecPtr;
		else
			urecptr = UndoGetPrevUndoRecptr(prev_urec_ptr,  uur->uur_prevurp,
											buffer);

		/* We have consumed all elements of the urp_array so expand its size. */
		if (urp_index >= urp_array_size)
		{
			urp_array_size *= 2;
			urp_array =
				repalloc(urp_array, sizeof(UndoRecInfo) * urp_array_size);
		}

		/* Add entry in the urp_array */
		urp_array[urp_index].index = urp_index;
		urp_array[urp_index].urp = prev_urec_ptr;
		urp_array[urp_index].uur = uur;
		urp_index++;

		/* We have fetched all the undo records for the transaction. */
		if (!UndoRecPtrIsValid(urecptr) || (prev_urec_ptr == to_urecptr))
			break;

		/*
		 * Including current record, if we have crossed the memory limit then
		 * stop processing more records.  Remember to set the from_urecptr so
		 * that on next call we can resume fetching undo records where we left
		 * it.
		 */
		size = UnpackedUndoRecordSize(uur);
		total_size += size;

		if (total_size >= undo_apply_size)
		{
			*from_urecptr = urecptr;
			break;
		}
	} while (true);

	/* Release the last buffer. */
	if (BufferIsValid(buffer))
		UnlockReleaseBuffer(buffer);

	*nrecords = urp_index;

	return urp_array;
}

/*
 * undo_record_comparator
 *
 * qsort comparator to handle undo record for applying undo actions of the
 * transaction.
 */
static int
undo_record_comparator(const void *left, const void *right)
{
	UnpackedUndoRecord *luur = ((UndoRecInfo *) left)->uur;
	UnpackedUndoRecord *ruur = ((UndoRecInfo *) right)->uur;

	if (luur->uur_reloid < ruur->uur_reloid)
		return -1;
	else if (luur->uur_reloid > ruur->uur_reloid)
		return 1;
	else if (luur->uur_block == ruur->uur_block)
	{
		/*
		 * If records are for the same block then maintain their existing
		 * order by comparing their index in the array.  Because for single
		 * block we need to maintain the order for applying undo action.
		 */
		if (((UndoRecInfo *) left)->index < ((UndoRecInfo *) right)->index)
			return -1;
		else
			return 1;
	}
	else if (luur->uur_block < ruur->uur_block)
		return -1;
	else
		return 1;
}

/*
 * execute_undo_actions - Execute the undo actions
 *
 * xid - Transaction id that is getting rolled back.
 * from_urecptr - undo record pointer from where to start applying undo action.
 * to_urecptr	- undo record pointer upto which point apply undo action.
 * nopartial	- true if rollback is for complete transaction.
 */
void
execute_undo_actions(FullTransactionId full_xid, UndoRecPtr from_urecptr,
					 UndoRecPtr to_urecptr, bool nopartial)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecInfo *urp_array;
	UndoRecPtr	urec_ptr;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber prev_block = InvalidBlockNumber;
	int			undo_apply_size = maintenance_work_mem * 1024L;
	TransactionId	xid = XidFromFullTransactionId(full_xid);

	/* 'from' and 'to' pointers must be valid. */
	Assert(from_urecptr != InvalidUndoRecPtr);
	Assert(to_urecptr != InvalidUndoRecPtr);

	urec_ptr = from_urecptr;

	if (nopartial)
	{
		/*
		 * It is important here to fetch the latest undo record and validate if
		 * the actions are already executed.  The reason is that it is possible
		 * that discard worker or backend might try to execute the rollback
		 * request which is already executed.  For ex., after discard worker
		 * fetches the record and found that this transaction need to be
		 * rolledback, backend might concurrently execute the actions and
		 * remove the request from rollback hash table. The similar problem
		 * can happen if the discard worker first pushes the request, the undo
		 * worker processed it and backend tries to process it some later point.
		 */
		uur = UndoFetchRecord(to_urecptr, InvalidBlockNumber, InvalidOffsetNumber,
							  InvalidTransactionId, NULL, NULL);

		/* already processed. */
		if (uur == NULL)
			return;

		/*
		 * We don't need to execute the undo actions if they are already
		 * executed.
		 */
		if (uur->uur_progress != 0)
		{
			UndoRecordRelease(uur);
			return;
		}

		Assert(xid == uur->uur_xid);

		UndoRecordRelease(uur);
		uur = NULL;
	}

	/*
	 * Fetch the multiple undo records which can fit into uur_segment; sort
	 * them in order of reloid and block number then apply them together
	 * page-wise. Repeat this until we get invalid undo record pointer.
	 */
	do
	{
		Oid			prev_reloid = InvalidOid;
		bool		blk_chain_complete;
		int			i;
		int			nrecords;
		int			last_index = 0;
		int			prefetch_pages = 0;

		/*
		 * If urec_ptr is not valid means we have complete all undo actions
		 * for this transaction, otherwise we need to fetch the next batch of
		 * the undo records.
		 */
		if (!UndoRecPtrIsValid(urec_ptr))
			break;

		/*
		 * Fetch multiple undo record in bulk.  This will return the array of
		 * undo record which will holds undo record pointers and the pointers
		 * to the actual unpacked undo record.   This will also update the
		 * number of undo records it has copied in the urp_array.  Also, for
		 * prefetching the target block ahead of applying undo actions it will
		 * update undo_blkinfo which will contains the information of the data
		 * blocks for which undo actions are going to applied for this undo
		 * record batch.
		 */
		urp_array = UndoRecordBulkFetch(&urec_ptr, to_urecptr, undo_apply_size,
										&nrecords, false);
		if (nrecords == 0)
			break;

		Assert(TransactionIdEquals(xid, urp_array[0].uur->uur_xid));

		/* Sort the undo record array in order of target blocks. */
		qsort((void *) urp_array, nrecords, sizeof(UndoRecInfo),
			  undo_record_comparator);

		if (nopartial && !UndoRecPtrIsValid(urec_ptr))
			blk_chain_complete = true;
		else
			blk_chain_complete = false;

		/*
		 * Now we have urp_array which is sorted in the block order so
		 * traverse this array and apply the undo action block by block.
		 */
		for (i = last_index; i < nrecords; i++)
		{
			UnpackedUndoRecord *uur = urp_array[i].uur;

			/*
			 * If this undo is not for the same block then apply all undo
			 * actions for the previous block.
			 */
			if (OidIsValid(prev_reloid) &&
				(prev_reloid != uur->uur_reloid ||
				 prev_fork != uur->uur_fork ||
				 prev_block != uur->uur_block))
			{
				execute_undo_actions_page(urp_array, last_index, i - 1,
										  prev_reloid, full_xid, prev_block,
										  blk_chain_complete);
				last_index = i;

				/* We have consumed one prefetched page. */
				if (prefetch_pages > 0)
					prefetch_pages--;
			}

			prev_reloid = uur->uur_reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;
		}

		/* Apply the last set of the actions. */
		execute_undo_actions_page(urp_array, last_index, i - 1,
								  prev_reloid, full_xid, prev_block,
								  blk_chain_complete);

		/* Free all undo records. */
		for (i = 0; i < nrecords; i++)
			UndoRecordRelease(urp_array[i].uur);

		/*
		 * Free urp array and undo_blkinfo array for the current batch of undo
		 * records.
		 */
		pfree(urp_array);
	} while (true);

	/*
	 * Set undo action apply progress as completed in the transaction header
	 * if this is a main transaction.
	 */
	if (nopartial)
	{
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
			 * FIXME : We need to register undo buffers and set LSN for them
			 * that will be required for FPW of the undo buffers.
			 */
			XLogBeginInsert();
			XLogRegisterData((char *) &xlrec, sizeof(xlrec));

			RegisterUndoLogBuffers(2);
			(void) XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_APPLY_PROGRESS);
			/* UndoLogBuffersSetLSN(recptr); */
		}

		END_CRIT_SECTION();
		UnlockReleaseUndoBuffers();

		/*
		 * Undo action is applied so delete the hash table entry.
		 */
		Assert(TransactionIdIsValid(xid));
		RollbackHTRemoveEntry(full_xid, to_urecptr);
	}
}

/*
 * execute_undo_actions_page - Execute the undo actions for a page
 *
 *	urp_array - array of undo records (along with their location) for which undo
 *				action needs to be applied.
 *	first_idx - index in the urp_array of the first undo action to be applied
 *	last_idx  - index in the urp_array of the first undo action to be applied
 *	reloid	- OID of relation on which undo actions needs to be applied.
 *	blkno	- block number on which undo actions needs to be applied.
 *	blk_chain_complete - indicates whether the undo chain for block is
 *						 complete.
 *
 *	returns true, if successfully applied the undo actions, otherwise, false.
 */
bool
execute_undo_actions_page(UndoRecInfo * urp_array, int first_idx, int last_idx,
						  Oid reloid, FullTransactionId full_xid, BlockNumber blkno,
						  bool blk_chain_complete)
{
	/*
	 * All records passed to us are for the same RMGR, so we just use the
	 * first record to dispatch.
	 */
	Assert(urp_array != NULL);

	return RmgrTable[urp_array[0].uur->uur_rmid].rm_undo(urp_array, first_idx,
														 last_idx, reloid,
														 full_xid, blkno,
														 blk_chain_complete);
}
