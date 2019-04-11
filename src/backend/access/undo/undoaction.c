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
#include "utils/syscache.h"
#include "miscadmin.h"
#include "storage/shmem.h"
#include "access/undodiscard.h"

#define ROLLBACK_HT_SIZE	1024

static void RollbackHTRemoveEntry(UndoRecPtr start_urec_ptr);
static bool RollbackHTRequestExist(UndoRecPtr start_urec_ptr);

/* This is the hash table to store all the rollabck requests. */
static HTAB *RollbackHT;

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
				ReleaseBuffer(buffer);
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
		ReleaseBuffer(buffer);

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
 *				  or for rollback to savepoint, we need not to lock as we
 *				  already have the lock on the table. In cases like error or
 *				  when rolling back from the undo worker we need to have proper
 *				  locks.
 */
void
execute_undo_actions(UndoRecPtr from_urecptr, UndoRecPtr to_urecptr,
					 bool nopartial, bool rewind, bool rellock)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecInfo *urp_array;
	UndoRecPtr	urec_ptr;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber prev_block = InvalidBlockNumber;
	TransactionId xid = InvalidTransactionId;
	int			undo_apply_size = maintenance_work_mem * 1024L;

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

	urec_ptr = from_urecptr;
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
		/*
		 * If we have come to execute undo actions from the worker then just
		 * confirm whether the undo request is still pending in the hash table
		 * or it's already completed because there is a possibility that the
		 * backend has applied the undo action and rewound the insert pointer
		 * and that might get used by another transaction.
		 */
		if (!rewind && !RollbackHTRequestExist(from_urecptr))
			return;
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

		xid = urp_array[0].uur->uur_xid;

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
										  prev_reloid, xid, prev_block,
										  blk_chain_complete, rellock);
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
								  prev_reloid, xid, prev_block,
								  blk_chain_complete, rellock);

		/* Free all undo records. */
		for (i = 0; i < nrecords; i++)
			UndoRecordRelease(urp_array[i].uur);

		/*
		 * Free urp array and undo_blkinfo array for the current batch of undo
		 * records.
		 */
		pfree(urp_array);
	} while (true);

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
		UndoLogRewind(to_urecptr);
		LWLockRelease(&log->rewind_lock);

		UndoRecordRelease(uur);
	}

	if (nopartial)
	{
		/* Undo action is applied so delete the hash table entry. */
		RollbackHTRemoveEntry(from_urecptr);

		/*
		 * Set undo action apply completed in the transaction header if this
		 * is a main transaction and we have not rewound its undo.
		 */
		if (!rewind)
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
execute_undo_actions_page(UndoRecInfo * urp_array, int first_idx, int last_idx,
						  Oid reloid, TransactionId xid, BlockNumber blkno,
						  bool blk_chain_complete, bool rellock)
{
	/*
	 * All records passed to us are for the same RMGR, so we just use the
	 * first record to dispatch.
	 */
	Assert(urp_array != NULL);

	return RmgrTable[urp_array[0].uur->uur_rmid].rm_undo(urp_array, first_idx,
														 last_idx, reloid, xid,
														 blkno,
														 blk_chain_complete,
														 rellock);
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
 * RollbackHTRequestExist - Check whether the rollback request exist in the
 * rollback hash table or not.
 */
static bool
RollbackHTRequestExist(UndoRecPtr start_urec_ptr)
{
	RollbackHashEntry	*rh;

	LWLockAcquire(RollbackHTLock, LW_EXCLUSIVE);

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &start_urec_ptr,
										   HASH_FIND, NULL);
	LWLockRelease(RollbackHTLock);

	if (rh == NULL)
		return false;

	return true;
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
