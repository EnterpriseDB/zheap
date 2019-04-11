/*-------------------------------------------------------------------------
 *
 * undoinsert.c
 *	  entry points for inserting undo records
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoinsert.c
 *
 * NOTES:
 * Undo record layout:
 *
 * Undo records are stored in sequential order in the undo log.  Each undo
 * record consists of a variable length header, tuple data, and payload
 * information.  The first undo record of each transaction contains a
 * transaction header that points to the next transaction's start header.
 * This allows us to discard the entire transaction's log at one-shot rather
 * than record-by-record.  The callers are not aware of transaction header,
 * this is entirely maintained and used by undo record layer.   See
 * undorecord.h for detailed information about undo record header.
 *
 * Handling multi log:
 *
 * It is possible that the undo record of a transaction can be spread across
 * multiple undo log.  And, we need some special handling while inserting the
 * undo for discard and rollback to work sanely.
 *
 * If the undorecord goes to next log then we insert a transaction header for
 * the first record in the new log and update the transaction header with this
 * new log's location. This will allow us to connect transactions across logs
 * when the same transaction span across log (for this we keep track of the
 * previous logno in undo log meta) which is required to find the latest undo
 * record pointer of the aborted transaction for executing the undo actions
 * before discard. If the next log get processed first in that case we
 * don't need to trace back the actual start pointer of the transaction,
 * in such case we can only execute the undo actions from the current log
 * because the undo pointer in the slot will be rewound and that will be enough
 * to avoid executing same actions.  However, there is possibility that after
 * executing the undo actions the undo pointer got discarded, now in later
 * stage while processing the previous log it might try to fetch the undo
 * record in the discarded log while chasing the transaction header chain.
 * To avoid this situation we first check if the next_urec of the transaction
 * is already discarded then no need to access that and start executing from
 * the last undo record in the current log.
 *
 *  We only connect to next log if the same transaction spread to next log
 *  otherwise don't.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/undorecord.h"
#include "access/undoinsert.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/xlogutils.h"
#include "catalog/pg_tablespace.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/buf_internals.h"
#include "storage/bufmgr.h"
#include "miscadmin.h"
#include "commands/tablecmds.h"

/*
 * XXX Do we want to support undo tuple size which is more than the BLCKSZ
 * if not than undo record can spread across 2 buffers at the max.
 */
#define MAX_BUFFER_PER_UNDO    2

/*
 * This defines the number of undo records that can be prepared before
 * calling insert by default.  If you need to prepare more than
 * MAX_PREPARED_UNDO undo records, then you must call UndoSetPrepareSize
 * first.
 */
#define MAX_PREPARED_UNDO 2

/*
 * Consider buffers needed for updating previous transaction's
 * starting undo record. Hence increased by 1.
 */
#define MAX_UNDO_BUFFERS       (MAX_PREPARED_UNDO + 1) * MAX_BUFFER_PER_UNDO

/*
 * Previous top transaction id which inserted the undo.  Whenever a new main
 * transaction try to prepare an undo record we will check if its txid not the
 * same as prev_txid then we will insert the start undo record.
 */
static TransactionId	prev_txid[UndoPersistenceLevels] = { 0 };

/* Undo block number to buffer mapping. */
typedef struct UndoBuffers
{
	UndoLogNumber	logno;			/* Undo log number */
	BlockNumber		blk;			/* block number */
	Buffer			buf;			/* buffer allocated for the block */
	bool			zero;			/* new block full of zeroes */
} UndoBuffers;

static UndoBuffers def_buffers[MAX_UNDO_BUFFERS];
static int	buffer_idx;

/*
 * Structure to hold the prepared undo information.
 */
typedef struct PreparedUndoSpace
{
	UndoRecPtr	urp;			/* undo record pointer */
	UnpackedUndoRecord *urec;	/* undo record */
	int			undo_buffer_idx[MAX_BUFFER_PER_UNDO];	/* undo_buffer array
														 * index */
} PreparedUndoSpace;

static PreparedUndoSpace def_prepared[MAX_PREPARED_UNDO];
static int	prepare_idx;
static int	max_prepared_undo = MAX_PREPARED_UNDO;
static UndoRecPtr prepared_urec_ptr = InvalidUndoRecPtr;
static bool update_prev_header = false;

/*
 * By default prepared_undo and undo_buffer points to the static memory.
 * In case caller wants to support more than default max_prepared undo records
 * then the limit can be increased by calling UndoSetPrepareSize function.
 * Therein, dynamic memory will be allocated and prepared_undo and undo_buffer
 * will start pointing to newly allocated memory, which will be released by
 * UnlockReleaseUndoBuffers and these variables will again set back to their
 * default values.
 */
static PreparedUndoSpace *prepared_undo = def_prepared;
static UndoBuffers *undo_buffer = def_buffers;

/*
 * Structure to hold the previous transaction's undo update information.  This
 * is populated while current transaction is updating its undo record pointer
 * in previous transactions first undo record.
 */
typedef struct XactUndoRecordInfo
{
	UndoRecPtr	urecptr;		/* txn's start urecptr */
	int			idx_undo_buffers[MAX_BUFFER_PER_UNDO];
	UnpackedUndoRecord uur;		/* undo record header */
} XactUndoRecordInfo;

static XactUndoRecordInfo xact_urec_info;

/* Prototypes for static functions. */
static UnpackedUndoRecord *UndoGetOneRecord(UnpackedUndoRecord *urec,
				 UndoRecPtr urp, RelFileNode rnode,
				 UndoPersistence persistence);
static void UndoRecordPrepareTransInfo(XLogReaderState *xlog_record,
						   UndoRecPtr urecptr,
						   bool log_switched);
static int UndoGetBufferSlot(RelFileNode rnode, BlockNumber blk,
				  ReadBufferMode rbm,
				  UndoPersistence persistence,
				  XLogReaderState *xlog_record);
static bool UndoRecordIsValid(UndoLogControl * log,
				  UndoRecPtr urp);

/*
 * Check whether the undo record is discarded or not.  If it's already discarded
 * return false otherwise return true.
 *
 * Caller must hold lock on log->discard_lock.  This function will release the
 * lock if return false otherwise lock will be held on return and the caller
 * need to release it.
 */
static bool
UndoRecordIsValid(UndoLogControl * log, UndoRecPtr urp)
{
	Assert(LWLockHeldByMeInMode(&log->discard_lock, LW_SHARED));

	if (log->oldest_data == InvalidUndoRecPtr)
	{
		/*
		 * oldest_data is only initialized when the DiscardWorker first time
		 * attempts to discard undo logs so we can not rely on this value to
		 * identify whether the undo record pointer is already discarded or
		 * not so we can check it by calling undo log routine.  If its not yet
		 * discarded then we have to reacquire the log->discard_lock so that
		 * the doesn't get discarded concurrently.
		 */
		LWLockRelease(&log->discard_lock);
		if (UndoLogIsDiscarded(urp))
			return false;
		LWLockAcquire(&log->discard_lock, LW_SHARED);
	}

	/* Check again if it's already discarded. */
	if (urp < log->oldest_data)
	{
		LWLockRelease(&log->discard_lock);
		return false;
	}

	return true;
}

/*
 * Prepare to update the previous transaction's next undo pointer to maintain
 * the transaction chain in the undo.  This will read the header of the first
 * undo record of the previous transaction and lock the necessary buffers.
 * The actual update will be done by UndoRecordUpdateTransInfo under the
 * critical section.
 */
static void
UndoRecordPrepareTransInfo(XLogReaderState *xlog_record, UndoRecPtr urecptr,
						   bool log_switched)
{
	UndoRecPtr	xact_urp;
	Buffer		buffer = InvalidBuffer;
	BlockNumber cur_blk;
	RelFileNode rnode;
	UndoLogNumber logno = UndoRecPtrGetLogNo(urecptr);
	UndoLogControl *log;
	Page		page;
	int			already_decoded = 0;
	int			starting_byte;
	int			bufidx;
	int			index = 0;

	log = UndoLogGet(logno);

	if (log_switched)
	{
		Assert(log->meta.prevlogno != InvalidUndoLogNumber);
		log = UndoLogGet(log->meta.prevlogno);
	}

	/*
	 * Temporary undo logs are discarded on transaction commit so we don't
	 * need to do anything.
	 */
	if (log->meta.persistence == UNDO_TEMP)
		return;

	/*
	 * We can read the previous transaction's location without locking,
	 * because only the backend attached to the log can write to it (or we're
	 * in recovery).
	 */
	Assert(AmAttachedToUndoLog(log) || InRecovery || log_switched);

	if (log->meta.last_xact_start == 0)
		xact_urp = InvalidUndoRecPtr;
	else
		xact_urp = MakeUndoRecPtr(log->logno, log->meta.last_xact_start);

	/*
	 * The absence of previous transaction's undo indicate that this backend
	 * is preparing its first undo in which case we have nothing to update.
	 */
	if (!UndoRecPtrIsValid(xact_urp))
		return;

	/*
	 * Acquire the discard lock before accessing the undo record so that
	 * discard worker doesn't remove the record while we are in process of
	 * reading it.
	 */
	LWLockAcquire(&log->discard_lock, LW_SHARED);

	/*
	 * The absence of previous transaction's undo indicate that this backend
	 * is preparing its first undo in which case we have nothing to update.
	 * UndoRecordIsValid will release the lock if it returns false.
	 */
	if (!UndoRecordIsValid(log, xact_urp))
		return;

	UndoRecPtrAssignRelFileNode(rnode, xact_urp);
	cur_blk = UndoRecPtrGetBlockNum(xact_urp);
	starting_byte = UndoRecPtrGetPageOffset(xact_urp);

	/*
	 * Read undo record header in by calling UnpackUndoRecord, if the undo
	 * record header is split across buffers then we need to read the complete
	 * header by invoking UnpackUndoRecord multiple times.
	 */
	while (true)
	{
		bufidx = UndoGetBufferSlot(rnode, cur_blk,
								   RBM_NORMAL,
								   log->meta.persistence,
								   xlog_record);

		xact_urec_info.idx_undo_buffers[index++] = bufidx;
		buffer = undo_buffer[bufidx].buf;
		page = BufferGetPage(buffer);

		if (UnpackUndoRecord(&xact_urec_info.uur, page, starting_byte,
							 &already_decoded, true))
			break;

		/* Could not fetch the complete header so go to the next block. */
		starting_byte = UndoLogBlockHeaderSize;
		cur_blk++;
	}

	xact_urec_info.uur.uur_next = urecptr;
	xact_urec_info.urecptr = xact_urp;
	LWLockRelease(&log->discard_lock);
}

/*
 * Update the progress of the undo record in the transaction header.
 */
void
PrepareUpdateUndoActionProgress(XLogReaderState *xlog_record,
								UndoRecPtr urecptr, int progress)
{
	Buffer		buffer = InvalidBuffer;
	BlockNumber	cur_blk;
	RelFileNode	rnode;
	UndoLogNumber logno = UndoRecPtrGetLogNo(urecptr);
	UndoLogControl *log;
	Page		page;
	int			already_decoded = 0;
	int			starting_byte;
	int			bufidx;
	int			index = 0;

	log = UndoLogGet(logno);

	if (log->meta.persistence == UNDO_TEMP)
		return;

	UndoRecPtrAssignRelFileNode(rnode, urecptr);
	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	while (true)
	{
		bufidx = UndoGetBufferSlot(rnode, cur_blk,
								   RBM_NORMAL,
								   log->meta.persistence,
								   xlog_record);

		xact_urec_info.idx_undo_buffers[index++] = bufidx;
		buffer = undo_buffer[bufidx].buf;
		page = BufferGetPage(buffer);

		if (UnpackUndoRecord(&xact_urec_info.uur, page, starting_byte,
							 &already_decoded, true))
			break;

		starting_byte = UndoLogBlockHeaderSize;
		cur_blk++;
	}

	xact_urec_info.urecptr = urecptr;
	xact_urec_info.uur.uur_progress = progress;
}

/*
 * Overwrite the first undo record of the previous transaction to update its
 * next pointer.  This will just insert the already prepared record by
 * UndoRecordPrepareTransInfo.  This must be called under the critical section.
 * This will just overwrite the undo header not the data.
 */
void
UndoRecordUpdateTransInfo(void)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(xact_urec_info.urecptr);
	Page		page;
	int			starting_byte;
	int			already_written = 0;
	int			idx = 0;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	UndoLogControl *log;

	log = UndoLogGet(logno);
	urec_ptr = xact_urec_info.urecptr;

	/*
	 * Acquire the discard lock before accessing the undo record so that
	 * discard worker can't remove the record while we are in process of
	 * reading it.
	 */
	LWLockAcquire(&log->discard_lock, LW_SHARED);

	if (!UndoRecordIsValid(log, urec_ptr))
		return;

	/*
	 * Update the next transactions start urecptr in the transaction header.
	 */
	starting_byte = UndoRecPtrGetPageOffset(urec_ptr);

	do
	{
		Buffer		buffer;
		int			buf_idx;

		buf_idx = xact_urec_info.idx_undo_buffers[idx];
		buffer = undo_buffer[buf_idx].buf;
		page = BufferGetPage(buffer);

		/* Overwrite the previously written undo. */
		if (InsertUndoRecord(&xact_urec_info.uur, page, starting_byte, &already_written, true))
		{
			MarkBufferDirty(buffer);
			break;
		}

		MarkBufferDirty(buffer);
		starting_byte = UndoLogBlockHeaderSize;
		idx++;

		Assert(idx < MAX_BUFFER_PER_UNDO);
	} while (true);

	LWLockRelease(&log->discard_lock);
}

/*
 * Find the block number in undo buffer array, if it's present then just return
 * its index otherwise search the buffer and insert an entry and lock the buffer
 * in exclusive mode.
 *
 * Undo log insertions are append-only.  If the caller is writing new data
 * that begins exactly at the beginning of a page, then there cannot be any
 * useful data after that point.  In that case RBM_ZERO can be passed in as
 * rbm so that we can skip a useless read of a disk block.  In all other
 * cases, RBM_NORMAL should be passed in, to read the page in if it doesn't
 * happen to be already in the buffer pool.
 */
static int
UndoGetBufferSlot(RelFileNode rnode,
				  BlockNumber blk,
				  ReadBufferMode rbm,
				  UndoPersistence persistence,
				  XLogReaderState *xlog_record)
{
	int			i;
	Buffer		buffer;

	/* Don't do anything, if we already have a buffer pinned for the block. */
	for (i = 0; i < buffer_idx; i++)
	{
		/*
		 * It's not enough to just compare the block number because the
		 * undo_buffer might holds the undo from different undo logs (e.g when
		 * previous transaction start header is in previous undo log) so
		 * compare (logno + blkno).
		 */
		if ((blk == undo_buffer[i].blk) &&
			(undo_buffer[i].logno == rnode.relNode))
		{
			/* caller must hold exclusive lock on buffer */
			Assert(BufferIsLocal(undo_buffer[i].buf) ||
				   LWLockHeldByMeInMode(BufferDescriptorGetContentLock(
																	   GetBufferDescriptor(undo_buffer[i].buf - 1)),
										LW_EXCLUSIVE));
			break;
		}
	}

	/*
	 * We did not find the block so allocate the buffer and insert into the
	 * undo buffer array
	 */
	if (i == buffer_idx)
	{
		/*
		 * Fetch the buffer in which we want to insert the undo record.
		 */
		if (InRecovery)
			XLogReadBufferForRedoBlock(xlog_record,
									   rnode,
									   UndoLogForkNum,
									   blk,
									   rbm,
									   false,
									   &buffer);
		else
		{
			buffer = ReadBufferWithoutRelcache(rnode,
											   UndoLogForkNum,
											   blk,
											   rbm,
											   NULL,
											   RelPersistenceForUndoPersistence(persistence));

			/* Lock the buffer */
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		}

		undo_buffer[buffer_idx].buf = buffer;
		undo_buffer[buffer_idx].blk = blk;
		undo_buffer[buffer_idx].logno = rnode.relNode;
		undo_buffer[buffer_idx].zero = rbm == RBM_ZERO;
		buffer_idx++;
	}

	return i;
}

/*
 * Calculate total size required by nrecords and allocate them in bulk. This is
 * required for some operation which can allocate multiple undo record in one
 * WAL operation e.g multi-insert.  If we don't allocate undo space for all the
 * record (which are inserted under one WAL) together than there is possibility
 * that both of them go under different undo log.  And, currently during
 * recovery we don't have mechanism to map xid to multiple log number during one
 * WAL operation.  So in short all the operation under one WAL must allocate
 * their undo from the same undo log.
 */
static UndoRecPtr
UndoRecordAllocate(UnpackedUndoRecord *undorecords, int nrecords,
				   TransactionId txid, UndoPersistence upersistence,
				   XLogReaderState *xlog_record,
				   xl_undolog_meta *undometa)
{
	UnpackedUndoRecord *urec = NULL;
	UndoLogControl *log;
	UndoRecordSize size;
	UndoRecPtr	urecptr;
	bool		need_xact_hdr = false;
	bool		log_switched = false;
	int			i;

	/* There must be at least one undo record. */
	if (nrecords <= 0)
		elog(ERROR, "cannot allocate space for zero undo records");

	/* Is this the first undo record of the transaction? */
	if ((InRecovery && IsTransactionFirstRec(txid)) ||
		(!InRecovery && prev_txid[upersistence] != txid))
		need_xact_hdr = true;

resize:
	size = 0;

	for (i = 0; i < nrecords; i++)
	{
		urec = undorecords + i;

		/*
		 * Prepare the transacion header for the first undo record of
		 * transaction.
		 *
		 * XXX There is also an option that instead of adding the
		 * information to this record we can prepare a new record which only
		 * contain transaction informations, but we can't see any clear
		 * advantage of the same.
		 */
		if (need_xact_hdr && i == 0)
		{
			urec->uur_next = InvalidUndoRecPtr;
			urec->uur_xidepoch = GetEpochForXid(txid);
			urec->uur_progress = 0;

			/* During recovery, get the database id from the undo log state. */
			if (InRecovery)
				urec->uur_dbid = UndoLogStateGetDatabaseId();
			else
				urec->uur_dbid = MyDatabaseId;

			/* Set uur_info to include the transaction header. */
			urec->uur_info |= UREC_INFO_TRANSACTION;
		}
		else
		{
			/*
			 * It is okay to initialize these variables with invalid values as
			 * these are used only with the first record of transaction.
			 */
			urec->uur_next = InvalidUndoRecPtr;
			urec->uur_xidepoch = 0;
			urec->uur_dbid = 0;
			urec->uur_progress = 0;
		}

		/* Calculate the size of the undo record based on the info required. */
		UndoRecordSetInfo(urec);
		size += UndoRecordExpectedSize(urec);
	}

	if (InRecovery)
		urecptr = UndoLogAllocateInRecovery(txid, size, upersistence);
	else
		urecptr = UndoLogAllocate(size, upersistence);

	log = UndoLogGet(UndoRecPtrGetLogNo(urecptr));

	/*
	 * By now, we must be attached to some undo log unless we are in recovery.
	 */
	Assert(AmAttachedToUndoLog(log) || InRecovery);

	/*
	 * We can consider the log as switched if this is the first record of the
	 * log and not the first record of the transaction i.e. same transaction
	 * continued from the previous log.
	 */
	if ((UndoRecPtrGetOffset(urecptr) == UndoLogBlockHeaderSize) &&
		log->meta.prevlogno != InvalidUndoLogNumber)
		log_switched = true;

	/*
	 * If we've rewound all the way back to the start of the transaction by
	 * rolling back the first subtransaction (which we can't detect until
	 * after we've allocated some space), we'll need a new transaction header.
	 * If we weren't already generating one, then do it now.
	 */
	if (!need_xact_hdr &&
		(log->meta.insert == log->meta.last_xact_start ||
		 UndoRecPtrGetOffset(urecptr) == UndoLogBlockHeaderSize))
	{
		need_xact_hdr = true;
		urec->uur_info = 0;		/* force recomputation of info bits */
		goto resize;
	}

	/* Copy undometa before advancing the insert location. */
	if (undometa)
	{
		undometa->meta = log->meta;
		undometa->logno = log->logno;
		undometa->xid = log->xid;
	}

	/* Update the previous transaction's start undo record, if required. */
	if (need_xact_hdr || log_switched)
	{
		/* Don't update our own start header. */
		if (log->meta.last_xact_start != log->meta.insert)
			UndoRecordPrepareTransInfo(xlog_record, urecptr, log_switched);

		/* Remember the current transaction's xid. */
		prev_txid[upersistence] = txid;

		/* Store the current transaction's start undorecptr in the undo log. */
		UndoLogSetLastXactStartPoint(urecptr);
		update_prev_header = false;
	}

	/*
	 * If the insertion is for temp table then register an on commit
	 * action for discarding the undo logs.
	 */
	if (upersistence == UNDO_TEMP)
	{
		/*
		 * We only need to register when we are inserting in temp undo logs
		 * for the first time after the discard.
		 */
		if (log->meta.insert == log->meta.discard)
		{
			/*
			 * XXX Here, we are overriding the first parameter of function
			 * which is a unsigned int with an integer argument, that should
			 * work fine because logno will always be positive.
			 */
			register_on_commit_action(log->logno, ONCOMMIT_TEMP_DISCARD);
		}
	}

	UndoLogAdvance(urecptr, size, upersistence);

	return urecptr;
}

/*
 * Call UndoSetPrepareSize to set the value of how many undo records can be
 * prepared before we can insert them.  If the size is greater than
 * MAX_PREPARED_UNDO then it will allocate extra memory to hold the extra
 * prepared undo.
 *
 * This is normally used when more than one undo record needs to be prepared.
 */
void
UndoSetPrepareSize(UnpackedUndoRecord *undorecords, int nrecords,
				   TransactionId xid, UndoPersistence upersistence,
				   XLogReaderState *xlog_record,
				   xl_undolog_meta *undometa)
{
	TransactionId txid;

	/* Get the top transaction id. */
	if (xid == InvalidTransactionId)
	{
		Assert(!InRecovery);
		txid = GetTopTransactionId();
	}
	else
	{
		Assert(InRecovery || (xid == GetTopTransactionId()));
		txid = xid;
	}

	prepared_urec_ptr = UndoRecordAllocate(undorecords, nrecords, txid,
										   upersistence, xlog_record,
										   undometa);
	if (nrecords <= MAX_PREPARED_UNDO)
		return;

	prepared_undo = palloc0(nrecords * sizeof(PreparedUndoSpace));

	/*
	 * Consider buffers needed for updating previous transaction's starting
	 * undo record. Hence increased by 1.
	 */
	undo_buffer = palloc0((nrecords + 1) * MAX_BUFFER_PER_UNDO *
						  sizeof(UndoBuffers));
	max_prepared_undo = nrecords;
}

/*
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned and
 * locked.
 *
 * This should be done before any critical section is established, since it
 * can fail.
 *
 * In recovery, 'xid' refers to the transaction id stored in WAL, otherwise,
 * it refers to the top transaction id because undo log only stores mapping
 * for the top most transactions.
 */
UndoRecPtr
PrepareUndoInsert(UnpackedUndoRecord *urec, TransactionId xid,
				  UndoPersistence upersistence,
				  XLogReaderState *xlog_record,
				  xl_undolog_meta *undometa)
{
	UndoRecordSize size;
	UndoRecPtr	urecptr;
	RelFileNode rnode;
	UndoRecordSize cur_size = 0;
	BlockNumber cur_blk;
	TransactionId txid;
	int			starting_byte;
	int			index = 0;
	int			bufidx;
	ReadBufferMode rbm;

	/* Already reached maximum prepared limit. */
	if (prepare_idx == max_prepared_undo)
		elog(ERROR, "already reached the maximum prepared limit");


	if (xid == InvalidTransactionId)
	{
		/* During recovery, we must have a valid transaction id. */
		Assert(!InRecovery);
		txid = GetTopTransactionId();
	}
	else
	{
		/*
		 * Assign the top transaction id because undo log only stores mapping
		 * for the top most transactions.
		 */
		Assert(InRecovery || (xid == GetTopTransactionId()));
		txid = xid;
	}

	if (!UndoRecPtrIsValid(prepared_urec_ptr))
		urecptr = UndoRecordAllocate(urec, 1, txid, upersistence,
									 xlog_record, undometa);
	else
		urecptr = prepared_urec_ptr;

	/* advance the prepared ptr location for next record. */
	size = UndoRecordExpectedSize(urec);
	if (UndoRecPtrIsValid(prepared_urec_ptr))
	{
		UndoLogOffset insert = UndoRecPtrGetOffset(prepared_urec_ptr);

		insert = UndoLogOffsetPlusUsableBytes(insert, size);
		prepared_urec_ptr = MakeUndoRecPtr(UndoRecPtrGetLogNo(urecptr), insert);
	}

	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	UndoRecPtrAssignRelFileNode(rnode, urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	/*
	 * If we happen to be writing the very first byte into this page, then
	 * there is no need to read from disk.
	 */
	if (starting_byte == UndoLogBlockHeaderSize)
		rbm = RBM_ZERO;
	else
		rbm = RBM_NORMAL;

	do
	{
		bufidx = UndoGetBufferSlot(rnode, cur_blk, rbm, upersistence,
								   xlog_record);
		if (cur_size == 0)
			cur_size = BLCKSZ - starting_byte;
		else
			cur_size += BLCKSZ - UndoLogBlockHeaderSize;

		/* undo record can't use buffers more than MAX_BUFFER_PER_UNDO. */
		Assert(index < MAX_BUFFER_PER_UNDO);

		/* Keep the track of the buffers we have pinned and locked. */
		prepared_undo[prepare_idx].undo_buffer_idx[index++] = bufidx;

		/*
		 * If we need more pages they'll be all new so we can definitely skip
		 * reading from disk.
		 */
		rbm = RBM_ZERO;
		cur_blk++;
	} while (cur_size < size);

	/*
	 * Save the undo record information to be later used by InsertPreparedUndo
	 * to insert the prepared record.
	 */
	prepared_undo[prepare_idx].urec = urec;
	prepared_undo[prepare_idx].urp = urecptr;
	prepare_idx++;

	return urecptr;
}

/*
 * Insert a previously-prepared undo record.  This will write the actual undo
 * record into the buffers already pinned and locked in PreparedUndoInsert,
 * and mark them dirty.  This step should be performed after entering a
 * criticalsection; it should never fail.
 */
void
InsertPreparedUndo(void)
{
	Page		page;
	int			starting_byte;
	int			already_written;
	int			bufidx = 0;
	int			idx;
	uint16		undo_len = 0;
	UndoRecPtr	urp;
	UnpackedUndoRecord *uur;
	UndoLogOffset offset;
	UndoLogControl *log;

	/* There must be atleast one prepared undo record. */
	Assert(prepare_idx > 0);

	/*
	 * This must be called under a critical section or we must be in recovery.
	 */
	Assert(InRecovery || CritSectionCount > 0);

	for (idx = 0; idx < prepare_idx; idx++)
	{
		uur = prepared_undo[idx].urec;
		urp = prepared_undo[idx].urp;

		already_written = 0;
		bufidx = 0;
		starting_byte = UndoRecPtrGetPageOffset(urp);
		offset = UndoRecPtrGetOffset(urp);

		log = UndoLogGet(UndoRecPtrGetLogNo(urp));
		Assert(AmAttachedToUndoLog(log) || InRecovery);

		/*
		 * Store the previous undo record length in the header.  We can read
		 * meta.prevlen without locking, because only we can write to it.
		 */
		uur->uur_prevlen = log->meta.prevlen;

		/*
		 * If starting a new log then there is no prevlen to store except when
		 * the same transaction is continuing from the previous undo log read
		 * detailed comment atop this file.
		 */
		if (offset == UndoLogBlockHeaderSize)
		{
			if (log->meta.prevlogno != InvalidUndoLogNumber)
			{
				UndoLogControl *prevlog = UndoLogGet(log->meta.prevlogno);
				uur->uur_prevlen = prevlog->meta.prevlen;
			}
			else
				uur->uur_prevlen = 0;
		}

		/*
		 * if starting from a new page then consider block header size in
		 * prevlen calculation.
		 */
		else if (starting_byte == UndoLogBlockHeaderSize)
			uur->uur_prevlen += UndoLogBlockHeaderSize;

		undo_len = 0;

		do
		{
			PreparedUndoSpace undospace = prepared_undo[idx];
			Buffer		buffer;

			buffer = undo_buffer[undospace.undo_buffer_idx[bufidx]].buf;
			page = BufferGetPage(buffer);

			/*
			 * Initialize the page whenever we try to write the first record
			 * in page.  We start writting immediately after the block header.
			 */
			if (starting_byte == UndoLogBlockHeaderSize)
				PageInit(page, BLCKSZ, 0);

			/*
			 * Try to insert the record into the current page. If it doesn't
			 * succeed then recall the routine with the next page.
			 */
			if (InsertUndoRecord(uur, page, starting_byte, &already_written, false))
			{
				undo_len += already_written;
				MarkBufferDirty(buffer);
				break;
			}

			MarkBufferDirty(buffer);

			/*
			 * If we are swithing to the next block then consider the header
			 * in total undo length.
			 */
			starting_byte = UndoLogBlockHeaderSize;
			undo_len += UndoLogBlockHeaderSize;
			bufidx++;

			/* undo record can't use buffers more than MAX_BUFFER_PER_UNDO. */
			Assert(bufidx < MAX_BUFFER_PER_UNDO);
		} while (true);

		UndoLogSetPrevLen(UndoRecPtrGetLogNo(urp), undo_len);

		/*
		 * Link the transactions in the same log so that we can discard all
		 * the transaction's undo log in one-shot.
		 */
		if (UndoRecPtrIsValid(xact_urec_info.urecptr))
			UndoRecordUpdateTransInfo();

		/*
		 * Set the current undo location for a transaction.  This is required
		 * to perform rollback during abort of transaction.
		 */
		SetCurrentUndoLocation(urp);
	}
}

/*
 * Helper function for UndoFetchRecord.  It will fetch the undo record pointed
 * by urp and unpack the record into urec.  This function will not release the
 * pin on the buffer if complete record is fetched from one buffer, so caller
 * can reuse the same urec to fetch the another undo record which is on the
 * same block.  Caller will be responsible to release the buffer inside urec
 * and set it to invalid if it wishes to fetch the record from another block.
 */
static UnpackedUndoRecord *
UndoGetOneRecord(UnpackedUndoRecord *urec, UndoRecPtr urp, RelFileNode rnode,
				 UndoPersistence persistence)
{
	Buffer		buffer = urec->uur_buffer;
	Page		page;
	int			starting_byte = UndoRecPtrGetPageOffset(urp);
	int			already_decoded = 0;
	BlockNumber cur_blk;
	bool		is_undo_rec_split = false;

	cur_blk = UndoRecPtrGetBlockNum(urp);

	/* If we already have a buffer pin then no need to allocate a new one. */
	if (!BufferIsValid(buffer))
	{
		buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
										   RBM_NORMAL, NULL,
										   RelPersistenceForUndoPersistence(persistence));

		urec->uur_buffer = buffer;
	}

	while (true)
	{
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);

		/*
		 * XXX This can be optimized to just fetch header first and only if
		 * matches with block number and offset then fetch the complete
		 * record.
		 */
		if (UnpackUndoRecord(urec, page, starting_byte, &already_decoded, false))
			break;

		starting_byte = UndoLogBlockHeaderSize;
		is_undo_rec_split = true;

		/*
		 * The record spans more than a page so we would have copied it (see
		 * UnpackUndoRecord).  In such cases, we can release the buffer.
		 */
		urec->uur_buffer = InvalidBuffer;
		UnlockReleaseBuffer(buffer);

		/* Go to next block. */
		cur_blk++;
		buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
										   RBM_NORMAL, NULL,
										   RelPersistenceForUndoPersistence(persistence));
	}

	/*
	 * If we have copied the data then release the buffer, otherwise, just
	 * unlock it.
	 */
	if (is_undo_rec_split)
		UnlockReleaseBuffer(buffer);
	else
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	return urec;
}

/*
 * ResetUndoRecord - Helper function for UndoFetchRecord to reset the current
 * record.
 */
static void
ResetUndoRecord(UnpackedUndoRecord *urec, UndoRecPtr urp, RelFileNode *rnode,
				RelFileNode *prevrec_rnode)
{
	/*
	 * If we have a valid buffer pinned then just ensure that we want to find
	 * the next tuple from the same block.  Otherwise release the buffer and
	 * set it invalid
	 */
	if (BufferIsValid(urec->uur_buffer))
	{
		/*
		 * Undo buffer will be changed if the next undo record belongs to a
		 * different block or undo log.
		 */
		if ((UndoRecPtrGetBlockNum(urp) !=
			 BufferGetBlockNumber(urec->uur_buffer)) ||
			(prevrec_rnode->relNode != rnode->relNode))
		{
			ReleaseBuffer(urec->uur_buffer);
			urec->uur_buffer = InvalidBuffer;
		}
	}
	else
	{
		/*
		 * If there is not a valid buffer in urec->uur_buffer that means we
		 * had copied the payload data and tuple data so free them.
		 */
		if (urec->uur_payload.data)
			pfree(urec->uur_payload.data);
		if (urec->uur_tuple.data)
			pfree(urec->uur_tuple.data);
	}

	/* Reset the urec before fetching the tuple */
	urec->uur_tuple.data = NULL;
	urec->uur_tuple.len = 0;
	urec->uur_payload.data = NULL;
	urec->uur_payload.len = 0;
}

/*
 * Fetch the next undo record for given blkno, offset and transaction id (if
 * valid).  The same tuple can be modified by multiple transactions, so during
 * undo chain traversal sometimes we need to distinguish based on transaction
 * id.  Callers that don't have any such requirement can pass
 * InvalidTransactionId.
 *
 * Start the search from urp.  Caller need to call UndoRecordRelease to release the
 * resources allocated by this function.
 *
 * urec_ptr_out is undo record pointer of the qualified undo record if valid
 * pointer is passed.
 *
 * callback function decides whether particular undo record satisfies the
 * condition of caller.
 *
 * Returns the required undo record if found, otherwise, return NULL which
 * means either the record is already discarded or there is no such record
 * in the undo chain.
 */
UnpackedUndoRecord *
UndoFetchRecord(UndoRecPtr urp, BlockNumber blkno, OffsetNumber offset,
				TransactionId xid, UndoRecPtr *urec_ptr_out,
				SatisfyUndoRecordCallback callback)
{
	RelFileNode rnode,
				prevrec_rnode = {0};
	UnpackedUndoRecord *urec = NULL;
	int			logno;

	if (urec_ptr_out)
		*urec_ptr_out = InvalidUndoRecPtr;

	urec = palloc0(sizeof(UnpackedUndoRecord));
	UndoRecPtrAssignRelFileNode(rnode, urp);

	/* Find the undo record pointer we are interested in. */
	while (true)
	{
		UndoLogControl *log;

		logno = UndoRecPtrGetLogNo(urp);
		log = UndoLogGet(logno);
		if (log == NULL)
		{
			if (BufferIsValid(urec->uur_buffer))
				ReleaseBuffer(urec->uur_buffer);
			return NULL;
		}

		/*
		 * Prevent UndoDiscardOneLog() from discarding data while we try to
		 * read it.  Usually we would acquire log->mutex to read log->meta
		 * members, but in this case we know that discard can't move without
		 * also holding log->discard_lock.
		 */
		LWLockAcquire(&log->discard_lock, LW_SHARED);
		if (!UndoRecordIsValid(log, urp))
		{
			if (BufferIsValid(urec->uur_buffer))
				ReleaseBuffer(urec->uur_buffer);
			return NULL;
		}

		/* Fetch the current undo record. */
		urec = UndoGetOneRecord(urec, urp, rnode, log->meta.persistence);
		LWLockRelease(&log->discard_lock);

		if (blkno == InvalidBlockNumber)
			break;

		/* Check whether the undorecord satisfies conditions */
		if (callback(urec, blkno, offset, xid))
			break;

		urp = urec->uur_blkprev;
		prevrec_rnode = rnode;

		/* Get rnode for the current undo record pointer. */
		UndoRecPtrAssignRelFileNode(rnode, urp);

		/* Reset the current undorecord before fetching the next. */
		ResetUndoRecord(urec, urp, &rnode, &prevrec_rnode);
	}

	if (urec_ptr_out)
		*urec_ptr_out = urp;
	return urec;
}

/*
 * Return the previous undo record pointer.
 *
 * This API can switch to the previous log if the current log is exhausted,
 * so the caller shouldn't use it where that is not expected.
 */
UndoRecPtr
UndoGetPrevUndoRecptr(UndoRecPtr urp, uint16 prevlen)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(urp);
	UndoLogOffset offset = UndoRecPtrGetOffset(urp);

	/*
	 * We have reached to the first undo record of this undo log, so fetch the
	 * previous undo record of the transaction from the previous log.
	 */
	if (offset == UndoLogBlockHeaderSize)
	{
		UndoLogControl *prevlog,
				   *log;

		log = UndoLogGet(logno);

		Assert(log->meta.prevlogno != InvalidUndoLogNumber);

		/* Fetch the previous log control. */
		prevlog = UndoLogGet(log->meta.prevlogno);
		logno = log->meta.prevlogno;
		offset = prevlog->meta.insert;
	}

	/* calculate the previous undo record pointer */
	return MakeUndoRecPtr(logno, offset - prevlen);
}

/*
 * Release the resources allocated by UndoFetchRecord.
 */
void
UndoRecordRelease(UnpackedUndoRecord *urec)
{
	/*
	 * If the undo record has a valid buffer then just release the buffer
	 * otherwise free the tuple and payload data.
	 */
	if (BufferIsValid(urec->uur_buffer))
	{
		ReleaseBuffer(urec->uur_buffer);
	}
	else
	{
		if (urec->uur_payload.data)
			pfree(urec->uur_payload.data);
		if (urec->uur_tuple.data)
			pfree(urec->uur_tuple.data);
	}

	pfree(urec);
}

/*
 * RegisterUndoLogBuffers - Register the undo buffers.
 */
void
RegisterUndoLogBuffers(uint8 first_block_id)
{
	int			idx;
	int			flags;

	for (idx = 0; idx < buffer_idx; idx++)
	{
		flags = undo_buffer[idx].zero ? REGBUF_WILL_INIT : 0;
		XLogRegisterBuffer(first_block_id + idx, undo_buffer[idx].buf, flags);
	}
}

/*
 * UndoLogBuffersSetLSN - Set LSN on undo page.
*/
void
UndoLogBuffersSetLSN(XLogRecPtr recptr)
{
	int			idx;

	for (idx = 0; idx < buffer_idx; idx++)
		PageSetLSN(BufferGetPage(undo_buffer[idx].buf), recptr);
}

/*
 * Reset the global variables related to undo buffers. This is required at the
 * transaction abort and while releasing the undo buffers.
 */
void
ResetUndoBuffers(void)
{
	int			i;

	for (i = 0; i < buffer_idx; i++)
	{
		undo_buffer[i].blk = InvalidBlockNumber;
		undo_buffer[i].buf = InvalidBuffer;
	}

	xact_urec_info.urecptr = InvalidUndoRecPtr;

	/* Reset the prepared index. */
	prepare_idx = 0;
	buffer_idx = 0;
	prepared_urec_ptr = InvalidUndoRecPtr;

	/*
	 * max_prepared_undo limit is changed so free the allocated memory and
	 * reset all the variable back to their default value.
	 */
	if (max_prepared_undo > MAX_PREPARED_UNDO)
	{
		pfree(undo_buffer);
		pfree(prepared_undo);
		undo_buffer = def_buffers;
		prepared_undo = def_prepared;
		max_prepared_undo = MAX_PREPARED_UNDO;
	}
}

/*
 * Unlock and release the undo buffers.  This step must be performed after
 * exiting any critical section where we have perfomed undo actions.
 */
void
UnlockReleaseUndoBuffers(void)
{
	int			i;

	for (i = 0; i < buffer_idx; i++)
		UnlockReleaseBuffer(undo_buffer[i].buf);

	ResetUndoBuffers();
}

/*
 * Called whenever we attach to a new undo log, so that we forget about our
 * translation-unit private state relating to the log we were last attached
 * to.
 */
void
UndoRecordOnUndoLogChange(UndoPersistence persistence)
{
	prev_txid[persistence] = InvalidTransactionId;
}
