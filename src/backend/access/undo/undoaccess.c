/*-------------------------------------------------------------------------
 *
 * undoaccess.c
 *	  entry points for inserting/fetching undo records
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoaccess.c
 *
 *	INTERFACE ROUTINES
 *		BeginUndoRecordInsert	- begin inserting one or multiple undo records
 *		PrepareUndoInsert		- prepare undo record
 *		InsertPreparedUndo		- insert prepared undo records
 *		FinishUndoRecordInsert	- cleanup the insertion
 *		BeginUndoFetch			- begin undo record fetch
 *		UndoFetchRecord			- fetch the actual record
 *		FinishUndoFetch			- cleanup after undo fetch record
 *		UndoRecordRelease		- Release memory for unpacked undo record
 *		UndoBulkFetchRecord		- Fetch undo record in bulk
 *
 * NOTES:
 * Undo record layout:
 *
 * In each undo log undo records are stored in sequential order.  Each undo
 * record consists of a undo record header, some optional headers and optional
 * payload information.  The first undo record of each transaction in each undo
 * log contains a group header that points to the next transaction's first undo
 * record in the same undo log. This allows us to discard the entire
 * transaction's undo log in one-shot.  The callers are not aware of the group
 * header, it is entirely maintained by the undo interface layer for discarding
 * the undo logs in groups.
 *
 * See undorecord.h for detailed information about the undo record header.
 *
 * Multiple logs:
 *
 * It is possible that the undo records for a transaction spans multiple undo
 * logs.  We need some special handling while inserting them to ensure that
 * discard and rollbacks can work sanely.
 *
 * We add a group header for the first record of the transaction for every log
 * and link those group headers by uur_next_group pointer.  Additionally, In the
 * first record of the transaction in new log after the log switch we will
 * include an additional header called log switch header which will keep a
 * pointer to the first undo record of the transaction in the previous log.
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/transam.h"
#include "access/undoaccess.h"
#include "access/undolog.h"
#include "access/undolog_xlog.h"
#include "access/undorecord.h"
#include "access/undorequest.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/xlogutils.h"
#include "catalog/pg_tablespace.h"
#include "commands/tablecmds.h"
#include "miscadmin.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/buf_internals.h"
#include "storage/bufmgr.h"

/*
 * Structure to hold the prepared undo information.  PreparedUndoInsert will
 * fill this information for each prepared undo.  InsertPreparedUndo will use
 * this information to insert all prepared undo records.
 */
struct PreparedUndoSpace
{
	UndoRecPtr	urp;			/* undo record pointer */
	UnpackedUndoRecord *urec;	/* unpacked undo record */
	uint16		size;			/* undo record size */
	int			undo_buffer_idx[MAX_BUFFER_PER_UNDO];	/* undo_buffer array
														 * index */
};

/*
 * Holds the undo buffers informations.  During prepare time (which is called
 * outside the critical section) we pin and lock all the buffer for inserting
 * the undo record and store the information in this structure.  Later, during
 * actual insert we use this information to insert the record into the buffers.
 */
struct PreparedUndoBuffer
{
	UndoLogNumber logno;		/* Undo log number */
	BlockNumber blk;			/* block number */
	Buffer		buf;			/* buffer allocated for the block */
	bool		zero;			/* new block full of zeroes */
};

static UnpackedUndoRecord *UndoGetOneRecord(UnpackedUndoRecord *urec,
											UndoRecPtr urp, RelFileNode rnode,
											UndoLogCategory category,
											Buffer *prevbuf);
static int	UndoGetBufferSlot(UndoRecordInsertContext *context,
							  RelFileNode rnode, BlockNumber blk,
							  ReadBufferMode rbm);

/*
 * Prepare undo record update
 *
 * It's a helper function for UndoRecordPrepareUpdateNext
 *
 * urecptr - Undo record pointer of the record which needs to be updated.
 * undo_offset - Offset of the undo record field which needs to be updated.
 */
static int
PrepareUndoRecordUpdate(UndoRecordInsertContext *context, UndoRecPtr urecptr,
						int size, int undo_offset)
{
	BlockNumber cur_blk;
	RelFileNode rnode;
	int			starting_byte;
	int			bufidx;
	int			index = 0;
	int			remaining_bytes;
	UndoRecordUpdateInfo *urec_update_info;

	/*
	 * Get a free slot to hold the prepared information for updating the undo
	 * record.
	 */
	urec_update_info = &context->urec_update_info[context->nurec_update_info];

	UndoRecPtrAssignRelFileNode(rnode, urecptr);
	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	/* Remaining bytes on the current block. */
	remaining_bytes = BLCKSZ - starting_byte;

	/*
	 * Compute the block number and the offset of the block where we need to
	 * start updating the undo record.
	 */
	if (remaining_bytes <= undo_offset)
	{
		/*
		 * If the given undo record offset is not in this block then go to the
		 * next block.
		 */
		cur_blk++;
		starting_byte = UndoLogBlockHeaderSize;
		starting_byte += (undo_offset - remaining_bytes);
	}
	else
		starting_byte += undo_offset;

	/* Remember the offset where we need to start updating the undo record. */
	urec_update_info->offset = starting_byte;

	Assert(size <= sizeof(UndoRecPtr));

	/*
	 * Loop until we have locked all the buffers which we need to update. At
	 * the max we will lock two buffers as we are just updating 8 bytes.
	 * Blocks are locked in the increasing order so we need not to worry about
	 * the deadlock.  We need to lock all the buffers in the prepare phase and
	 * the actual update will be done in the update phase under the critical
	 * section.
	 */
	while (1)
	{
		/* Read and lock the buffer if not already locked. */
		bufidx = UndoGetBufferSlot(context, rnode, cur_blk, RBM_NORMAL);

		/* Should never lock more than 2 buffers. */
		Assert(index < 2);

		/* Remember the prepared buffer index. */
		urec_update_info->idx_undo_buffers[index++] = bufidx;
		size -= (BLCKSZ - starting_byte);

		/*
		 * If the field we want to update is completely in the current block
		 * then we are done.  Otherwise we need to go to the next block.
		 */
		if (size <= 0)
			break;

		starting_byte = UndoLogBlockHeaderSize;
		cur_blk++;
	}

	/*
	 * Remember the undo record pointer which we are updating and return the
	 * index of the undo update info.  The caller will store the next/progress
	 * field value in it based on which field it wants to update.
	 */
	urec_update_info->next = InvalidUndoRecPtr;
	urec_update_info->progress = 0;
	urec_update_info->urecptr = urecptr;

	context->nurec_update_info++;
	return (context->nurec_update_info - 1);
}

/*
 * Prepare to update an undo record
 *
 * Prepare undo record update info for updating the the uur_next_group field
 * in the undo record.  This function is called during the prepare phase it will
 * pin and Lock all the necessary buffers required for updating the undo record.
 * This function is called for
 * a. Updating the next_group link in the group header.  This will make sure
 * that the multiple transaction's undo record in the same log are linked and
 * that will make it easy to traverse the undo during discard processing
 * transaction by transaction.
 * b. For multi-log transaction update the next_group link in the group header
 * to connect the transaction first undo record across the undo logs.  This is
 * required for collecting all the undo records of the transaction while
 * applying the undo actions of the transaction.
 *
 * urecptr - undo record pointer of the next group which need to be set in the
 *			 undo record pointed by prevurp.
 * prevurp - undo record pointer to be updated.
 */
static void
PrepareUndoRecordUpdateNext(UndoRecordInsertContext *context,
							UndoRecPtr urecptr, UndoRecPtr prevurp)
{
	UndoLogSlot *slot;
	int			index = 0;
	int			offset;

	/*
	 * The absence of previous transaction's undo indicates that this backend
	 * is preparing its first undo so there is nothing to be updated.
	 */
	if (!UndoRecPtrIsValid(prevurp))
		return;

	slot = UndoLogGetSlot(UndoRecPtrGetLogNo(prevurp), false);

	/*
	 * Acquire the discard update lock before reading the undo record so that
	 * the undo record doesn't get discarded while we are reading undo
	 * buffers.
	 */
	LWLockAcquire(&slot->discard_update_lock, LW_SHARED);

	/* Check if it is already discarded. */
	if (UndoRecPtrIsDiscarded(prevurp))
	{
		/* Release lock and return. */
		LWLockRelease(&slot->discard_update_lock);
		return;
	}

	/* Compute the offset of the uur_next_group in the undo record. */
	offset = SizeOfUndoRecordHeader +
		offsetof(UndoRecordGroup, urec_next_group);

	index = PrepareUndoRecordUpdate(context, prevurp, sizeof(UndoRecPtr),
									offset);

	/* Store the next group's undo record pointer in urec_update_info. */
	context->urec_update_info[index].next = urecptr;

	/*
	 * We can now release the discard lock as we have already acquired the
	 * buffer locks.
	 */
	LWLockRelease(&slot->discard_update_lock);
}

/*
 * Update the undo record
 *
 * This will overwrite uur_next_group or uur_progress fields in the undo record.
 * Exact offset to be updated is already computed and necessary buffers are
 * locked during the prepare phase.
 */
static void
UndoRecordUpdate(UndoRecordInsertContext *context, int idx)
{
	Page		page = NULL;
	int			i = 0;
	int			write_bytes;
	int			write_offset;
	char	   *sourceptr;
	UndoRecordUpdateInfo *urec_update_info = &context->urec_update_info[idx];

	/* Whether to update the next or progress. */
	if (UndoRecPtrIsValid(urec_update_info->next))
	{
		sourceptr = (char *) &urec_update_info->next;
		write_bytes = sizeof(urec_update_info->next);
	}
	else
	{
		sourceptr = (char *) &urec_update_info->progress;
		write_bytes = sizeof(urec_update_info->progress);
	}

	/* Where to start writing in the current block. */
	write_offset = urec_update_info->offset;

	/*
	 * Start writing directly from the write offset calculated during prepare
	 * phase.  And, loop until we write required bytes.
	 */
	while (1)
	{
		Buffer		buffer;
		int			buf_idx;
		int			can_write;
		char	   *writeptr;

		/* Should never write in more than 2 buffers. */
		Assert(i < 2);

		buf_idx = urec_update_info->idx_undo_buffers[i];
		buffer = context->prepared_undo_buffers[buf_idx].buf;

		/* How may bytes can be written in the current page. */
		can_write = Min((BLCKSZ - write_offset), write_bytes);

		/* If buffer is valid then write it otherwise just skip writing it. */
		if (BufferIsValid(buffer))
		{
			page = BufferGetPage(buffer);

			/* Compute the write pointer; write the buffer and mark it dirty. */
			writeptr = (char *) page + write_offset;
			memcpy(writeptr, sourceptr, can_write);
			MarkBufferDirty(buffer);
		}
		else
			Assert(InRecovery);

		write_bytes -= can_write;

		/*
		 * If we have no more data to be written the break it otherwise go to
		 * next block and continue writing there.
		 */
		if (write_bytes <= 0)
			break;

		sourceptr += can_write;
		write_offset = UndoLogBlockHeaderSize;
		i++;
	}
}

/*
 * Find or add the block info in the insert context's prepared buffer array.
 *
 * If the block is it is present in the prepared buffer array then just return
 * its index otherwise read and lock the buffer and add an entry.
 *
 * Undo log insertions are append-only.  If the caller is writing new data that
 * begins exactly at the beginning of a page, then there cannot be any useful
 * data after that point.  In that case RBM_ZERO can be passed in as rbm so that
 * we can skip a useless read of a disk block.  In all other cases, RBM_NORMAL
 * should be passed in, to read the page in if it doesn't happen to be already
 * in the buffer pool.
 */
static int
UndoGetBufferSlot(UndoRecordInsertContext *context,
				  RelFileNode rnode,
				  BlockNumber blk,
				  ReadBufferMode rbm)
{
	int			blkIndex;
	Buffer		buffer;
	XLogRedoAction action = BLK_NEEDS_REDO;
	PreparedUndoBuffer *prepared_buffer;
	UndoLogCategory category = context->alloc_context.category;

	/*
	 * Search the block in the prepared undo buffer array in our insert
	 * context if we find it then simply return the index.
	 */
	for (blkIndex = 0; blkIndex < context->nprepared_undo_buffer; blkIndex++)
	{
		prepared_buffer = &context->prepared_undo_buffers[blkIndex];

		/*
		 * It's not enough to just compare the block number because this might
		 * hold the blocks from different undo logs so compare the logno and
		 * the blkno.
		 */
		if ((blk == prepared_buffer->blk) &&
			(prepared_buffer->logno == rnode.relNode))
		{
			/* caller must hold exclusive lock on buffer */
			Assert(BufferIsLocal(prepared_buffer->buf) ||
				   LWLockHeldByMeInMode(BufferDescriptorGetContentLock(
																	   GetBufferDescriptor(prepared_buffer->buf - 1)),
										LW_EXCLUSIVE));
			return blkIndex;
		}
	}

	/*
	 * We did not find the block the prepared buffer array so read the buffer
	 * and add its entry.
	 */
	if (InRecovery)
	{
		/*
		 * If block is found then this API will return the locked buffer so we
		 * need not to lock it outside.
		 */
		action = XLogReadBufferForRedoBlock(context->alloc_context.xlog_record,
											rnode,
											UndoLogForkNum,
											blk,
											rbm,
											false,
											&buffer);
	}
	else
	{
		buffer = ReadBufferWithoutRelcache(rnode,
										   UndoLogForkNum,
										   blk,
										   rbm,
										   NULL,
										   RelPersistenceForUndoLogCategory(category));

		/* Lock the buffer */
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	}

	/*
	 * Get the next empty slot in the prepared buffer array to store the
	 * information of the new buffer we have locked.
	 */
	prepared_buffer =
		&context->prepared_undo_buffers[context->nprepared_undo_buffer];

	/*
	 * During the recovery it's possible that the block is completely
	 * discarded so just store it as InvalidBuffer in the prepared buffer
	 * entry so that during actual insert we can skip inserting into these
	 * blocks.
	 */
	if (action == BLK_NOTFOUND)
	{
		Assert(InRecovery);

		prepared_buffer->buf = InvalidBuffer;
		prepared_buffer->blk = blk;
	}
	else
	{
		/*
		 * Remember the block and buffer information so that during multi
		 * prepare we don't try to lock the same buffer again.
		 */
		prepared_buffer->buf = buffer;
		prepared_buffer->blk = blk;
		prepared_buffer->logno = rnode.relNode;
		prepared_buffer->zero = rbm == RBM_ZERO;
	}

	context->nprepared_undo_buffer++;

	return blkIndex;
}

/*
 * Compress the undo record.
 *
 * Read the compression information from the first complete record of the page
 * and try to compress the input undo record based on the compression
 * information.
 */
static bool
CompressUndoRecord(UndoRecordInsertContext *context, UndoRecPtr urecptr,
				   UnpackedUndoRecord *urec, RelFileNode rnode)
{
	UndoPageHeader phdr;
	Buffer		buffer;
	Page		page;
	int			bufidx;
	int			offset;
	UndoCompressionInfo compression_info;

	/*
	 * Read the buffer and compute the compression info.  We anyway need to
	 * lock this buffer for inserting the undo record so locking here will not
	 * cost us anything.  UndoGetBufferSlot will remember the reference to
	 * this so that we will not try to read the buffer again.
	 */
	bufidx = UndoGetBufferSlot(context, rnode, UndoRecPtrGetBlockNum(urecptr),
							   RBM_NORMAL);
	buffer = context->prepared_undo_buffers[bufidx].buf;
	page = BufferGetPage(buffer);
	phdr = (UndoPageHeader) page;

	/* Compute the offset of the next complete record on the page. */
	offset = SizeOfUndoPageHeaderData + phdr->undo_len - phdr->record_offset;

	/*
	 * If we are inserting the first record after the partial record then
	 * there is no complete record on the page based on which we can compress
	 * our record.
	 */
	if (UndoRecPtrGetPageOffset(urecptr) == offset)
		return false;

	/* Read compression information from the record. */
	UndoRecordGetCompressionInfo(page, offset, &compression_info);

	/*
	 * If the first record is not for the same transaction id for which we are
	 * inserting the record then we can not compress this record.
	 */
	if (!FullTransactionIdEquals(urec->uur_fxid, compression_info.fxid))
		return false;

	/*
	 * Exclude the information from the record which are same as the first
	 * complete record of the page.
	 */
	urec->uur_info &= ~UREC_INFO_FXID;

	if (urec->uur_rmid == compression_info.rmid)
		urec->uur_info &= ~UREC_INFO_RMID;

	if (urec->uur_reloid == compression_info.reloid)
		urec->uur_info &= ~UREC_INFO_RELOID;

	if (urec->uur_cid == compression_info.cid)
		urec->uur_info &= ~UREC_INFO_CID;

	return true;
}

/*
 * Begin inserting undo records.
 *
 * This function must be called before all the undo records which are going to
 * get inserted under a single WAL record.
 * context - Undo insert context,  this will holds the memory and buffer
 * information for preparing and inserting the undo records.  Caller must hold
 * this memory until it insert undo record.
 * category - Undo log category
 * nprepared - max number of undo records that can be prepared before insert.
 * xlog_record - In recovery for inserting the undo record the caller must pass
 * its xlog reader state so that we can identify from which undo logno we need
 * to allocate the space for the WAL.  To achieve this during DO time the caller
 * must register all the undo buffer it has updated by calling
 * RegisterUndoBuffers.
 */
void
BeginUndoRecordInsert(UndoRecordInsertContext *context,
					  UndoLogCategory category,
					  int nprepared,
					  XLogReaderState *xlog_record)
{
	uint32		nbuffers;

	/* At least one prepared record should be there. */
	if (nprepared <= 0)
		elog(ERROR, "at least one undo record should be prepared");

	/* Initialize undo log context. */
	UndoLogBeginInsert(&context->alloc_context, category, xlog_record);

	/* Initialize undo insert context. */
	context->max_prepared_undo = nprepared;
	context->nprepared_undo = 0;
	context->nprepared_undo_buffer = 0;
	context->nurec_update_info = 0;

	/* Allocate memory for prepared undo record space. */
	context->prepared_undo = (PreparedUndoSpace *) palloc(nprepared *
														  sizeof(PreparedUndoSpace));

	/* Compute number of buffers. */
	nbuffers = (nprepared + MAX_UNDO_UPDATE_INFO) * MAX_BUFFER_PER_UNDO;

	/* Allocate memory for the prepared buffers. */
	context->prepared_undo_buffers =
		palloc(nbuffers * sizeof(PreparedUndoBuffer));
}

/*
 * Prepare to insert an undo record.
 *
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned and
 * locked.
 *
 * This should be called outside the  critical section.
 */
UndoRecPtr
PrepareUndoInsert(UndoRecordInsertContext *context,
				  UnpackedUndoRecord *urec,
				  Oid dbid)
{
	UndoRecordSize size;
	UndoRecPtr	urecptr = InvalidUndoRecPtr;
	RelFileNode rnode;
	UndoRecordSize cur_size = 0;
	BlockNumber cur_blk;
	FullTransactionId fxid;
	int			starting_byte;
	int			index = 0;
	int			bufidx;
	bool		resize = false;
	ReadBufferMode rbm;
	bool		need_xact_header;
	UndoRecPtr	last_xact_start;
	UndoRecPtr	prevlog_xact_start = InvalidUndoRecPtr;
	PreparedUndoSpace *prepared_undo;

	/* Already reached maximum prepared limit. */
	if (context->nprepared_undo == context->max_prepared_undo)
		elog(ERROR, "already reached the maximum prepared limit");

	/* Extract the full transaction id from the input undo record. */
	fxid = urec->uur_fxid;
	Assert(FullTransactionIdIsValid(fxid));

	/*
	 * We don't yet know if this record needs a transaction header (ie is the
	 * first undo record for a given transaction in a given undo log), because
	 * you can only find out by allocating.  We'll resolve this circularity by
	 * allocating enough space for a transaction header.  Similarly log switch
	 * will only be detected after allocation so include the log switch header
	 * and common information because in case of log switch we need to include
	 * log switch header and also we need to include common header.  After
	 * allocation, we'll only advance by as many bytes as we turn out to need.
	 */
	UndoRecordSetInfo(urec);
	urec->uur_info |= UREC_INFO_GROUP;
	urec->uur_info |= UREC_INFO_LOGSWITCH;
	urec->uur_info |= UREC_INFO_PAGE_COMMON;

	size = UndoRecordExpectedSize(urec);

	/* Allocate space for the undo record. */
	if (InRecovery)
	{
		/*
		 * We'll figure out where the space needs to be allocated by
		 * inspecting the xlog_record.  We don't expect to see temporary or
		 * unlogged undo data here.
		 */
		Assert(context->alloc_context.category != UNDO_TEMP &&
			   context->alloc_context.category != UNDO_UNLOGGED);
		urecptr = UndoLogAllocateInRecovery(&context->alloc_context,
											XidFromFullTransactionId(fxid),
											size,
											&need_xact_header,
											&last_xact_start,
											&prevlog_xact_start);
	}
	else
		urecptr = UndoLogAllocate(&context->alloc_context,
								  size,
								  &need_xact_header, &last_xact_start,
								  &prevlog_xact_start);

	/*
	 * If we need a group header then allocate memory for it and initialize
	 * the same.
	 */
	if (need_xact_header)
	{
		urec->uur_group = palloc(sizeof(UndoRecordGroup));
		urec->uur_group->urec_dbid = dbid;
		urec->uur_group->urec_progress = XACT_APPLY_PROGRESS_NOT_STARTED;
		urec->uur_group->urec_next_group = InvalidUndoRecPtr;
	}
	else
	{
		/* We don't need a group header after all. */
		urec->uur_info &= ~UREC_INFO_GROUP;
		resize = true;
		urec->uur_group = NULL;
	}

	/*
	 * If undo log got switched then allocate the memory for the log switch
	 * header and initialize the same.
	 */
	if (UndoRecPtrIsValid(prevlog_xact_start))
	{
		urec->uur_logswitch = palloc(sizeof(UndoRecordLogSwitch));
		urec->uur_logswitch->urec_prevlogstart = prevlog_xact_start;
	}
	else
	{
		/* We don't need a log switch header after all. */
		urec->uur_info &= ~UREC_INFO_LOGSWITCH;
		resize = true;
		urec->uur_logswitch = NULL;
	}

	/* Populate the rnode for the undo record pointer. */
	UndoRecPtrAssignRelFileNode(rnode, urecptr);

	/*
	 * If this is not the first record of the transaction for this log and we
	 * are not inserting the first record on the page then we can compress
	 * this record by avoid including the field which are same as the first
	 * complete record on the page provided that is from the same transaction.
	 */
	if (!need_xact_header && !prevlog_xact_start &&
		UndoRecPtrGetPageOffset(urecptr) != SizeOfUndoPageHeaderData &&
		CompressUndoRecord(context, urecptr, urec, rnode))
		resize = true;

	/*
	 * We might have excluded some of the header from the undo record so
	 * recompute the expected record size.
	 */
	if (resize)
		size = UndoRecordExpectedSize(urec);

	/*
	 * If the transaction's undo records are split across the undo logs then
	 * link the transaction's group header in the previous log to the
	 * transaction group header in the current log by updating the
	 * uur_next_group field in the group header.
	 */
	if (UndoRecPtrIsValid(prevlog_xact_start))
		PrepareUndoRecordUpdateNext(context, urecptr, prevlog_xact_start);

	/*
	 * If there is a physically preceding transaction in this undo log, and we
	 * are writing the first record for this transaction that is in this undo
	 * log (not necessarily the first ever for the transaction, because we
	 * could have switched logs), then we need to set this transaction's group
	 * header pointer in the previous transaction's group header.
	 */
	if (need_xact_header)
		PrepareUndoRecordUpdateNext(context, urecptr, last_xact_start);

	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	/*
	 * If we happen to be writing the very first byte into this page, then
	 * there is no need to read from disk.
	 */
	if (starting_byte == UndoLogBlockHeaderSize)
		rbm = RBM_ZERO;
	else
		rbm = RBM_NORMAL;

	/* Get a free slot in the prepare undo space for preparing our undo. */
	prepared_undo = &context->prepared_undo[context->nprepared_undo];

	/* Loop to lock the required buffers for inserting this undo record. */
	do
	{
		bufidx = UndoGetBufferSlot(context, rnode, cur_blk, rbm);
		if (cur_size == 0)
			cur_size = BLCKSZ - starting_byte;
		else
			cur_size += BLCKSZ - UndoLogBlockHeaderSize;

		/* undo record can't use buffers more than MAX_BUFFER_PER_UNDO. */
		Assert(index < MAX_BUFFER_PER_UNDO);

		/* Keep the track of the buffers we have pinned and locked. */
		prepared_undo->undo_buffer_idx[index++] = bufidx;

		/*
		 * If we need more pages they'll be all new so we can definitely skip
		 * reading from disk.
		 */
		rbm = RBM_ZERO;
		cur_blk++;
	} while (cur_size < size);

	/*
	 * Advance the local insert pointer in the context past this record so
	 * that during multi-prepare we get the correct insert location for the
	 * next record.
	 */
	UndoLogAdvance(&context->alloc_context, size);

	/*
	 * Save prepared undo record information into the context which will be
	 * used by InsertPreparedUndo to insert the undo record.
	 */
	prepared_undo->urec = urec;
	prepared_undo->urp = urecptr;
	prepared_undo->size = size;
	context->nprepared_undo++;

	return urecptr;
}

/*
 * Insert one undo record
 *
 * Helper function for InsertPreparedUndo.
 */
static void
InsertUndoRecord(UndoRecordInsertContext *context,
				 PreparedUndoSpace * prepared_undo)
{
	Buffer		buffer;
	Page		page = NULL;
	int			starting_byte;
	int			bufidx = 0;
	UndoPackContext ucontext = {{0}};
	PreparedUndoBuffer *prepared_buffres = context->prepared_undo_buffers;
	UnpackedUndoRecord *urec = prepared_undo->urec;

	/* Compute starting offset of the page where to start inserting. */
	starting_byte = UndoRecPtrGetPageOffset(prepared_undo->urp);

	/* Initiate inserting the undo record. */
	BeginInsertUndo(&ucontext, urec, prepared_undo->size);

	/* Main loop for writing the undo record. */
	while (1)
	{
		/* undo record can't use buffers more than MAX_BUFFER_PER_UNDO. */
		Assert(bufidx < MAX_BUFFER_PER_UNDO);
		buffer = prepared_buffres[prepared_undo->undo_buffer_idx[bufidx]].buf;

		/*
		 * During recovery, there might be some blocks which are already
		 * deleted due to some discard command so we can just skip inserting
		 * into those blocks.
		 */
		if (!BufferIsValid(buffer))
		{
			Assert(InRecovery);

			/*
			 * Instead of inserting the actual record this function will just
			 * update the bookkeeping information in the context.
			 */
			SkipInsertingUndoData(&ucontext, BLCKSZ - starting_byte);
		}
		else
		{
			page = BufferGetPage(buffer);

			/*
			 * Initialize the page whenever we try to write the first record
			 * in page.  We start writing immediately after the block header.
			 */
			if (starting_byte == UndoLogBlockHeaderSize)
				UndoPageInit(page, BLCKSZ, urec->uur_info,
							 ucontext.already_processed, prepared_undo->size);

			/*
			 * Write undo record data into the page and mark the buffer dirty.
			 */
			InsertUndoData(&ucontext, page, starting_byte);
			MarkBufferDirty(buffer);
		}

		/* Record insertion is complete. */
		if (ucontext.stage == UNDO_PACK_STAGE_DONE)
			break;

		/*
		 * Record couldn't fit in the current block so insert the remaining
		 * record in the next block.  In next block start inserting right
		 * after the block header.
		 */
		starting_byte = UndoLogBlockHeaderSize;
		bufidx++;
	}
}

/*
 * Insert previously-prepared undo records.
 *
 * This function will write the actual undo record into the buffers which are
 * already pinned and locked in PreparedUndoInsert, and mark them dirty.  This
 * step should be performed inside a critical section.
 */
void
InsertPreparedUndo(UndoRecordInsertContext *context)
{
	PreparedUndoSpace *prepared_undo;
	int			idx;
	int			i;

	/* There must be at least one prepared undo record. */
	Assert(context->nprepared_undo > 0);

	/*
	 * This must be called under a critical section or we must be in recovery.
	 */
	Assert(InRecovery || CritSectionCount > 0);

	for (idx = 0; idx < context->nprepared_undo; idx++)
	{
		prepared_undo = &context->prepared_undo[idx];

		Assert(prepared_undo->size ==
			   UndoRecordExpectedSize(prepared_undo->urec));

		/* Insert the undo record. */
		InsertUndoRecord(context, prepared_undo);

		/* Advance the insert pointer past this record. */
		UndoLogAdvanceFinal(prepared_undo->urp, prepared_undo->size);
	}

	/* Update the group header of the previous transaction. */
	for (i = 0; i < context->nurec_update_info; i++)
		UndoRecordUpdate(context, i);
}

/*
 * Release all the memory and buffer pins hold for inserting the undo records.
 */
void
FinishUndoRecordInsert(UndoRecordInsertContext *context)
{
	int			i;

	/* Release buffer pins and locks. */
	for (i = 0; i < context->nprepared_undo_buffer; i++)
		if (BufferIsValid(context->prepared_undo_buffers[i].buf))
			UnlockReleaseBuffer(context->prepared_undo_buffers[i].buf);

	/*
	 * Release memory for the transaction header and log switch header if we
	 * have allocated it during the prepare time.
	 */
	for (i = 0; i < context->nprepared_undo; i++)
	{
		if (context->prepared_undo[i].urec->uur_group)
			pfree(context->prepared_undo[i].urec->uur_group);

		if (context->prepared_undo[i].urec->uur_logswitch)
			pfree(context->prepared_undo[i].urec->uur_logswitch);
	}

	/*
	 * Free the memory allocated for the prepared undo space and the prepared
	 * undo buffers.
	 */
	pfree(context->prepared_undo_buffers);
	pfree(context->prepared_undo);
}

/*
 * Get undo page compression information.
 *
 * Read undo record compression information from the first complete record of
 * the page and store them in the current unpack context.
 */
static void
UndoPageGetCompressionInfo(UndoPackContext *ucontext, UndoRecPtr urp, Page page)
{
	int			offset;
	UndoPageHeader phdr = (UndoPageHeader) page;
	UndoCompressionInfo compresssion_info;

	/* Compute the offset of the next complete record on the page. */
	offset = SizeOfUndoPageHeaderData + phdr->undo_len - phdr->record_offset;

	/* Fetch the undo page compression informations. */
	UndoRecordGetCompressionInfo(page, offset, &compresssion_info);

	/*
	 * Get all missing common header information from the first undo record of
	 * the page.
	 */
	if ((ucontext->urec_hd.urec_info & UREC_INFO_RMID) == 0)
		ucontext->urec_rmid = compresssion_info.rmid;

	if ((ucontext->urec_hd.urec_info & UREC_INFO_RELOID) == 0)
		ucontext->urec_reloid = compresssion_info.reloid;

	if ((ucontext->urec_hd.urec_info & UREC_INFO_FXID) == 0)
		ucontext->urec_fxid = compresssion_info.fxid;

	if ((ucontext->urec_hd.urec_info & UREC_INFO_CID) == 0)
		ucontext->urec_cid = compresssion_info.cid;

	ucontext->urec_hd.urec_info |= UREC_INFO_PAGE_COMMON;
}

/*
 * Helper function for UndoFetchRecord and UndoBulkFetchRecord
 *
 * curbuf - If an input buffer is valid then this function will not release the
 * pin on that buffer.  If the buffer is not valid then it will assign curbuf
 * with the first buffer of the current undo record and also it will keep the
 * pin on that buffer in a hope that while traversing the undo chain the caller
 * might want to read the previous undo record from the same block.
 */
static UnpackedUndoRecord *
UndoGetOneRecord(UnpackedUndoRecord *urec, UndoRecPtr urp, RelFileNode rnode,
				 UndoLogCategory category, Buffer *curbuf)
{
	Page		page;
	int			starting_byte = UndoRecPtrGetPageOffset(urp);
	BlockNumber cur_blk;
	UndoPackContext ucontext = {{0}};
	Buffer		buffer = *curbuf;

	cur_blk = UndoRecPtrGetBlockNum(urp);

	/* Initiate unpacking one undo record. */
	BeginUnpackUndo(&ucontext);

	while (true)
	{
		/* If we already have a buffer then no need to allocate a new one. */
		if (!BufferIsValid(buffer))
		{
			buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
											   RBM_NORMAL, NULL,
											   RelPersistenceForUndoLogCategory(category));

			/*
			 * Remember the first buffer where this undo started as next undo
			 * record what we fetch might fall on the same buffer.
			 */
			if (!BufferIsValid(*curbuf))
				*curbuf = buffer;
		}

		/* Acquire shared lock on the buffer before reading undo from it. */
		LockBuffer(buffer, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buffer);

		UnpackUndoData(&ucontext, page, starting_byte);

		/*
		 * We are done if we have reached to the done stage otherwise move to
		 * next block and continue reading from there.
		 */
		if (ucontext.stage == UNDO_PACK_STAGE_DONE)
		{
			/*
			 * If the buffer is input buffer or the first buffer of the record
			 * then just release the lock and keep the pin.  Otherwise, unlock
			 * the buffer and also release the pin.
			 */
			if (buffer == *curbuf)
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			else
				UnlockReleaseBuffer(buffer);

			/*
			 * If any of the common header field is not available in the
			 * current undo record then we must read it from the first
			 * complete record of the page.  If any of these common field is
			 * missing from the undo record then it's guarantee that the first
			 * complete record on the page must be from the same transaction
			 * otherwise we will always include all these common fields in the
			 * undo record.
			 */
			if ((ucontext.urec_hd.urec_info & UREC_INFO_PAGE_COMMON) !=
				UREC_INFO_PAGE_COMMON)
				UndoPageGetCompressionInfo(&ucontext, urp,
										   BufferGetPage(*curbuf));

			break;
		}

		/*
		 * If the buffer is input buffer or the first buffer of the record
		 * then just release the lock and keep the pin.  Otherwise, unlock the
		 * buffer and also release the pin.
		 */
		if (buffer == *curbuf)
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		else
			UnlockReleaseBuffer(buffer);

		buffer = InvalidBuffer;

		/* Go to next block. */
		cur_blk++;
		starting_byte = UndoLogBlockHeaderSize;
	}

	/* Final step of unpacking. */
	FinishUnpackUndo(&ucontext, urec);

	return urec;
}

/*
 * BeginUndoFetch to fetch undo record.
 */
void
BeginUndoFetch(UndoRecordFetchContext *context)
{
	context->buffer = InvalidBuffer;
	context->urp = InvalidUndoRecPtr;
}

/*
 * Fetch the undo record for given undo record pointer.
 *
 * This will internally allocate the memory for the unpacked undo record which
 * will hold the pointers to the optional headers and the variable data.
 * The undo record should be freed by the caller by calling ReleaseUndoRecord.
 * This function will hold the pin on the buffer where we read the previous undo
 * record so that when this function is called repeatedly with the same context
 * then it can be benefitted by avoid reading the buffer again if the current
 * undo record is in the same buffer.
 */
UnpackedUndoRecord *
UndoFetchRecord(UndoRecordFetchContext *context, UndoRecPtr urp)
{
	RelFileNode rnode;
	int			logno;
	UndoLogSlot *slot;
	UnpackedUndoRecord *uur = NULL;

	logno = UndoRecPtrGetLogNo(urp);
	slot = UndoLogGetSlot(logno, true);

	/*
	 * If slot is NULL that means undo log number is unknown.  Presumably it
	 * has been entirely discarded.
	 */
	if (slot == NULL)
		return NULL;

	/*
	 * Prevent UndoDiscardOneLog() from discarding data while we try to read
	 * it.  Usually we would acquire log->mutex to read log->meta members, but
	 * in this case we know that discard can't move without also holding
	 * log->discard_lock.
	 *
	 * In Hot Standby mode log->oldest_data is never initialized because it's
	 * get updated by undo discard worker whereas in HotStandby undo logs are
	 * getting discarded using discard WAL.  So in HotStandby we can directly
	 * check whether the undo record pointer is discarded or not.  But, we can
	 * not do same for normal case because discard worker can concurrently
	 * discard the undo logs.
	 *
	 * XXX We can avoid this check by always initializing log->oldest_data in
	 * HotStandby mode as well whenever we apply discard WAL.  But, for doing
	 * that we need to acquire discard lock just for setting this variable?
	 */
	if (InHotStandby)
	{
		if (UndoRecPtrIsDiscarded(urp))
			return NULL;
	}
	else
	{
		LWLockAcquire(&slot->discard_lock, LW_SHARED);
		if (slot->logno != logno || urp < slot->oldest_data)
		{
			/*
			 * The slot has been recycled because the undo log was entirely
			 * discarded, or the pointer is before the oldest data.
			 */
			LWLockRelease(&slot->discard_lock);
			return NULL;
		}
	}

	/*
	 * Allocate memory for holding the undo record, caller should be
	 * responsible for freeing this memory by calling UndoRecordRelease.
	 */
	uur = palloc0(sizeof(UnpackedUndoRecord));
	UndoRecPtrAssignRelFileNode(rnode, urp);

	/*
	 * Before fetching the next record check whether we have a valid buffer in
	 * the context.  If so and if we are reading the current record from the
	 * same then pass that buffer to fetch the undo record, otherwise release
	 * the buffer.
	 */
	if (BufferIsValid(context->buffer) &&
		(UndoRecPtrGetLogNo(context->urp) != UndoRecPtrGetLogNo(urp) ||
		 UndoRecPtrGetBlockNum(context->urp) != UndoRecPtrGetBlockNum(urp)))
	{
		ReleaseBuffer(context->buffer);
		context->buffer = InvalidBuffer;
	}

	/* Fetch the current undo record. */
	UndoGetOneRecord(uur, urp, rnode, slot->meta.category, &context->buffer);

	/* Release the discard lock after fetching the record. */
	if (!InHotStandby)
		LWLockRelease(&slot->discard_lock);

	context->urp = urp;

	return uur;
}

/*
 * Finish undo record fetch.
 */
void
FinishUndoFetch(UndoRecordFetchContext *context)
{
	if (BufferIsValid(context->buffer))
		ReleaseBuffer(context->buffer);
}

/*
 * Release the memory of the undo record.
 *
 * Release memory of the undo record and other variable data of the undo record
 * allocated by UndoFetchRecord and UndoBulkFetchRecord.
 */
void
UndoRecordRelease(UnpackedUndoRecord *urec)
{
	if (urec->uur_payload.data)
		pfree(urec->uur_payload.data);

	if (urec->uur_tuple.data)
		pfree(urec->uur_tuple.data);

	if (urec->uur_group)
		pfree(urec->uur_group);

	if (urec->uur_logswitch)
		pfree(urec->uur_logswitch);

	/* Release the memory of the undo record. */
	pfree(urec);
}

/*
 * Prefetch undo pages, if the prefetch_pages are behind the prefetch_target
 */
static void
PrefetchUndoPages(RelFileNode rnode, int prefetch_target, int *prefetch_pages,
				  BlockNumber to_blkno, BlockNumber from_blkno,
				  UndoLogCategory category)
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
									  category == UNDO_TEMP);
		(*prefetch_pages)++;
	}
}

/*
 * Read undo records of the transaction in bulk
 *
 * Read undo records between from_urecptr and to_urecptr until we exhaust the
 * the memory size specified by max_result_size.  This will start reading undo
 * records starting from from_urecptr.  It will read the transaction's undo
 * record backwardly all the way upto to_urecptr.
 *
 * If we could not read all the records till to_urecptr then the caller should
 * consume current set of records and call this function again.
 *
 * While traversing the undo record if the log switch is encountered then this
 * API will stop processing further record and set the last record in the
 * previous log as the from_urecptr so that the caller can call this API again
 * to fetch the remaining records.
 *
 * XXX instead of this API handles this we can make caller to pass from and to
 * urecptr from the same undo log?
 *
 * from_urecptr		- Where to start fetching the undo records.  If we can not
 *					  read all the records because of memory limit then this
 *					  will be set to the next from undo record pointer from
 *					  where we need to start fetching on next call. Otherwise it
 *					  will be set to InvalidUndoRecPtr.
 * to_urecptr		- Last undo record pointer to be fetched.
 * max_result_size	- Memory segment limit to collect undo records.
 * nrecords			- Number of undo records read.
 */
UndoRecInfo *
UndoBulkFetchRecord(UndoRecPtr *from_urecptr, UndoRecPtr to_urecptr,
					int max_result_size, int *nrecords)
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

	/*
	 * If we are fetching undo records from more than one logs, We can not
	 * compute how many block to prefetch from the current log because we
	 * don't know that in how many blocks of the log this transaction has
	 * inserted the undo.  Hence, we can't use prefetching in this case.
	 *
	 * XXX should we always restrict caller to input from and to urecptr from
	 * the same undo log.  But, it may not be possible for the caller to
	 * always detect that?
	 */
	if (UndoRecPtrGetLogNo(*from_urecptr) == UndoRecPtrGetLogNo(to_urecptr))
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
	while (1)
	{
		BlockNumber from_blkno;
		UndoLogSlot *slot;
		UndoLogCategory category;
		int			logno;

		logno = UndoRecPtrGetLogNo(urecptr);
		slot = UndoLogGetSlot(logno, true);
		if (slot == NULL)
		{
			if (BufferIsValid(buffer))
				ReleaseBuffer(buffer);
			return NULL;
		}
		category = slot->meta.category;

		UndoRecPtrAssignRelFileNode(rnode, urecptr);
		to_blkno = UndoRecPtrGetBlockNum(to_urecptr);
		from_blkno = UndoRecPtrGetBlockNum(urecptr);

		/* Allocate memory for next undo record. */
		uur = palloc0(sizeof(UnpackedUndoRecord));

		/*
		 * If next undo record pointer to be fetched is not on the same block
		 * then release the old buffer and reduce the prefetch_pages count by
		 * one as we have consumed one page. Otherwise, just pass the old
		 * buffer into the UndoGetOneRecord so that it doesn't read the buffer
		 * again.
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

		/*
		 * If prefetch_pages are behind prefetch_target then it's time to
		 * prefetch again.
		 */
		if (prefetch_pages < prefetch_target)
			PrefetchUndoPages(rnode, prefetch_target, &prefetch_pages, to_blkno,
							  from_blkno, category);

		/* Get the undo record. */
		UndoGetOneRecord(uur, urecptr, rnode, category, &buffer);

		/* Remember the previous undo record pointer. */
		prev_urec_ptr = urecptr;

		/*
		 * Calculate the previous undo record pointer of the transaction.  If
		 * we have detected the log switch then compute the latest undo record
		 * of the transaction in the previous log and set this as next
		 * from_urecptr.  On log_switch don't process further record and
		 * return handle to the caller with appropriate from_urecptr so that
		 * caller can resume the fetching.
		 */
		if (uur->uur_logswitch)
		{
			urecptr = UndoGetPrevUrp(uur, prev_urec_ptr, buffer, category);
			*from_urecptr = urecptr;
		}
		else if (prev_urec_ptr == to_urecptr)
			urecptr = InvalidUndoRecPtr;
		else
			urecptr = UndoGetPrevUrp(uur, prev_urec_ptr, buffer, category);

		/*
		 * We have consumed all the elements of the urp_array so expand its
		 * size.
		 */
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

		/* Add the size required to store unpacked undo record in memory. */
		total_size += sizeof(UnpackedUndoRecord) + UndoRecordPayloadSize(uur);

		/*
		 * Including current record, if we have crossed the memory limit or
		 * undo log got switched then stop processing more records.  Remember
		 * to set the from_urecptr so that on next call we can resume fetching
		 * undo records where we left it.
		 *
		 * XXX we need this special handling for the log switch because in
		 * some cases caller is enable to identify the log boundary but it
		 * expect us to read the undo record only for one log at a time.
		 */
		if (total_size >= max_result_size || uur->uur_logswitch)
		{
			*from_urecptr = urecptr;
			break;
		}
	}

	/* Release the last buffer. */
	if (BufferIsValid(buffer))
		ReleaseBuffer(buffer);

	*nrecords = urp_index;

	return urp_array;
}

/*
 * Register the undo buffers.
 */
void
RegisterUndoLogBuffers(UndoRecordInsertContext *context, uint8 first_block_id)
{
	int			idx;
	int			flags;

	for (idx = 0; idx < context->nprepared_undo_buffer; idx++)
	{
		flags = context->prepared_undo_buffers[idx].zero
			? REGBUF_KEEP_DATA_AFTER_CP | REGBUF_WILL_INIT
			: REGBUF_KEEP_DATA_AFTER_CP;
		XLogRegisterBuffer(first_block_id + idx,
						   context->prepared_undo_buffers[idx].buf, flags);
		UndoLogRegister(&context->alloc_context, first_block_id + idx,
						context->prepared_undo_buffers[idx].logno);
	}
}

/*
 * Set LSN on undo page.
*/
void
UndoLogBuffersSetLSN(UndoRecordInsertContext *context, XLogRecPtr recptr)
{
	int			idx;

	for (idx = 0; idx < context->nprepared_undo_buffer; idx++)
		PageSetLSN(BufferGetPage(context->prepared_undo_buffers[idx].buf),
				   recptr);
}

/*
 * Read length of the previous undo record.
 *
 * This function will take an undo record pointer as an input and read the
 * length of the previous undo record which is stored at the end of the previous
 * undo record.  If the undo record is split then this will add the undo block
 * header size in the total length.
 */
static uint16
UndoGetPrevRecordLen(UndoRecPtr urp, Buffer input_buffer,
					 UndoLogCategory category)
{
	UndoLogOffset offset = UndoRecPtrGetPageOffset(urp) - 1;
	BlockNumber cur_blk = UndoRecPtrGetBlockNum(urp);
	Buffer		buffer = input_buffer;
	Page		page = NULL;
	char	   *pagedata = NULL;
	union
	{
		char		len_bytes[2];
		uint16		len;
	}			prevlen;
	RelFileNode rnode;
	int			byte_to_read = 2;
	char		persistence;
	uint16		prev_rec_len = 0;

	/* Get relfilenode. */
	UndoRecPtrAssignRelFileNode(rnode, urp);
	persistence = RelPersistenceForUndoLogCategory(category);

	if (BufferIsValid(buffer))
	{
		page = BufferGetPage(buffer);
		pagedata = (char *) page;
	}

	/*
	 * Length of the previous undo record is store at the end of that record
	 * so just read the last 2 bytes.  But, these 2 bytes can be split acorss
	 * pages so we can not directly memcpy these 2 bytes, instead we need to
	 * read them byte by byte.
	 */
	while (byte_to_read > 0)
	{
		/* Read buffer if the current buffer is not valid. */
		if (!BufferIsValid(buffer))
		{
			buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum,
											   cur_blk, RBM_NORMAL, NULL,
											   persistence);
			LockBuffer(buffer, BUFFER_LOCK_SHARE);
			page = BufferGetPage(buffer);
			pagedata = (char *) page;
		}

		/*
		 * Read current prevlen byte from current block if the read offset
		 * hasn't reach to undo block header.  Otherwise, go to the previous
		 * block and continue reading from there.
		 */
		if (offset >= UndoLogBlockHeaderSize)
		{
			prevlen.len_bytes[byte_to_read - 1] = pagedata[offset];
			byte_to_read -= 1;
			offset -= 1;

			continue;
		}

		/*
		 * Could not read complete prevlen from the current block so go to the
		 * previous block and start reading from end of the block.
		 */
		cur_blk -= 1;
		offset = BLCKSZ - 1;

		/* Release the current buffer if it is not provide by the caller. */
		if (input_buffer != buffer)
			UnlockReleaseBuffer(buffer);

		buffer = InvalidBuffer;
	}

	prev_rec_len = prevlen.len;

	/*
	 * If previous undo record is split across the pages then include the
	 * block header size in its length for computing the start location of the
	 * previous undo record.
	 */
	if (UndoRecPtrGetPageOffset(urp) - UndoLogBlockHeaderSize < prevlen.len)
		prev_rec_len += UndoLogBlockHeaderSize;

	/* Release the buffer if we have locally read it. */
	if (input_buffer != buffer)
		UnlockReleaseBuffer(buffer);

	return prev_rec_len;
}

/*
 * Calculate the previous undo record pointer for the transaction.
 *
 * This will take current undo record pointer of the transaction as an input
 * and calculate the previous undo record pointer of the transaction.
 */
UndoRecPtr
UndoGetPrevUrp(UnpackedUndoRecord *uur, UndoRecPtr urp, Buffer buffer,
			   UndoLogCategory category)
{
	UndoLogOffset offset = UndoRecPtrGetOffset(urp);
	uint16		prevlen;

	/*
	 * If this is the first record of the transaction for this log then we
	 * need to get the previous undo record pointer from the previous undo
	 * log. We can get the logno from the log switch header stored in this
	 * record and then we can compute the undo record pointer of the last
	 * record on that log by using the insert location and the length of the
	 * last record on that log.
	 */
	if (uur && uur->uur_logswitch)
	{
		UndoLogNumber logno =
		UndoRecPtrGetLogNo(uur->uur_logswitch->urec_prevlogstart);

		urp = MakeUndoRecPtr(logno, UndoLogGetNextInsertPtr(logno));

		/*
		 * If we are reading the length from the another undo log then we can
		 * not use the buffer of the current log so pass invalid buffer.
		 */
		prevlen = UndoGetPrevRecordLen(urp, InvalidBuffer, category);
	}
	else
		prevlen = UndoGetPrevRecordLen(urp, buffer, category);

	/*
	 * We have got the length of the previous record.  Now using the offset of
	 * the current record and the length of the previous record we can compute
	 * the undo record pointer of the previous record.
	 */
	offset = UndoRecPtrGetOffset(urp);

	/* calculate the previous undo record pointer */
	return MakeUndoRecPtr(UndoRecPtrGetLogNo(urp), offset - prevlen);
}

/*
 * Returns the undo record pointer corresponding to first record in the given
 * block.
 */
UndoRecPtr
UndoBlockGetFirstUndoRecord(BlockNumber blkno, UndoRecPtr urec_ptr,
							UndoLogCategory category)
{
	Buffer buffer;
	Page page;
	UndoPageHeader	phdr;
	RelFileNode		rnode;
	UndoLogOffset	log_cur_off;
	Size			partial_rec_size;
	int				offset_cur_page;

	if (!BlockNumberIsValid(blkno))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid undo block number")));

	UndoRecPtrAssignRelFileNode(rnode, urec_ptr);

	buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, blkno,
									   RBM_NORMAL, NULL,
									   RelPersistenceForUndoLogCategory(category));

	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buffer);
	phdr = (UndoPageHeader)page;

	/* Calculate the size of the partial record. */
	partial_rec_size = phdr->undo_len - phdr->record_offset;

	/* calculate the offset in current log. */
	offset_cur_page = SizeOfUndoPageHeaderData + partial_rec_size;
	log_cur_off = (blkno * BLCKSZ) + offset_cur_page;

	UnlockReleaseBuffer(buffer);

	/* calculate the undo record pointer based on current offset in log. */
	return MakeUndoRecPtr(UndoRecPtrGetLogNo(urec_ptr), log_cur_off);
}
