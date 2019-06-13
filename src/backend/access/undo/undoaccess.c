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
 * Multiple logs:
 *
 * It is possible that the undo records for a transaction spans multiple undo
 * logs.  We need some special handling while inserting them to ensure that
 * discard and rollbacks can work sanely.
 *
 * When the undo record for a transaction gets inserted in the next log then we
 * add a transaction header for the first record of the transaction in the new
 * log and connect this undo record to the first record of the transaction in
 * the next log by updating the "uur_next" field.
 *
 * We will also keep a previous undo record pointer to the first and last undo
 * record of the transaction in the previous log.  The last undo record
 * location is used find the previous undo record pointer during rollback.
 * The first undo record location is used to find the previous transaction
 * header which is required to update the undo apply progress.
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/transam.h"
#include "access/undorecord.h"
#include "access/undoaccess.h"
#include "access/undolog_xlog.h"
#include "access/undorequest.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/xlogutils.h"
#include "catalog/pg_tablespace.h"
#include "commands/tablecmds.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/buf_internals.h"
#include "storage/bufmgr.h"
#include "miscadmin.h"

/*
 * Information for compression of the undo records on a page so that we can
 * avoid duplicating same values across multiple undo records on a page.
 *
 * The cid/xid/reloid/rmid information will be added in the undo record header
 * in the following cases:
 * a) The first undo record of the transaction.
 * b) First undo record of the page.
 * c) All subsequent record for the transaction which is not the first
 *	  transaction on the page.
 * Except above cases,  If the rmid/reloid/xid/cid is same in the subsequent
 * records this information will not be stored in the record, these information
 * will be retrieved from the first undo record of that page.
 * If any of the member rmid/reloid/xid/cid has changed, the changed information
 * will be stored in the undo record and the remaining information will be
 * retrieved from the first complete undo record of the page
 */
UndoCompressionInfo undo_compression_info[UndoLogCategories];

/* Prototypes for static functions. */
static UnpackedUndoRecord *UndoGetOneRecord(UnpackedUndoRecord *urec,
											UndoRecPtr urp, RelFileNode rnode,
											UndoLogCategory category,
											Buffer *prevbuf);
static int	UndoRecordPrepareTransInfo(UndoRecordInsertContext *context,
									   UndoRecPtr xact_urp, int size, int offset);
static void UndoRecordUpdateTransInfo(UndoRecordInsertContext *context,
									  int idx);
static void UndoRecordPrepareUpdateNext(UndoRecordInsertContext *context,
										UndoRecPtr urecptr, UndoRecPtr xact_urp);
static int	UndoGetBufferSlot(UndoRecordInsertContext *context,
							  RelFileNode rnode, BlockNumber blk,
							  ReadBufferMode rbm);
static uint16 UndoGetPrevRecordLen(UndoRecPtr urp, Buffer input_buffer,
								   UndoLogCategory category);
static bool UndoSetCommonInfo(UndoCompressionInfo *compressioninfo,
							  UnpackedUndoRecord *urec, UndoRecPtr urp,
							  Buffer buffer);

/*
 * Structure to hold the prepared undo information.
 */
struct PreparedUndoSpace
{
	UndoRecPtr	urp;			/* undo record pointer */
	UnpackedUndoRecord *urec;	/* undo record */
	uint16		size;			/* undo record size */
	int			undo_buffer_idx[MAX_BUFFER_PER_UNDO];	/* undo_buffer array
														 * index */
};

/*
 * This holds undo buffers information required for PreparedUndoSpace during
 * prepare undo time.  Basically, during prepare time which is called outside
 * the critical section we will acquire all necessary undo buffers pin and lock.
 * Later, during insert phase we will write actual records into thse buffers.
 */
struct PreparedUndoBuffer
{
	UndoLogNumber logno;		/* Undo log number */
	BlockNumber blk;			/* block number */
	Buffer		buf;			/* buffer allocated for the block */
	bool		zero;			/* new block full of zeroes */
};

/*
 * Compute the size of the partial record on the undo page.
 *
 * Compute the complete record size by uur_info and variable field length
 * stored in the page header and then subtract the offset of the record so that
 * we can get the exact size of partial record in this page.
 */
static inline Size
UndoPagePartialRecSize(UndoPageHeader phdr)
{
	Size		size = UndoRecordHeaderSize(phdr->uur_info);

	/*
	 * Add length of the variable part and undo length. Now, we know the
	 * complete length of the undo record.
	 */
	size += phdr->tuple_len + phdr->payload_len + sizeof(uint16);

	/*
	 * Subtract the size which is stored in the previous page to get the
	 * partial record size stored in this page.
	 */
	size -= phdr->record_offset;

	return size;
}

/*
 * Prepare to update the transaction header
 *
 * It's a helper function for PrepareUpdateNext and
 * PrepareUpdateUndoActionProgress
 *
 * xact_urp  - undo record pointer to be updated.
 * size - number of bytes to be updated.
 * offset - offset in undo record where to start update.
 */
static int
UndoRecordPrepareTransInfo(UndoRecordInsertContext *context,
						   UndoRecPtr xact_urp, int size, int offset)
{
	BlockNumber cur_blk;
	RelFileNode rnode;
	int			starting_byte;
	int			bufidx;
	int			index = 0;
	int			remaining_bytes;
	XactUndoRecordInfo *xact_info;

	xact_info = &context->xact_urec_info[context->nxact_urec_info];

	UndoRecPtrAssignRelFileNode(rnode, xact_urp);
	cur_blk = UndoRecPtrGetBlockNum(xact_urp);
	starting_byte = UndoRecPtrGetPageOffset(xact_urp);

	/* Remaining bytes on the current block. */
	remaining_bytes = BLCKSZ - starting_byte;

	/*
	 * Is there some byte of the urec_next on the current block, if not then
	 * start from the next block.
	 */
	if (remaining_bytes <= offset)
	{
		cur_blk++;
		starting_byte = UndoLogBlockHeaderSize;
		starting_byte += (offset - remaining_bytes);
	}
	else
		starting_byte += offset;

	/*
	 * Set the offset in the first block where we need to start writing,
	 * during the prepare phase so that during update phase we need not to
	 * compute it again.
	 */
	xact_info->offset = starting_byte;

	/* Loop until we have fetched all the buffers in which we need to write. */
	while (size > 0)
	{
		bufidx = UndoGetBufferSlot(context, rnode, cur_blk, RBM_NORMAL);

		Assert(index < MAX_BUFFER_PER_UNDO);

		xact_info->idx_undo_buffers[index++] = bufidx;
		size -= (BLCKSZ - starting_byte);
		starting_byte = UndoLogBlockHeaderSize;
		cur_blk++;
	}

	xact_info->next = InvalidUndoRecPtr;
	xact_info->progress = 0;
	xact_info->urecptr = xact_urp;
	context->nxact_urec_info++;

	return (context->nxact_urec_info - 1);
}

/*
 * Prepare to update the transaction's next undo pointer.
 *
 * Lock necessary buffer for updating the next of the transaction header.  This
 * function is called for
 * a. Updating the current transaction's start undo record pointer in previous
 * transaction's start header.
 * b. For multi-log transaction update the start undo record pointer of the
 * current log in the same transaction's start undo record pointer in the
 * previous log.
 *
 * xact_urp - undo record pointer to be updated
 * urecptr - current transaction's undo record pointer which need to be set in
 *			 the previous transaction's header.
 */
static void
UndoRecordPrepareUpdateNext(UndoRecordInsertContext *context,
							UndoRecPtr urecptr, UndoRecPtr xact_urp)
{
	UndoLogSlot *slot;
	int			index = 0;
	int			offset;

	/*
	 * The absence of previous transaction's undo indicate that this backend
	 * is preparing its first undo in which case we have nothing to update.
	 */
	if (!UndoRecPtrIsValid(xact_urp))
		return;

	slot = UndoLogGetSlot(UndoRecPtrGetLogNo(xact_urp), false);

	/*
	 * Acquire the discard lock before reading the undo record so that discard
	 * worker doesn't remove the record while we are in process of reading it.
	 */
	LWLockAcquire(&slot->discard_update_lock, LW_SHARED);
	/* Check if it is already discarded. */
	if (UndoRecPtrIsDiscarded(xact_urp))
	{
		/* Release lock and return. */
		LWLockRelease(&slot->discard_update_lock);
		return;
	}

	/* Compute the offset of the uur_next in the undo record. */
	offset = SizeOfUndoRecordHeader +
		offsetof(UndoRecordTransaction, urec_next);

	index = UndoRecordPrepareTransInfo(context, xact_urp,
									   sizeof(UndoRecPtr), offset);

	/*
	 * Set the next pointer in xact_urec_info, this will be overwritten in
	 * actual undo record during update phase.
	 */
	context->xact_urec_info[index].next = urecptr;

	/* We can now release the discard lock as we have read the undo record. */
	LWLockRelease(&slot->discard_update_lock);
}

/*
 * Overwrite the first undo record of the previous transaction to update its
 * next pointer.
 *
 * This will insert the already prepared record by UndoRecordPrepareTransInfo.
 * This must be called under the critical section.  This will just overwrite the
 * header of the undo record.
 */
static void
UndoRecordUpdateTransInfo(UndoRecordInsertContext *context, int idx)
{
	Page		page = NULL;
	int			i = 0;
	int			write_bytes;
	int			write_offset;
	char	   *sourceptr;
	XactUndoRecordInfo *xact_info = &context->xact_urec_info[idx];

	/* Whether to update the next or undo apply progress. */
	if (UndoRecPtrIsValid(xact_info->next))
	{
		sourceptr = (char *) &xact_info->next;
		write_bytes = sizeof(xact_info->next);
	}
	else
	{
		sourceptr = (char *) &xact_info->progress;
		write_bytes = sizeof(xact_info->progress);
	}

	/* Where to start writing in the current block. */
	write_offset = xact_info->offset;

	/*
	 * Start writing directly from the write offset calculated during prepare
	 * phase.  And, loop until we write required bytes.
	 */
	while (write_bytes > 0)
	{
		Buffer		buffer;
		int			buf_idx;
		int			can_write;
		char	   *writeptr;

		buf_idx = xact_info->idx_undo_buffers[i];
		buffer = context->prepared_undo_buffers[buf_idx].buf;

		/* How may bytes can be written in the current page. */
		can_write = Min((BLCKSZ - write_offset), write_bytes);

		/*
		 * If buffer is valid then write it otherwise just skip writing it but
		 * compute the variable for writing into the next block.
		 */
		if (BufferIsValid(buffer))
		{
			page = BufferGetPage(buffer);

			/* Compute the write pointer. */
			writeptr = (char *) page + write_offset;

			/* Copy the bytes we can write. */
			memcpy(writeptr, sourceptr, can_write);
			MarkBufferDirty(buffer);
		}

		/* Update bookkeeping information. */
		write_bytes -= can_write;
		sourceptr += can_write;
		write_offset = UndoLogBlockHeaderSize;
		i++;
	}
}

/*
 * Find the block number in undo buffer array
 *
 * If it is present then just return its index otherwise search the buffer and
 * insert an entry and lock the buffer in exclusive mode.
 *
 * Undo log insertions are append-only.  If the caller is writing new data
 * that begins exactly at the beginning of a page, then there cannot be any
 * useful data after that point.  In that case RBM_ZERO can be passed in as
 * rbm so that we can skip a useless read of a disk block.  In all other
 * cases, RBM_NORMAL should be passed in, to read the page in if it doesn't
 * happen to be already in the buffer pool.
 */
static int
UndoGetBufferSlot(UndoRecordInsertContext *context,
				  RelFileNode rnode,
				  BlockNumber blk,
				  ReadBufferMode rbm)
{
	int			i;
	Buffer		buffer;
	XLogRedoAction action = BLK_NEEDS_REDO;
	PreparedUndoBuffer *prepared_buffer;
	UndoLogCategory category = context->alloc_context.category;

	/* Don't do anything, if we already have a buffer pinned for the block. */
	for (i = 0; i < context->nprepared_undo_buffer; i++)
	{
		prepared_buffer = &context->prepared_undo_buffers[i];

		/*
		 * It's not enough to just compare the block number because the
		 * undo_buffer might holds the undo from different undo logs (e.g when
		 * previous transaction start header is in previous undo log) so
		 * compare (logno + blkno).
		 */
		if ((blk == prepared_buffer->blk) &&
			(prepared_buffer->logno == rnode.relNode))
		{
			/* caller must hold exclusive lock on buffer */
			Assert(BufferIsLocal(prepared_buffer->buf) ||
				   LWLockHeldByMeInMode(BufferDescriptorGetContentLock(
																	   GetBufferDescriptor(prepared_buffer->buf - 1)),
										LW_EXCLUSIVE));
			return i;
		}
	}

	/*
	 * We did not find the block so allocate the buffer and insert into the
	 * undo buffer array.
	 */
	if (InRecovery)
		action = XLogReadBufferForRedoBlock(context->alloc_context.xlog_record,
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
										   RelPersistenceForUndoLogCategory(category));

		/* Lock the buffer */
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	}

	prepared_buffer =
		&context->prepared_undo_buffers[context->nprepared_undo_buffer];

	if (action == BLK_NOTFOUND)
	{
		Assert(InRecovery);

		prepared_buffer->buf = InvalidBuffer;
		prepared_buffer->blk = InvalidBlockNumber;
	}
	else
	{
		prepared_buffer->buf = buffer;
		prepared_buffer->blk = blk;
		prepared_buffer->logno = rnode.relNode;
		prepared_buffer->zero = rbm == RBM_ZERO;
	}

	context->nprepared_undo_buffer++;

	return i;
}

/*
 * Exclude the common info in undo record flag and also set the compression
 * info in the context.
 *
 * This function will check what information we need to include in the current
 * undo record based on the undo compression information.  And, it will also
 * update the compression info if we are writing the first undo record on the
 * page.
 */
static bool
UndoSetCommonInfo(UndoCompressionInfo *compressioninfo,
				  UnpackedUndoRecord *urec, UndoRecPtr urp,
				  Buffer buffer)
{
	bool		record_updated = false;
	bool		first_complete_undo = false;
	UndoRecPtr	lasturp = compressioninfo->last_urecptr;

	/*
	 * If we have valid compression info and the for the same transaction and
	 * the current undo record is on the same block as the last undo record
	 * then exclude the common information which are same as first complete
	 * record on the page.
	 */
	if (compressioninfo->valid &&
		FullTransactionIdEquals(compressioninfo->fxid, urec->uur_fxid) &&
		UndoRecPtrGetBlockNum(urp) == UndoRecPtrGetBlockNum(lasturp))
	{
		urec->uur_info &= ~UREC_INFO_XID;

		/* Don't include rmid if it's same. */
		if (urec->uur_rmid == compressioninfo->rmid)
			urec->uur_info &= ~UREC_INFO_RMID;

		/* Don't include reloid if it's same. */
		if (urec->uur_reloid == compressioninfo->reloid)
			urec->uur_info &= ~UREC_INFO_RELOID;

		/* Don't include cid if it's same. */
		if (urec->uur_cid == compressioninfo->cid)
			urec->uur_info &= ~UREC_INFO_CID;

		record_updated = true;
	}

	/*
	 * If the undo record is starting just after the undo page header then
	 * this is the first complete undo on the page.
	 */
	if (UndoRecPtrGetPageOffset(urp) == SizeOfUndoPageHeaderData)
		first_complete_undo = true;
	else if (UndoRecPtrIsValid(lasturp))
	{
		/*
		 * If we already have the valid last undo record pointer which
		 * inserted undo in this log then we can identify whether this is the
		 * first undo of the page by checking the block number of the previous
		 * record and the current record.
		 */
		if (UndoRecPtrGetBlockNum(urp) != UndoRecPtrGetBlockNum(lasturp))
			first_complete_undo = true;
	}
	else
	{
		Page		page = BufferGetPage(buffer);
		uint16		offset;
		UndoPageHeader phdr = (UndoPageHeader) page;

		/*
		 * We need to compute the offset of the first complete record of the
		 * page and if this undo record starting from that page then this is
		 * the first complete record on the page.
		 */
		offset = SizeOfUndoPageHeaderData + UndoPagePartialRecSize(phdr);
		if (UndoRecPtrGetPageOffset(urp) == offset)
			first_complete_undo = true;
	}

	/*
	 * If we are writing first undo record for the page the we can set the
	 * compression so that subsequent records from the same transaction can
	 * avoid including common information in the undo records.
	 */
	if (first_complete_undo)
	{
		/* Set this information. */
		compressioninfo->rmid = urec->uur_rmid;
		compressioninfo->reloid = urec->uur_reloid;
		compressioninfo->fxid = urec->uur_fxid;
		compressioninfo->cid = urec->uur_cid;

		/* Set that we have valid compression info. */
		compressioninfo->valid = true;
	}

	return record_updated;
}

/*
 * This function must be called before all the undo records which are going to
 * get inserted under a single WAL record.
 *
 * nprepared - This defines the max number of undo records that can be
 * prepared before inserting them.
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
	context->nxact_urec_info = 0;

	/* Allocate memory for prepared undo record space. */
	context->prepared_undo = (PreparedUndoSpace *) palloc(nprepared *
														  sizeof(PreparedUndoSpace));

	/* Compute number of buffers. */
	nbuffers = (nprepared + MAX_XACT_UNDO_INFO) * MAX_BUFFER_PER_UNDO;

	/*
	 * Copy the compression global compression info to our context before
	 * starting prepare because this value might get updated multiple time in
	 * case of multi-prepare but the global value should be updated only after
	 * we have successfully inserted the undo record.
	 */
	memcpy(&context->undo_compression_info[category],
		   &undo_compression_info[category], sizeof(UndoCompressionInfo));

	/* Allocate memory for the prepared buffers. */
	context->prepared_undo_buffers =
		palloc(nbuffers * sizeof(PreparedUndoBuffer));
}

/*
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned and
 * locked.
 *
 * This should be done before any critical section is established, since it
 * can fail.
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
	bool		logswitched = false;
	bool		resize = false;
	ReadBufferMode rbm;
	bool		need_xact_header;
	UndoRecPtr	last_xact_start;
	UndoRecPtr	prevlog_xact_start = InvalidUndoRecPtr;
	UndoRecPtr	prevlog_insert_urp = InvalidUndoRecPtr;
	UndoRecPtr	prevlogurp = InvalidUndoRecPtr;
	PreparedUndoSpace *prepared_undo;
	UndoCompressionInfo *compression_info =
	&context->undo_compression_info[context->alloc_context.category];

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
	 * allocation We'll only advance by as many bytes as we turn out to need.
	 */
	UndoRecordSetInfo(urec);
	urec->uur_info |= UREC_INFO_TRANSACTION;
	urec->uur_info |= UREC_INFO_LOGSWITCH;
	urec->uur_info |= UREC_INFO_PAGE_COMMON;

	size = UndoRecordExpectedSize(urec);

	/* Allocate space for the record. */
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
											&prevlog_xact_start,
											&prevlogurp);
	}
	else
	{
		/* Allocate space for writing the undo record. */
		urecptr = UndoLogAllocate(&context->alloc_context,
								  size,
								  &need_xact_header, &last_xact_start,
								  &prevlog_xact_start, &prevlog_insert_urp);

		/*
		 * If prevlog_xact_start is a valid undo record pointer that means
		 * this transaction's undo records are split across undo logs.
		 */
		if (UndoRecPtrIsValid(prevlog_xact_start))
		{
			uint16		prevlen;

			/*
			 * If undo log is switch during transaction then we must get a
			 * valid insert location in the previous undo log so that we can
			 * compute the undo record pointer of the transaction's last
			 * record in the previous undo log.
			 */
			Assert(UndoRecPtrIsValid(prevlog_insert_urp));

			/* Fetch length of the last undo record of the previous log. */
			prevlen = UndoGetPrevRecordLen(prevlog_insert_urp, InvalidBuffer,
										   context->alloc_context.category);

			/*
			 * If the undo log got switched during the transaction then for
			 * collecting all the undo record for the transaction during bulk
			 * fetch,  we  can not read the prevlen from the end of the record
			 * as we will not know what was the previous undo log.  So during
			 * log switch we will directly store the last undo record pointer
			 * of the transaction into transaction's first record of the next
			 * undo log.
			 *
			 * TODO:  instead of storing this in the transaction header we can
			 * have separate undo log switch header and store it there.
			 */
			prevlogurp =
				MakeUndoRecPtr(UndoRecPtrGetLogNo(prevlog_insert_urp),
							   (UndoRecPtrGetOffset(prevlog_insert_urp) - prevlen));

			/*
			 * Undo log switched so set prevlog info in current undo log.
			 *
			 * XXX can we do this directly in UndoLogAllocate ? but for that
			 * the UndoLogAllocate might need to read the length of the last
			 * undo record from the previous undo log but for that it might
			 * use callback?
			 */
			UndoLogSwitchSetPrevLogInfo(UndoRecPtrGetLogNo(urecptr),
										prevlog_xact_start, prevlogurp);
		}
	}

	/*
	 * If undo log is switched then set the logswitch flag and also reset the
	 * compression info because we can use same compression info for the new
	 * undo log.
	 */
	if (UndoRecPtrIsValid(prevlog_xact_start))
	{
		logswitched = true;
		compression_info->valid = false;
		compression_info->last_urecptr = InvalidUndoRecPtr;
	}

	/*
	 * If we need a transaction header then allocate memory for it and
	 * initialize it.
	 */
	if (need_xact_header)
	{
		urec->uur_txn = palloc(SizeOfUndoRecordTransaction);
		urec->uur_txn->urec_dbid = dbid;
		urec->uur_txn->urec_progress = XACT_APPLY_PROGRESS_NOT_STARTED;
		urec->uur_txn->urec_next = InvalidUndoRecPtr;
	}
	else
	{
		/* We don't need a transaction header after all. */
		urec->uur_info &= ~UREC_INFO_TRANSACTION;
		resize = true;
		urec->uur_txn = NULL;
	}

	/*
	 * If undo log got switched then initialize the log switch header
	 * otherwise reset it in uur_info and recalculate the size.
	 */
	if (logswitched)
	{
		urec->uur_logswitch = palloc(SizeOfUndoRecordLogSwitch);
		urec->uur_logswitch->urec_prevurp = prevlogurp;
		urec->uur_logswitch->urec_prevlogstart = prevlog_xact_start;
	}
	else
	{
		/* We don't need a log transaction header after all. */
		urec->uur_info &= ~UREC_INFO_LOGSWITCH;
		resize = true;
		urec->uur_logswitch = NULL;
	}

	/*
	 * If there is a physically preceding transaction in this undo log, and we
	 * are writing the first record for this transaction that is in this undo
	 * log (not necessarily the first ever for the transaction, because we
	 * could have switched logs), then we need to update the size of the
	 * preceding transaction.
	 */
	if (need_xact_header &&
		UndoRecPtrGetOffset(urecptr) > UndoLogBlockHeaderSize)
		UndoRecordPrepareUpdateNext(context, urecptr, last_xact_start);

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

	prepared_undo = &context->prepared_undo[context->nprepared_undo];

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
	 * Set/overwrite compression info if required and also exclude the common
	 * fields from the undo record if possible.
	 */
	if (UndoSetCommonInfo(compression_info, urec, urecptr,
						  context->prepared_undo_buffers[prepared_undo->undo_buffer_idx[0]].buf))
		resize = true;

	if (resize)
		size = UndoRecordExpectedSize(urec);

	/*
	 * If the transaction's undo records are split across the undo logs.  So
	 * we need to  update our own transaction header in the previous log.
	 */
	if (logswitched)
	{
		Assert(UndoRecPtrIsValid(prevlogurp));
		UndoRecordPrepareUpdateNext(context, urecptr, prevlog_xact_start);
	}

	UndoLogAdvance(&context->alloc_context, size);

	/*
	 * Save prepared undo record information into the context which will be
	 * used by InsertPreparedUndo to insert the undo record.
	 */
	prepared_undo->urec = urec;
	prepared_undo->urp = urecptr;
	prepared_undo->size = size;

	/* Set the current undo pointer in the compression info. */
	compression_info->last_urecptr = urecptr;

	context->nprepared_undo++;

	return urecptr;
}

/*
 * Insert a previously-prepared undo records.
 *
 * This function will write the actual undo record into the buffers which are
 * already pinned and locked in PreparedUndoInsert, and mark them dirty.  This
 * step should be performed inside a critical section.
 */
void
InsertPreparedUndo(UndoRecordInsertContext *context)
{
	UndoPackContext ucontext = {{0}};
	PreparedUndoSpace *prepared_undo;
	Page		page = NULL;
	int			starting_byte;
	int			bufidx = 0;
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

		bufidx = 0;

		/*
		 * Compute starting offset of the page where to start inserting undo
		 * record.
		 */
		starting_byte = UndoRecPtrGetPageOffset(prepared_undo->urp);

		/* Initiate inserting the undo record. */
		BeginInsertUndo(&ucontext, prepared_undo->urec);

		/* Main loop for writing the undo record. */
		do
		{
			Buffer		buffer;

			buffer = context->prepared_undo_buffers[
													prepared_undo->undo_buffer_idx[bufidx]].buf;

			/*
			 * During recovery, there might be some blocks which are already
			 * deleted due to some discard command so we can just skip
			 * inserting into those blocks.
			 */
			if (!BufferIsValid(buffer))
			{
				Assert(InRecovery);

				/*
				 * Skip actual writing just update the context so that we have
				 * write offset for inserting into next blocks.
				 */
				SkipInsertingUndoData(&ucontext, BLCKSZ - starting_byte);
				if (ucontext.stage == UNDO_PACK_STAGE_DONE)
					break;
			}
			else
			{
				page = BufferGetPage(buffer);

				/*
				 * Initialize the page whenever we try to write the first
				 * record in page.  We start writing immediately after the
				 * block header.
				 */
				if (starting_byte == UndoLogBlockHeaderSize)
					UndoPageInit(page, BLCKSZ, prepared_undo->urec->uur_info,
								 ucontext.already_processed,
								 prepared_undo->urec->uur_tuple.len,
								 prepared_undo->urec->uur_payload.len);

				/*
				 * Try to insert the record into the current page. If it
				 * doesn't succeed then recall the routine with the next page.
				 */
				InsertUndoData(&ucontext, page, starting_byte);
				if (ucontext.stage == UNDO_PACK_STAGE_DONE)
				{
					MarkBufferDirty(buffer);
					break;
				}
				MarkBufferDirty(buffer);
			}

			/* Insert remaining record in next block. */
			starting_byte = UndoLogBlockHeaderSize;
			bufidx++;

			/* undo record can't use buffers more than MAX_BUFFER_PER_UNDO. */
			Assert(bufidx < MAX_BUFFER_PER_UNDO);
		} while (true);

		/* Advance the insert pointer past this record. */
		UndoLogAdvanceFinal(prepared_undo->urp, prepared_undo->size);
	}

	/* Update previously prepared transaction headers. */
	for (i = 0; i < context->nxact_urec_info; i++)
		UndoRecordUpdateTransInfo(context, i);

	/*
	 * We have successfully inserted prepared undo records so overwrite the
	 * global compression.
	 */
	memcpy(&undo_compression_info[context->alloc_context.category],
		   &context->undo_compression_info[context->alloc_context.category],
		   sizeof(UndoCompressionInfo));

}

/*
 * Release all the memory and buffer pins hold for inserting the undo records.
 */
void
FinishUndoRecordInsert(UndoRecordInsertContext *context)
{
	int			i;

	/* Release buffer pins and lock. */
	for (i = 0; i < context->nprepared_undo_buffer; i++)
	{
		if (BufferIsValid(context->prepared_undo_buffers[i].buf))
			UnlockReleaseBuffer(context->prepared_undo_buffers[i].buf);
	}

	/*
	 * Release memory for the transaction header and log switch header if we
	 * have allocated it in the prepare time.
	 */
	for (i = 0; i < context->nprepared_undo; i++)
	{
		if (context->prepared_undo[i].urec->uur_txn)
			pfree(context->prepared_undo[i].urec->uur_txn);
		if (context->prepared_undo[i].urec->uur_logswitch)
			pfree(context->prepared_undo[i].urec->uur_logswitch);
	}

	/* Free memory allocated for the prepare undo and prepared buffers. */
	pfree(context->prepared_undo_buffers);
	pfree(context->prepared_undo);
}

/*
 * Helper function for UndoGetOneRecord
 *
 * If any of  rmid/reloid/xid/cid is not available in the undo record, then
 * it will get the information from the first complete undo record in the
 * page.
 */
static void
GetCommonUndoRecInfo(UndoPackContext *ucontext, UndoRecPtr urp,
					 RelFileNode rnode, UndoLogCategory category, Buffer buffer)
{
	/*
	 * If any of the common header field is not available in the current undo
	 * record then we must read it from the first complete record of the page.
	 */
	if ((ucontext->urec_hd.urec_info & UREC_INFO_PAGE_COMMON) !=
		UREC_INFO_PAGE_COMMON)
	{
		UnpackedUndoRecord first_uur = {0};
		Page		page = BufferGetPage(buffer);
		UndoPageHeader undo_phdr = (UndoPageHeader) page;
		UndoRecPtr	first_urp = InvalidUndoRecPtr;
		Size		partial_rec_size = SizeOfUndoPageHeaderData;
		BlockNumber blkno = UndoRecPtrGetBlockNum(urp);

		/*
		 * If there is a partial record in the page then compute the size of
		 * it so that we can compute the undo record pointer of the first
		 * complete undo record of the page.
		 */
		if (undo_phdr->record_offset != 0)
			partial_rec_size += UndoPagePartialRecSize(undo_phdr);

		/*
		 * Compute the undo record pointer of the first complete record of the
		 * page.
		 */
		first_urp = MakeUndoRecPtr(rnode.relNode,
								   UndoRecPageOffsetGetRecPtr(partial_rec_size, blkno));

		/* Fetch the first undo record of the page. */
		UndoGetOneRecord(&first_uur, first_urp, rnode, category, &buffer);

		/*
		 * Get all missing common header information from the first undo
		 * records.
		 */
		if ((ucontext->urec_hd.urec_info & UREC_INFO_RMID) == 0)
			ucontext->urec_rmid = first_uur.uur_rmid;

		if ((ucontext->urec_hd.urec_info & UREC_INFO_RELOID) == 0)
			ucontext->urec_reloid = first_uur.uur_reloid;

		if ((ucontext->urec_hd.urec_info & UREC_INFO_XID) == 0)
			ucontext->urec_fxid = first_uur.uur_fxid;

		if ((ucontext->urec_hd.urec_info & UREC_INFO_CID) == 0)
			ucontext->urec_cid = first_uur.uur_cid;

		ucontext->urec_hd.urec_info |= UREC_INFO_PAGE_COMMON;
	}
}

/*
 * Helper function for UndoFetchRecord and UndoBulkFetchRecord
 *
 * curbuf - If an input buffer is valid then this function will not release the
 * pin on that buffer.  If the buffer is not valid then it will assign curbuf
 * with the first buffer of the current undo record and also it will keep the
 * pin and lock on that buffer in a hope that while traversing the undo chain
 * the caller might want to read the previous undo record from the same block.
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
			if (buffer != *curbuf)
				UnlockReleaseBuffer(buffer);

			/*
			 * Get any of the missing fields from the first record of the
			 * page.
			 */
			GetCommonUndoRecInfo(&ucontext, urp, rnode, category, *curbuf);
			break;
		}

		/*
		 * The record spans more than a page so we would have copied it (see
		 * UnpackUndoRecord).  In such cases, we can release the buffer.
		 */
		if (buffer != *curbuf)
			UnlockReleaseBuffer(buffer);
		buffer = InvalidBuffer;

		/* Go to next block. */
		cur_blk++;
		starting_byte = UndoLogBlockHeaderSize;
	}

	/* Final step of unpacking. */
	FinishUnpackUndo(&ucontext, urec);

	/* Unlock the buffer but keep the pin. */
	LockBuffer(*curbuf, BUFFER_LOCK_UNLOCK);

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
 * intern will hold the pointers to the optional headers and the variable data.
 * The undo record should be freed by the caller by calling ReleaseUndoRecord.
 * This function will old the pin on the buffer where we read the previous undo
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
 * Release the memory of the undo record allocated by UndoFetchRecord and
 * UndoBulkFetchRecord.
 */
void
UndoRecordRelease(UnpackedUndoRecord *urec)
{
	/* Release the memory of payload data if we allocated it. */
	if (urec->uur_payload.data)
		pfree(urec->uur_payload.data);

	/* Release memory of tuple data if we allocated it. */
	if (urec->uur_tuple.data)
		pfree(urec->uur_tuple.data);

	/* Release memory of the transaction header if we allocated it. */
	if (urec->uur_txn)
		pfree(urec->uur_txn);

	/* Release memory of the logswitch header if we allocated it. */
	if (urec->uur_logswitch)
		pfree(urec->uur_logswitch);

	/* Release the memory of the undo record. */
	pfree(urec);
}

/*
 * Prefetch undo pages, if prefetch_pages are behind prefetch_target
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
 *					  complete transaction.  If this is set true then instead
 *					  of following transaction undo chain using prevlen we will
 *					  follow the block prev chain of the block so that we can
 *					  avoid reading many unnecessary undo records of the
 *					  transaction.
 */
UndoRecInfo *
UndoBulkFetchRecord(UndoRecPtr *from_urecptr, UndoRecPtr to_urecptr,
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
	FullTransactionId fxid = InvalidFullTransactionId;

	/*
	 * In one_page mode we are fetching undo only for one page instead of
	 * fetching all the undo of the transaction.  Basically, we are fetching
	 * interleaved undo records.  So it does not make sense to do any prefetch
	 * in that case.  Also, if we are fetching undo records from more than one
	 * log, we don't know the boundaries for prefetching.  Hence, we can't use
	 * prefetching in this case.
	 */
	if (!one_page &&
		(UndoRecPtrGetLogNo(*from_urecptr) == UndoRecPtrGetLogNo(to_urecptr)))
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
		int			size;
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

		/*
		 * If prefetch_pages are half of the prefetch_target then it's time to
		 * prefetch again.
		 */
		if (prefetch_pages < prefetch_target / 2)
			PrefetchUndoPages(rnode, prefetch_target, &prefetch_pages, to_blkno,
							  from_blkno, category);

		/*
		 * In one_page mode it's possible that the undo of the transaction
		 * might have been applied by worker and undo got discarded. Prevent
		 * discard worker from discarding undo data while we are reading it.
		 * See detail comment in UndoFetchRecord.  In normal mode we are
		 * holding transaction undo action lock so it can not be discarded.
		 */
		if (one_page)
		{
			/* Refer comments in UndoFetchRecord. */
			if (InHotStandby)
			{
				if (UndoRecPtrIsDiscarded(urecptr))
					break;
			}
			else
			{
				LWLockAcquire(&slot->discard_lock, LW_SHARED);
				if (slot->logno != logno || urecptr < slot->oldest_data)
				{
					/*
					 * The undo log slot has been recycled because it was
					 * entirely discarded, or the data has been discarded
					 * already.
					 */
					LWLockRelease(&slot->discard_lock);
					break;
				}
			}

			/* Read the undo record. */
			UndoGetOneRecord(uur, urecptr, rnode, category, &buffer);

			/* Release the discard lock after fetching the record. */
			if (!InHotStandby)
				LWLockRelease(&slot->discard_lock);
		}
		else
			UndoGetOneRecord(uur, urecptr, rnode, category, &buffer);

		/*
		 * As soon as the transaction id is changed we can stop fetching the
		 * undo record.  Ideally, to_urecptr should control this but while
		 * reading undo only for a page we don't know what is the end undo
		 * record pointer for the transaction.
		 */
		if (one_page)
		{
			if (!FullTransactionIdIsValid(fxid))
				fxid = uur->uur_fxid;
			else if (!FullTransactionIdEquals(fxid, uur->uur_fxid))
				break;
		}

		/* Remember the previous undo record pointer. */
		prev_urec_ptr = urecptr;

		/*
		 * Calculate the previous undo record pointer of the transaction.  If
		 * we are reading undo only for a page then follow the blkprev chain
		 * of the page.  Otherwise, calculate the previous undo record pointer
		 * using transaction's current undo record pointer and the prevlen. If
		 * undo record has a valid uur_prevurp, this is the case of log switch
		 * during the transaction so we can directly use uur_prevurp as our
		 * previous undo record pointer of the transaction.
		 */
		if (one_page)
			urecptr = uur->uur_prevundo;
		else if (uur->uur_logswitch)
			urecptr = uur->uur_logswitch->urec_prevurp;
		else if (prev_urec_ptr == to_urecptr ||
				 uur->uur_info & UREC_INFO_TRANSACTION)
			urecptr = InvalidUndoRecPtr;
		else
			urecptr = UndoGetPrevUndoRecptr(prev_urec_ptr, buffer, category);

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

		size = UnpackedUndoRecordSize(uur);
		total_size += size;

		/*
		 * Including current record, if we have crossed the memory limit or
		 * undo log got switched then stop processing more records.  Remember
		 * to set the from_urecptr so that on next call we can resume fetching
		 * undo records where we left it.
		 */
		if (total_size >= undo_apply_size || uur->uur_logswitch)
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
	UndoLogOffset page_offset = UndoRecPtrGetPageOffset(urp);
	BlockNumber cur_blk = UndoRecPtrGetBlockNum(urp);
	Buffer		buffer = input_buffer;
	Page		page = NULL;
	char	   *pagedata = NULL;
	char		prevlen[2];
	RelFileNode rnode;
	int			byte_to_read = sizeof(uint16);
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
	 * Length if the previous undo record is store at the end of that record
	 * so just fetch last 2 bytes.
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

		page_offset -= 1;

		/*
		 * Read current prevlen byte from current block if page_offset hasn't
		 * reach to undo block header.  Otherwise, go to the previous block
		 * and continue reading from there.
		 */
		if (page_offset >= UndoLogBlockHeaderSize)
		{
			prevlen[byte_to_read - 1] = pagedata[page_offset];
			byte_to_read -= 1;
		}
		else
		{
			/*
			 * Release the current buffer if it is not provide by the caller.
			 */
			if (input_buffer != buffer)
				UnlockReleaseBuffer(buffer);

			/*
			 * Could not read complete prevlen from the current block so go to
			 * the previous block and start reading from end of the block.
			 */
			cur_blk -= 1;
			page_offset = BLCKSZ;

			/*
			 * Reset buffer so that we can read it again for the previous
			 * block.
			 */
			buffer = InvalidBuffer;
		}
	}

	prev_rec_len = *(uint16 *) (prevlen);

	/*
	 * If previous undo record is not completely stored in this page then add
	 * UndoLogBlockHeaderSize in total length so that the call can use this
	 * length to compute the undo record pointer of the previous undo record.
	 */
	if (UndoRecPtrGetPageOffset(urp) - UndoLogBlockHeaderSize < prev_rec_len)
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
UndoGetPrevUndoRecptr(UndoRecPtr urp, Buffer buffer,
					  UndoLogCategory category)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(urp);
	UndoLogOffset offset = UndoRecPtrGetOffset(urp);
	uint16		prevlen;

	/* Read length of the previous undo record. */
	prevlen = UndoGetPrevRecordLen(urp, buffer, category);

	/* calculate the previous undo record pointer */
	return MakeUndoRecPtr(logno, offset - prevlen);
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
	partial_rec_size = UndoRecordHeaderSize(phdr->uur_info) +
						phdr->tuple_len + phdr->payload_len -
						phdr->record_offset;

	/* calculate the offset in current log. */
	offset_cur_page = SizeOfUndoPageHeaderData + partial_rec_size;
	log_cur_off = (blkno * BLCKSZ) + offset_cur_page;

	UnlockReleaseBuffer(buffer);

	/* calculate the undo record pointer based on current offset in log. */
	return MakeUndoRecPtr(UndoRecPtrGetLogNo(urec_ptr), log_cur_off);
}
