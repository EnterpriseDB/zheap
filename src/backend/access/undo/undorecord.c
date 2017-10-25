/*-------------------------------------------------------------------------
 *
 * undorecord.c
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undorecord.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/xact.h"
#include "access/undodiscard.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/undoinsert.h"
#include "catalog/pg_tablespace.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "miscadmin.h"

/*
 * FIXME:  Do we want to support undo tuple size which is more than the BLCKSZ
 * if not than undo record can spread across 2 buffers at the max.
 */
#define MAX_BUFFER_PER_UNDO    2
#define MAX_UNDO_BUFFERS       MAX_PREPARED_UNDO * MAX_BUFFER_PER_UNDO

/* Maximum number of undo record that can be prepared before calling insert. */
#define MAX_PREPARED_UNDO 2

/* Workspace for InsertUndoRecord and UnpackUndoRecord. */
static UndoRecordHeader work_hdr;
static UndoRecordRelationDetails work_rd;
static UndoRecordBlock work_blk;
static UndoRecordTransaction work_txn;
static UndoRecordPayload work_payload;

/*
 * Previous top transaction id which inserted the undo.  Whenever a new main
 * transaction try to prepare an undo record we will check if its txid not the
 * same as prev_txid then we will insert the start undo record.  We will keep
 * the reference of the previous transaction's start undo record in
 * prev_xact_urp.
 */
static TransactionId	prev_txid = InvalidTransactionId;
static UndoRecPtr		prev_xact_urp = InvalidUndoRecPtr;
static uint16			prev_undolen = 0;

/* Undo block number to buffer mapping. */
typedef struct UndoBuffers
{
	BlockNumber		blk;			/* block number */
	Buffer			buf;			/* buffer allocated for the block */
} UndoBuffers;

static UndoBuffers def_buffers[MAX_UNDO_BUFFERS];
static int	buffer_idx;

/*
 * Structure to hold the prepared undo information.
 */
typedef struct PreparedUndoSpace
{
	UndoRecPtr urp;						/* undo record pointer */
	UnpackedUndoRecord *urec;			/* undo record */
	int undo_buffer_idx[MAX_BUFFER_PER_UNDO]; /* undo_buffer array index */
} PreparedUndoSpace;

static PreparedUndoSpace  def_prepared[MAX_PREPARED_UNDO];
static int prepare_idx;
static int	max_prepare_undo = MAX_PREPARED_UNDO;

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

/* Prototypes for static functions. */
static void UndoRecordSetInfo(UnpackedUndoRecord *uur);
static bool InsertUndoBytes(char *sourceptr, int sourcelen,
				char **writeptr, char *endptr,
				int *my_bytes_written, int *total_bytes_written);
static bool ReadUndoBytes(char *destptr, int readlen,
			  char **readptr, char *endptr,
			  int *my_bytes_read, int *total_bytes_read, bool nocopy);
static UnpackedUndoRecord* UndoGetOneRecord(UnpackedUndoRecord *urec,
											UndoRecPtr urp, RelFileNode rnode);
static void UndoRecordUpdateTransactionInfo(UndoRecPtr urecptr);

/*
 * Compute and return the expected size of an undo record.
 */
Size
UndoRecordExpectedSize(UnpackedUndoRecord *uur)
{
	Size	size;

	if (uur->uur_info == 0)
		UndoRecordSetInfo(uur);

	size = SizeOfUndoRecordHeader;
	if ((uur->uur_info & UREC_INFO_RELATION_DETAILS) != 0)
		size += SizeOfUndoRecordRelationDetails;
	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
		size += SizeOfUndoRecordBlock;
	if ((uur->uur_info & UREC_INFO_TRANSACTION) != 0)
		size += SizeOfUndoRecordTransaction;
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		size += SizeOfUndoRecordPayload;
		size += uur->uur_payload.len;
		size += uur->uur_tuple.len;
	}

	return size;
}

/*
 * Insert as much of an undo record as will fit in the given page.
 * starting_byte is the byte within the give page at which to begin
 * writing, while *already_written is the number of bytes written to
 * previous pages.  Returns true if the remainder of the record was
 * written and false if more bytes remain to be written; in either
 * case, *already_written is set to the number of bytes written thus
 * far.
 *
 * This function assumes that if *already_written is non-zero on entry,
 * the same UnpackedUndoRecord is passed each time.  It also assumes
 * that UnpackUndoRecord is not called between successive calls to
 * InsertUndoRecord for the same UnpackedUndoRecord.
 */
bool
InsertUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_written)
{
	char   *writeptr = (char *) page + starting_byte;
	char   *endptr = (char *) page + BLCKSZ;
	int		my_bytes_written = *already_written;

	if (uur->uur_info == 0)
		UndoRecordSetInfo(uur);

	/*
	 * If this is the first call, copy the UnpackedUndoRecord into the
	 * temporary variables of the types that will actually be stored in the
	 * undo pages.  We just initialize everything here, on the assumption
	 * that it's not worth adding branches to save a handful of assignments.
	 */
	if (*already_written == 0)
	{
		work_hdr.urec_type = uur->uur_type;
		work_hdr.urec_info = uur->uur_info;
		work_hdr.urec_prevlen = uur->uur_prevlen;
		work_hdr.urec_relfilenode = uur->uur_relfilenode;
		work_hdr.urec_prevxid = uur->uur_prevxid;
		work_hdr.urec_xid = uur->uur_xid;
		work_hdr.urec_cid = uur->uur_cid;
		work_rd.urec_tsid = uur->uur_tsid;
		work_rd.urec_fork = uur->uur_fork;
		work_blk.urec_blkprev = uur->uur_blkprev;
		work_blk.urec_block = uur->uur_block;
		work_blk.urec_offset = uur->uur_offset;
		work_txn.urec_next = uur->uur_next;
		work_payload.urec_payload_len = uur->uur_payload.len;
		work_payload.urec_tuple_len = uur->uur_tuple.len;
	}
	else
	{
		/*
		 * We should have been passed the same record descriptor as before,
		 * or caller has messed up.
		 */
		Assert(work_hdr.urec_type == uur->uur_type);
		Assert(work_hdr.urec_info == uur->uur_info);
		Assert(work_hdr.urec_prevlen == uur->uur_prevlen);
		Assert(work_hdr.urec_relfilenode == uur->uur_relfilenode);
		Assert(work_hdr.urec_prevxid == uur->uur_prevxid);
		Assert(work_hdr.urec_xid == uur->uur_xid);
		Assert(work_hdr.urec_cid == uur->uur_cid);
		Assert(work_rd.urec_tsid == uur->uur_tsid);
		Assert(work_rd.urec_fork == uur->uur_fork);
		Assert(work_blk.urec_blkprev == uur->uur_blkprev);
		Assert(work_blk.urec_block == uur->uur_block);
		Assert(work_blk.urec_offset == uur->uur_offset);
		Assert(work_txn.urec_next == uur->uur_next);
		Assert(work_payload.urec_payload_len == uur->uur_payload.len);
		Assert(work_payload.urec_tuple_len == uur->uur_tuple.len);
	}

	/* Write header (if not already done). */
	if (!InsertUndoBytes((char *) &work_hdr, SizeOfUndoRecordHeader,
						 &writeptr, endptr,
						 &my_bytes_written, already_written))
		return false;

	/* Write relation details (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_RELATION_DETAILS) != 0 &&
		!InsertUndoBytes((char *) &work_rd, SizeOfUndoRecordRelationDetails,
						 &writeptr, endptr,
						 &my_bytes_written, already_written))
		return false;

	/* Write block information (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_BLOCK) != 0 &&
		!InsertUndoBytes((char *) &work_blk, SizeOfUndoRecordBlock,
						 &writeptr, endptr,
						 &my_bytes_written, already_written))
		return false;

	/* Write transaction information (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_TRANSACTION) != 0 &&
		!InsertUndoBytes((char *) &work_txn, SizeOfUndoRecordTransaction,
						 &writeptr, endptr,
						 &my_bytes_written, already_written))
		return false;

	/* Write payload information (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		/* Payload header. */
		if (!InsertUndoBytes((char *) &work_payload, SizeOfUndoRecordPayload,
							 &writeptr, endptr,
							 &my_bytes_written, already_written))
			return false;

		/* Payload bytes. */
		if (uur->uur_payload.len > 0 &&
			!InsertUndoBytes(uur->uur_payload.data, uur->uur_payload.len,
							 &writeptr, endptr,
							 &my_bytes_written, already_written))
			return false;

		/* Tuple bytes. */
		if (uur->uur_tuple.len > 0 &&
			!InsertUndoBytes(uur->uur_tuple.data, uur->uur_tuple.len,
							 &writeptr, endptr,
							 &my_bytes_written, already_written))
			return false;
	}

	/* Hooray! */
	return true;
}

/*
 * Write undo bytes from a particular source, but only to the extent that
 * they weren't written previously and will fit.
 *
 * 'sourceptr' points to the source data, and 'sourcelen' is the length of
 * that data in bytes.
 *
 * 'writeptr' points to the insertion point for these bytes, and is updated
 * for whatever we write.  The insertion point must not pass 'endptr', which
 * represents the end of the buffer into which we are writing.
 *
 * 'my_bytes_written' is a pointer to the count of previous-written bytes
 * from this and following structures in this undo record; that is, any
 * bytes that are part of previous structures in the record have already
 * been subtracted out.  We must update it for the bytes we write.
 *
 * 'total_bytes_written' points to the count of all previously-written bytes,
 * and must likewise be updated for the bytes we write.
 *
 * The return value is false if we ran out of space before writing all
 * the bytes, and otherwise true.
 */
static bool
InsertUndoBytes(char *sourceptr, int sourcelen,
				char **writeptr, char *endptr,
				int *my_bytes_written, int *total_bytes_written)
{
	int		can_write;
	int		remaining;

	/*
	 * If we've previously written all of these bytes, there's nothing
	 * to do except update *my_bytes_written, which we must do to ensure
	 * that the next call to this function gets the right starting value.
	 */
	if (*my_bytes_written >= sourcelen)
	{
		*my_bytes_written -= sourcelen;
		return true;
	}

	/* Compute number of bytes we can write. */
	remaining = sourcelen - *my_bytes_written;
	can_write = Min(remaining, endptr - *writeptr);

	/* Bail out if no bytes can be written. */
	if (can_write == 0)
		return false;

	/* Copy the bytes we can write. */
	memcpy(*writeptr, sourceptr + *my_bytes_written, can_write);

	/* Update bookkeeeping infrormation. */
	*writeptr += can_write;
	*total_bytes_written += can_write;
	*my_bytes_written = 0;

	/* Return true only if we wrote the whole thing. */
	return (can_write == remaining);
}

/*
 * Call UnpackUndoRecord() one or more times to unpack an undo record.  For
 * the first call, starting_byte should be set to the beginning of the undo
 * record within the specified page, and *already_decoded should be set to 0;
 * the function will update it based on the number of bytes decoded.  The
 * return value is true if the entire record was unpacked and false if the
 * record continues on the next page.  In the latter case, the function
 * should be called again with the next page, passing starting_byte as the
 * sizeof(PageHeaderData).
 */
bool UnpackUndoRecord(UnpackedUndoRecord *uur, Page page, int starting_byte,
					  int *already_decoded)
{
	char	*readptr = (char *)page + starting_byte;
	char	*endptr = (char *) page + BLCKSZ;
	int		my_bytes_decoded = *already_decoded;
	bool	is_undo_splited = (my_bytes_decoded > 0) ? true : false;

	/* Decode header (if not already done). */
	if (!ReadUndoBytes((char *) &work_hdr, SizeOfUndoRecordHeader,
					   &readptr, endptr,
					   &my_bytes_decoded, already_decoded, false))
		return false;

	uur->uur_type = work_hdr.urec_type;
	uur->uur_info = work_hdr.urec_info;
	uur->uur_prevlen = work_hdr.urec_prevlen;
	uur->uur_relfilenode = work_hdr.urec_relfilenode;
	uur->uur_prevxid = work_hdr.urec_prevxid;
	uur->uur_xid = work_hdr.urec_xid;
	uur->uur_cid = work_hdr.urec_cid;

	if ((uur->uur_info & UREC_INFO_RELATION_DETAILS) != 0)
	{
		/* Decode header (if not already done). */
		if (!ReadUndoBytes((char *) &work_rd, SizeOfUndoRecordRelationDetails,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded, false))
			return false;

		uur->uur_tsid = work_rd.urec_tsid;
		uur->uur_fork = work_rd.urec_fork;
	}

	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		if (!ReadUndoBytes((char *) &work_blk, SizeOfUndoRecordBlock,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded, false))
			return false;

		uur->uur_blkprev = work_blk.urec_blkprev;
		uur->uur_block = work_blk.urec_block;
		uur->uur_offset = work_blk.urec_offset;
	}

	if ((uur->uur_info & UREC_INFO_TRANSACTION) != 0)
	{
		if (!ReadUndoBytes((char *) &work_txn, SizeOfUndoRecordTransaction,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded, false))
			return false;

		uur->uur_next = work_txn.urec_next;
	}

	/* Read payload information (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		if (!ReadUndoBytes((char *) &work_payload, SizeOfUndoRecordPayload,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded, false))
			return false;

		uur->uur_payload.len = work_payload.urec_payload_len;
		uur->uur_tuple.len = work_payload.urec_tuple_len;

		/*
		 * If we can read the complete record from a single page then just
		 * point payload data and tuple data into the page otherwise allocate
		 * the memory.
		 *
		 * XXX There is possibility of optimization that instead of always
		 * allocating the memory whenever tuple is split we can check if any of
		 * the payload or tuple data falling into the same page then don't
		 * allocate the memory for that.
		 */
		if (!is_undo_splited &&
			uur->uur_payload.len + uur->uur_tuple.len <= (endptr - readptr))
		{
			uur->uur_payload.data = readptr;
			readptr += uur->uur_payload.len;

			uur->uur_tuple.data = readptr;
		}
		else
		{
			if (uur->uur_payload.len > 0 && uur->uur_payload.data == NULL)
				uur->uur_payload.data = (char *) palloc0(uur->uur_payload.len);

			if (uur->uur_tuple.len > 0 && uur->uur_tuple.data == NULL)
				uur->uur_tuple.data = (char *) palloc0(uur->uur_tuple.len);

			if (!ReadUndoBytes((char *) uur->uur_payload.data,
							   uur->uur_payload.len, &readptr, endptr,
							   &my_bytes_decoded, already_decoded, false))
				return false;

			if (!ReadUndoBytes((char *) uur->uur_tuple.data,
							   uur->uur_tuple.len, &readptr, endptr,
							   &my_bytes_decoded, already_decoded, false))
				return false;
		}
	}

	return true;
}

/*
 * Read undo bytes into a particular destination,
 *
 * 'destptr' points to the source data, and 'readlen' is the length of
 * that data to be read in bytes.
 *
 * 'readptr' points to the read point for these bytes, and is updated
 * for how much we read.  The read point must not pass 'endptr', which
 * represents the end of the buffer from which we are reading.
 *
 * 'my_bytes_read' is a pointer to the count of previous-read bytes
 * from this and following structures in this undo record; that is, any
 * bytes that are part of previous structures in the record have already
 * been subtracted out.  We must update it for the bytes we read.
 *
 * 'total_bytes_read' points to the count of all previously-read bytes,
 * and must likewise be updated for the bytes we read.
 *
 * nocopy if this flag is set true then it will just skip the readlen
 * size in undo but it will not copy into the buffer.
 *
 * The return value is false if we ran out of space before read all
 * the bytes, and otherwise true.
 */
static bool
ReadUndoBytes(char *destptr, int readlen, char **readptr, char *endptr,
			  int *my_bytes_read, int *total_bytes_read, bool nocopy)
{
	int		can_read;
	int		remaining;

	if (*my_bytes_read >= readlen)
	{
		*my_bytes_read -= readlen;
		return true;
	}

	/* Compute number of bytes we can read. */
	remaining = readlen - *my_bytes_read;
	can_read = Min(remaining, endptr - *readptr);

	/* Bail out if no bytes can be read. */
	if (can_read == 0)
		return false;

	/* Copy the bytes we can read. */
	if (!nocopy)
		memcpy(destptr + *my_bytes_read, *readptr, can_read);

	/* Update bookkeeping information. */
	*readptr += can_read;
	*total_bytes_read += can_read;
	*my_bytes_read = 0;

	/* Return true only if we wrote the whole thing. */
	return (can_read == remaining);
}

/*
 * Update the transaction information inside the undo record
 *
 * First prepare undo record for the new transaction will invoke this routine
 * to update its first undo record pointer in previous transaction's first undo
 * record.
 *
 * FIXME this should be WAL logged.
 */
void
UndoRecordUpdateTransactionInfo(UndoRecPtr urecptr)
{
	Buffer		buffer = InvalidBuffer;
	BlockNumber	cur_blk;
	RelFileNode	rnode;
	UndoLogNumber logno = UndoRecPtrGetLogNo(urecptr);
	Page		page;
	char	   *readptr;
	char	   *endptr;
	int			my_bytes_decoded = 0;
	int			already_decoded = 0;
	int			starting_byte;

	/*
	 * If previous transaction's urp is not valid means this backend is
	 * preparing its first undo so fetch the information from the undo log
	 * if it's still invalid urp means this is the first undo record for this
	 * log and we have nothing to update.
	 */
	if (!UndoRecPtrIsValid(prev_xact_urp) || InRecovery)
		prev_xact_urp = UndoLogGetLastXactStartPoint(logno);

	if (!UndoRecPtrIsValid(prev_xact_urp))
		return;

	/*
	 * Acquire the discard lock before accessing the undo record so that
	 * discard worker doen't remove the record while we are in process of
	 * reading it.
	 */
	LWLockAcquire(&UndoDiscardInfo[logno].mutex, LW_SHARED);

	UndoRecPtrAssignRelFileNode(rnode, prev_xact_urp);
	cur_blk = UndoRecPtrGetBlockNum(prev_xact_urp);
	starting_byte = UndoRecPtrGetPageOffset(prev_xact_urp);

	/* If it's already discarded then we have nothing to do. */
	if (prev_xact_urp < UndoDiscardInfo[logno].undo_recptr)
	{
		LWLockRelease(&UndoDiscardInfo[logno].mutex);
		return;
	}

	while (true)
	{
		/* Go to the next block if already_decoded is non zero */
		if (already_decoded != 0)
		{
			starting_byte = UndoLogBlockHeaderSize;
			my_bytes_decoded = already_decoded;
			UnlockReleaseBuffer(buffer);
			cur_blk++;
		}

		buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
										   RBM_NORMAL, NULL);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);

		readptr = (char *)page + starting_byte;
		endptr = (char *) page + BLCKSZ;

		/* Decode header. */
		if (!ReadUndoBytes((char *) &work_hdr, SizeOfUndoRecordHeader,
						   &readptr, endptr,
						   &my_bytes_decoded, &already_decoded, false))
			continue;

		/* If the undo record has the relation header then just skip it. */
		if ((work_hdr.urec_info & UREC_INFO_RELATION_DETAILS) != 0)
		{
			if (!ReadUndoBytes((char *) &work_rd, SizeOfUndoRecordRelationDetails,
							   &readptr, endptr,
							   &my_bytes_decoded, &already_decoded, true))
				continue;
		}

		/* If the undo record has the block header then just skip it. */
		if ((work_hdr.urec_info & UREC_INFO_BLOCK) != 0)
		{
			if (!ReadUndoBytes((char *) &work_blk, SizeOfUndoRecordBlock,
							   &readptr, endptr,
							   &my_bytes_decoded, &already_decoded, true))
				continue;
		}

		/* The undo record must have transaction header. */
		Assert(work_hdr.urec_info & UREC_INFO_TRANSACTION);

		/*
		 * Update the next transactions start urecptr in the transaction
		 * header.
		 */
		work_txn.urec_next = urecptr;
		if (!InsertUndoBytes((char*)&work_txn, SizeOfUndoRecordTransaction,
							&readptr, endptr,
							&my_bytes_decoded, &already_decoded))
			continue;

		UnlockReleaseBuffer(buffer);

		break;
	}

	LWLockRelease(&UndoDiscardInfo[logno].mutex);
}

/*
 * Set uur_info for an UnpackedUndoRecord appropriately based on which
 * other fields are set.
 */
static void
UndoRecordSetInfo(UnpackedUndoRecord *uur)
{
	if (uur->uur_tsid != DEFAULTTABLESPACE_OID ||
		uur->uur_fork != MAIN_FORKNUM)
		uur->uur_info |= UREC_INFO_RELATION_DETAILS;
	if (uur->uur_block != InvalidBlockNumber)
		uur->uur_info |= UREC_INFO_BLOCK;
	if (uur->uur_next != InvalidUndoRecPtr)
		uur->uur_info |= UREC_INFO_TRANSACTION;
	if (uur->uur_payload.len || uur->uur_tuple.len)
		uur->uur_info |= UREC_INFO_PAYLOAD;
}

/*
 * Find the block number in undo buffer array, if it's present then just return
 * its index otherwise search the buffer and insert an entry.
 */
static int
InsertFindBufferSlot(RelFileNode rnode, BlockNumber blk)
{
	int 	i;
	Buffer 	buffer;

	/* Don't do anything, if we already have a buffer pinned for the block. */
	for (i = 0; i < buffer_idx; i++)
	{
		if (blk == undo_buffer[i].blk)
			break;
	}

	/*
	 * We did not find the block so allocate the buffer and insert into the
	 * undo buffer array
	 */
	if (i == buffer_idx)
	{
		/*
		 * Fetch the buffer in which we want to insert the undo record.
		 *
		 * FIXME: This API can't be used for persistence level temporary
		 * and unlogged.
		 */
		buffer = ReadBufferWithoutRelcache(rnode,
										   UndoLogForkNum,
										   blk,
										   RBM_NORMAL,
										   NULL);
		undo_buffer[buffer_idx].buf = buffer;
		undo_buffer[buffer_idx].blk = blk;
		buffer_idx++;
	}

	return i;
}

/*
 * Call UndoSetPrepareSize to set the value of how many maximum prepared can
 * be done before inserting the prepared undo.  If size is > MAX_PREPARED_UNDO
 * then it will allocate extra memory to hold the extra prepared undo.
 */
void
UndoSetPrepareSize(int max_prepare)
{
	if (max_prepare <= MAX_PREPARED_UNDO)
		return;

	prepared_undo = palloc0(max_prepare * sizeof(PreparedUndoSpace));
	undo_buffer = palloc0(max_prepare * MAX_BUFFER_PER_UNDO *
						 sizeof(UndoBuffers));
	max_prepare_undo = max_prepare;
}

/*
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned.
 * This should be done before any critical section is established, since it
 * can fail.
 */
UndoRecPtr
PrepareUndoInsert(UnpackedUndoRecord *urec, UndoPersistence upersistence,
				  TransactionId xid)
{
	UndoRecordSize	size;
	UndoRecPtr		urecptr;
	RelFileNode		rnode;
	UndoRecordSize  cur_size = 0;
	BlockNumber		cur_blk;
	TransactionId	txid;
	int				starting_byte;
	int				index = 0;
	int				bufidx;
	bool			need_start_undo = false;

	/* Already reached maximum prepared limit. */
	if (prepare_idx == max_prepare_undo)
		return InvalidUndoRecPtr;

	/*
	 * If this is the first undo record for this top transaction add the
	 * transaction information to the undo record.
	 *
	 * XXX there is also an option that instead of adding the information to
	 * this record we can prepare a new record which only contain transaction
	 * informations.
	 */
	if (xid == InvalidTransactionId)
	{
		/* we expect during recovery, we always have a valid transaction id. */
		Assert (!InRecovery);
		txid = GetTopTransactionId();
	}
	else
	{
		/*
		 * Get the top transaction id because undo log only stores mapping for
		 * the top most transactions.
		 */
		txid = SubTransGetTopmostTransaction(xid);
	}


	/*
	 * If this is the first undo record for this transaction then set the
	 * uur_next to the SpecialUndoRecPtr.  This is the indication to allocate
	 * the space for the transaction header and the valid value of the uur_next
	 * will be updated while preparing the first undo record of the next
	 * transaction.
	 */
	if (prev_txid != txid && (!InRecovery || IsTransactionFirstRec(txid)))
		need_start_undo = true;

	if (need_start_undo)
		urec->uur_next = SpecialUndoRecPtr;
	else
		urec->uur_next = InvalidUndoRecPtr;

	/* calculate the size of the undo record. */
	size = UndoRecordExpectedSize(urec);

	if (InRecovery)
		urecptr = UndoLogAllocateInRecovery(xid, size, upersistence);
	else
		urecptr = UndoLogAllocate(size, upersistence);

	/*
	 * If transaction id is switched then update the previous transaction's
	 * start undo record.
	 */
	if (need_start_undo)
	{
		UndoRecordUpdateTransactionInfo(urecptr);

		/* Remember the current transactions xid and start undorecptr. */
		prev_xact_urp = urecptr;
		prev_txid = txid;

		/* Store the current transaction's start undorecptr in the undo log. */
		UndoLogSetLastXactStartPoint(urecptr);
	}

	UndoLogAdvance(urecptr, size);
	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	UndoRecPtrAssignRelFileNode(rnode, urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	do
	{
		bufidx = InsertFindBufferSlot(rnode, cur_blk);
		if (cur_size == 0)
			cur_size = BLCKSZ - starting_byte;
		else
			cur_size += BLCKSZ - UndoLogBlockHeaderSize;

		/* FIXME: Should we just report error ? */
		Assert(index < MAX_BUFFER_PER_UNDO);

		/* Keep the track of the buffers we have pinned. */
		prepared_undo[prepare_idx].undo_buffer_idx[index++] = bufidx;

		/* Undo record can not fit into this block so go to the next block. */
		cur_blk++;
	} while (cur_size < size);

	/*
	 * Save referenced of undo record pointer as well as undo record.
	 * InsertPreparedUndo will use these to insert the prepared record.
	 */
	prepared_undo[prepare_idx].urec = urec;
	prepared_undo[prepare_idx].urp = urecptr;
	prepare_idx++;

	return urecptr;
}

/*
 * Insert a previously-prepared undo record.  This will lock the buffers
 * pinned in the previous step, write the actual undo record into them,
 * and mark them dirty.  For persistent undo, this step should be performed
 * after entering a critical section; it should never fail.
 */
void
InsertPreparedUndo(void)
{
	Page	page;
	int		starting_byte;
	int		already_written;
	int		bufidx = 0;
	int		idx;
	uint16	undo_len = 0;
	UndoRecPtr	urp;
	UnpackedUndoRecord	*uur;

	Assert(prepare_idx > 0);

	/* Lock all the buffers and mark them dirty. */
	for (idx = 0; idx < buffer_idx; idx++)
		LockBuffer(undo_buffer[idx].buf, BUFFER_LOCK_EXCLUSIVE);

	for (idx = 0; idx < prepare_idx; idx++)
	{
		uur = prepared_undo[idx].urec;
		urp = prepared_undo[idx].urp;

		already_written = 0;
		bufidx = 0;
		starting_byte = UndoRecPtrGetPageOffset(urp);

		/* store the previous undo record length in the header */
		uur->uur_prevlen = prev_undolen;
		undo_len = 0;

		do
		{
			PreparedUndoSpace undospace = prepared_undo[idx];
			Buffer  buffer;

			buffer = undo_buffer[undospace.undo_buffer_idx[bufidx]].buf;
			page = BufferGetPage(buffer);

			/*
			 * Initialize the page whenever we try to write the first record
			 * in page.
			 */
			if (starting_byte == UndoLogBlockHeaderSize)
				PageInit(page, BLCKSZ, 0);

			/*
			 * Try to insert the record into the current page. If it doesn't
			 * succeed then recall the routine with the next page.
			 */
			if (InsertUndoRecord(uur, page, starting_byte, &already_written))
			{
				undo_len = already_written;
				MarkBufferDirty(buffer);
				break;
			}

			undo_len = already_written;

			MarkBufferDirty(buffer);
			starting_byte = UndoLogBlockHeaderSize;
			bufidx++;

			/*
			 * If we are swithing to the next block then consider the header
			 * in total undo length.
			 */
			undo_len += UndoLogBlockHeaderSize;

			Assert(bufidx < MAX_BUFFER_PER_UNDO);
		} while(true);

		prev_undolen = undo_len;

		/*
		 * Set the current undo location for a transaction.  This is required
		 * to perform rollback during abort of transaction.
		 */
		SetCurrentUndoLocation(urp);
	}
}

/*
 * Prototype just to ensure that code gets compiled.
 */
void
SetUndoPageLSNs(XLogRecPtr lsn)
{
	return;
}

/*
 * Unlock and release undo buffers.  This step performed after exiting any
 * critical section.
 */
void
UnlockReleaseUndoBuffers(void)
{
	int	i;
	for (i = 0; i < buffer_idx; i++)
	{
		UnlockReleaseBuffer(undo_buffer[i].buf);
		undo_buffer[i].blk = InvalidBlockNumber;
		undo_buffer[i].buf = InvalidBlockNumber;
	}

	/* Reset the prepared index. */
	prepare_idx = 0;
	buffer_idx = 0;

	/*
	 * max_prepare_undo limit is changed so free the allocated memory and reset
	 * all the variable back to its default value.
	 */
	if (max_prepare_undo > MAX_PREPARED_UNDO)
	{
		pfree(undo_buffer);
		pfree(prepared_undo);
		undo_buffer = def_buffers;
		prepared_undo = def_prepared;
		max_prepare_undo = MAX_PREPARED_UNDO;
	}
}

/*
 * Helper function for UndoFetchRecord.  It will fetch the undo record pointed
 * by urp and unpack the record into urec.  This function will not release the
 * pin on the buffer if complete record is fetched from one buffer,  now caller
 * can reuse the same urec to fetch the another undo record which is on the
 * same block.  Caller will be responsible to release the buffer inside urec
 * and set it to invalid if he wishes to fetch the record from another block.
 */
static UnpackedUndoRecord*
UndoGetOneRecord(UnpackedUndoRecord *urec, UndoRecPtr urp, RelFileNode rnode)
{
	Buffer			 buffer = urec->uur_buffer;
	Page			 page;
	int				 starting_byte = UndoRecPtrGetPageOffset(urp);
	int				 already_decoded = 0;
	BlockNumber		 cur_blk;
	bool			 is_undo_splited = false;

	cur_blk = UndoRecPtrGetBlockNum(urp);

	/* If we already have a previous buffer then no need to allocate new. */
	if (!BufferIsValid(buffer))
	{
		buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
										   RBM_NORMAL, NULL);

		urec->uur_buffer = buffer;
	}

	while (true)
	{
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);

		/*
		 * FIXME: This can be optimized to just fetch header first and only
		 * if matches with block number and offset then fetch the complete
		 * record.
		 */
		if (UnpackUndoRecord(urec, page, starting_byte, &already_decoded))
			break;

		starting_byte = UndoLogBlockHeaderSize;
		is_undo_splited = true;

		/*
		 * Complete record is not fitting into one buffer so release the buffer
		 * pin and also set invalid buffer in the undo record.
		 */
		urec->uur_buffer = InvalidBuffer;
		UnlockReleaseBuffer(buffer);

		/* Go to next block. */
		cur_blk++;
		buffer = ReadBufferWithoutRelcache(rnode, UndoLogForkNum, cur_blk,
										   RBM_NORMAL, NULL);
	}

	/*
	 * If we have copied the data then release the buffer. Otherwise just
	 * unlock it.
	 */
	if (is_undo_splited)
		UnlockReleaseBuffer(buffer);
	else
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	return urec;
}

/*
 * Fetch the next undo record for given blkno, offset and transaction id (if
 * valid).  We need to match transaction id along with block number and offset
 * because in some cases (like reuse of slot for committed transaction), we
 * need to skip the record if it is modified by a transaction later than the
 * transaction indicated by previous undo record.  For example, consider a
 * case where tuple (ctid - 0,1) is modified by transaction id 500 which
 * belongs to transaction slot 0. Then, the same tuple is modified by
 * transaction id 501 which belongs to transaction slot 1.  Then, both the
 * transaction slots are marked for reuse. Then, again the same tuple is
 * modified by transaction id 502 which has used slot 0.  Now, some
 * transaction which has started before transaction 500 wants to traverse the
 * chain to find visible tuple will keep on rotating infinitely between undo
 * tuple written by 502 and 501.  In such a case, we need to skip the undo
 * tuple written by transaction 502 when we want to find the undo record
 * indicated by the previous pointer of undo tuple written by transaction 501.
 * Start the search from urp.  Caller need to call UndoRecordRelease to release the
 * resources allocated by this function.
 */
UnpackedUndoRecord*
UndoFetchRecord(UndoRecPtr urp, BlockNumber blkno, OffsetNumber offset,
				TransactionId xid)
{
	RelFileNode		 rnode, prevrnode = {0};
	UnpackedUndoRecord *urec = NULL;
	int	logno;

	urec = palloc0(sizeof(UnpackedUndoRecord));

	/* Find the undo record pointer we are interested in. */
	while (true)
	{
		UndoRecPtrAssignRelFileNode(rnode, urp);

		/*
		 * If we have a valid buffer pinned then just ensure that we want to
		 * find the next tuple from the same block.  Otherwise release the
		 * buffer and set it invalid
		 */
		if (BufferIsValid(urec->uur_buffer))
		{
			/*
			 * Undo buffer will be changed if the next undo record belongs to a
			 * different block or undo log.
			 */
			if (UndoRecPtrGetBlockNum(urp) != BufferGetBlockNumber(urec->uur_buffer) ||
				(prevrnode.relNode != rnode.relNode))
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
		prevrnode = rnode;

		logno = UndoRecPtrGetLogNo(urp);
		LWLockAcquire(&UndoDiscardInfo[logno].mutex, LW_SHARED);

		if (urp < UndoDiscardInfo[logno].undo_recptr)
		{
			LWLockRelease(&UndoDiscardInfo[logno].mutex);

			if (BufferIsValid(urec->uur_buffer))
				ReleaseBuffer(urec->uur_buffer);

			return NULL;
		}

		LWLockRelease(&UndoDiscardInfo[logno].mutex);

		/* Fetch the current undo record. */
		urec = UndoGetOneRecord(urec, urp, rnode);
		if (blkno == InvalidBlockNumber)
			break;

		if ((urec->uur_block == blkno && urec->uur_offset == offset) &&
			(!TransactionIdIsValid(xid) || TransactionIdEquals(xid, urec->uur_xid)))
			break;

		urp = urec->uur_blkprev;
	}

	return urec;
}

/*
 * Return the previous undo record pointer.
 */
UndoRecPtr
UndoGetPrevUndoRecptr(UndoRecPtr urp, uint16 prevlen)
{
	UndoLogNumber logno = UndoRecPtrGetLogNo(urp);
	UndoLogOffset offset = UndoRecPtrGetOffset(urp);

	/* calculate the previous undo record pointer */
	return MakeUndoRecPtr (logno, offset - prevlen);
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

	pfree (urec);
}
