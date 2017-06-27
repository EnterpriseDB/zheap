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

#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/undoinsert.h"
#include "catalog/pg_tablespace.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"

/*
 * FIXME:  Do we want to support undo tuple size which is more than the BLCKSZ
 * if not than undo record can spread across 2 buffers at the max.
 */
#define MAX_UNDO_BUUFER	2

/* Workspace for InsertUndoRecord and UnpackUndoRecord. */
static UndoRecordHeader work_hdr;
static UndoRecordRelationDetails work_rd;
static UndoRecordBlock work_blk;
static UndoRecordPayload work_payload;
static Buffer undobuffers[MAX_UNDO_BUUFER];

/*
 * Unpacked undo record reference passed to PrepareUndoInsert which will be
 * later used by InsertPreparedUndo.
 */
static UnpackedUndoRecord *undo_rec;

/*
 * undo record pointer allocated for storing the current undo which will be
 * later used by InsertPreparedUndo.
 */
static UndoRecPtr undo_rec_ptr;

/* Prototypes for static functions. */
static void UndoRecordSetInfo(UnpackedUndoRecord *uur);
static bool InsertUndoBytes(char *sourceptr, int sourcelen,
				char **writeptr, char *endptr,
				int *my_bytes_written, int *total_bytes_written);
static bool ReadUndoBytes(char *destptr, int readlen,
			  char **readptr, char *endptr,
			  int *my_bytes_read, int *total_bytes_read);
static UnpackedUndoRecord* UndoGetOneRecord(UnpackedUndoRecord *urec,
											UndoRecPtr urp, RelFileNode rnode);

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
		work_rd.urec_tsid = uur->uur_tsid;
		work_rd.urec_fork = uur->uur_fork;
		work_blk.urec_blkprev = uur->uur_blkprev;
		work_blk.urec_block = uur->uur_block;
		work_blk.urec_offset = uur->uur_offset;
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
		Assert(work_rd.urec_tsid == uur->uur_tsid);
		Assert(work_rd.urec_fork == uur->uur_fork);
		Assert(work_blk.urec_blkprev == uur->uur_blkprev);
		Assert(work_blk.urec_block == uur->uur_block);
		Assert(work_blk.urec_offset == uur->uur_offset);
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

	if (*already_decoded == 0)
	{
		UndoRecordHeader *wrk_hdr = (UndoRecordHeader*)readptr;

		uur->uur_type = wrk_hdr->urec_type;
		uur->uur_info = wrk_hdr->urec_info;
		uur->uur_prevlen = wrk_hdr->urec_prevlen;
		uur->uur_relfilenode = wrk_hdr->urec_relfilenode;

		readptr += SizeOfUndoRecordHeader;
	}

	if ((uur->uur_info & UREC_INFO_RELATION_DETAILS) != 0)
	{
		/* Decode header (if not already done). */
		if (!ReadUndoBytes((char *) &work_rd, SizeOfUndoRecordRelationDetails,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded))
			return false;

		uur->uur_tsid = work_rd.urec_tsid;
		uur->uur_fork = work_rd.urec_fork;
	}

	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		if (!ReadUndoBytes((char *) &work_blk, SizeOfUndoRecordBlock,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded))
			return false;

		uur->uur_blkprev = work_blk.urec_blkprev;
		uur->uur_block = work_blk.urec_block;
		uur->uur_offset = work_blk.urec_offset;
	}

	/* Read payload information (if needed and not already done). */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		if (!ReadUndoBytes((char *) &work_payload, SizeOfUndoRecordPayload,
							&readptr, endptr,
							&my_bytes_decoded, already_decoded))
			return false;

		uur->uur_payload.len = work_payload.urec_payload_len;
		uur->uur_tuple.len = work_payload.urec_tuple_len;

		/* Payload bytes. */
		if (uur->uur_payload.len > 0)
		{
			if (uur->uur_payload.data == NULL)
			{
				uur->uur_payload.data = readptr;
				readptr += uur->uur_payload.len;
			}
			else if (!ReadUndoBytes((char *) uur->uur_payload.data,
					 uur->uur_payload.len, &readptr, endptr,
					 &my_bytes_decoded, already_decoded))
				return false;
		}

		/* Tuple bytes. */
		if (uur->uur_tuple.len > 0)
		{
			if (uur->uur_tuple.data == NULL)
				uur->uur_tuple.data = readptr;
			else if (!ReadUndoBytes((char *) uur->uur_tuple.data,
					 uur->uur_tuple.len, &readptr, endptr,
					 &my_bytes_decoded, already_decoded))
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
 * The return value is false if we ran out of space before read all
 * the bytes, and otherwise true.
 */
static bool
ReadUndoBytes(char *destptr, int readlen,
			  char **readptr, char *endptr,
			  int *my_bytes_read, int *total_bytes_read)
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
	memcpy(destptr + *my_bytes_read, *readptr, can_read);

	/* Update bookkeeping information. */
	*readptr += can_read;
	*total_bytes_read += can_read;
	*my_bytes_read = 0;

	/* Return true only if we wrote the whole thing. */
	return (can_read == remaining);
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
	if (uur->uur_payload.len || uur->uur_tuple.len)
		uur->uur_info |= UREC_INFO_PAYLOAD;
}

/*
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned.
 * This should be done before any critical section is established, since it
 * can fail.
 */
UndoRecPtr
PrepareUndoInsert(UnpackedUndoRecord *urec, UndoPersistence upersistence)
{
	UndoRecordSize	size;
	UndoRecPtr		urecptr;
	RelFileNode		rnode;
	Buffer			buffer;
	UndoRecordSize  cur_size = 0;
	BlockNumber		cur_blk;
	int				starting_byte;
	int				index = 0;

	/* calculate the size of the undo record */
	size = UndoRecordExpectedSize(urec);

	urecptr = UndoLogAllocate(size, upersistence);
	UndoLogAdvance(urecptr, size);
	cur_blk = UndoRecPtrGetBlockNum(urecptr);
	UndoRecPtrAssignRelFileNode(rnode, urecptr);
	starting_byte = UndoRecPtrGetPageOffset(urecptr);

	do
	{
		/*
		 * FIXME: This API can't be used for persistence level temporary
		 * and unlogged.
		 */

		/* Fetch the buffer in which we want to insert the undo record. */
		buffer = ReadBufferWithoutRelcache(rnode,
										   UndoLogForkNum,
										   cur_blk,
										   RBM_NORMAL,
										   NULL);
		if (cur_size == 0)
			cur_size = BLCKSZ - starting_byte;
		else
			cur_size += BLCKSZ;

		/*
		 * Keep the track of the buffers we have pinned.  InsertPreparedUndo
		 * will release the pins and free the memory after inserting the undo
		 * record.
		 */
		undobuffers[index++] = buffer;

		/* FIXME: Should we just report error ? */
		Assert(index < MAX_UNDO_BUUFER);

		/* Undo record can not fit into this block so go to the next block. */
		cur_blk++;
	} while (cur_size < size);

	undobuffers[index] = InvalidBuffer;

	/*
	 * Save referenced of undo record pointer as well as undo record.
	 * InsertPreparedUndo will use these to insert the prepared record.
	 */
	undo_rec = urec;
	undo_rec_ptr = urecptr;

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
	int		already_written = 0;
	int		i;

	starting_byte = UndoRecPtrGetPageOffset(undo_rec_ptr);

	for(i = 0; i < MAX_UNDO_BUUFER; i++)
	{
		Buffer	buffer = undobuffers[i];

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

		page = BufferGetPage(buffer);
		/*
		 * Try to insert the record into the current page. If it doesn't
		 * succeed then recall the routine with the next page.
		 */
		if (InsertUndoRecord(undo_rec, page, starting_byte, &already_written))
			break;

		starting_byte = 0;
	}

	return;
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
	int i;

	for(i = 0; i < MAX_UNDO_BUUFER; i++)
	{
		if (!BufferIsValid(undobuffers[i]))
			break;

		UnlockReleaseBuffer(undobuffers[i]);
	}

	return;
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
	bool			 data_allocated = false;

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

		/*
		 * Complete record is not fitting into one buffer so allocate memory
		 * for payload and tuple data and make copy.
		 */
		urec->uur_buffer = InvalidBuffer;
		if (!data_allocated &&
			(urec->uur_payload.len > 0 || urec->uur_tuple.len > 0))
		{
			char *data;

			if (urec->uur_payload.len)
				data = palloc(urec->uur_payload.len);

			/*
			 * It's possible that we have already decoded the payload header
			 * but havn't yet got the data.
			 */
			if (urec->uur_payload.data)
			{
				memcpy(data, urec->uur_payload.data, urec->uur_payload.len);
				urec->uur_payload.data = data;
			}

			if (urec->uur_tuple.len)
				data = palloc(urec->uur_payload.len);

			if (urec->uur_tuple.data)
			{
				memcpy(data, urec->uur_tuple.data, urec->uur_tuple.len);
				urec->uur_tuple.data = data;
			}

			/*
			 * We have already allocated the memory for payload and tuple data
			 * so we can set this flag.  UnpackUndoRecord will take care of
			 * copying the data if we have already allocated the memory so
			 * next time we need not to worry about copying the data if we
			 * haven't copied.
			 */
			data_allocated = true;
		}

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
	if (data_allocated)
		UnlockReleaseBuffer(buffer);
	else
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	return urec;
}

/*
 * Fetch the next undo record for given blkno and offset.  Start the search
 * from urp.  Caller need to call UndoRecordRelease to release the resources
 * allocated by this function.
 */
UnpackedUndoRecord*
UndoFetchRecord(UndoRecPtr urp, BlockNumber blkno, OffsetNumber offset)
{
	RelFileNode		 rnode;
	BlockNumber		 cur_blk;
	UnpackedUndoRecord *urec;

	urec = palloc0(sizeof(UnpackedUndoRecord));
	cur_blk = UndoRecPtrGetBlockNum(urp);
	UndoRecPtrAssignRelFileNode(rnode, urp);

	/* Find the undo record pointer we are interested in. */
	while (true)
	{
		urec = UndoGetOneRecord(urec, urp, rnode);

		if (blkno == InvalidBlockNumber)
			break;

		if (urec->uur_block == blkno && urec->uur_offset == offset)
		{
			break;
		}
		urp = urec->uur_blkprev;

		/*
		 * If we have a valid buffer pinned then just ensure that we want to
		 * find the next tuple from the same block.  Otherwise release the
		 * buffer and set it invalid
		 */
		if (BufferIsValid(urec->uur_buffer))
		{
			cur_blk = UndoRecPtrGetBlockNum(urp);
			if (cur_blk != BufferGetBlockNumber(urec->uur_buffer))
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

		/* Reset the urec before fetching the next tuple */
		urec->uur_tuple.data = NULL;
		urec->uur_tuple.len = 0;
		urec->uur_payload.data = NULL;
		urec->uur_payload.len = 0;
	}

	return urec;
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
