/*-------------------------------------------------------------------------
 *
 * undorecord.c
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undorecord.c
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/subtrans.h"
#include "access/undorecord.h"
#include "catalog/pg_tablespace.h"
#include "storage/block.h"

/* Workspace for InsertUndoRecord and UnpackUndoRecord. */
static UndoRecordHeader work_hdr;
static UndoRecordRelationDetails work_rd;
static UndoRecordBlock work_blk;
static UndoRecordTransaction work_txn;
static UndoRecordPayload work_payload;

/* Prototypes for static functions. */
static bool InsertUndoBytes(char *sourceptr, int sourcelen,
				char **writeptr, char *endptr,
				int *my_bytes_written, int *total_bytes_written);
static bool ReadUndoBytes(char *destptr, int readlen,
			  char **readptr, char *endptr,
			  int *my_bytes_read, int *total_bytes_read, bool nocopy);

/*
 * Compute and return the expected size of an undo record.
 */
Size
UndoRecordExpectedSize(UnpackedUndoRecord *uur)
{
	Size		size;

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
 * To insert an undo record, call InsertUndoRecord() repeatedly until it
 * returns true.
 *
 * Insert as much of an undo record as will fit in the given page.
 * starting_byte is the byte within the give page at which to begin writing,
 * while *already_written is the number of bytes written to previous pages.
 *
 * Returns true if the remainder of the record was written and false if more
 * bytes remain to be written; in either case, *already_written is set to the
 * number of bytes written thus far.
 *
 * This function assumes that if *already_written is non-zero on entry, the
 * same UnpackedUndoRecord is passed each time.  It also assumes that
 * UnpackUndoRecord is not called between successive calls to InsertUndoRecord
 * for the same UnpackedUndoRecord.
 *
 * If this function is called again to continue writing the record, the
 * previous value for *already_written should be passed again, and
 * starting_byte should be passed as sizeof(PageHeaderData) (since the record
 * will continue immediately following the page header).
 *
 * This function sets uur->uur_info as a side effect.
 */
bool
InsertUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_written, bool header_only)
{
	char	   *writeptr = (char *) page + starting_byte;
	char	   *endptr = (char *) page + BLCKSZ;
	int			my_bytes_written = *already_written;

	/* The undo record must contain a valid information. */
	Assert(uur->uur_info != 0);

	/*
	 * If this is the first call, copy the UnpackedUndoRecord into the
	 * temporary variables of the types that will actually be stored in the
	 * undo pages.  We just initialize everything here, on the assumption that
	 * it's not worth adding branches to save a handful of assignments.
	 */
	if (*already_written == 0)
	{
		work_hdr.urec_type = uur->uur_type;
		work_hdr.urec_info = uur->uur_info;
		work_hdr.urec_prevlen = uur->uur_prevlen;
		work_hdr.urec_reloid = uur->uur_reloid;
		work_hdr.urec_prevxid = uur->uur_prevxid;
		work_hdr.urec_xid = uur->uur_xid;
		work_hdr.urec_cid = uur->uur_cid;
		work_rd.urec_fork = uur->uur_fork;
		work_blk.urec_blkprev = uur->uur_blkprev;
		work_blk.urec_block = uur->uur_block;
		work_blk.urec_offset = uur->uur_offset;
		work_txn.urec_next = uur->uur_next;
		work_txn.urec_xidepoch = uur->uur_xidepoch;
		work_txn.urec_progress = uur->uur_progress;
		work_txn.urec_prevurp = uur->uur_prevurp;
		work_txn.urec_dbid = uur->uur_dbid;
		work_payload.urec_payload_len = uur->uur_payload.len;
		work_payload.urec_tuple_len = uur->uur_tuple.len;
	}
	else
	{
		/*
		 * We should have been passed the same record descriptor as before, or
		 * caller has messed up.
		 */
		Assert(work_hdr.urec_type == uur->uur_type);
		Assert(work_hdr.urec_info == uur->uur_info);
		Assert(work_hdr.urec_prevlen == uur->uur_prevlen);
		Assert(work_hdr.urec_reloid == uur->uur_reloid);
		Assert(work_hdr.urec_prevxid == uur->uur_prevxid);
		Assert(work_hdr.urec_xid == uur->uur_xid);
		Assert(work_hdr.urec_cid == uur->uur_cid);
		Assert(work_rd.urec_fork == uur->uur_fork);
		Assert(work_blk.urec_blkprev == uur->uur_blkprev);
		Assert(work_blk.urec_block == uur->uur_block);
		Assert(work_blk.urec_offset == uur->uur_offset);
		Assert(work_txn.urec_next == uur->uur_next);
		Assert(work_txn.urec_progress == uur->uur_progress);
		Assert(work_txn.urec_prevurp == uur->uur_prevurp);
		Assert(work_txn.urec_dbid == uur->uur_dbid);
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

	if (header_only)
		return true;

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
	int			can_write;
	int			remaining;

	/*
	 * If we've previously written all of these bytes, there's nothing to do
	 * except update *my_bytes_written, which we must do to ensure that the
	 * next call to this function gets the right starting value.
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
bool
UnpackUndoRecord(UnpackedUndoRecord *uur, Page page, int starting_byte,
				 int *already_decoded, bool header_only)
{
	char	   *readptr = (char *) page + starting_byte;
	char	   *endptr = (char *) page + BLCKSZ;
	int			my_bytes_decoded = *already_decoded;
	bool		is_undo_splited = (my_bytes_decoded > 0) ? true : false;

	/* Decode header (if not already done). */
	if (!ReadUndoBytes((char *) &work_hdr, SizeOfUndoRecordHeader,
					   &readptr, endptr,
					   &my_bytes_decoded, already_decoded, false))
		return false;

	uur->uur_type = work_hdr.urec_type;
	uur->uur_info = work_hdr.urec_info;
	uur->uur_prevlen = work_hdr.urec_prevlen;
	uur->uur_reloid = work_hdr.urec_reloid;
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
		uur->uur_xidepoch = work_txn.urec_xidepoch;
		uur->uur_progress = work_txn.urec_progress;
		uur->uur_prevurp = work_txn.urec_prevurp;
		uur->uur_dbid = work_txn.urec_dbid;
	}

	if (header_only)
		return true;

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
		 * allocating the memory whenever tuple is split we can check if any
		 * of the payload or tuple data falling into the same page then don't
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
	int			can_read;
	int			remaining;

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
 * Set uur_info for an UnpackedUndoRecord appropriately based on which
 * other fields are set.
 */
void
UndoRecordSetInfo(UnpackedUndoRecord *uur)
{
	if (uur->uur_fork != MAIN_FORKNUM)
		uur->uur_info |= UREC_INFO_RELATION_DETAILS;
	if (uur->uur_block != InvalidBlockNumber)
		uur->uur_info |= UREC_INFO_BLOCK;
	if (uur->uur_next != InvalidUndoRecPtr)
		uur->uur_info |= UREC_INFO_TRANSACTION;
	if (uur->uur_payload.len || uur->uur_tuple.len)
		uur->uur_info |= UREC_INFO_PAYLOAD;
}
