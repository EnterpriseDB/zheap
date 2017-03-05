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

#include "access/undorecord.h"
#include "catalog/pg_tablespace.h"

/* Workspace for InsertUndoRecord and UnpackUndoRecord. */
static UndoRecordHeader work_hdr;
static UndoRecordRelationDetails work_rd;
static UndoRecordBlock work_blk;
static UndoRecordPayload work_payload;

/* Prototypes for static functions. */
static void UndoRecordSetInfo(UnpackedUndoRecord *uur);
static bool InsertUndoBytes(char *sourceptr, int sourcelen,
				char **writeptr, char *endptr,
				int *my_bytes_written, int *total_bytes_written);

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
