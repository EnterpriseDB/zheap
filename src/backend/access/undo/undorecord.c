/*-------------------------------------------------------------------------
 *
 * undorecord.c
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undorecord.c
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/bufmask.h"
#include "access/subtrans.h"
#include "access/undorecord.h"
#include "catalog/pg_tablespace.h"
#include "storage/block.h"

/* Prototypes for static functions. */
static bool InsertUndoBytes(char *sourceptr, int sourcelen, char *writebuf,
							int *offset, int bufsize, int *total_bytes_written,
							int *partial_write, bool skip);
static bool ReadUndoBytes(char *destptr, int readlen,
						  char **readptr, char *endptr,
						  int *total_bytes_read, int *partial_read);

 /*
  * Compute the header size of the undo record.
  */
static size_t
UndoRecordHeaderSize(uint16 uur_info)
{
	size_t		size;

	/* Add fixed header size. */
	size = SizeOfUndoRecordHeader;

	/* Add optional headers sizes. */
	if ((uur_info & UREC_INFO_GROUP) != 0)
		size += SizeOfUndoRecordGroup;

	if ((uur_info & UREC_INFO_RMID) != 0)
		size += sizeof(RmgrId);

	if ((uur_info & UREC_INFO_RELOID) != 0)
		size += sizeof(Oid);

	if ((uur_info & UREC_INFO_FXID) != 0)
		size += sizeof(FullTransactionId);

	if ((uur_info & UREC_INFO_FORK) != 0)
		size += sizeof(ForkNumber);

	if ((uur_info & UREC_INFO_PREVUNDO) != 0)
		size += sizeof(UndoRecPtr);

	if ((uur_info & UREC_INFO_BLOCK) != 0)
		size += (sizeof(BlockNumber) + sizeof(OffsetNumber));

	if ((uur_info & UREC_INFO_LOGSWITCH) != 0)
		size += SizeOfUndoRecordLogSwitch;

	if ((uur_info & UREC_INFO_PAYLOAD) != 0)
		size += SizeOfUndoRecordPayload;

	return size;
}

/*
 * Compute the size of the payload data for the unpacked undo record.
 */
size_t
UndoRecordPayloadSize(UnpackedUndoRecord *uur)
{
	size_t		size = 0;

	/* Add payload size if record contains payload data. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		size += uur->uur_payload.len;
		size += uur->uur_tuple.len;
	}

	return size;
}

/*
 * Compute the expected size of the undo record.
 *
 * This function will take UnpackedUndoRecord as input and base on the uur_info
 * and the variable headers it will compute the exact size required to store
 * this record on the page.
 */
Size
UndoRecordExpectedSize(UnpackedUndoRecord *uur)
{
	/* Header size + payload data + undo record length. */
	return UndoRecordHeaderSize(uur->uur_info) +
		UndoRecordPayloadSize(uur) +
		sizeof(uint16);
}

/*
 * Serialize the unpacked undo record.
 *
 * It will allocate the memory and pack the undo record into that.  The caller
 * will be responsible for releasing that memory.  The packed data will directly
 * be inserted to undo pages.
 */
char *
SerializeUndoRecord(UnpackedUndoRecord *uur, size_t size)
{
	char	   *pack_data;
	char	   *data;

	/* Allocate memory for packing the complete undo record. */
	pack_data = data = palloc(size);

	/* Pack the undo record header. */
	memcpy(data, (char *) &uur->uur_info, SizeOfUndoRecordHeader);
	data += SizeOfUndoRecordHeader;

	/* Pack the optional undo record headers if they present. */
	if ((uur->uur_info & UREC_INFO_GROUP) != 0)
	{
		memcpy(data, (char *) uur->uur_group, SizeOfUndoRecordGroup);
		data += SizeOfUndoRecordGroup;
	}

	if ((uur->uur_info & UREC_INFO_RMID) != 0)
	{
		memcpy(data, (char *) &uur->uur_rmid, sizeof(uur->uur_rmid));
		data += sizeof(uur->uur_rmid);
	}

	if ((uur->uur_info & UREC_INFO_RELOID) != 0)
	{
		memcpy(data, (char *) &uur->uur_reloid, sizeof(uur->uur_reloid));
		data += sizeof(uur->uur_reloid);
	}

	if ((uur->uur_info & UREC_INFO_FXID) != 0)
	{
		memcpy(data, (char *) &uur->uur_fxid, sizeof(uur->uur_fxid));
		data += sizeof(uur->uur_fxid);
	}

	if ((uur->uur_info & UREC_INFO_FORK) != 0)
	{
		memcpy(data, (char *) &uur->uur_fork, sizeof(uur->uur_fork));
		data += sizeof(uur->uur_fork);
	}
	if ((uur->uur_info & UREC_INFO_PREVUNDO) != 0)
	{
		memcpy(data, (char *) &uur->uur_prevundo, SizeOfUndoRecordLogSwitch);
		data += SizeOfUndoRecordLogSwitch;
	}

	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		memcpy(data, (char *) &uur->uur_block, sizeof(uur->uur_block));
		data += sizeof(uur->uur_block);
		memcpy(data, (char *) &uur->uur_offset, sizeof(uur->uur_offset));
		data += sizeof(uur->uur_offset);
	}

	if ((uur->uur_info & UREC_INFO_LOGSWITCH) != 0)
	{
		memcpy(data, (char *) uur->uur_logswitch, sizeof(uur->uur_offset));
		data += sizeof(uur->uur_offset);
	}

	/* Pack the payload header and the payload data. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		UndoRecordPayload payload;

		payload.urec_payload_len = uur->uur_payload.len;
		payload.urec_tuple_len = uur->uur_tuple.len;
		memcpy(data, (char *) &payload, SizeOfUndoRecordPayload);
		data += SizeOfUndoRecordPayload;

		if (uur->uur_payload.len > 0)
		{
			memcpy(data, uur->uur_payload.data, uur->uur_payload.len);
			data += uur->uur_payload.len;
		}
		if (uur->uur_tuple.len > 0)
		{
			memcpy(data, uur->uur_tuple.data, uur->uur_tuple.len);
			data += uur->uur_tuple.len;
		}
	}

	/* Pack the undo record length. */
	memcpy(data, (char *) &size, sizeof(uint16));

	return pack_data;
}

/*
 * Initiate inserting an undo record.
 *
 * This will pack all the fields of the undo record to the pack data in the
 * context so that we can directly copy this data to the undo buffers during
 * InsertUndoData.
 */
void
BeginInsertUndo(UndoPackContext *ucontext, char *pack_data, uint16 undo_len)
{
	/* Remember how much data we need to copy to the buffers */
	ucontext->pack_data = pack_data;
	ucontext->undo_len = undo_len;

	/* Initialize the bookkeeping informations. */
	ucontext->already_processed = 0;
	ucontext->partial_bytes = 0;
}

/*
 * Insert the undo record into the input page from the unpack undo context.
 *
 * Caller can  call this function multiple times until desired stage is reached.
 * This will write the undo record into the page.
 *
 * skip - skip writing the actual data to the page if set.
 */
bool
InsertUndoData(UndoPackContext *ucontext, Page page, int offset, bool skip)
{
	char	   *writeptr = NULL;

	if (!skip)
		writeptr = (char *) page;

	/* Insert undo record. */
	return InsertUndoBytes(ucontext->pack_data, ucontext->undo_len, writeptr,
						   &offset, BLCKSZ, &ucontext->already_processed,
						   &ucontext->partial_bytes, skip);
}

/*
 * Write undo bytes from a particular source, but only to the extent that
 * they weren't written previously and will fit.
 *
 * 'sourceptr' points to the source data, and 'sourcelen' is the length of
 * that data in bytes.
 *
 * 'writebuf' buffer in which we need to write these bytes.
 *
 * 'offset' offset in the buffer where we need to write these bytes.
 *
 * 'bufsize' size of the buffer.
 *
 * 'my_bytes_written' is a pointer to the count of previous-written bytes
 * from this and following structures in this undo record; that is, any
 * bytes that are part of previous structures in the record have already
 * been subtracted out.
 *
 * 'total_bytes_written' points to the count of all previously-written bytes,
 * and must it must be updated for the bytes we write.
 *
 * 'skip' skip actual writing if it is set.
 *
 * The return value is false if we ran out of space before writing all
 * the bytes, and otherwise true.
 */
static bool
InsertUndoBytes(char *sourceptr, int sourcelen, char *writebuf, int *offset,
				int bufsize, int *total_bytes_written, int *partial_write,
				bool skip)
{
	int			can_write;
	int			remaining;

	/* Compute number of bytes we can write. */
	remaining = sourcelen - *partial_write;
	can_write = Min(remaining, bufsize - *offset);

	/* Bail out if no bytes can be written. */
	if (can_write == 0)
		return false;

	/* Copy the bytes we can write. */
	if (!skip)
		memcpy(writebuf + *offset, sourceptr + *partial_write, can_write);

	/* Update bookkeeping information. */
	*offset += can_write;
	*total_bytes_written += can_write;

	/* Could not read whole data so set the partial_read. */
	if (can_write < remaining)
	{
		*partial_write += can_write;
		return false;
	}

	/* Return true only if we wrote the whole thing. */
	*partial_write = 0;
	return true;
}

/*
 * Initiate unpacking an undo record.
 *
 * This function will initialize the context for unpacking the undo record which
 * will be unpacked by calling UnpackUndoData.
 */
void
BeginUnpackUndo(UndoPackContext *ucontext, UnpackedUndoRecord *uur)
{
	ucontext->stage = UNDO_UNPACK_STAGE_UNDO_INFO;
	ucontext->already_processed = 0;
	ucontext->partial_bytes = 0;
	ucontext->uur = uur;
}

/*
 * Read the undo record from the input page to the unpack undo context.
 *
 * Caller can  call this function multiple times until it reach to the done
 * stage.  This will read the undo record from the page and store the data into
 * unpack undo context, which can be later be unpacked by calling
 * FinishUnpackUndo.
 */
void
UnpackUndoData(UndoPackContext *ucontext, Page page, int starting_byte)
{
	char	   *readptr = (char *) page + starting_byte;
	char	   *endptr = (char *) page + BLCKSZ;
	UnpackedUndoRecord *uur = ucontext->uur;

	switch (ucontext->stage)
	{
		case UNDO_UNPACK_STAGE_UNDO_INFO:
			if (!ReadUndoBytes((char *) &uur->uur_info, SizeOfUndoRecordHeader,
							   &readptr, endptr, &ucontext->already_processed,
							   &ucontext->partial_bytes))
				return;

			/*
			 * We have already read the undo record header.  Next we need to
			 * read the optional headers so compute the optional headers size
			 * and remember in the context so that if undo record is split we
			 * can read the optional headers in the subsequent call.
			 */
			ucontext->undo_len =
				UndoRecordHeaderSize(uur->uur_info) - SizeOfUndoRecordHeader;

			ucontext->stage = UNDO_UNPACK_STAGE_HEADERS;
			/* fall through */

		case UNDO_UNPACK_STAGE_HEADERS:
			if (ucontext->undo_len > 0)
			{
				if (ucontext->pack_data == NULL)
					ucontext->pack_data = palloc(ucontext->undo_len);
				if (!ReadUndoBytes(ucontext->pack_data,
								   ucontext->undo_len,
								   &readptr, endptr,
								   &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;

				/*
				 * Compute the size of the payload data.  We have read all the
				 * optional headers in the pack_data and payload header is the
				 * last header in that.  So we can compute the payload header
				 * offset and read the payload from the pack_data.
				 */
				if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
				{
					UndoRecordPayload payload;
					int	offset = ucontext->undo_len - SizeOfUndoRecordPayload;

					memcpy((char *) &payload, ucontext->pack_data + offset,
						   SizeOfUndoRecordPayload);
					uur->uur_payload.len = payload.urec_payload_len;
					uur->uur_tuple.len = payload.urec_tuple_len;
				}
			}
			ucontext->stage = UNDO_UNPACK_STAGE_PAYLOAD_DATA;
			/* fall through */

		case UNDO_UNPACK_STAGE_PAYLOAD_DATA:
			if (uur->uur_payload.len > 0)
			{
				int			len = uur->uur_payload.len;

				/*
				 * Allocate memory for the payload data and read it directly
				 * in to the unpacked undo record so that we don't need to
				 * expand the size of the pack data and then copy it back to
				 * the unpacked undo record.
				 */
				if (uur->uur_payload.data == NULL)
					uur->uur_payload.data = palloc(len);

				if (!ReadUndoBytes(uur->uur_payload.data,
								   len, &readptr, endptr,
								   &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_UNPACK_STAGE_TUPLE_DATA;
			/* fall through */
		case UNDO_UNPACK_STAGE_TUPLE_DATA:
			if (uur->uur_tuple.len > 0)
			{
				int			len = uur->uur_tuple.len;

				/*
				 * Allocate memory for the tuple data and read it directly
				 * into the unpacked undo record.
				 */
				if (uur->uur_tuple.data == NULL)
					uur->uur_tuple.data = palloc(len);
				if (!ReadUndoBytes(uur->uur_tuple.data, len, &readptr, endptr,
								   &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_UNPACK_STAGE_DONE;
			break;
		default:
			Assert(0);			/* Invalid stage */
	}

	return;
}

/*
 * Final step of unpacking the undo record.
 *
 * Unpack the undo record to the unpacked undo record.
 */
void
FinishUnpackUndo(UndoPackContext *ucontext)
{
	UnpackedUndoRecord *uur = ucontext->uur;
	char	   *pack_data = ucontext->pack_data;

	/*
	 * During UnpackUndoData we have already read the undo record header, the
	 * payload headers and the payload data directly into to the unpacked undo
	 * record so nothing to be done for those header.  We still have to unpack
	 * other optional header into the unpacked undo record.
	 */
	if ((uur->uur_info & UREC_INFO_GROUP) != 0)
	{
		uur->uur_group = palloc(SizeOfUndoRecordGroup);
		memcpy((char *) uur->uur_group, pack_data, SizeOfUndoRecordGroup);
		pack_data += SizeOfUndoRecordGroup;
	}

	if ((uur->uur_info & UREC_INFO_RMID) != 0)
	{
		memcpy((char *) &uur->uur_rmid, pack_data, sizeof(uur->uur_rmid));
		pack_data += sizeof(uur->uur_rmid);
	}

	if ((uur->uur_info & UREC_INFO_RELOID) != 0)
	{
		memcpy((char *) &uur->uur_reloid, pack_data, sizeof(uur->uur_reloid));
		pack_data += sizeof(uur->uur_reloid);
	}

	if ((uur->uur_info & UREC_INFO_FXID) != 0)
	{
		memcpy((char *) &uur->uur_fxid, pack_data, sizeof(uur->uur_fxid));
		pack_data += sizeof(uur->uur_fxid);
	}

	if ((uur->uur_info & UREC_INFO_FORK) != 0)
	{
		memcpy((char *) &uur->uur_fork, pack_data, sizeof(uur->uur_fork));
		pack_data += sizeof(uur->uur_fork);
	}
	if ((uur->uur_info & UREC_INFO_PREVUNDO) != 0)
	{
		memcpy((char *) &uur->uur_prevundo, pack_data, sizeof(uur->uur_prevundo));
		pack_data += sizeof(uur->uur_prevundo);
	}

	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		memcpy(pack_data, (char *) &uur->uur_block, sizeof(uur->uur_block));
		pack_data += sizeof(uur->uur_block);
		memcpy(pack_data, (char *) &uur->uur_offset, sizeof(uur->uur_offset));
		pack_data += sizeof(uur->uur_offset);
	}

	if ((uur->uur_info & UREC_INFO_LOGSWITCH) != 0)
	{
		uur->uur_logswitch = palloc(SizeOfUndoRecordLogSwitch);
		memcpy((char *) uur->uur_logswitch, pack_data,
			   SizeOfUndoRecordLogSwitch);
		pack_data += SizeOfUndoRecordLogSwitch;
	}

	/* Release the memory for the packed data. */
	pfree(ucontext->pack_data);
}

/*
 * Directly read the undo compression info from the undo record starting at
 * given offset.
 */
void
UndoRecordGetCompressionInfo(Page page, int starting_byte,
							 UndoCompressionInfo *compresssion)
{
	uint16		urec_info;
	char	   *readptr = (char *) page + starting_byte;

	/* Read the main header */
	memcpy((char *) &urec_info, readptr, sizeof(urec_info));
	readptr += SizeOfUndoRecordHeader;

	/* If we have the group header then skip it. */
	if (urec_info & UREC_INFO_GROUP)
		readptr += SizeOfUndoRecordGroup;

	/* Read compression info. */
	memcpy((char *) &compresssion->rmid, readptr, sizeof(RmgrId));
	readptr += sizeof(RmgrId);
	memcpy((char *) &compresssion->reloid, readptr, sizeof(Oid));
	readptr += sizeof(Oid);
	memcpy((char *) &compresssion->fxid, readptr, sizeof(FullTransactionId));
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
 * 'partial_read' is a pointer to the count of previous partial read bytes
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
			  int *total_bytes_read, int *partial_read)
{
	int			can_read;
	int			remaining;

	/* Compute number of bytes we can read. */
	remaining = readlen - *partial_read;
	can_read = Min(remaining, endptr - *readptr);

	/* Bail out if no bytes can be read. */
	if (can_read == 0)
		return false;

	/* Copy the bytes we can read. */
	memcpy(destptr + *partial_read, *readptr, can_read);

	/* Update bookkeeping information. */
	*readptr += can_read;
	*total_bytes_read += can_read;

	/* Could not read whole data so set the partial_read. */
	if (can_read < remaining)
	{
		*partial_read += can_read;
		return false;
	}

	/* Return true only if we wrote the whole thing. */
	*partial_read = 0;

	return true;
}

/*
 * Set uur_info for an UnpackedUndoRecord appropriately based on which fields
 * are set.
 */
void
UndoRecordSetInfo(UnpackedUndoRecord *uur)
{
	/*
	 * If fork number is not the main fork then we need to store it in the
	 * undo record so set the flag.
	 */
	if (uur->uur_fork != MAIN_FORKNUM)
		uur->uur_info |= UREC_INFO_FORK;

	/* If prevundo is valid undo record pointer then set the flag. */
	if (uur->uur_prevundo != InvalidUndoRecPtr)
		uur->uur_info |= UREC_INFO_PREVUNDO;

	/* If the block number is valid then set the flag for the block header. */
	if (uur->uur_block != InvalidBlockNumber)
		uur->uur_info |= UREC_INFO_BLOCK;

	/*
	 * Either of the payload or the tuple length is non-zero then we need the
	 * payload header.
	 */
	if (uur->uur_payload.len || uur->uur_tuple.len)
		uur->uur_info |= UREC_INFO_PAYLOAD;
}
