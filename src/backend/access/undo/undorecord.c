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
static bool InsertUndoBytes(char *sourceptr, int sourcelen,
							char **writeptr, char *endptr,
							int *total_bytes_written, int *partial_write);
static bool ReadUndoBytes(char *destptr, int readlen,
						  char **readptr, char *endptr,
						  int *total_bytes_read, int *partial_read);

 /*
  * Compute the header size of the undo record.
  */
Size
UndoRecordHeaderSize(uint16 uur_info)
{
	Size		size;

	/* Add fixed header size. */
	size = SizeOfUndoRecordHeader;

	/* Add size of transaction header if it presets. */
	if ((uur_info & UREC_INFO_TRANSACTION) != 0)
		size += SizeOfUndoRecordTransaction;

	/* Add size of rmid if it presets. */
	if ((uur_info & UREC_INFO_RMID) != 0)
		size += sizeof(RmgrId);

	/* Add size of reloid if it presets. */
	if ((uur_info & UREC_INFO_RELOID) != 0)
		size += sizeof(Oid);

	/* Add size of fxid if it presets. */
	if ((uur_info & UREC_INFO_XID) != 0)
		size += sizeof(FullTransactionId);

	/* Add size of cid if it presets. */
	if ((uur_info & UREC_INFO_CID) != 0)
		size += sizeof(CommandId);

	/* Add size of forknum if it presets. */
	if ((uur_info & UREC_INFO_FORK) != 0)
		size += sizeof(ForkNumber);

	/* Add size of prevundo if it presets. */
	if ((uur_info & UREC_INFO_PREVUNDO) != 0)
		size += sizeof(UndoRecPtr);

	/* Add size of the block header if it presets. */
	if ((uur_info & UREC_INFO_BLOCK) != 0)
		size += SizeOfUndoRecordBlock;

	/* Add size of the log switch header if it presets. */
	if ((uur_info & UREC_INFO_LOGSWITCH) != 0)
		size += SizeOfUndoRecordLogSwitch;

	/* Add size of the payload header if it presets. */
	if ((uur_info & UREC_INFO_PAYLOAD) != 0)
		size += SizeOfUndoRecordPayload;

	return size;
}

/*
 * Compute and return the expected size of an undo record.
 */
Size
UndoRecordExpectedSize(UnpackedUndoRecord *uur)
{
	Size		size;

	/* Header size. */
	size = UndoRecordHeaderSize(uur->uur_info);

	/* Payload data size. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		size += uur->uur_payload.len;
		size += uur->uur_tuple.len;
	}

	/* Add undo record length size. */
	size += sizeof(uint16);

	return size;
}

/*
 * Calculate the size of the undo record stored on the page.
 */
static inline Size
UndoRecordSizeOnPage(char *page_ptr)
{
	uint16		uur_info = ((UndoRecordHeader *) page_ptr)->urec_info;
	Size		size;

	/* Header size. */
	size = UndoRecordHeaderSize(uur_info);

	/* Payload data size. */
	if ((uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		UndoRecordPayload *payload = (UndoRecordPayload *) (page_ptr + size);

		size += payload->urec_payload_len;
		size += payload->urec_tuple_len;
	}

	return size;
}

/*
 * Compute size of the Unpacked undo record in memory
 */
Size
UnpackedUndoRecordSize(UnpackedUndoRecord *uur)
{
	Size		size;

	size = sizeof(UnpackedUndoRecord);

	/* Add payload size if record contains payload data. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		size += uur->uur_payload.len;
		size += uur->uur_tuple.len;
	}

	return size;
}

/*
 * Initiate inserting an undo record.
 *
 * This function will initialize the context for inserting and undo record
 * which will be inserted by calling InsertUndoData.
 */
void
BeginInsertUndo(UndoPackContext *ucontext, UnpackedUndoRecord *uur)
{
	ucontext->stage = UNDO_PACK_STAGE_HEADER;
	ucontext->already_processed = 0;
	ucontext->partial_bytes = 0;

	/* Copy undo record header. */
	ucontext->urec_hd.urec_type = uur->uur_type;
	ucontext->urec_hd.urec_info = uur->uur_info;

	/* Copy undo record transaction header if it is present. */
	if ((uur->uur_info & UREC_INFO_TRANSACTION) != 0)
		memcpy(&ucontext->urec_txn, uur->uur_txn, SizeOfUndoRecordTransaction);

	/* Copy rmid if present. */
	if ((uur->uur_info & UREC_INFO_RMID) != 0)
		ucontext->urec_rmid = uur->uur_rmid;

	/* Copy reloid if present. */
	if ((uur->uur_info & UREC_INFO_RELOID) != 0)
		ucontext->urec_reloid = uur->uur_reloid;

	/* Copy fxid if present. */
	if ((uur->uur_info & UREC_INFO_XID) != 0)
		ucontext->urec_fxid = uur->uur_fxid;

	/* Copy cid if present. */
	if ((uur->uur_info & UREC_INFO_CID) != 0)
		ucontext->urec_cid = uur->uur_cid;

	/* Copy undo record relation header if it is present. */
	if ((uur->uur_info & UREC_INFO_FORK) != 0)
		ucontext->urec_fork = uur->uur_fork;

	/* Copy prev undo record pointer if it is present. */
	if ((uur->uur_info & UREC_INFO_PREVUNDO) != 0)
		ucontext->urec_prevundo = uur->uur_prevundo;

	/* Copy undo record block header if it is present. */
	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		ucontext->urec_blk.urec_block = uur->uur_block;
		ucontext->urec_blk.urec_offset = uur->uur_offset;
	}

	/* Copy undo record log switch header if it is present. */
	if ((uur->uur_info & UREC_INFO_LOGSWITCH) != 0)
		memcpy(&ucontext->urec_logswitch, uur->uur_logswitch,
			   SizeOfUndoRecordLogSwitch);

	/* Copy undo record payload header and data if it is present. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		ucontext->urec_payload.urec_payload_len = uur->uur_payload.len;
		ucontext->urec_payload.urec_tuple_len = uur->uur_tuple.len;
		ucontext->urec_payloaddata = uur->uur_payload.data;
		ucontext->urec_tupledata = uur->uur_tuple.data;
	}
	else
	{
		ucontext->urec_payload.urec_payload_len = 0;
		ucontext->urec_payload.urec_tuple_len = 0;
	}

	/* Compute undo record expected size and store in the context. */
	ucontext->undo_len = UndoRecordExpectedSize(uur);
}

/*
 * Insert the undo record into the input page from the unpack undo context.
 *
 * Caller can  call this function multiple times until desired stage is reached.
 * This will write the undo record into the page.
 */
void
InsertUndoData(UndoPackContext *ucontext, Page page, int starting_byte)
{
	char	   *writeptr = (char *) page + starting_byte;
	char	   *endptr = (char *) page + BLCKSZ;

	switch (ucontext->stage)
	{
		case UNDO_PACK_STAGE_HEADER:
			/* Insert undo record header. */
			if (!InsertUndoBytes((char *) &ucontext->urec_hd,
								 SizeOfUndoRecordHeader, &writeptr, endptr,
								 &ucontext->already_processed,
								 &ucontext->partial_bytes))
				return;
			ucontext->stage = UNDO_PACK_STAGE_TRANSACTION;
			/* fall through */

		case UNDO_PACK_STAGE_TRANSACTION:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_TRANSACTION) != 0)
			{
				/* Insert undo record transaction header. */
				if (!InsertUndoBytes((char *) &ucontext->urec_txn,
									 SizeOfUndoRecordTransaction,
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_RMID;
			/* fall through */

		case UNDO_PACK_STAGE_RMID:
			/* Write rmid(if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_RMID) != 0)
			{
				if (!InsertUndoBytes((char *) &(ucontext->urec_rmid), sizeof(RmgrId),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_RELOID;
			/* fall through */

		case UNDO_PACK_STAGE_RELOID:
			/* Write reloid(if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_RELOID) != 0)
			{
				if (!InsertUndoBytes((char *) &(ucontext->urec_reloid), sizeof(Oid),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_XID;
			/* fall through */

		case UNDO_PACK_STAGE_XID:
			/* Write xid(if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_XID) != 0)
			{
				if (!InsertUndoBytes((char *) &(ucontext->urec_fxid), sizeof(FullTransactionId),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_CID;
			/* fall through */

		case UNDO_PACK_STAGE_CID:
			/* Write cid(if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_CID) != 0)
			{
				if (!InsertUndoBytes((char *) &(ucontext->urec_cid), sizeof(CommandId),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_FORKNUM;
			/* fall through */

		case UNDO_PACK_STAGE_FORKNUM:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_FORK) != 0)
			{
				/* Insert undo record fork number. */
				if (!InsertUndoBytes((char *) &ucontext->urec_fork,
									 sizeof(ForkNumber),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PREVUNDO;
			/* fall through */

		case UNDO_PACK_STAGE_PREVUNDO:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_PREVUNDO) != 0)
			{
				/* Insert undo record blkprev. */
				if (!InsertUndoBytes((char *) &ucontext->urec_prevundo,
									 sizeof(UndoRecPtr),
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_BLOCK;
			/* fall through */

		case UNDO_PACK_STAGE_BLOCK:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_BLOCK) != 0)
			{
				/* Insert undo record block header. */
				if (!InsertUndoBytes((char *) &ucontext->urec_blk,
									 SizeOfUndoRecordBlock,
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_LOGSWITCH;
			/* fall through */

		case UNDO_PACK_STAGE_LOGSWITCH:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_LOGSWITCH) != 0)
			{
				/* Insert undo record transaction header. */
				if (!InsertUndoBytes((char *) &ucontext->urec_logswitch,
									 SizeOfUndoRecordLogSwitch,
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD;
			/* fall through */

		case UNDO_PACK_STAGE_PAYLOAD:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_PAYLOAD) != 0)
			{
				/* Insert undo record payload header. */
				if (!InsertUndoBytes((char *) &ucontext->urec_payload,
									 SizeOfUndoRecordPayload,
									 &writeptr, endptr,
									 &ucontext->already_processed,
									 &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD_DATA;
			/* fall through */

		case UNDO_PACK_STAGE_PAYLOAD_DATA:
			{
				int			len = ucontext->urec_payload.urec_payload_len;

				if (len > 0)
				{
					/* Insert payload data. */
					if (!InsertUndoBytes((char *) ucontext->urec_payloaddata,
										 len, &writeptr, endptr,
										 &ucontext->already_processed,
										 &ucontext->partial_bytes))
						return;
				}
				ucontext->stage = UNDO_PACK_STAGE_TUPLE_DATA;
			}
			/* fall through */

		case UNDO_PACK_STAGE_TUPLE_DATA:
			{
				int			len = ucontext->urec_payload.urec_tuple_len;

				if (len > 0)
				{
					/* Insert tuple data. */
					if (!InsertUndoBytes((char *) ucontext->urec_tupledata,
										 len, &writeptr, endptr,
										 &ucontext->already_processed,
										 &ucontext->partial_bytes))
						return;
				}
				ucontext->stage = UNDO_PACK_STAGE_UNDO_LENGTH;
			}
			/* fall through */

		case UNDO_PACK_STAGE_UNDO_LENGTH:
			/* Insert undo length. */
			if (!InsertUndoBytes((char *) &ucontext->undo_len,
								 sizeof(uint16), &writeptr, endptr,
								 &ucontext->already_processed,
								 &ucontext->partial_bytes))
				return;

			ucontext->stage = UNDO_PACK_STAGE_DONE;
			/* fall through */

		case UNDO_PACK_STAGE_DONE:
			/* Nothing to be done. */
			break;

		default:
			Assert(0);			/* Invalid stage */
	}
}

/*
 * Skip inserting undo record
 *
 * Don't insert the actual undo record instead just update the context data
 * so that if we need to insert the remaining partial record to the next
 * block then we have right context.
 */
void
SkipInsertingUndoData(UndoPackContext *ucontext, int bytes_to_skip)
{
	switch (ucontext->stage)
	{
		case UNDO_PACK_STAGE_HEADER:
			if (bytes_to_skip < SizeOfUndoRecordHeader)
			{
				ucontext->partial_bytes = bytes_to_skip;
				return;
			}
			bytes_to_skip -= SizeOfUndoRecordHeader;
			ucontext->stage = UNDO_PACK_STAGE_TRANSACTION;
			/* fall through */

		case UNDO_PACK_STAGE_TRANSACTION:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_TRANSACTION) != 0)
			{
				if (bytes_to_skip < SizeOfUndoRecordTransaction)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= SizeOfUndoRecordTransaction;
			}

			ucontext->stage = UNDO_PACK_STAGE_RMID;
			/* fall through */

		case UNDO_PACK_STAGE_RMID:
			/* Write rmid (if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UNDO_PACK_STAGE_RMID) != 0)
			{
				if (bytes_to_skip < (sizeof(RmgrId)))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(RmgrId);
			}
			ucontext->stage = UNDO_PACK_STAGE_RELOID;
			/* fall through */

		case UNDO_PACK_STAGE_RELOID:
			/* Write reloid (if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UNDO_PACK_STAGE_RELOID) != 0)
			{
				if (bytes_to_skip < sizeof(Oid))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(Oid);
			}
			ucontext->stage = UNDO_PACK_STAGE_XID;
			/* fall through */

		case UNDO_PACK_STAGE_XID:
			/* Write xid (if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UNDO_PACK_STAGE_XID) != 0)
			{
				if (bytes_to_skip < (sizeof(TransactionId)))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(TransactionId);
			}
			ucontext->stage = UNDO_PACK_STAGE_CID;
			/* fall through */

		case UNDO_PACK_STAGE_CID:
			/* Write cid (if needed and not already done). */
			if ((ucontext->urec_hd.urec_info & UNDO_PACK_STAGE_CID) != 0)
			{
				if (bytes_to_skip < sizeof(CommandId))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(CommandId);
			}
			ucontext->stage = UNDO_PACK_STAGE_FORKNUM;
			/* fall through */

		case UNDO_PACK_STAGE_FORKNUM:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_FORK) != 0)
			{
				if (bytes_to_skip < sizeof(ForkNumber))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(ForkNumber);
			}

			ucontext->stage = UNDO_PACK_STAGE_PREVUNDO;
			/* fall through */

		case UNDO_PACK_STAGE_PREVUNDO:
			if ((ucontext->urec_hd.urec_info & UNDO_PACK_STAGE_PREVUNDO) != 0)
			{
				if (bytes_to_skip < sizeof(UndoRecPtr))
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= sizeof(UndoRecPtr);
			}
			ucontext->stage = UNDO_PACK_STAGE_BLOCK;
			/* fall through */

		case UNDO_PACK_STAGE_BLOCK:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_BLOCK) != 0)
			{
				if (bytes_to_skip < SizeOfUndoRecordBlock)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= SizeOfUndoRecordBlock;
			}
			ucontext->stage = UNDO_PACK_STAGE_LOGSWITCH;
			/* fall through */

		case UNDO_PACK_STAGE_LOGSWITCH:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_LOGSWITCH) != 0)
			{
				if (bytes_to_skip < SizeOfUndoRecordLogSwitch)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= SizeOfUndoRecordLogSwitch;
			}

			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD;
			/* fall through */

		case UNDO_PACK_STAGE_PAYLOAD:
			/* Skip payload header. */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_PAYLOAD) != 0)
			{
				if (bytes_to_skip < SizeOfUndoRecordPayload)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= SizeOfUndoRecordPayload;
			}
			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD_DATA;
			/* fall through */

		case UNDO_PACK_STAGE_PAYLOAD_DATA:
			if (ucontext->urec_payload.urec_payload_len > 0)
			{
				if (bytes_to_skip < ucontext->urec_payload.urec_payload_len)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= ucontext->urec_payload.urec_payload_len;
			}
			ucontext->stage = UNDO_PACK_STAGE_TUPLE_DATA;
			/* fall through */

		case UNDO_PACK_STAGE_TUPLE_DATA:
			if (ucontext->urec_payload.urec_tuple_len > 0)
			{
				if (bytes_to_skip < ucontext->urec_payload.urec_tuple_len)
				{
					ucontext->partial_bytes = bytes_to_skip;
					return;
				}
				bytes_to_skip -= ucontext->urec_payload.urec_tuple_len;
			}
			ucontext->stage = UNDO_PACK_STAGE_UNDO_LENGTH;
			/* fall through */

		case UNDO_PACK_STAGE_UNDO_LENGTH:
			ucontext->stage = UNDO_PACK_STAGE_DONE;
			 /* fall through */ ;

		case UNDO_PACK_STAGE_DONE:
			/* Nothing to be done. */
			break;

		default:
			Assert(0);			/* Invalid stage */
	}
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
 * been subtracted out.
 *
 * 'total_bytes_written' points to the count of all previously-written bytes,
 * and must it must be updated for the bytes we write.
 *
 * The return value is false if we ran out of space before writing all
 * the bytes, and otherwise true.
 */
static bool
InsertUndoBytes(char *sourceptr, int sourcelen, char **writeptr, char *endptr,
				int *total_bytes_written, int *partial_write)
{
	int			can_write;
	int			remaining;

	/* Compute number of bytes we can write. */
	remaining = sourcelen - *partial_write;
	can_write = Min(remaining, endptr - *writeptr);

	/* Bail out if no bytes can be written. */
	if (can_write == 0)
		return false;

	/* Copy the bytes we can write. */
	memcpy(*writeptr, sourceptr + *partial_write, can_write);

	/* Update bookkeeping information. */
	*writeptr += can_write;
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
BeginUnpackUndo(UndoPackContext *ucontext)
{
	ucontext->stage = UNDO_PACK_STAGE_HEADER;
	ucontext->already_processed = 0;
	ucontext->partial_bytes = 0;
}

/*
 * Read the undo record from the input page to the unpack undo context.
 *
 * Caller can  call this function multiple times until desired stage is reached.
 * This will read the undo record from the page and store the data into unpack
 * undo context, which can be later copied to unpacked undo record by calling
 * FinishUnpackUndo.
 */
void
UnpackUndoData(UndoPackContext *ucontext, Page page, int starting_byte)
{
	char	   *readptr = (char *) page + starting_byte;
	char	   *endptr = (char *) page + BLCKSZ;

	switch (ucontext->stage)
	{
		case UNDO_PACK_STAGE_HEADER:
			if (!ReadUndoBytes((char *) &ucontext->urec_hd,
							   SizeOfUndoRecordHeader, &readptr, endptr,
							   &ucontext->already_processed,
							   &ucontext->partial_bytes))
				return;
			ucontext->stage = UNDO_PACK_STAGE_TRANSACTION;
			/* fall through */
		case UNDO_PACK_STAGE_TRANSACTION:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_TRANSACTION) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_txn,
								   SizeOfUndoRecordTransaction,
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_RMID;
			/* fall through */
		case UNDO_PACK_STAGE_RMID:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_RMID) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_rmid,
								   sizeof(RmgrId),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_RELOID;
			/* fall through */
		case UNDO_PACK_STAGE_RELOID:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_RELOID) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_reloid,
								   sizeof(Oid),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_XID;
			/* fall through */
		case UNDO_PACK_STAGE_XID:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_XID) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_fxid,
								   sizeof(FullTransactionId),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_CID;
			/* fall through */
		case UNDO_PACK_STAGE_CID:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_CID) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_cid,
								   sizeof(CommandId),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_FORKNUM;
			/* fall through */
		case UNDO_PACK_STAGE_FORKNUM:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_FORK) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_fork,
								   sizeof(ForkNumber),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PREVUNDO;
			/* fall through */
		case UNDO_PACK_STAGE_PREVUNDO:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_PREVUNDO) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_prevundo,
								   sizeof(UndoRecPtr),
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_BLOCK;
			/* fall through */

		case UNDO_PACK_STAGE_BLOCK:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_BLOCK) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_blk,
								   SizeOfUndoRecordBlock,
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_LOGSWITCH;
			/* fall through */
		case UNDO_PACK_STAGE_LOGSWITCH:
			if ((ucontext->urec_hd.urec_info & UREC_INFO_LOGSWITCH) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_logswitch,
								   SizeOfUndoRecordLogSwitch,
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD;
			/* fall through */
		case UNDO_PACK_STAGE_PAYLOAD:
			/* Read payload header. */
			if ((ucontext->urec_hd.urec_info & UREC_INFO_PAYLOAD) != 0)
			{
				if (!ReadUndoBytes((char *) &ucontext->urec_payload,
								   SizeOfUndoRecordPayload,
								   &readptr, endptr, &ucontext->already_processed,
								   &ucontext->partial_bytes))
					return;
			}
			ucontext->stage = UNDO_PACK_STAGE_PAYLOAD_DATA;
			/* fall through */
		case UNDO_PACK_STAGE_PAYLOAD_DATA:
			{
				int			len = ucontext->urec_payload.urec_payload_len;

				/* Allocate memory for the payload data if not already done. */
				if (len > 0)
				{
					if (ucontext->urec_payloaddata == NULL)
						ucontext->urec_payloaddata = (char *) palloc(len);

					/* Read payload data. */
					if (!ReadUndoBytes((char *) ucontext->urec_payloaddata, len,
									   &readptr, endptr, &ucontext->already_processed,
									   &ucontext->partial_bytes))
						return;
				}
				ucontext->stage = UNDO_PACK_STAGE_TUPLE_DATA;
				/* fall through */
			}
		case UNDO_PACK_STAGE_TUPLE_DATA:
			{
				int			len = ucontext->urec_payload.urec_tuple_len;

				/* Allocate memory for the tuple data if not already done. */
				if (len > 0)
				{
					if (ucontext->urec_tupledata == NULL)
						ucontext->urec_tupledata = (char *) palloc(len);

					/* Read tuple data. */
					if (!ReadUndoBytes((char *) ucontext->urec_tupledata, len,
									   &readptr, endptr, &ucontext->already_processed,
									   &ucontext->partial_bytes))
						return;
				}

				ucontext->stage = UNDO_PACK_STAGE_DONE;
				/* fall through */
			}
		case UNDO_PACK_STAGE_DONE:
			/* Nothing to be done. */
			break;
		default:
			Assert(0);			/* Invalid stage */
	}

	return;
}

/*
 * Final step of unpacking the undo record.
 *
 * Copy the undo record data from the unpack undo context to the input unpacked
 * undo record.
 */
void
FinishUnpackUndo(UndoPackContext *ucontext, UnpackedUndoRecord *uur)
{
	/* Copy undo record header. */
	uur->uur_type = ucontext->urec_hd.urec_type;
	uur->uur_info = ucontext->urec_hd.urec_info;

	/* Copy undo record transaction header if it is present. */
	if ((uur->uur_info & UREC_INFO_TRANSACTION) != 0)
	{
		uur->uur_txn = palloc(SizeOfUndoRecordTransaction);
		memcpy(uur->uur_txn, &ucontext->urec_txn, SizeOfUndoRecordTransaction);
	}

	/*
	 * Copy the common field.  All of these field must present in the final
	 * unpacked undo record.
	 */
	Assert((uur->uur_info & UREC_INFO_PAGE_COMMON) == UREC_INFO_PAGE_COMMON);

	uur->uur_rmid = ucontext->urec_rmid;
	uur->uur_reloid = ucontext->urec_reloid;
	uur->uur_fxid = ucontext->urec_fxid;
	uur->uur_cid = ucontext->urec_cid;

	/* Copy undo record relation header if it is present. */
	if ((uur->uur_info & UREC_INFO_FORK) != 0)
		uur->uur_fork = ucontext->urec_fork;

	/* Copy previous undo record pointer if it is present. */
	if ((uur->uur_info & UREC_INFO_PREVUNDO) != 0)
		uur->uur_prevundo = ucontext->urec_prevundo;

	/* Copy undo record block header if it is present. */
	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		uur->uur_block = ucontext->urec_blk.urec_block;
		uur->uur_offset = ucontext->urec_blk.urec_offset;
	}

	/* Copy undo record log switch header if it is present. */
	if ((uur->uur_info & UREC_INFO_LOGSWITCH) != 0)
	{
		uur->uur_logswitch = palloc(SizeOfUndoRecordLogSwitch);
		memcpy(uur->uur_logswitch, &ucontext->urec_logswitch,
			   SizeOfUndoRecordLogSwitch);
	}

	/* Copy undo record payload header and data if it is present. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		uur->uur_payload.len = ucontext->urec_payload.urec_payload_len;
		uur->uur_tuple.len = ucontext->urec_payload.urec_tuple_len;

		/* Read payload data if its length is not 0. */
		if (uur->uur_payload.len != 0)
			uur->uur_payload.data = ucontext->urec_payloaddata;

		/* Read tuple data if its length is not 0. */
		if (uur->uur_tuple.len != 0)
			uur->uur_tuple.data = ucontext->urec_tupledata;
	}
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
 * Set uur_info for an UnpackedUndoRecord appropriately based on which
 * fields are set.
 *
 * Other flags i.e UREC_INFO_TRANSACTION, UREC_INFO_PAGE_COMMON and,
 * UREC_INFO_LOGSWITCH are directly set by the PrepareUndoInsert function.
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

/*
 * Get the offset of cid information in undo record.
 */
static Size
get_undo_rec_cid_offset(uint16 urec_info)
{
	Size		offset_size = SizeOfUndoRecordHeader;

	if ((urec_info & UREC_INFO_TRANSACTION) != 0)
		offset_size += SizeOfUndoRecordTransaction;

	if ((urec_info & UREC_INFO_RMID) != 0)
		offset_size += sizeof(RmgrId);

	if ((urec_info & UREC_INFO_RELOID) != 0)
		offset_size += sizeof(Oid);

	if ((urec_info & UREC_INFO_XID) != 0)
		offset_size += sizeof(FullTransactionId);

	return offset_size;
}

/*
 * Mask a undo page before performing consistency checks on it.
 */
void
mask_undo_page(char *pagedata)
{
	Page		page = (Page) pagedata;
	char	   *page_end = pagedata + PageGetPageSize(page);
	char	   *next_record;
	int			cid_offset;
	UndoPageHeader phdr = (UndoPageHeader) page;

	next_record = (char *) page + SizeOfUndoPageHeaderData;

	/*
	 * If record_offset is non-zero value in the page header that means page
	 * has a partial record.
	 */
	if (phdr->record_offset != 0)
	{
		Size		partial_rec_size;

		/* Calculate the size of the partial record. */
		partial_rec_size = UndoRecordHeaderSize(phdr->uur_info) +
			phdr->tuple_len + phdr->payload_len -
			phdr->record_offset;
		if ((phdr->uur_info & UREC_INFO_CID) != 0)
		{
			cid_offset = get_undo_rec_cid_offset(phdr->uur_info);

			/*
			 * We just want to mask the cid in the undo record header.  So
			 * only if the partial record in the current page include the undo
			 * record header then we need to mask the cid bytes in this page.
			 * Otherwise, directly jump to the next record.
			 */
			if (phdr->record_offset < (cid_offset + sizeof(CommandId)))
			{
				char	   *cid_data;
				Size		mask_size;

				mask_size = Min(cid_offset - phdr->record_offset,
								sizeof(CommandId));

				cid_data = next_record + cid_offset - phdr->record_offset;
				memset(&cid_data, MASK_MARKER, mask_size);
			}
		}

		next_record += partial_rec_size;
	}

	/*
	 * Process the undo record of the page and mask their cid filed.
	 */
	while (next_record < page_end)
	{
		UndoRecordHeader *header = (UndoRecordHeader *) next_record;

		/* If this undo record has cid present, then mask it */
		if ((header->urec_info & UREC_INFO_CID) != 0)
		{
			cid_offset = get_undo_rec_cid_offset(header->urec_info);

			/*
			 * If this is not complete record then check whether cid is on
			 * this page or not.  If not then we are done with this page.
			 */
			if ((next_record + cid_offset + sizeof(CommandId)) > page_end)
			{
				int			mask_size = page_end - next_record - cid_offset;

				if (mask_size > 0)
					memset(next_record + cid_offset, MASK_MARKER, mask_size);
				break;
			}
			else
			{
				/* Mask cid */
				memset(next_record + cid_offset, MASK_MARKER, sizeof(CommandId));
			}
		}
		/* Go to next record. */
		next_record += UndoRecordSizeOnPage(next_record);
	}
}
