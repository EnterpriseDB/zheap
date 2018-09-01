#include "postgres.h"

#include "access/transam.h"
#include "access/undolog.h"
#include "catalog/pg_class.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"

#include <stdlib.h>
#include <unistd.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(undo_allocate);
PG_FUNCTION_INFO_V1(undo_advance);
PG_FUNCTION_INFO_V1(undo_append);
PG_FUNCTION_INFO_V1(undo_append_file);
PG_FUNCTION_INFO_V1(undo_append_transaction_header);
PG_FUNCTION_INFO_V1(undo_extract_file);
PG_FUNCTION_INFO_V1(undo_dump);
PG_FUNCTION_INFO_V1(undo_discard);
PG_FUNCTION_INFO_V1(undo_is_discarded);
PG_FUNCTION_INFO_V1(undo_foreground_discard_test);
PG_FUNCTION_INFO_V1(undo_detach_full);

/*
 * It's nice to show UndoRecPtr always as hex, because that way you can see
 * the components easily.  Bigint just doesn't really work because it's
 * signed.
 */
static text *
undo_rec_ptr_to_text(UndoRecPtr undo_ptr)
{
	char buffer[17];

	snprintf(buffer, sizeof(buffer), UndoRecPtrFormat, undo_ptr);
	return cstring_to_text(buffer);
}

static UndoRecPtr
undo_rec_ptr_from_text(text *t)
{
	UndoRecPtr undo_ptr;

	if (sscanf(text_to_cstring(t), "%zx", &undo_ptr) != 1)
		elog(ERROR, "could not parse UndoRecPtr (expected hex)");
	return undo_ptr;
}

static UndoPersistence
undo_persistence_from_text(text *t)
{
	char *str = text_to_cstring(t);

	if (strcmp(str, "permanent") == 0)
		return UNDO_PERMANENT;
	else if (strcmp(str, "temporary") == 0)
		return UNDO_TEMP;
	else if (strcmp(str, "unlogged") == 0)
		return UNDO_UNLOGGED;
	else
		elog(ERROR, "unknown undo persistence level: %s", str);
}

/*
 * Just allocate some undo space, for testing.  This may cause us to be
 * attached to an undo log, possibly creating it on demand.
 */
Datum
undo_allocate(PG_FUNCTION_ARGS)
{
	int size = PG_GETARG_INT32(0);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(1));
	UndoRecPtr undo_ptr;

	undo_ptr = UndoLogAllocate(size, persistence);

	PG_RETURN_TEXT_P(undo_rec_ptr_to_text(undo_ptr));
}

/*
 * Advance the insert pointer for an undo log, for testing.  This must
 * undo_ptr value give must have been returned by undo_allocate(), and the
 * size give must be the argument that was given to undo_allocate().  The call
 * to undo_allocate() reserved space for us and told us where it is, and now
 * we are advancing the insertion pointer (presumably having written data
 * there).
 */
Datum
undo_advance(PG_FUNCTION_ARGS)
{
	UndoRecPtr undo_ptr = undo_rec_ptr_from_text(PG_GETARG_TEXT_PP(0));
	int size = PG_GETARG_INT32(1);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(2));

	UndoLogAdvance(undo_ptr, size, persistence);

	PG_RETURN_VOID();
}

/*
 * Advance the discard pointer in an undo log.
 */
Datum
undo_discard(PG_FUNCTION_ARGS)
{
	UndoRecPtr undo_ptr = undo_rec_ptr_from_text(PG_GETARG_TEXT_PP(0));

	UndoLogDiscard(undo_ptr, InvalidTransactionId);

	PG_RETURN_VOID();
}

/*
 * Allocate space and write the contents of a file into it.
 */
Datum
undo_append_file(PG_FUNCTION_ARGS)
{
	char *path = text_to_cstring(PG_GETARG_TEXT_PP(0));
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(1));
	size_t size;
	size_t remaining;
	UndoRecPtr start_undo_ptr;
	UndoRecPtr insert_undo_ptr;
	int fd;

	/* Open the file and check its size. */
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		elog(ERROR, "could not open file '%s': %m", path);
	size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	/* Allocate undo log space. */
	start_undo_ptr = UndoLogAllocate(size, persistence);

	elog(NOTICE, "will copy %zu bytes into undo log", size);

	/* Copy data into shared buffers. */
	insert_undo_ptr = start_undo_ptr;
	remaining = size;
	while (remaining > 0)
	{
		RelFileNode rfn;
		Buffer buffer;
		char *page;
		size_t this_chunk_offset;
		size_t this_chunk_size;
		char data[BLCKSZ];
		ssize_t bytes_read;

		/*
		 * Figure out how much we can fit on the page that insert_undo_ptr
		 * points to.
		 */
		this_chunk_offset = UndoRecPtrGetPageOffset(insert_undo_ptr);
		this_chunk_size = Min(remaining, BLCKSZ - this_chunk_offset);

		Assert(this_chunk_offset >= UndoLogBlockHeaderSize);
		Assert(this_chunk_size <= UndoLogUsableBytesPerPage);
		Assert(this_chunk_offset + this_chunk_size <= BLCKSZ);

		bytes_read = read(fd, data, this_chunk_size);
		if (bytes_read < 0)
		{
			int save_errno = errno;
			close(fd);
			errno = save_errno;
			elog(ERROR, "failed to read from '%s': %m", path);
		}
		if (bytes_read < this_chunk_size)
		{
			/*
			 * This is a bit silly, we should be prepared to handle this but
			 * for this demo code we'll just give up.
			 */
			close(fd);
			elog(ERROR, "short read from '%s'", path);
		}

		/* Copy the chunk onto the page. */
		UndoRecPtrAssignRelFileNode(rfn, insert_undo_ptr);
		buffer =
			ReadBufferWithoutRelcache(rfn,
									  UndoLogForkNum,
									  UndoRecPtrGetBlockNum(insert_undo_ptr),
									  RBM_NORMAL,
									  NULL,
									  persistence);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);
		if (this_chunk_offset == UndoLogBlockHeaderSize)
			PageInit(page, BLCKSZ, 0);
		memcpy(page + this_chunk_offset, data, this_chunk_size);
		MarkBufferDirty(buffer);
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buffer);

		/* Prepare to put the next chunk on the next page. */
		insert_undo_ptr += this_chunk_size;
		remaining -= this_chunk_size;

		/* Step over the page header if we landed at the start of page. */
		if (UndoRecPtrGetPageOffset(insert_undo_ptr) == 0)
			insert_undo_ptr += UndoLogBlockHeaderSize;
	}

	/* Advance the undo log insert point.  No need to consider headers. */
	UndoLogAdvance(start_undo_ptr, size, persistence);

	/*
	 * We'd leak a file descriptor if code above raised an error, but not
	 * worrying about that for this demo code.
	 */
	close(fd);

	PG_RETURN_TEXT_P(undo_rec_ptr_to_text(start_undo_ptr));
}

/*
 * Extract the contents of an undo log into a file.
 */
Datum
undo_extract_file(PG_FUNCTION_ARGS)
{
	char *path = text_to_cstring(PG_GETARG_TEXT_PP(0));
	UndoRecPtr undo_ptr = undo_rec_ptr_from_text(PG_GETARG_TEXT_PP(1));
	size_t size = (size_t) PG_GETARG_INT32(2);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(3));
	size_t remaining = size;
	int fd;

	if (UndoRecPtrGetPageOffset(undo_ptr) < UndoLogBlockHeaderSize)
		elog(ERROR, "undo pointer points to header data");

	fd = open(path, O_WRONLY | O_CREAT, 0664);
	if (fd < 0)
		elog(ERROR, "can't open '%s': %m", path);

	while (remaining > 0)
	{
		RelFileNode rfn;
		Buffer buffer;
		char *page;
		size_t this_chunk_offset;
		size_t this_chunk_size;
		char data[BLCKSZ];
		ssize_t bytes_written;

		/*
		 * Figure out how much we can read from the page that undo_ptr points
		 * to.
		 */
		this_chunk_offset = UndoRecPtrGetPageOffset(undo_ptr);
		this_chunk_size = Min(remaining, BLCKSZ - this_chunk_offset);

		/* Copy region of page contents to buffer. */
		UndoRecPtrAssignRelFileNode(rfn, undo_ptr);
		buffer =
			ReadBufferWithoutRelcache(rfn,
									  UndoLogForkNum,
									  UndoRecPtrGetBlockNum(undo_ptr),
									  RBM_NORMAL,
									  NULL,
									  persistence);
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);
		memcpy(data, page + this_chunk_offset, this_chunk_size);
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buffer);

		/* Write out. */
		bytes_written = write(fd, data, this_chunk_size);
		if (bytes_written < 0)
		{
			int save_errno = errno;
			close(fd);
			errno = save_errno;
			elog(ERROR, "failed to write to '%s': %m", path);
		}
		if (bytes_written < this_chunk_size)
		{
			/*
			 * This is a bit silly, we should be prepared to handle this but
			 * for this demo code we'll just give up.
			 */
			close(fd);
			elog(ERROR, "short write to '%s'", path);
		}

		/* Prepare to put the next chunk on the next page. */
		undo_ptr += this_chunk_size;
		remaining -= this_chunk_size;

		/* Step over the page header if we landed at the start of page. */
		if (UndoRecPtrGetPageOffset(undo_ptr) == 0)
			undo_ptr += UndoLogBlockHeaderSize;
	}
	PG_RETURN_VOID();
}

/*
 * Allocate space and write data into it.
 */
static UndoRecPtr
undo_append_raw(void *data, size_t size, UndoPersistence persistence)
{
	size_t remaining;
	UndoRecPtr start_undo_ptr;
	UndoRecPtr insert_undo_ptr;

	/* Allocate undo log space for our data. */
	start_undo_ptr = UndoLogAllocate(size, persistence);

	elog(NOTICE, "will copy %zu bytes into undo log at " UndoRecPtrFormat,
		 size, start_undo_ptr);

	/*
	 * Copy data into shared buffers.  Real code that does this would need to
	 * WAL-log something that would redo this.
	 */
	insert_undo_ptr = start_undo_ptr;
	remaining = size;
	while (remaining > 0)
	{
		RelFileNode rfn;
		Buffer buffer;
		char *page;
		size_t this_chunk_offset;
		size_t this_chunk_size;

		/*
		 * Figure out how much we can fit on the page that insert_undo_ptr
		 * points to.
		 */
		this_chunk_offset = UndoRecPtrGetPageOffset(insert_undo_ptr);
		this_chunk_size = Min(remaining, BLCKSZ - this_chunk_offset);

		Assert(this_chunk_offset >= UndoLogBlockHeaderSize);
		Assert(this_chunk_size <= UndoLogUsableBytesPerPage);
		Assert(this_chunk_offset + this_chunk_size <= BLCKSZ);
		elog(NOTICE, "writing chunk at offset %zu", this_chunk_offset);

		/* Copy the chunk onto the page. */
		UndoRecPtrAssignRelFileNode(rfn, insert_undo_ptr);
		buffer =
			ReadBufferWithoutRelcache(rfn,
									  UndoLogForkNum,
									  UndoRecPtrGetBlockNum(insert_undo_ptr),
									  RBM_NORMAL,
									  NULL,
									  persistence);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);
		if (this_chunk_offset == UndoLogBlockHeaderSize)
			PageInit(page, BLCKSZ, 0);
		memcpy(page + this_chunk_offset, data, this_chunk_size);
		MarkBufferDirty(buffer);
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buffer);

		/* Prepare to put the next chunk on the next page. */
		insert_undo_ptr += this_chunk_size;
		data = (char *) data + this_chunk_size;
		remaining -= this_chunk_size;

		/* Step over the page header if we landed at the start of page. */
		if (UndoRecPtrGetPageOffset(insert_undo_ptr) == 0)
			insert_undo_ptr += UndoLogBlockHeaderSize;
	}

	/* Advance the undo log insert point.  No need to consider headers. */
	UndoLogAdvance(start_undo_ptr, size, persistence);

	return start_undo_ptr;
}

/*
 * Allocate space and write data into it.
 */
Datum
undo_append(PG_FUNCTION_ARGS)
{
	bytea *input = PG_GETARG_BYTEA_PP(0);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(1));
	void *data = VARDATA_ANY(input);
	size_t size = VARSIZE_ANY_EXHDR(input);

	PG_RETURN_TEXT_P(undo_rec_ptr_to_text(undo_append_raw(data, size, persistence)));
}


/*
 * We need to be able to write a transaction header that will prevent the undo
 * background worker from discarding any data that follows it until the
 * referenced xid has committed.  We define this here to avoid problematic
 * interactions with later patches that add record level abstractions, but it
 * might be removed later.
 */
typedef struct TestRecordHeader
{
	uint8		urec_type;
	uint8		urec_info;
	uint16		urec_prevlen;
	Oid			urec_relfilenode;
	TransactionId urec_prevxid;
	TransactionId urec_xid;
	CommandId	urec_cid;
} TestRecordHeader;

typedef struct TestRecordTransaction
{
	uint32			urec_xidepoch;
	uint64			urec_next;
} TestRecordTransaction;

Datum
undo_append_transaction_header(PG_FUNCTION_ARGS)
{
	TestRecordHeader header1;
	TestRecordTransaction header2;
	TransactionId xid = DatumGetTransactionId(PG_GETARG_DATUM(0));
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(1));
	UndoRecPtr	result;

	memset(&header1, 0, sizeof(header1));
	header1.urec_type = 0x08;
	header1.urec_xid = xid;
	memset(&header2, 0, sizeof(header2));
	header2.urec_next = InvalidUndoRecPtr;

	result =
		undo_append_raw(&header1,
						offsetof(TestRecordHeader, urec_cid) +
						sizeof(CommandId),
						persistence);
	undo_append_raw(&header2, sizeof(header2), persistence);

	PG_RETURN_TEXT_P(undo_rec_ptr_to_text(result));
}

Datum
undo_dump(PG_FUNCTION_ARGS)
{
	UndoRecPtr undo_ptr = undo_rec_ptr_from_text(PG_GETARG_TEXT_PP(0));
	size_t size = (size_t) PG_GETARG_INT32(1);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(2));
	size_t remaining;


	/* Rewind so that we start on an 8-byte block. */
	if (undo_ptr % 8 != 0)
	{
		int extra_prefix = 8 - undo_ptr % 8;

		undo_ptr -= extra_prefix;
		size += extra_prefix;
	}
	/* Extend size so we show an 8-byte block. */
	if (size % 8 != 0)
		size += 8 - size % 8;
	remaining = size;

	while (remaining > 0)
	{
		RelFileNode rfn;
		Buffer buffer;
		char *page;
		size_t this_chunk_offset;
		size_t this_chunk_size;
		unsigned char data[8];
		char line[80];
		int i;

		/*
		 * Figure out how much we can read from the page that undo_ptr points
		 * to.
		 */
		this_chunk_offset = UndoRecPtrGetPageOffset(undo_ptr);
		this_chunk_size = 8;

		/* Copy region of page contents to buffer. */
		UndoRecPtrAssignRelFileNode(rfn, undo_ptr);
		buffer =
			ReadBufferWithoutRelcache(rfn,
									  UndoLogForkNum,
									  UndoRecPtrGetBlockNum(undo_ptr),
									  RBM_NORMAL,
									  NULL,
									  persistence);
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);
		memcpy(data, page + this_chunk_offset, this_chunk_size);
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buffer);

		/* Write out.  Apologies for this horrible code. */
		snprintf(line, sizeof(line), UndoRecPtrFormat ": ", undo_ptr);
		for (i = 0; i < 8; ++i)
			snprintf(&line[18 + 3 * i], 4, "%02x ", data[i]);
		for (i = 0; i < 8; ++i)
		{
			char c = '.';

			if (data[i] >= ' ' && data[i] <= 127)
				c = data[i];
			line[18 + 3 * 8 + i] = c;
		}
		line[18 + 3 * i + i] = '\0';
		elog(NOTICE, "%s", line);

		/* Prepare to put the next chunk on the next page. */
		undo_ptr += this_chunk_size;
		remaining -= this_chunk_size;

		/* Step over the page header if we landed at the start of page. */
		if (UndoRecPtrGetPageOffset(undo_ptr) == 0)
			undo_ptr += UndoLogBlockHeaderSize;
	}
	PG_RETURN_VOID();
}

Datum
undo_foreground_discard_test(PG_FUNCTION_ARGS)
{
	int loops = PG_GETARG_INT32(0);
	int size = PG_GETARG_INT32(1);
	UndoPersistence persistence = undo_persistence_from_text(PG_GETARG_TEXT_PP(2));
	int i;

	if (size > BLCKSZ)
		elog(ERROR, "data too large");

	for (i = 0; i < loops; ++i)
	{
		UndoRecPtr undo_ptr;

		/* Allocate some space. */
		undo_ptr = UndoLogAllocate(size, persistence);
		UndoLogAdvance(undo_ptr, size, persistence);

		/* Discard the space that we just allocated. */
		UndoLogDiscard(undo_ptr + size, InvalidTransactionId);
	}

	PG_RETURN_VOID();
}

/*
 * Check if an undo pointer has been discarded.
 */
Datum
undo_is_discarded(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(UndoLogIsDiscarded(undo_rec_ptr_from_text(PG_GETARG_TEXT_PP(0))));
}

/*
 * Mark the currently attached undo log(s) as full and detach.  Normally
 * this happens automatically when UndoLogAllocate() hits the end of the 1TB
 * space inside an undo log, before it attaches to a new one.  It's useful for
 * testing to be able to force that at an arbitrary time.
 */
Datum
undo_detach_full(PG_FUNCTION_ARGS)
{
	UndoLogDetachFull();
	PG_RETURN_VOID();
}
