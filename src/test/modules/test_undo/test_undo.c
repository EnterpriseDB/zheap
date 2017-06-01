#include "postgres.h"

#include "access/undolog.h"
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
PG_FUNCTION_INFO_V1(undo_read);
PG_FUNCTION_INFO_V1(undo_discard);

/*
 * Just allocate some undo space, for testing.
 */
Datum
undo_allocate(PG_FUNCTION_ARGS)
{
	int size = PG_GETARG_INT32(0);
	UndoRecPtr undo_ptr;

	undo_ptr = UndoLogAllocate(size, RELPERSISTENCE_PERMANENT);

	PG_RETURN_INT64(undo_ptr);
}

/*
 * Advance the insert pointer for an undo log, for testing.
 */
Datum
undo_advance(PG_FUNCTION_ARGS)
{
	UndoRecPtr undo_ptr = PG_GETARG_INT64(0);
	int size = PG_GETARG_INT32(1);

	UndoLogAdvance(undo_ptr, size);

	PG_RETURN_VOID();
}

/*
 * Allocate space and write data into it.
 */
Datum
undo_append(PG_FUNCTION_ARGS)
{
	bytea *input = PG_GETARG_BYTEA_PP(0);
	char *data;
	size_t size;
	size_t remaining;
	UndoRecPtr start_undo_ptr;
	UndoRecPtr insert_undo_ptr;

	data = VARDATA_ANY(input);
	size = VARSIZE_ANY_EXHDR(input);
	/* TODO: what is max undo record size? */
	if (size > BLCKSZ)
		elog(ERROR, "data too large");

	/* Allocate undo log space for our data. */
	start_undo_ptr = UndoLogAllocate(size, RELPERSISTENCE_PERMANENT);

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
		char *contents;
		size_t this_chunk_offset;
		size_t this_chunk_size;

		/* Figure out where the first chunk belongs. */
		this_chunk_offset = UndoRecPtrGetPageOffset(insert_undo_ptr);
		this_chunk_size =
			Min(remaining, UndoLogUsableBytesPerPage - this_chunk_offset);

		/* Copy the chunk onto the page. */
		UndoRecPtrAssignRelFileNode(rfn, insert_undo_ptr);
		buffer =
			ReadBufferWithoutRelcache(rfn,
									  UndoLogForkNum,
									  UndoRecPtrGetBlockNum(insert_undo_ptr),
									  RBM_NORMAL,
									  NULL);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		contents = PageGetContents(BufferGetPage(buffer));
		memcpy(contents + this_chunk_offset, data, this_chunk_size);
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buffer);

		/* Prepare to put the next chunk on the next page. */
		insert_undo_ptr += this_chunk_size;
		data += this_chunk_size;
		remaining -= this_chunk_size;
	}

	/* Advance the undo log insert point. */
	UndoLogAdvance(start_undo_ptr, size);

	PG_RETURN_INT64(start_undo_ptr);
}

Datum
undo_read(PG_FUNCTION_ARGS)
{
	/*
	int64 undo_ptr = PG_GETARG_INT64(0);
	int size = PG_GETARG_INT32(1);
	*/


	return (Datum) 0;
}

Datum
undo_discard(PG_FUNCTION_ARGS)
{
	/* TODO: write me */
	PG_RETURN_VOID();
}
