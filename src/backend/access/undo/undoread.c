/*
 * XXX: THIS IS NOT A PROPER SEPARATION OF CONCERNS - a fair bit of this
 * probably should be moved to other files.
 *
 * FIXME:
 * - need to signal what undo we're reading
 * - don't just copy everything into memory
 * - introduce efficient reading interface
 */

#include "postgres.h"

#include "access/undo.h"
#include "access/undolog.h"
#include "access/undopage.h"
#include "access/undoread.h"
#include "access/undorecordset.h"
#include "access/xactundo.h"
#include "storage/bufmgr.h"


/* ---
 * Generic undo helpers (i.e. no URS awareness)
 * ---
 */

static void
undo_release_buffer(UndoCachedBuffer *cached_buffer)
{
	if (BufferIsValid(cached_buffer->pinned_buffer))
	{
		Assert(cached_buffer->pinned_block != InvalidBlockNumber);

		ReleaseBuffer(cached_buffer->pinned_buffer);
		cached_buffer->pinned_buffer = InvalidBuffer;
		cached_buffer->pinned_block = InvalidBlockNumber;
	}
	else
		Assert(cached_buffer->pinned_block == InvalidBlockNumber);
}

static Buffer
undo_read_block(UndoCachedBuffer *cached_buffer,
				char relpersistence,
				UndoRecPtr urp)
{
	RelFileNode rnode;
	BlockNumber blockno = UndoRecPtrGetBlockNum(urp);

	if (cached_buffer->pinned_block == blockno)
	{
		Assert(BufferIsValid(cached_buffer->pinned_buffer));
		return cached_buffer->pinned_buffer;
	}
	else
		undo_release_buffer(cached_buffer);

	UndoRecPtrAssignRelFileNode(rnode, urp);

	cached_buffer->pinned_buffer =
		ReadBufferWithoutRelcache(rnode,
								  MAIN_FORKNUM,
								  blockno,
								  RBM_NORMAL,
								  NULL,
								  relpersistence);
	cached_buffer->pinned_block = blockno;

	return cached_buffer->pinned_buffer;
}

static UndoRecPtr
undo_read_bytes(UndoCachedBuffer *cached_buffer,
				char relpersistence,
				UndoRecPtr urp,
				size_t nbytes,
				char *data)
{
	size_t data_off = 0;

	while (nbytes > 0)
	{
		int page_off = UndoRecPtrGetPageOffset(urp);
		int nread;
		Page page;

		if (page_off < SizeOfUndoPageHeaderData)
			page_off = SizeOfUndoPageHeaderData;

		undo_read_block(cached_buffer, relpersistence, urp);

		page = BufferGetPage(cached_buffer->pinned_buffer);

		if (page_off + nbytes > BLCKSZ)
			nread = BLCKSZ - page_off;
		else
			nread = nbytes;

		LockBuffer(cached_buffer->pinned_buffer, BUFFER_LOCK_SHARE);

		{
			UndoPageHeader uph = (UndoPageHeader) page;

			if (unlikely(page_off + nread > uph->ud_insertion_point))
				elog(ERROR, "asked to read [%u, %u) but insertion point is %u",
					 page_off, page_off + nread, uph->ud_insertion_point);
		}

		memcpy(data + data_off, (char *) page + page_off, nread);

		LockBuffer(cached_buffer->pinned_buffer, BUFFER_LOCK_UNLOCK);

		nbytes -= nread;
		data_off += nread;
		urp = (urp - urp % BLCKSZ) + page_off + nread;
	}

	return urp;
}

static UndoPageHeaderData
undo_read_page_header(UndoCachedBuffer *cached_buffer,
					  char relpersistence,
					  UndoRecPtr urp)
{
	UndoPageHeaderData uph;
	Page page;

	undo_read_block(cached_buffer, relpersistence, urp);

	page = BufferGetPage(cached_buffer->pinned_buffer);

	LockBuffer(cached_buffer->pinned_buffer, BUFFER_LOCK_SHARE);
	uph = *(UndoPageHeader) page;
	LockBuffer(cached_buffer->pinned_buffer, BUFFER_LOCK_UNLOCK);

	return uph;
}


/* ---
 * Functions for reading an URS.
 * ---
 */

/*
 * Helper function for urs_chunk_find_start, to iterate through all the chunks
 * starting on the page, stopping at the one starting at urp (if exact = true)
 * or containing urp (exact = false).  Iff end_location is not invalid, urp is
 * in a currently open chunk, e.g. because we're doing a subtransaction
 * rollback.
 */
static UndoRecPtr
urs_chunk_find_start_on_page(UndoCachedBuffer *cached_buffer,
							 char relpersistence,
							 UndoRecPtr urp, UndoRecPtr end_location,
							 bool exact,
							 UndoRecordSetChunkHeader *urs_header)
{
	int target_off = UndoRecPtrGetPageOffset(urp);
	UndoRecPtr urp_page_start = urp - target_off;
	int current_off;
	UndoPageHeaderData uph;


	uph = undo_read_page_header(cached_buffer, relpersistence, urp_page_start);
	current_off = uph.ud_first_chunk;

	while (true)
	{
		UndoLogOffset effective_header_size;

		Assert(current_off >= SizeOfUndoPageHeaderData);
		Assert(target_off >= current_off);

		undo_read_bytes(cached_buffer, relpersistence,
						urp_page_start + current_off,
						SizeOfUndoRecordSetChunkHeader, (char *) urs_header);

		effective_header_size = urs_header->size;
		if (effective_header_size == 0)
		{
			if (end_location != InvalidUndoRecPtr &&
				UndoRecPtrGetBlockNum(end_location) == UndoRecPtrGetBlockNum(urp))
				effective_header_size = end_location - (urp_page_start + current_off);
			else
				elog(ERROR, "found open chunk at %lu", urp);
		}

		if (exact)
		{
			/* found target */
			if (target_off == current_off)
				break;

			if (target_off < (current_off + effective_header_size))
				elog(ERROR, "invalid page: pointing to the middle of chunk");
		}
		else
		{
			/* found target */
			if (target_off <= (current_off + effective_header_size))
				break;
		}

		if (urs_header->size == 0)
			elog(ERROR, "target chunk beyond open chunk");

		/* look at next chunk */
		current_off = current_off + urs_header->size;

		if (current_off >= BLCKSZ)
			elog(ERROR, "requested chunk header not on page");
	}

	if (end_location != InvalidUndoRecPtr &&
		urs_header->size != 0)
		elog(ERROR, "looking foropen chunk, found closed");

	/* FIXME: verify chunk type */

	return urp_page_start + current_off;
}

/*
 * Identify the chunk containing urp. Iff end_location is not invalid, urp is
 * in a currently open chunk, e.g. because we're doing a subtransaction
 * rollback.  At exit urs_header will contain the header for the identified
 * chunk, or an error will have been raised.
 */
static UndoRecPtr
urs_chunk_find_start(UndoCachedBuffer *cached_buffer,
					 char relpersistence,
					 UndoRecPtr urp,
					 UndoRecPtr end_location,
					 UndoRecordSetChunkHeader *urs_header)
{
	UndoPageHeaderData uph_initial;
	int off = UndoRecPtrGetPageOffset(urp);
	UndoRecPtr urp_chunk_header;

	uph_initial = undo_read_page_header(cached_buffer, relpersistence, urp);

	if (uph_initial.ud_insertion_point == 0)
		elog(ERROR, "page not initialized");
	else if (off >= uph_initial.ud_insertion_point)
		elog(ERROR, "invalid urp: beyond insertion point");
	else if (uph_initial.ud_first_chunk == 0 || off <= uph_initial.ud_first_chunk)
	{
		/*
		 * The start of the urp is on a preceding page. Perform some
		 * verification, and then continue by reading the start of the urp at
		 * the other page.
		 */

		if (uph_initial.ud_continue_chunk == InvalidUndoRecPtr)
			elog(ERROR, "invalid page: continue invalid");
		if (uph_initial.ud_continue_chunk >= (urp - (urp % BLCKSZ)))
			elog(ERROR, "invalid page: continue too large");
		/* FIXME: validate chunk starts in same log */
		/* FIXME: validate chunk type */

		urp_chunk_header = uph_initial.ud_continue_chunk;

		urp_chunk_header =
			urs_chunk_find_start_on_page(cached_buffer, relpersistence,
										 urp_chunk_header, end_location, true, urs_header);
		Assert(urp_chunk_header == uph_initial.ud_continue_chunk);
	}
	else
	{
		urp_chunk_header =
			urs_chunk_find_start_on_page(cached_buffer, relpersistence,
										 urp, end_location, false, urs_header);
	}

	Assert(urp_chunk_header <= urp);

	return urp_chunk_header;
}

/*
 * Build list of all chunks preceding the chunk already in cl.
 */
static void
urs_load_preceding_chunks(UndoCachedBuffer *cached_buffer,
						  char relpersistence,
						  UndoRecordSetChunkList *cl)
{
	UndoRecordSetChunkListItem *cur;
	UndoRecordSetChunkListItem *prev;

	Assert(cl->nchunks == 1 && cl->chunks != NULL);

	while (true)
	{
		cur = &cl->chunks[0];

		if (!cur->header.previous_chunk)
			break;

		/* different log, blocknos could be the same */
		undo_release_buffer(cached_buffer);

		cl->chunks =
			repalloc(cl->chunks,
					 sizeof(UndoRecordSetChunkListItem) * (cl->nchunks + 1));
		memmove((char *) cl->chunks + sizeof(UndoRecordSetChunkListItem),
				(char *) cl->chunks,
				sizeof(UndoRecordSetChunkListItem) * cl->nchunks);

		cur = &cl->chunks[0];
		prev = &cl->chunks[1];
		cl->nchunks++;

		memset(&cur->header, 0, sizeof(UndoRecordSetChunkHeader));
		cur->urp_chunk_header = prev->header.previous_chunk;

		if (cur->urp_chunk_header == prev->urp_chunk_header)
			elog(ERROR, "previous urs chunk is the same as current");
		if (UndoRecPtrGetLogNo(cur->urp_chunk_header) == UndoRecPtrGetLogNo(prev->urp_chunk_header))
			elog(ERROR, "previous urs chunk is in the same log as current");

		urs_chunk_find_start_on_page(cached_buffer, relpersistence,
									 cur->urp_chunk_header, InvalidUndoRecPtr,
									 /* exact = */ true, &cur->header);

		cur->urp_chunk_end = cur->urp_chunk_header + cur->header.size;
		if (UndoRecPtrGetPageOffset(cur->urp_chunk_end) <= SizeOfUndoPageHeaderData)
		{
			if (UndoRecPtrGetPageOffset(cur->urp_chunk_end) < SizeOfUndoPageHeaderData)
				elog(ERROR, "chunk end in page header");
			cur->urp_chunk_end -= SizeOfUndoPageHeaderData;
		}

		elog(DEBUG1, "found chunk %lu, len %lu, end at %lu, continuing from %lu",
			 cur->urp_chunk_header, cur->header.size,
			 cur->urp_chunk_header + cur->header.size,
			 cur->header.previous_chunk);
	}
}

/*
 * Undo reader specific helpers
 */

#if NOT_NEEDED_RN
static void
undo_reader_read_block(UndoRSReaderState *r, UndoRecPtr urp)
{
	undo_read_block(&r->pinned_blockno,
					&r->pinned_buffer,
					urp, r->relpersistence);
}
#endif

/*
 * Read a number of bytes of undo content, correctly crossing page boundaries
 * if necessary. Returns pointer to the byte after the data.
 */
static UndoRecPtr
undo_reader_read_bytes(UndoRSReaderState *r,
					   UndoRecPtr urp,
					   size_t nbytes)
{
	XLogRecPtr ret;

	enlargeStringInfo(&r->buf, nbytes);

	ret = undo_read_bytes(&r->cached_buffer,
						  r->relpersistence,
						  urp,
						  nbytes,
						  r->buf.data + r->buf.len);

	r->buf.len = nbytes;

	return ret;
}

static void
undo_reader_release_buffer(UndoRSReaderState *r)
{
	undo_release_buffer(&r->cached_buffer);
}

/*
 * XXX: This is not how it's going to look going forward, but an intermediary
 * step.
 */

/*
 * Initialize reading an entire undo record set. Urp can point to either the
 * header, or anywhere within the urs.
 *
 * FIXME: relies on CurrentMemoryContext - probably OK?
 */
void
UndoRSReaderInit(UndoRSReaderState *r,
				 UndoRecPtr start, UndoRecPtr end,
				 char relpersistence, bool toplevel)
{
	UndoRecordSetChunkListItem *last_chunk;
	UndoRecordSetChunkListItem *first_chunk;
	UndoRecPtr end_within;

	memset(r, 0, sizeof(UndoRSReaderState));

	r->start_reading = start;
	r->end_reading = end;

	r->cached_buffer.pinned_buffer = InvalidBuffer;
	r->cached_buffer.pinned_block = InvalidBlockNumber;
	r->relpersistence = relpersistence;
	initStringInfo(&r->buf);

	/*
	 * FIXME: end location points to the *end* of the chunk, i.e. to just
	 * after the last record. But to keep the urs_* routines reusable, we want
	 * to pass a location *within* the chunk. Thus rewind 1 byte. But that'd
	 * potentially point inside the page header, which we treat as an error -
	 * so rewind more if that's the case.
	 */
	end_within = end - 1;
	if (UndoRecPtrGetPageOffset(end_within) < SizeOfUndoPageHeaderData)
		end_within -= (UndoRecPtrGetPageOffset(end_within) + 1);

	r->chunks.nchunks = 1;
	r->chunks.chunks = palloc(sizeof(UndoRecordSetChunkListItem));

	/*
	 * For the end location we do not always know where the containing chunk
	 * is. Identify the chunk based on page contents.
	 */
	last_chunk = &r->chunks.chunks[0];
	last_chunk->urp_chunk_header =
		urs_chunk_find_start(&r->cached_buffer, r->relpersistence,
							 end_within,
							 toplevel ? InvalidUndoRecPtr : end,
							 &last_chunk->header);

	elog(DEBUG1, "found chunk for end urp %lu at %lu, len %lu, end at %lu, continuing from %lu",
		 end, last_chunk->urp_chunk_header, last_chunk->header.size, last_chunk->urp_chunk_header + last_chunk->header.size,
		 last_chunk->header.previous_chunk);

	if (toplevel)
		last_chunk->urp_chunk_end = last_chunk->urp_chunk_header + last_chunk->header.size;
	else
	{
		if (last_chunk->header.size != 0)
			elog(ERROR, "unexpected closed URS for subtransaction");
		/* fill in a size for the chunk */
		last_chunk->urp_chunk_end = end;
	}

	if (UndoRecPtrGetPageOffset(last_chunk->urp_chunk_end) <= SizeOfUndoPageHeaderData)
	{
		if (UndoRecPtrGetPageOffset(last_chunk->urp_chunk_end) < SizeOfUndoPageHeaderData)
			elog(ERROR, "chunk end in page header");
		last_chunk->urp_chunk_end -= SizeOfUndoPageHeaderData;
	}

	/*
	 * Now that we have one chunk the urs, build list of all chunks.
	 */
	urs_load_preceding_chunks(&r->cached_buffer, r->relpersistence,
							  &r->chunks);
	first_chunk = &r->chunks.chunks[0];
	last_chunk = &r->chunks.chunks[r->chunks.nchunks - 1];

	Assert(first_chunk->header.previous_chunk == InvalidUndoRecPtr);

	r->current_chunk = 1;
}

/*
 * Read one record in forward direction, with the first record returned being
 * the one at start as passed to UndoRSReaderInit(), ending at end.
 */
bool
UndoRSReaderReadOneForward(UndoRSReaderState *r)
{
	UndoRecPtr urp_content;
	UndoRecPtr next;
	UndoRecordSetChunkListItem *curchunk;

	/* read all */
	if (r->current_chunk == -1)
		return false;

	Assert(r->current_chunk > 0 && r->current_chunk <= r->chunks.nchunks);

	curchunk = &r->chunks.chunks[r->current_chunk - 1];

	if (r->next_urp == InvalidUndoRecPtr)
	{
		if (curchunk->urp_chunk_header == r->start_reading ||
			UndoRecPtrGetLogNo(curchunk->urp_chunk_header) != UndoRecPtrGetLogNo(r->start_reading))
		{
			/* first skip over the chunk header */
			r->next_urp =
				UndoRecPtrPlusUsableBytes(curchunk->urp_chunk_header, SizeOfUndoRecordSetChunkHeader);

			/* and then over the type specific header */
			// FIXME: use proper size of type specific header
			if (curchunk->header.previous_chunk == InvalidUndoRecPtr)
				r->next_urp = UndoRecPtrPlusUsableBytes(r->next_urp,  16);
		}
		else
		{
			r->next_urp = r->start_reading;
		}
	}

	if (r->next_urp == InvalidUndoRecPtr)
		return false;

	/* first read the URS record length, could be split over pages */
	{
		/*
		 * XXX: Right now we use a fixed width length encoding, but once this
		 * is encoded as a variable length integer, there's no way around
		 * reading this separately.
		 */
		resetStringInfo(&r->buf);
		urp_content = undo_reader_read_bytes(r, r->next_urp, sizeof(r->node.n.length));
		r->node.location = r->next_urp;
		r->node.n.length = *(uint16*) r->buf.data;
	}

	/* same with type */
	{
		resetStringInfo(&r->buf);

		urp_content = undo_reader_read_bytes(r, urp_content, sizeof(r->node.n.type));
		r->node.n.type = *(uint16*) r->buf.data;
	}

	/* then read the entire record */
	resetStringInfo(&r->buf);
	next = undo_reader_read_bytes(r, urp_content, r->node.n.length);
	r->node.n.data = r->buf.data;

	/* FIXME: also check r->end_reading for the last chunk */
	if (next >= curchunk->urp_chunk_end)
	{
		r->next_urp = InvalidUndoRecPtr;
		if (r->current_chunk < r->chunks.nchunks)
			r->current_chunk++;
		else
			r->current_chunk = -1;

		/* block numbers in next chunk could be identical */
		undo_reader_release_buffer(r);
	}
	else
		r->next_urp = next;

	return true;
}

/*
 * Read one record in backward direction, with the first record returned being
 * the one at end as passed to UndoRSReaderInit(), ending at start.
 */
extern bool
UndoRSReaderReadOneBackward(UndoRSReaderState *r)
{
	if (!r->backward.init)
	{
		List *records = NIL;

		/*
		 * Implement backward iteration the naivest possible way. Read all
		 * records into memory, iterate backwards.
		 *
		 * FIXME: obviously this needs to be replaced.
		 */
		while (UndoRSReaderReadOneForward(r))
		{
			WrittenUndoNode *node = palloc(MAXALIGN(sizeof(WrittenUndoNode)) +
										   r->node.n.length);

			node->location = r->node.location;
			node->n = r->node.n;
			node->n.data = (char *) node + MAXALIGN(sizeof(WrittenUndoNode));
			memcpy(node->n.data, r->node.n.data, r->node.n.length);

			records = lappend(records, node);
		}

		r->backward.init = true;
		r->backward.records = records;
		r->backward.cur = list_length(r->backward.records);
	}

	if (r->backward.cur == 0)
		return false;
	--r->backward.cur;
	r->node = *(WrittenUndoNode *) list_nth(r->backward.records, r->backward.cur);
	return true;
}

void
UndoRSReaderClose(UndoRSReaderState *r)
{
	undo_reader_release_buffer(r);

	if (r->backward.records)
		list_free_deep(r->backward.records);

	if (r->buf.data)
		pfree(r->buf.data);
}
