/*-------------------------------------------------------------------------
 *
 * undorecordset_xlog.c
 *	  xlog support routines for undo record sets
 *
 * src/backend/access/undo/undorecordset_xlog.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "access/undorecordset_xlog.h"

#ifndef FRONTEND
#include "access/xloginsert.h"
#endif

/*
 * Expand the data encoded by EncodeUndoRecordSetXLogBufData() and attached to
 * a registed block, to fill in the parts of 'out' that are present.  If no
 * data is registered, 'out' is initialized with an empty 'flags' member.
 * Returns true on success, false on invalid data.  We can't use elog() here
 * because the same code is used in pg_waldump.
 */
bool
DecodeUndoRecordSetXLogBufData(UndoRecordSetXLogBufData *out,
							   XLogReaderState *record,
							   uint8 block_id)
{
	size_t size;
	char *in;

	/* If there is no data at all, that is valid. */
	memset(out, 0, sizeof(*out));
	in = XLogRecGetBlockData(record, block_id, &size);
	if (!in)
		return true;

	/* Macros that copy data, returning false if they run out of data. */
#define DESERIALIZE_FIXED(dst) \
	do { \
		if (size < sizeof(*(dst))) \
			return false; \
		memcpy((dst), in, sizeof(*(dst))); \
		in += sizeof(*(dst)); \
		size -= sizeof(*(dst)); \
	} while (0)
#define DESERIALIZE_PTR(dst, len) \
	do { \
		if (size < (len)) \
			return false; \
		*(dst) = in; \
		in += (len); \
		size -= (len); \
	} while (0)

	DESERIALIZE_FIXED(&out->flags);
	if (out->flags & URS_XLOG_HAS_TYPE_MASK)
		DESERIALIZE_FIXED(&out->urs_type);
	if (out->flags & URS_XLOG_HAS_TYPE_HEADER_MASK)
	{
		DESERIALIZE_FIXED(&out->type_header_size);
		DESERIALIZE_PTR(&out->type_header, out->type_header_size);
	}
	if (out->flags & URS_XLOG_ADD_CHUNK)
		DESERIALIZE_FIXED(&out->previous_chunk_header_location);
	if (out->flags & URS_XLOG_CLOSE_CHUNK)
	{
		DESERIALIZE_FIXED(&out->chunk_size_page_offset);
		DESERIALIZE_FIXED(&out->chunk_size);
	}
	if (out->flags & URS_XLOG_CLOSE_MULTI_CHUNK)
		DESERIALIZE_FIXED(&out->first_chunk_header_location);
	if (out->flags & URS_XLOG_INSERT)
		DESERIALIZE_FIXED(&out->insert_page_offset);
	if (out->flags & URS_XLOG_ADD_PAGE)
		DESERIALIZE_FIXED(&out->chunk_header_location);

	/* If there is still data left over, there is a format error. */
	if (size != 0)
		return false;

	return true;
}

#ifndef FRONTEND
/*
 * Attach 'in' to the given block, so that it can be replayed by UndoReplay().
 * Only include the parts that are present, according to the flags.
 */
void
EncodeUndoRecordSetXLogBufData(const UndoRecordSetXLogBufData *in,
							   uint8 block_id)
{
#define SERIALIZE(src, len) \
	XLogRegisterBufData(block_id, (char *) (src), (len))
#define SERIALIZE_FIXED(src) \
	SERIALIZE((src), sizeof(*(src)))

	SERIALIZE_FIXED(&in->flags);
	if (in->flags & URS_XLOG_HAS_TYPE_MASK)
		SERIALIZE_FIXED(&in->urs_type);
	if (in->flags & URS_XLOG_HAS_TYPE_HEADER_MASK)
	{
		SERIALIZE_FIXED(&in->type_header_size);
		SERIALIZE(in->type_header, in->type_header_size);
	}
	if (in->flags & URS_XLOG_ADD_CHUNK)
		SERIALIZE_FIXED(&in->previous_chunk_header_location);
	if (in->flags & URS_XLOG_CLOSE_CHUNK)
	{
		SERIALIZE_FIXED(&in->chunk_size_page_offset);
		SERIALIZE_FIXED(&in->chunk_size);
	}
	if (in->flags & URS_XLOG_CLOSE_MULTI_CHUNK)
		SERIALIZE_FIXED(&in->first_chunk_header_location);
	if (in->flags & URS_XLOG_INSERT)
		SERIALIZE_FIXED(&in->insert_page_offset);
	if (in->flags & URS_XLOG_ADD_PAGE)
		SERIALIZE_FIXED(&in->chunk_header_location);
}
#endif
