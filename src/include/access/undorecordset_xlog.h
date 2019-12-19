/*-------------------------------------------------------------------------
 *
 * undorecordset_xlog.h
 *	  undo record set XLOG definitions.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorecordset_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORDSET_XLOG_H
#define UNDORECORDSET_XLOG_H

#include "access/undorecordset.h"
#include "access/xlogreader.h"

/*
 * UndoRecordSet operations don't have WAL records of their own.  Instead,
 * they sometimes attach extra control information to the undo pages that are
 * registered with XLogRegisterBuffer().  While undo-aware AMs are responsible
 * for replaying undo record contents by calling UndoReplay(), the
 * UndoRecordSet machinery is responsible for controlling their location in
 * the undo address space, and inserting and updating headers used to manage
 * URS chunks.
 */

#define URS_XLOG_CREATE				0x01
#define URS_XLOG_ADD_CHUNK			0x02
#define URS_XLOG_CLOSE_CHUNK		0x04
#define URS_XLOG_CLOSE				0x08
#define URS_XLOG_CLOSE_MULTI_CHUNK	0x10
#define URS_XLOG_INSERT				0x20
#define URS_XLOG_ADD_PAGE			0x40

#define URS_XLOG_HAS_TYPE_MASK									\
	(URS_XLOG_CREATE | URS_XLOG_ADD_PAGE | URS_XLOG_ADD_CHUNK | \
	 URS_XLOG_CLOSE)

#define URS_XLOG_HAS_TYPE_HEADER_MASK									\
	(URS_XLOG_CREATE | URS_XLOG_CLOSE)

/*
 * A lightly decoded representation of the data associated with an undo
 * buffer.
 */
typedef struct UndoRecordSetXLogBufData
{
	uint8		flags;			/* Flags indicating which members are set. */

	/*
	 * If any of the the flags in URS_XLOG_HAS_TYPE_MASK is set, then the URS
	 * type is recorded.
	 */
	UndoRecordSetType urs_type;

	/*
	 * If any of the flags in URS_XLOG_HAS_TYPE_HEADER_MASK is set, then the
	 * following members point to the type-specific header.  When a new URS is
	 * created, this is used to log the type-specific header.  When a URS is
	 * closed, we log another copy of it, just so that it can be provided to
	 * the owning module's callback.  In practice, this is for the benefit of
	 * xactundo.c, which wants to know the transaction Id (we could also
	 * extract that from the containing WAL record, but when replaying records
	 * created by CloseDanglingUndoRecordSets() it wouldn't be available).
	 */
	char	   *type_header;
	size_t		type_header_size;

	/*
	 * If URS_XLOG_ADD_CHUNK is set, then a new chunk is being created for an
	 * existing undo record set.  The new chunk will have a header that points
	 * back to the previous chunk.  The chunk header begins on this page, but
	 * may spill over onto a following page.
	 */
	UndoRecPtr	previous_chunk_header_location;

	/*
	 * If URS_XLOG_CLOSE_CHUNK is set, then a chunk is being closed.  The
	 * following members contain the offset of the chunk size within the page,
	 * and the chunk size that should be written there.  The location begins
	 * on this page, but may spill over to the following page.
	 */
	uint16		chunk_size_page_offset;
	size_t		chunk_size;

	/*
	 * If URS_XLOG_CLOSE_MULTI_CHUNK is set, then we are closing a multi-chunk
	 * URS, and must include the location of the first chunk header.
	 * Otherwise, it's implied by chunk_size_page_offset.
	 */
	UndoRecPtr	first_chunk_header_location;

	/*
	 * If URS_XLOG_INSERT is set, then the following member contains the
	 * offset within the page of an undo record insertion.  The actual data is
	 * not captured in the WAL (it's the job of the AM that owns the WAL
	 * record to supply the same data at redo time).  We also need to know the
	 * start of the chunk, for the page header.
	 */
	uint16		insert_page_offset;

	/*
	 * If URS_XLOG_ADD_PAGE is set, then we're inserting the first data on a
	 * page and we need to supply the location of the chunk header and the URS
	 * type, to go in the page header.
	 */
	UndoRecPtr	chunk_header_location;
} UndoRecordSetXLogBufData;

extern bool
DecodeUndoRecordSetXLogBufData(UndoRecordSetXLogBufData *out,
							   XLogReaderState *record,
							   uint8 block_id);


extern void
EncodeUndoRecordSetXLogBufData(const UndoRecordSetXLogBufData *in,
							   uint8 block_id);

#endif
