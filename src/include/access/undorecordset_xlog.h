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

#define URS_XLOG_CREATE			0x01
#define URS_XLOG_ADD_CHUNK		0x02
#define URS_XLOG_CLOSE_CHUNK	0x04
#define URS_XLOG_INSERTION		0x08

/*
 * A lightly decoded representation of the data associated with an undo
 * buffer.
 */
typedef struct UndoRecordSetXLogBufData
{
	UndoRecordSetType type;		/* The type of UndoRecordSet. */
	uint8		flags;			/* Flags indicating which members are set. */

	/*
	 * If URS_XLOG_CREATE is set, then the following members point to an
	 * unaligned type-specific header that should be inserted into the
	 * initial chunk.
	 */
	char	   *type_header;
	size_t		type_header_size;

	/*
	 * If URS_XLOG_ADD_CHUNK is set, then a new chunk is being created for an
	 * existing undo record set.  The new chunk will point back to the
	 * previous chunk.  The chunk header begins on this page, but may spill
	 * over onto a following page.
	 */
	UndoRecPtr	previous_chunk;

	/*
	 * If URS_XLOG_CLOSE_CHUNK is set, then the following members contain the
	 * offset of the chunk size within the page, and the chunk size that
	 * should be written there.  The location begins on this page, but may
	 * spill over to the following page.
	 */
	uint16		chunk_size_location;
	size_t		chunk_size;

	/*
	 * If URS_XLOG_INSERTION is set, then the following member contains the
	 * offset within the page of an undo record insertion.  The actual data is
	 * not captured in the WAL.
	 */
	uint16		insertion_point;
} UndoRecordSetXLogBufData;

extern bool
DecodeUndoRecordSetXLogBufData(UndoRecordSetXLogBufData *out,
							   XLogReaderState *record,
							   uint8 block_id);


extern void
EncodeUndoRecordSetXLogBufData(const UndoRecordSetXLogBufData *in,
							   uint8 block_id);

#endif
