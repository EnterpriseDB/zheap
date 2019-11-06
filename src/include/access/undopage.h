/*-------------------------------------------------------------------------
 *
 * undopage.h
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undopage.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOPAGE_H
#define UNDOPAGE_H

#include "access/undolog.h"
#include "access/undorecordset.h"
#include "storage/bufpage.h"

/*
 * Header for an undo data page.
 *
 * Like a standard page header (cf. storage/bufpage.h), this must begin with
 * an LSN stored in PageXLogRecPtr format, but we can use the other fields
 * as we wish.
 *
 * ud_checksum is an optional checksum, just as for a standard page.
 *
 * ud_insertion_point is the byte offset of the first unused byte within
 * the page.
 *
 * ud_first_record is the offset of the first byte of the first record
 * that begins on this page. Data prior to this offset is part either the
 * page header or a record continued from a previous page.
 *
 * ud_first_chunk is the offset of the first byte of the first record set chunk
 * that begins on this page, or 0 if no record set chunk begins on this page.
 *
 * ud_continue_chunk is the location where any undo record set chunk that
 * continues onto this page starts. It should be InvalidUndoRecPtr if and
 * only if ud_first_chunk == SizeOfUndoPageHeaderData.
 *
 * ud_continue_chunk_type is the type of the record set which is continued onto
 * this page from the previous page. It should be URST_INVALID if and only
 * ud_first_chunk == SizeOfUndoPageHeaderData.
 */
typedef struct UndoPageHeaderData
{
	PageXLogRecPtr		ud_lsn;
	uint16				ud_checksum;
	uint16				ud_insertion_point;
	uint16				ud_first_record;
	uint16				ud_first_chunk;
	UndoRecPtr			ud_continue_chunk;
	uint8				ud_continue_chunk_type;
} UndoPageHeaderData;

typedef UndoPageHeaderData *UndoPageHeader;

#define SizeOfUndoPageHeaderData \
	(offsetof(UndoPageHeaderData, ud_continue_chunk_type) + sizeof(UndoRecPtr))
#define UsableBytesPerUndoPage \
	(BLCKSZ - SizeOfUndoPageHeaderData)

/*
 * Increment an UndoLogOffset by a given number of bytes, stepping over page
 * headers.
 *
 * Caller must be careful not to use the result without checking that it is
 * less than UndoLogMaxSize!
 */
static inline UndoLogOffset
UndoLogOffsetPlusUsableBytes(UndoLogOffset offset, uint64 n)
{
	uint64 ubo;
	UndoLogOffset result;

	/* Convert offset to usable byte offset. */
	ubo = (offset / BLCKSZ) * UsableBytesPerUndoPage;
	ubo += (offset % BLCKSZ) - SizeOfUndoPageHeaderData;

	/* Add increment. */
	ubo += n;

	/* Convert back to UndoLogOffset. */
	result = (ubo / UsableBytesPerUndoPage) * BLCKSZ;
	result += (ubo % UsableBytesPerUndoPage) + SizeOfUndoPageHeaderData;

	return result;
}

/*
 * Increment an UndoRecPtr by a given number of bytes, stepping over page
 * headers.
 */
static inline UndoRecPtr
UndoRecPtrPlusUsableBytes(UndoRecPtr urp, uint64 n)
{
	UndoLogNumber	logno = UndoRecPtrGetLogNo(urp);
	UndoLogOffset	offset = UndoRecPtrGetOffset(urp);
	UndoRecPtr		result;

	offset = UndoLogOffsetPlusUsableBytes(offset, n);
	result = MakeUndoRecPtr(logno, offset);
	Assert(UndoRecPtrGetLogNo(result) == logno);
	return result;
}

extern void UndoPageInit(Page page);

extern int UndoPageInsertHeader(Page page, int page_offset, int header_offset,
								UndoRecordSetChunkHeader *header,
								Size type_header_size, char *type_header,
								UndoRecPtr chunk_start);
extern int UndoPageInsertRecord(Page page, int page_offset, int data_offset,
								Size data_size, char *data,
								UndoRecPtr chunk_start,
								UndoRecordSetType chunk_type);
extern int UndoPageOverwrite(Page page, int page_offset, int data_offset,
							 Size data_size, char *data);

extern int UndoPageSkipHeader(int page_offset, int header_offset,
							  size_t type_header_size);
extern int UndoPageSkipRecord(int page_offset, int data_offset,
							  size_t data_size);

#endif
