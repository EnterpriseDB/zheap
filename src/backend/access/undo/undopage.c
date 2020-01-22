/*
 *-------------------------------------------------------------------------
 *
 * undopage.c
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undopage.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undopage.h"

/*
 * Initialize an undo page.
 *
 * Undo pages use a non-standard page format, so it's not appropriate to
 * just call PageInit().
 */
void
UndoPageInit(Page page)
{
	UndoPageHeader uph = (UndoPageHeader) page;

	MemSet(page, 0, BLCKSZ);
	uph->ud_insertion_point = SizeOfUndoPageHeaderData;
}

/*
 * Insert all or part of a chunk header, and optionally also a type-specific
 * header, into an undo page.  If the header is split across multiple
 * pages, call this once per page, with appropriate arguments.
 *
 * page_offset is the byte-offset within the page to which data should be
 * written; header_offset is the byte-offset within the data that should
 * begin at that location.
 *
 * If we're not writing a type-specific header, pass type_header_size as 0;
 * otherwise, type_header_size and type_header describe the type-specific
 * header to be written.
 *
 * chunk_start is the UndoRecPtr where the chunk starts.  If this chunk is
 * split across multiple pages, we'll need to store this in the page header
 * of the continuation page.  It can be InvalidUndoRecPtr when writing the
 * first part of the data.
 *
 * The return value is the number of bytes written into the page.
 */
int
UndoPageInsertHeader(Page page, int page_offset, int header_offset,
					 UndoRecordSetChunkHeader *header,
					 Size type_header_size, char *type_header,
					 UndoRecPtr chunk_start)
{
	UndoPageHeader uph = (UndoPageHeader) page;
	Size	total_bytes = SizeOfUndoRecordSetChunkHeader + type_header_size;
	int		data_bytes = 0;
	int		type_header_offset;

	/* Must not overwrite the page header. */
	Assert(page_offset >= SizeOfUndoPageHeaderData);

	/* Must not overrun the end of the page. */
	Assert(page_offset < BLCKSZ);

	/* Must not overrun the end of the new data, either. */
	Assert(header_offset < total_bytes);

	/* Continuation data must start at beginning of page. */
	Assert(header_offset == 0 || page_offset == SizeOfUndoPageHeaderData);

	/* Insertion point must be as expected. */
	Assert(page_offset == uph->ud_insertion_point);

	/*
	 * If the entire chunk header hasn't yet been written, then write the
	 * remaining bytes and start the type header just afterward. If we've
	 * already written the whole chunk header, just account for its length
	 * in deciding from where to start writing the type header.
	 */
	if (header_offset < SizeOfUndoRecordSetChunkHeader)
	{
		Size	chunk_header_bytes;

		chunk_header_bytes = SizeOfUndoRecordSetChunkHeader - header_offset;
		memcpy(page + page_offset, header, chunk_header_bytes);
		data_bytes += chunk_header_bytes;
		type_header_offset = 0;
	}
	else
		type_header_offset = header_offset - SizeOfUndoRecordSetChunkHeader;

	/*
	 * If we've still got room, and if there's a type header to write, write
	 * as much of it as will fit.
	 */
	if (page_offset + data_bytes < BLCKSZ && type_header_size > 0)
	{
		Size	type_header_bytes;

		type_header_bytes =
			Min(BLCKSZ - page_offset + data_bytes,
				type_header_size - type_header_offset);
		memcpy(page + page_offset + data_bytes,
			   type_header + type_header_offset,
			   type_header_bytes);
		data_bytes += type_header_bytes;
	}

	/* New insertion point follows the data we've written. */
	uph->ud_insertion_point += data_bytes;

	/*
	 * If the header we're writing starts on this page, and this page doesn't
	 * contain any chunks yet, then make the "first chunk" pointer point
	 * to this.
	 */
	if (header_offset == 0 && uph->ud_first_chunk == 0)
		uph->ud_first_chunk = page_offset;

	/*
	 * If we're continuing this header from the previous page, then we've
	 * got to indicate the chunk type and where it starts.
	 */
	if (header_offset > 0)
	{
		Assert(chunk_start != InvalidUndoRecPtr);
		uph->ud_continue_chunk = chunk_start;
		uph->ud_continue_chunk_type = header->type;
	}

	return data_bytes;
}

/*
 * Compute the number of header bytes that would have been written into a page.
 *
 * This function returns the same value that UndoPageInsertHeader would have
 * returned given the same arguments, but without writing anything.
 */
int
UndoPageSkipHeader(int page_offset, int header_offset, size_t type_header_size)
{
	size_t all_header_size = SizeOfUndoRecordSetChunkHeader + type_header_size;

	/* Must not overwrite the page header. */
	Assert(page_offset >= SizeOfUndoPageHeaderData);

	/* Must not overrun the end of the page. */
	Assert(page_offset < BLCKSZ);

	return Min(BLCKSZ - page_offset, all_header_size);
}

/*
 * Insert all or part of a record into an undo page.  If the header is split
 * across multiple pages, call this once per page, with appropriate arguments.
 *
 * page_offset is the byte-offset within the page to which data should be
 * written; header_offset is the byte-offset within the data that should
 * begin at that location.
 *
 * chunk_start and chunk_type should describe the chunk that contains this
 * record; as the record set grows to multiple pages, this data must be
 * stored in the page header of each continuation page.  It is OK to pass
 * InvalidUndoRecPtr and URST_INVALID when writing data to the very first
 * page of the record set, or when some other complete record has already been
 * written to this page.
 *
 * The return value is the number of bytes written into the page.
 */
int
UndoPageInsertRecord(Page page, int page_offset, int data_offset,
					 Size data_size, char *data,
					 UndoRecPtr chunk_start, UndoRecordSetType chunk_type)
{
	UndoPageHeader uph = (UndoPageHeader) page;
	Size		data_bytes;

	/* Can't insert nothing. */
	Assert(data_size > 0);

	/* Must not overwrite the page header. */
	Assert(page_offset >= SizeOfUndoPageHeaderData);

	/* Must not overrun the end of the page. */
	Assert(page_offset < BLCKSZ);

	/* Must not overrun the end of the new data, either. */
	Assert(data_offset < data_size);

	/* Continuation data must start at beginning of page. */
	Assert(data_offset == 0 || page_offset == SizeOfUndoPageHeaderData);

	/* Insertion point must be as expected. */
	Assert(page_offset == uph->ud_insertion_point);

	/* Copy as much data as we have, or as much as will fit. */
	data_bytes = Min(BLCKSZ - page_offset, data_size - data_offset);
	memcpy(page + page_offset, data + data_offset, data_bytes);

	/* New insertion point follows the data we've written. */
	uph->ud_insertion_point = page_offset + data_bytes;

	/*
	 * If the record we're writing starts on this page, and this page doesn't
	 * contain any records yet, then make the "first record" pointer point
	 * to this.
	 */
	if (data_offset == 0 && uph->ud_first_record == 0)
		uph->ud_first_record = page_offset;

	/*
	 * If we're continuing this record set from the previous page, then
	 * we've got to indicate the chunk type and where it starts.
	 */
	if (data_offset > 0 || page_offset == SizeOfUndoPageHeaderData)
	{
		Assert(chunk_start != InvalidUndoRecPtr);
		Assert(chunk_type != URST_INVALID);
		uph->ud_continue_chunk = chunk_start;
		uph->ud_continue_chunk_type = (uint8) chunk_type;
	}

	return data_bytes;
}

/*
 * Compute the number of data bytes that would have been written into a page.
 *
 * This function returns the same value that UndoPageInsertHeader would have
 * returned given the same arguments, but without writing anything.
 */
int
UndoPageSkipRecord(int page_offset, int data_offset, size_t data_size)
{
	/* Must not overwrite the page header. */
	Assert(page_offset >= SizeOfUndoPageHeaderData);

	/* Must not overrun the end of the page. */
	Assert(page_offset < BLCKSZ);

	return Min(BLCKSZ - page_offset, data_size);
}

/*
 * Overwrite previously-written undo data.
 *
 * page_offset is the byte-offset within the page to which data should be
 * written; header_offset is the byte-offset within the data that should
 * begin at that location; data_size is the total size of the data, including
 * data on the previous page.
 *
 * The return value is the number of bytes written into the page.
 */
int
UndoPageOverwrite(Page page, int page_offset, int data_offset, Size data_size,
				  char *data)
{
	UndoPageHeader uph = (UndoPageHeader) page;
	int		this_page_bytes;

	/* Copy as much data as we have, or as much as will fit. */
	this_page_bytes = Min(BLCKSZ - page_offset, data_size - data_offset);

	/* Must not overwrite the page header. */
	Assert(page_offset >= SizeOfUndoPageHeaderData);

	/* Must not overrun the end of the page. */
	Assert(page_offset < BLCKSZ);
	Assert(page_offset + this_page_bytes <= BLCKSZ);

	/* Must not overrun the end of the replacement data, either. */
	Assert(data_offset < data_size);

	/* Continuation data must start at beginning of page. */
	Assert(data_offset == 0 || page_offset == SizeOfUndoPageHeaderData);

	/* Shouldn't be updating data more data than we've inserted. */
	Assert(page_offset + this_page_bytes <= uph->ud_insertion_point);

	memcpy(page + page_offset, data + data_offset, this_page_bytes);

	return this_page_bytes;
}
