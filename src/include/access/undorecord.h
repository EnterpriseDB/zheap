/*-------------------------------------------------------------------------
 *
 * undorecord.h
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorecord.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORD_H
#define UNDORECORD_H

#include "common/relpath.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "storage/off.h"

typedef enum undorectype
{
	UNDO_INSERT,
	UNDO_DELETE,
	UNDO_UPDATE
} undorectype;

/*
 * Every undo record begins with an UndoRecordHeader structure, which is
 * followed by the additional structures indicated by the contents of
 * urec_info.  All structures are packed into the alignment without padding
 * bytes, and the undo record itself need not be aligned either, so care
 * must be taken when reading the header.
 */
typedef struct UndoRecordHeader
{
	uint8		urec_type;		/* record type code */
	uint8		urec_info;		/* flag bits */
	uint16		urec_prevlen;	/* length of previous record in bytes */
	Oid			urec_relfilenode;		/* relfilenode for relation */
} UndoRecordHeader;

#define SizeOfUndoRecordHeader	\
	(offsetof(UndoRecordHeader, urec_relfilenode) + sizeof(Oid))

/*
 * If UREC_INFO_RELATION_DETAILS is set, an UndoRecordRelationDetails structure
 * follows.
 *
 * If UREC_INFO_BLOCK is set, an UndoRecordBlock structure follows.
 *
 * If UREC_INFO_PAYLOAD is set, an UndoRecordPayload structure follows.
 *
 * When (as will often be the case) multiple structures are present, they
 * appear in the same order in which the constants are defined here.  That is,
 * UndoRecordRelationDetails appears first.
 */
#define UREC_INFO_RELATION_DETAILS	0x01
#define UREC_INFO_BLOCK				0x02
#define UREC_INFO_PAYLOAD			0x04

/*
 * Additional information about a relation to which this record pertains,
 * namely the tablespace OID and fork number.  If the tablespace OID is
 * DEFAULTTABLESPACE_OID and the fork number is MAIN_FORKNUM, this structure
 * can (and should) be omitted.
 */
typedef struct UndoRecordRelationDetails
{
	Oid			urec_tsid;		/* tablespace OID */
	uint8		urec_fork;		/* fork number */
} UndoRecordRelationDetails;

#define SizeOfUndoRecordRelationDetails \
	(offsetof(UndoRecordRelationDetails, urec_fork) + sizeof(uint8))

/*
 * Identifying information for a block to which this record pertains, and
 * a pointer to the previous record for the same block.
 */
typedef struct UndoRecordBlock
{
	uint64		urec_blkprev;	/* byte offset of previous undo for block */
	BlockNumber urec_block;		/* block number */
	OffsetNumber urec_offset;	/* offset number */
} UndoRecordBlock;

#define SizeOfUndoRecordBlock \
	(offsetof(UndoRecordBlock, urec_offset) + sizeof(OffsetNumber))

/*
 * Information about the amount of payload data and tuple data present
 * in this record.  The payload bytes immediately follow the structures
 * specified by flag bits in urec_info, and the tuple bytes follow the
 * payload bytes.
 */
typedef struct UndoRecordPayload
{
	uint16		urec_payload_len;		/* # of payload bytes */
	uint16		urec_tuple_len; /* # of tuple bytes */
} UndoRecordPayload;

#define SizeOfUndoRecordPayload \
	(offsetof(UndoRecordPayload, urec_tuple_len) + sizeof(uint16))

/*
 * Information that can be used to create an undo record or that can be
 * extracted from one previously created.  The raw undo record format is
 * difficult to manage, so this structure provides a convenient intermediate
 * form that is easier for callers to manage.
 *
 * When creating an undo record from an UnpackedUndoRecord, caller should
 * set uur_info to 0.  It will be initialized by the first call to
 * UndoRecordExpectedSize or InsertUndoRecord.
 *
 * When an undo record is decoded into an UnpackedUndoRecord, all fields
 * will be initialized, but those for which no information is available
 * will be set to invalid or default values, as appropriate.
 */
typedef struct UnpackedUndoRecord
{
	uint8		uur_type;		/* record type code */
	uint8		uur_info;		/* flag bits */
	uint16		uur_prevlen;	/* length of previous record */
	Oid			uur_relfilenode;	/* relfilenode for relation */
	Oid			uur_tsid;		/* tablespace OID */
	ForkNumber	uur_fork;		/* fork number */
	uint64		uur_blkprev;	/* byte offset of previous undo for block */
	BlockNumber uur_block;		/* block number */
	OffsetNumber uur_offset;	/* offset number */
	StringInfoData uur_payload;	/* payload bytes */
	StringInfoData uur_tuple;	/* tuple bytes */
} UnpackedUndoRecord;

/*
 * Compute the number of bytes of storage that will be required to insert
 * an undo record.  Sets uur->uur_info as a side effect.
 */
extern Size UndoRecordExpectedSize(UnpackedUndoRecord *uur);

/*
 * To insert an undo record, call InsertUndoRecord() repeatedly until it
 * returns true.  For the first call, the given page should be the one which
 * the caller has determined to contain the current insertion point,
 * starting_byte should be the byte offset within that page which corresponds
 * to the current insertion point, and *already_written should be 0.  The
 * return value will be true if the entire record is successfully written
 * into that page, and false if not.  In either case, *already_written will
 * be updated to the number of bytes written by all InsertUndoRecord calls
 * for this record to date.  If this function is called again to continue
 * writing the record, the previous value for *already_written should be
 * passed again, and starting_byte should be passed as sizeof(PageHeaderData)
 * (since the record will continue immediately following the page header).
 *
 * This function sets uur->uur_info as a side effect.
 */
extern bool InsertUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_written);

/*
 * Call UnpackUndoRecord() one or more times to unpack an undo record.  For
 * the first call, starting_byte should be set to the beginning of the undo
 * record within the specified page, and *already_decoded should be set to 0;
 * the function will update it based on the number of bytes decoded.  The
 * return value is true if the entire record was unpacked and false if the
 * record continues on the next page.  In the latter case, the function
 * should be called again with the next page, passing starting_byte as the
 * sizeof(PageHeaderData).
 */
extern bool UnpackUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_decoded);

#endif   /* UNDORECORD_H */
