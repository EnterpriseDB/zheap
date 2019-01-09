/*-------------------------------------------------------------------------
 *
 * undorecord.h
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorecord.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORD_H
#define UNDORECORD_H

#include "access/undolog.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "storage/buf.h"
#include "storage/off.h"

typedef enum undorectype
{
	UNDO_INSERT,
	UNDO_MULTI_INSERT,
	UNDO_DELETE,
	UNDO_INPLACE_UPDATE,
	UNDO_UPDATE,
	UNDO_XID_LOCK_ONLY,
	UNDO_XID_LOCK_FOR_UPDATE,
	UNDO_XID_MULTI_LOCK_ONLY,
	UNDO_ITEMID_UNUSED
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
	Oid			urec_reloid;	/* relation OID */

	/*
	 * Transaction id that has modified the tuple present in this undo record.
	 * If this is older than oldestXidWithEpochHavingUndo, then we can consider
	 * the tuple in this undo record as visible.
	 */
	TransactionId urec_prevxid;

	/*
	 * Transaction id that has modified the tuple for which this undo record
	 * is written.  We use this to skip the undo records.  See comments atop
	 * function UndoFetchRecord.
	 */
	TransactionId urec_xid;		/* Transaction id */
	CommandId	urec_cid;		/* command id */
} UndoRecordHeader;

#define SizeOfUndoRecordHeader	\
	(offsetof(UndoRecordHeader, urec_cid) + sizeof(CommandId))

/*
 * If UREC_INFO_RELATION_DETAILS is set, an UndoRecordRelationDetails structure
 * follows.
 *
 * If UREC_INFO_BLOCK is set, an UndoRecordBlock structure follows.
 *
 * If UREC_INFO_TRANSACTION is set, an UndoRecordTransaction structure
 * follows.
 *
 * If UREC_INFO_PAYLOAD is set, an UndoRecordPayload structure follows.
 *
 * When (as will often be the case) multiple structures are present, they
 * appear in the same order in which the constants are defined here.  That is,
 * UndoRecordRelationDetails appears first.
 */
#define UREC_INFO_RELATION_DETAILS			0x01
#define UREC_INFO_BLOCK						0x02
#define UREC_INFO_PAYLOAD					0x04
#define UREC_INFO_TRANSACTION				0x08
#define UREC_INFO_PAYLOAD_CONTAINS_SLOT		0x10
#define UREC_INFO_PAYLOAD_CONTAINS_SUBXACT	0x20
/*
 * Additional information about a relation to which this record pertains,
 * namely the fork number.  If the fork number is MAIN_FORKNUM, this structure
 * can (and should) be omitted.
 */
typedef struct UndoRecordRelationDetails
{
	ForkNumber	urec_fork;		/* fork number */
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
 * Identifying information for a transaction to which this undo belongs.  This
 * also stores the dbid and the progress of the undo apply during rollback.
 */
typedef struct UndoRecordTransaction
{
	/*
	 * This indicates undo action apply progress, 0 means not started, 1 means
	 * completed.  In future, it can also be used to show the progress of how
	 * much undo has been applied so far with some formula.
	 */
	uint32		urec_progress;
	uint32		urec_xidepoch;	/* epoch of the current transaction */
	Oid			urec_dbid;		/* database id */

	/*
	 * Transaction previous undo record pointer when transaction split across
	 * undo log.  The first undo record in the new log will stores the previous
	 * undo record pointer in the previous log as we can not calculate that
	 * directly using prevlen during rollback.
	 */
	uint64		urec_prevurp;
	uint64		urec_next;		/* urec pointer of the next transaction */
} UndoRecordTransaction;

#define SizeOfUrecNext (sizeof(UndoRecPtr))
#define SizeOfUndoRecordTransaction \
	(offsetof(UndoRecordTransaction, urec_next) + SizeOfUrecNext)

/*
 * Information about the amount of payload data and tuple data present
 * in this record.  The payload bytes immediately follow the structures
 * specified by flag bits in urec_info, and the tuple bytes follow the
 * payload bytes.
 */
typedef struct UndoRecordPayload
{
	uint16		urec_payload_len;	/* # of payload bytes */
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
 * UndoRecordSetInfo or InsertUndoRecord.  We do set it in
 * UndoRecordAllocate for transaction specific header information.
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
	Oid			uur_reloid;		/* relation OID */
	TransactionId uur_prevxid;	/* transaction id */
	TransactionId uur_xid;		/* transaction id */
	CommandId	uur_cid;		/* command id */
	ForkNumber	uur_fork;		/* fork number */
	uint64		uur_blkprev;	/* byte offset of previous undo for block */
	BlockNumber uur_block;		/* block number */
	OffsetNumber uur_offset;	/* offset number */
	Buffer		uur_buffer;		/* buffer in which undo record data points */
	uint32		uur_xidepoch;	/* epoch of the inserting transaction. */
	uint64		uur_prevurp;
	uint64		uur_next;		/* urec pointer of the next transaction */
	Oid			uur_dbid;		/* database id */

	/* undo applying progress, see detail comment in UndoRecordTransaction*/
	uint32		uur_progress;
	StringInfoData uur_payload; /* payload bytes */
	StringInfoData uur_tuple;	/* tuple bytes */
} UnpackedUndoRecord;


extern void UndoRecordSetInfo(UnpackedUndoRecord *uur);
extern Size UndoRecordExpectedSize(UnpackedUndoRecord *uur);
extern bool InsertUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_written, bool header_only);
extern bool UnpackUndoRecord(UnpackedUndoRecord *uur, Page page,
				 int starting_byte, int *already_decoded, bool header_only);

#endif							/* UNDORECORD_H */
