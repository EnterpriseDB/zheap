/*-------------------------------------------------------------------------
 *
 * undorecord.h
 *	  encode and decode undo records
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorecord.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORD_H
#define UNDORECORD_H

#include "access/undolog.h"
#include "access/transam.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "storage/buf.h"
#include "storage/off.h"

/*
 * The below common information will be stored in the first undo record of the
 * page.  Every subsequent undo record will not store this information, if it's
 * the same as the relevant fields in the first record.
 */
typedef struct UndoCompressionInfo
{
	RmgrId		rmid;			/* rmgr ID */
	Oid			reloid;			/* relation OID */
	FullTransactionId fxid;
	CommandId	cid;			/* command id */
} UndoCompressionInfo;

/*
 * If UREC_INFO_GROUP is set, an UndoRecordGroup structure follows.
 * If UREC_INFO_RMID is set, rmgr id follows.
 * if UREC_INFO_RELOID	is set, relation oid follows.
 * If UREC_INFO_FXID	is set, full transaction id follows.
 * If UREC_INFO_CID	is set, command id follows.
 * If UREC_INFO_FORK is set, fork number follows.
 * If UREC_INFO_PREVUNDO is set, previous undo record pointer follows.
 * If UREC_INFO_BLOCK is set, an UndoRecordBlock structure follows.
 * If UREC_INFO_LOGSWITCH is set, an UndoRecordLogSwitch structure follows.
 * If UREC_INFO_PAYLOAD is set, an UndoRecordPayload structure follows.
 *
 * When (as will often be the case) multiple structures are present, they
 * appear in the same order in which the constants are defined here.  That is,
 * UndoRecordTransaction appears first.
 */
#define UREC_INFO_GROUP						0x001
#define UREC_INFO_RMID						0x002
#define UREC_INFO_RELOID					0x004
#define UREC_INFO_FXID						0x008
#define UREC_INFO_CID						0x010
#define UREC_INFO_FORK						0x020
#define UREC_INFO_PREVUNDO					0x040
#define UREC_INFO_BLOCK						0x080
#define UREC_INFO_LOGSWITCH					0x100
#define UREC_INFO_PAYLOAD					0x200

#define UREC_INFO_PAGE_COMMON  (UREC_INFO_RMID | UREC_INFO_RELOID | UREC_INFO_FXID | UREC_INFO_CID)

/*
 * Every undo record begins with an UndoRecordHeader structure, which is
 * followed by the additional structures indicated by the contents of
 * urec_info.  All structures are packed into undo pages without considering
 * the alignment and without trailing padding bytes. So care must be taken when
 * reading the header.
 */
typedef struct UndoRecordHeader
{
	uint8		urec_type;		/* record type code */
	uint16		urec_info;		/* flag bits */
} UndoRecordHeader;

#define SizeOfUndoRecordHeader	\
	(offsetof(UndoRecordHeader, urec_info) + sizeof(uint16))

/*
 * Undo group header keep the information per undo group which can be discarded
 * in single shot.  This contains the undo record pointer to the next group.
 * Additionally, it also contains the progress of undo apply and the dbid.
 */
typedef struct UndoRecordGroup
{
	/*
	 * Undo block number where we need to start reading the undo for applying
	 * the undo action.   InvalidBlockNumber means undo applying hasn't
	 * started for the transaction and MaxBlockNumber mean undo completely
	 * applied. And, any other block number means we have applied partial undo
	 * so next we can start from this block.
	 */
	BlockNumber urec_progress;
	Oid			urec_dbid;		/* database id */
	UndoRecPtr	urec_next_group;	/* urec pointer of the next group */
} UndoRecordGroup;

#define SizeOfUndoRecordGroup \
	(offsetof(UndoRecordGroup, urec_next_group) + sizeof(UndoRecPtr))

/*
 *  Information for a block to which this record pertains.
 */
typedef struct UndoRecordBlock
{
	BlockNumber urec_block;		/* block number */
	OffsetNumber urec_offset;	/* offset number */
} UndoRecordBlock;

#define SizeOfUndoRecordBlock \
	(offsetof(UndoRecordBlock, urec_offset) + sizeof(OffsetNumber))

/*
 * Information of the transaction's undo in the previous log.  If a transaction
 * is split across the undo logs then this header will be included in the first
 * undo record of the transaction in next log.
 */
typedef struct UndoRecordLogSwitch
{
	UndoRecPtr	urec_prevlogstart;	/* Transaction's first undo record pointer
									 * in previous undo log. */
} UndoRecordLogSwitch;

#define SizeOfUndoRecordLogSwitch \
	(offsetof(UndoRecordLogSwitch, urec_prevlogstart) + sizeof(UndoRecPtr))

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

typedef enum UndoPackStage
{
	UNDO_PACK_STAGE_HEADER,		/* We have not yet processed even the record
								 * header; we need to do that next. */
	UNDO_PACK_STAGE_GROUP,		/* The next thing to be processed is the group
								 * header, if present. */
	UNDO_PACK_STAGE_RMID,		/* The next thing to be processed is the rmid
								 * if present */

	UNDO_PACK_STAGE_RELOID,		/* The next thing to be processed is the
								 * reloid if present */

	UNDO_PACK_STAGE_XID,		/* The next thing to be processed is the xid
								 * if present */

	UNDO_PACK_STAGE_CID,		/* The next thing to be processed is the cid
								 * if present */

	UNDO_PACK_STAGE_FORKNUM,	/* The next thing to be processed is the
								 * relation fork number, if present. */
	UNDO_PACK_STAGE_PREVUNDO,	/* The next thing to be processed is the prev
								 * undo info. */

	UNDO_PACK_STAGE_BLOCK,		/* The next thing to be processed is the block
								 * details, if present. */
	UNDO_PACK_STAGE_LOGSWITCH,	/* The next thing to be processed is the log
								 * switch details. */
	UNDO_PACK_STAGE_PAYLOAD,	/* The next thing to be processed is the
								 * payload details, if present */
	UNDO_PACK_STAGE_PAYLOAD_DATA,	/* The next thing to be processed is the
									 * payload data */
	UNDO_PACK_STAGE_TUPLE_DATA, /* The next thing to be processed is the tuple
								 * data */
	UNDO_PACK_STAGE_UNDO_LENGTH,	/* Next thing to processed is undo length. */

	UNDO_PACK_STAGE_DONE		/* complete */
} UndoPackStage;

/*
 * Undo record context for inserting/unpacking undo record.  This will hold
 * intermediate state of undo record processed so far.
 */
typedef struct UndoPackContext
{
	UndoRecordHeader urec_hd;	/* Main header */
	UndoRecordGroup urec_group; /* Undo record group header */
	RmgrId		urec_rmid;		/* rmgrid */
	Oid			urec_reloid;	/* relation OID */

	/*
	 * Transaction id that has modified the tuple for which this undo record
	 * is written.  We use this to skip the undo records.  See comments atop
	 * function UndoFetchRecord.
	 */
	FullTransactionId urec_fxid;	/* Transaction id */
	CommandId	urec_cid;		/* command id */

	ForkNumber	urec_fork;		/* Relation fork number */
	UndoRecPtr	urec_prevundo;	/* Block prev */
	UndoRecordBlock urec_blk;	/* Block header */
	UndoRecordLogSwitch urec_logswitch; /* Log switch header */
	UndoRecordPayload urec_payload; /* Payload data */
	char	   *urec_payloaddata;
	char	   *urec_tupledata;
	uint16		undo_len;		/* Length of the undo record. */
	int			already_processed;	/* Number of bytes read/written so far */
	int			partial_bytes;	/* Number of partial bytes read/written */
	UndoPackStage stage;		/* Undo pack stage */
} UndoPackContext;

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
	RmgrId		uur_rmid;		/* rmgr ID */
	uint8		uur_type;		/* record type code */
	uint16		uur_info;		/* flag bits */
	Oid			uur_reloid;		/* relation OID */
	CommandId	uur_cid;		/* command id */
	ForkNumber	uur_fork;		/* fork number */
	UndoRecPtr	uur_prevundo;	/* byte offset of previous undo for block */
	BlockNumber uur_block;		/* block number */
	OffsetNumber uur_offset;	/* offset number */
	FullTransactionId uur_fxid; /* transaction id */
	StringInfoData uur_payload; /* payload bytes */
	StringInfoData uur_tuple;	/* tuple bytes */

	/*
	 * Below header will be internally set by the undo layer.  Above this all
	 * information should be set by the caller.
	 */
	UndoRecordGroup *uur_group; /* Group header, included in the first record
								 * of the group in a undo log. */
	UndoRecordLogSwitch *uur_logswitch; /* Log switch header, included in the
										 * first record of the transaction
										 * only after undo log is switched
										 * during a transaction. */
} UnpackedUndoRecord;

extern size_t UndoRecordExpectedSize(UnpackedUndoRecord *uur);
extern size_t UndoRecordPayloadSize(UnpackedUndoRecord *uur);
extern void BeginInsertUndo(UndoPackContext *ucontext, UnpackedUndoRecord *uur,
							uint16 undo_len);
extern void InsertUndoData(UndoPackContext *ucontext, Page page,
						   int starting_byte);
extern void SkipInsertingUndoData(UndoPackContext *ucontext,
								  int bytes_to_skip);
extern void BeginUnpackUndo(UndoPackContext *ucontext);
extern void UnpackUndoData(UndoPackContext *ucontext, Page page,
						   int starting_byte);
extern void FinishUnpackUndo(UndoPackContext *ucontext,
							 UnpackedUndoRecord *uur);
extern void UndoRecordGetCompressionInfo(Page page, int starting_byte,
										 UndoCompressionInfo *compresssion_info);
extern void UndoRecordSetInfo(UnpackedUndoRecord *uur);

#endif							/* UNDORECORD_H */
