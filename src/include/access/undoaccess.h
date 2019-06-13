/*-------------------------------------------------------------------------
 *
 * undoaccess.h
 *	  entry points for inserting/fetching undo records
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoaccess.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOACCESS_H
#define UNDOACCESS_H

#include "access/transam.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/xlogdefs.h"
#include "catalog/pg_class.h"

/*
 * XXX Do we want to support undo tuple size which is more than the BLCKSZ
 * if not than undo record can spread across 2 buffers at the max.
 */
#define MAX_BUFFER_PER_UNDO    2

/*
 * Maximum number of the UndoRecordUpdateInfo for updating the undo record.
 * Usually it's 1 for updating next link of previous transaction's header
 * if we are starting a new transaction.  But, in some cases where the same
 * transaction is spilled to the next log, we update our own transaction's
 * header in previous undo log as well as the header of the previous transaction
 * in the new log.
 */
#define MAX_UNDO_UPDATE_INFO	2

typedef struct PreparedUndoSpace PreparedUndoSpace;
typedef struct PreparedUndoBuffer PreparedUndoBuffer;

/*
 * Undo record element.  Used for storing the group of undo record in a array
 * using UndoBulkFetchRecord.
 */
typedef struct UndoRecInfo
{
	int			index;			/* Index of the element.  For stable qsort. */
	UndoRecPtr	urp;			/* undo recptr (undo record location). */
	UnpackedUndoRecord *uur;	/* actual undo record. */
} UndoRecInfo;

/*
 * This structure holds the informations for updating the undo record.  We need
 * to update the group header for various purposes
 * a) Setting the "uur_next" which points to the next group's first undo record
 * in the undo log.
 * b) updating the undo apply progress while applying undo actions.  During
 * prepare phase we will keep all the information handy in this structure and
 * that will be used for updating the actual record inside the critical section.
 */
typedef struct UndoRecordUpdateInfo
{
	UndoRecPtr	urecptr;		/* Undo record pointer to be updated. */
	uint32		offset;			/* offset in page where to start updating. */
	UndoRecPtr	next;			/* first urp of the next group which is to be
								 * set in the group header */
	BlockNumber progress;		/* undo apply action progress. */
	int			idx_undo_buffers[MAX_BUFFER_PER_UNDO];
} UndoRecordUpdateInfo;

/*
 * Context for preparing and inserting undo records.
 */
typedef struct UndoRecordInsertContext
{
	UndoLogAllocContext alloc_context;
	PreparedUndoSpace *prepared_undo;	/* prepared undo. */
	PreparedUndoBuffer *prepared_undo_buffers;	/* Buffers for prepared undo. */
	UndoRecordUpdateInfo urec_update_info[MAX_UNDO_UPDATE_INFO];	/* Information for undo
																	 * update */
	int			nprepared_undo; /* Number of prepared undo records. */
	int			max_prepared_undo;	/* Max prepared undo for this operation. */
	int			nprepared_undo_buffer;	/* Number of undo buffers. */
	int			nurec_update_info;	/* Number of prepared undo update info. */
} UndoRecordInsertContext;

/*
 * Context for fetching the required undo record.
 */
typedef struct UndoRecordFetchContext
{
	Buffer		buffer;			/* Previous undo record pinned buffer. */
	UndoRecPtr	urp;			/* Previous undo record pointer. */
} UndoRecordFetchContext;

extern void PrepareUndoRecordApplyProgress(UndoRecordInsertContext *context,
									UndoRecPtr urecptr, BlockNumber progress);
extern void UndoRecordUpdate(UndoRecordInsertContext *context, int idx);
extern void BeginUndoRecordInsert(UndoRecordInsertContext *context,
								  UndoLogCategory category,
								  int nprepared,
								  XLogReaderState *xlog_record);
extern UndoRecPtr PrepareUndoInsert(UndoRecordInsertContext *context,
									UnpackedUndoRecord *urec, Oid dbid);
extern void InsertPreparedUndo(UndoRecordInsertContext *context);
extern void FinishUndoRecordInsert(UndoRecordInsertContext *context);
extern void BeginUndoFetch(UndoRecordFetchContext *context);
extern UnpackedUndoRecord *UndoFetchRecord(UndoRecordFetchContext *context,
										   UndoRecPtr urp);
extern void FinishUndoFetch(UndoRecordFetchContext *context);
extern void UndoRecordRelease(UnpackedUndoRecord *urec);
extern UndoRecInfo *UndoBulkFetchRecord(UndoRecPtr *from_urecptr,
										UndoRecPtr to_urecptr,
										int undo_apply_size, int *nrecords);
extern void RegisterUndoLogBuffers(UndoRecordInsertContext *context,
								   uint8 first_block_id);
extern void UndoLogBuffersSetLSN(UndoRecordInsertContext *context,
								 XLogRecPtr recptr);
extern UndoRecPtr UndoGetPrevUrp(UnpackedUndoRecord *uur, UndoRecPtr urp,
								 Buffer buffer, UndoLogCategory category);
extern UndoRecPtr UndoBlockGetFirstUndoRecord(BlockNumber blkno,
											  UndoRecPtr urec_ptr,
											  UndoLogCategory category);


#endif							/* UNDOINSERT_H */
