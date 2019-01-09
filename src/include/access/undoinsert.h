/*-------------------------------------------------------------------------
 *
 * undoinsert.h
 *	  entry points for inserting undo records
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoinsert.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOINSERT_H
#define UNDOINSERT_H

#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/xlogdefs.h"
#include "catalog/pg_class.h"

/*
 * Typedef for callback function for UndoFetchRecord.
 *
 * This checks whether an undorecord satisfies the given conditions.
 */
typedef bool (*SatisfyUndoRecordCallback) (UnpackedUndoRecord *urec,
										   BlockNumber blkno,
										   OffsetNumber offset,
										   TransactionId xid);

extern UndoRecPtr PrepareUndoInsert(UnpackedUndoRecord *, FullTransactionId xid,
				  UndoPersistence, XLogReaderState *xlog_record,
				  xl_undolog_meta *);

extern void InsertPreparedUndo(void);
extern void RegisterUndoLogBuffers(uint8 first_block_id);
extern void UndoLogBuffersSetLSN(XLogRecPtr recptr);
extern void UnlockReleaseUndoBuffers(void);

extern UnpackedUndoRecord *UndoFetchRecord(UndoRecPtr urp,
				BlockNumber blkno, OffsetNumber offset,
				TransactionId xid, UndoRecPtr *urec_ptr_out,
				SatisfyUndoRecordCallback callback);
extern void UndoRecordRelease(UnpackedUndoRecord *urec);
extern void UndoRecordSetPrevUndoLen(uint16 len);
extern void UndoSetPrepareSize(UnpackedUndoRecord *undorecords, int nrecords,
				   FullTransactionId fxid, UndoPersistence upersistence,
				   XLogReaderState *xlog_record, xl_undolog_meta *undometa);

extern UndoRecPtr UndoGetPrevUndoRecptr(UndoRecPtr urp, uint16 prevlen, UndoRecPtr prevurp);

extern void UndoRecordOnUndoLogChange(UndoPersistence persistence);

extern void PrepareUpdateUndoActionProgress(XLogReaderState *xlog_record,
											UndoRecPtr urecptr, int progress);
extern void UndoRecordUpdateTransInfo(int idx);

extern void ResetUndoBuffers(void);

#endif							/* UNDOINSERT_H */
