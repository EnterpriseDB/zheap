/*-------------------------------------------------------------------------
 *
 * undoinsert.h
 *	  entry points for inserting undo records
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
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
typedef bool (*SatisfyUndoRecordCallback) (UnpackedUndoRecord* urec,
											BlockNumber blkno,
											OffsetNumber offset,
											TransactionId xid);

/*
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned and
 * locked.
 * This should be done before any critical section is established, since it
 * can fail.
 *
 * If not in recovery, 'xid' should refer to the top transaction id because
 * undo log only stores mapping for the top most transactions.
 * If in recovery, 'xid' refers to the transaction id stored in WAL.
 */
extern UndoRecPtr PrepareUndoInsert(UnpackedUndoRecord *, UndoPersistence,
									TransactionId, xl_undolog_meta *);

/*
 * Insert a previously-prepared undo record.  This will write the actual undo
 * record into the buffers already pinned and locked in PreparedUndoInsert,
 * and mark them dirty.  For persistent undo, this step should be performed
 * after entering a critical section; it should never fail.
 */
extern void InsertPreparedUndo(void);

/*
 * Unlock and release undo buffers.  This step performed after exiting any
 * critical section.
 */
extern void UnlockReleaseUndoBuffers(void);

/*
 * Forget about any previously-prepared undo record.  Error recovery calls
 * this, but it can also be used by other code that changes its mind about
 * inserting undo after having prepared a record for insertion.
 */
extern void CancelPreparedUndo(void);

/*
 * Fetch the next undo record for given blkno and offset.  Start the search
 * from urp.  Caller need to call UndoRecordRelease to release the resources
 * allocated by this function.
 */
extern UnpackedUndoRecord* UndoFetchRecord(UndoRecPtr urp,
										   BlockNumber blkno,
										   OffsetNumber offset,
										   TransactionId xid,
										   UndoRecPtr *urec_ptr_out,
										   SatisfyUndoRecordCallback callback);
/*
 * Release the resources allocated by UndoFetchRecord.
 */
extern void UndoRecordRelease(UnpackedUndoRecord *urec);

/*
 * Set the value of PrevUndoLen.
 */
extern void UndoRecordSetPrevUndoLen(uint16 len);

/*
 * Call UndoSetPrepareSize to set the value of how many maximum prepared can
 * be done before inserting the prepared undo.  If size is > MAX_PREPARED_UNDO
 * then it will allocate extra memory to hold the extra prepared undo.
 */
extern void UndoSetPrepareSize(int max_prepare, UnpackedUndoRecord *undorecords,
							   TransactionId xid, UndoPersistence upersistence,
							   xl_undolog_meta *undometa);

/*
 * return the previous undo record pointer.
 */
extern UndoRecPtr UndoGetPrevUndoRecptr(UndoRecPtr urp, uint16 prevlen);

extern void UndoRecordOnUndoLogChange(UndoPersistence persistence);

extern void PrepareUpdateUndoActionProgress(UndoRecPtr urecptr, int progress);
extern void UndoRecordUpdateTransInfo(void);

/* Reset globals related to undo buffers */
extern void ResetUndoBuffers(void);
#endif   /* UNDOINSERT_H */
