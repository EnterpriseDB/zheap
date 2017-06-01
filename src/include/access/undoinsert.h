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
 * Call PrepareUndoInsert to tell the undo subsystem about the undo record you
 * intended to insert.  Upon return, the necessary undo buffers are pinned.
 * This should be done before any critical section is established, since it
 * can fail.
 */
extern UndoRecPtr PrepareUndoInsert(UnpackedUndoRecord *, UndoPersistence);

/*
 * Insert a previously-prepared undo record.  This will lock the buffers
 * pinned in the previous step, write the actual undo record into them,
 * and mark them dirty.  For persistent undo, this step should be performed
 * after entering a critical section; it should never fail.
 */
extern void InsertPreparedUndo(void);

/*
 * Set the page LSNs of the buffers into which a previously-prepared undo
 * record was inserted.  Pass the LSN returned by XLogInsert to this function.
 * This step is required only for persistent undo; otherwise, there's no LSN.
 * This function must be called before exiting the critical section.
 */
extern void SetUndoPageLSNs(XLogRecPtr);

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

#endif   /* UNDOINSERT_H */
