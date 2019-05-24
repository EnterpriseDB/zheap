/*-------------------------------------------------------------------------
 *
 * undoinsert.h
 *	  undo discard definitions
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undodiscard.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDODISCARD_H
#define UNDODISCARD_H

#include "access/undolog.h"
#include "access/xlogdefs.h"
#include "catalog/pg_class.h"
#include "storage/lwlock.h"

extern void UndoDiscard(TransactionId xmin, bool *hibernate);
extern void UndoLogDiscardAll(void);
extern void TempUndoDiscard(UndoLogNumber);

#endif							/* UNDODISCARD_H */
