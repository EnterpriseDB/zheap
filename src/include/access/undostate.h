/*-------------------------------------------------------------------------
 *
 * undostate.h
 *		Undo system state management and transaction integration.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undostate.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOSTATE_H
#define UNDOSTATE_H

#include "access/undodefs.h"

extern Size UndoStateShmemSize(void);
extern void UndoStateShmemInit(void);

extern void UndoStateAccumulateRecord(UndoPersistenceLevel plevel,
									  UndoRecPtr start_location,
									  Size size);

extern Oid InitializeBackgroundUndoState(bool minimum_runtime_reached);
extern void FinishBackgroundUndo(void);

extern void PerformUndoActions(int nestingLevel);

extern void AtCommit_UndoState(void);
extern void AtAbort_UndoState(bool *perform_foreground_undo);
extern void AtSubCommit_UndoState(int level);
extern void AtSubAbort_UndoState(int level, bool *perform_foreground_undo);

/* XXX what about prepare? */

#endif
