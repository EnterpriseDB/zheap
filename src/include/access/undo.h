/*-------------------------------------------------------------------------
 *
 * undo.h
 *	  common undo code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undo.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UNDO_H
#define UNDO_H

extern Size UndoShmemSize(void);
extern void UndoShmemInit(void);

/* Context for undo-related data. */
extern MemoryContext UndoContext;

#endif
