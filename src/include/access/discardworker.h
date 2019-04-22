/*-------------------------------------------------------------------------
 *
 * discardworker.h
 *	  Exports from access/undo/discardworker.c.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/discardworker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _DISCARDWORKER_H
#define _DISCARDWORKER_H

extern void DiscardWorkerRegister(void);
extern void DiscardWorkerMain(Datum main_arg) pg_attribute_noreturn();
extern bool IsDiscardProcess(void);

#endif							/* _DISCARDWORKER_H */
