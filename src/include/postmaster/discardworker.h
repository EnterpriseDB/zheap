/*-------------------------------------------------------------------------
 *
 * discardworker.h
 *	  Exports from postmaster/discardworker.c.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/postmaster/discardworker.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _DISCARDWORKER_H
#define _DISCARDWORKER_H

/*
 * This function will perform multiple actions based on need. (a) retrieve
 * transactions which have become all-visible and truncate the associated undo
 * logs or will increment the tail pointer. (b) drop the buffers corresponding
 * to truncated pages.
 */
extern void DiscardWorkerMain(Datum main_arg) pg_attribute_noreturn();
extern void DiscardWorkerRegister(void);

#endif   /* _DISCARDWORKER_H */
