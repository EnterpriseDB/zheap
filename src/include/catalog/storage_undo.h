/*-------------------------------------------------------------------------
 *
 * storage_undo.h
 *	  prototypes for UNDO support for backend/catalog/storage.c
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/storage_undo.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef STORAGE_UNDO_H
#define STORAGE_UNDO_H

#include "access/undoaccess.h"
#include "lib/stringinfo.h"
#include "nodes/pg_list.h"

#define UNDO_SMGR_CREATE 0

extern void smgr_undo(int nrecords, UndoRecInfo *records);
extern void smgr_undo_desc(StringInfo buf, UnpackedUndoRecord *record);

#endif
