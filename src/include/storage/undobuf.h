/*-------------------------------------------------------------------------
 *
 * undobuf.h
 *	  Definitions for undo buffers 
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/undobuf.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDO_BUF_H
#define UNDO_BUF_H

#include "access/undorecord.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"

/*
 * This function will invalidate the buffer and return it to the free pool of
 * buffers.  Caller is expected to have a pin on buffer and ensure that nobody
 * else has a pin on this buffer.  This API will differentiate between local
 * and share buffers and take the appropriate actions accordingly.
 */
extern void DropUndoBuffer(Buffer buf_id);

#endif   /* UNDO_BUF_H */
