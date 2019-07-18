/*-------------------------------------------------------------------------
 *
 * hio.h
 *	  POSTGRES zheap access method input/output definitions.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zhio.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHIO_H
#define ZHIO_H

#include "utils/relcache.h"
#include "storage/buf.h"


extern Buffer RelationGetBufferForZTuple(Relation relation, Size len,
										 Buffer otherBuffer, int options,
										 BulkInsertState bistate,
										 Buffer *vmbuffer, Buffer *vmbuffer_other);

#endif							/* ZHIO_H */
