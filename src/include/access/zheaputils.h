/*-------------------------------------------------------------------------
 *
 * zheaputils.h
 *	  POSTGRES zheap utility header definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheaputils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHEAPUTILS_H
#define ZHEAPUTILS_H

#include "postgres.h"

#include "access/genham.h"
#include "access/hio.h"
#include "access/undoinsert.h"
#include "access/zhtup.h"
#include "executor/executor.h"
#include "nodes/execnodes.h"
#include "utils/rel.h"
#include "utils/snapshot.h"

extern HeapTuple zheap_to_heap(ZHeapTuple ztuple, TupleDesc tupDesc);
extern MinimalTuple zheap_to_minimal(ZHeapTuple ztuple, TupleDesc tupDesc);
extern ZHeapTuple heap_to_zheap(HeapTuple ztuple, TupleDesc tupDesc);
extern ZHeapTuple zheap_copytuple(ZHeapTuple tuple);


#endif   /* ZHEAPUTILS_H */
