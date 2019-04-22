/*-------------------------------------------------------------------------
 *
 * rewritezheap.h
 *	  Declarations for zheap rewrite support functions
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * src/include/access/rewritezheap.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef REWRITE_ZHEAP_H
#define REWRITE_ZHEAP_H

#include "access/zhtup.h"
#include "utils/relcache.h"

/* struct definition is private to rewritezheap.c */
typedef struct RewriteZheapStateData *RewriteZheapState;

extern RewriteZheapState begin_zheap_rewrite(Relation OldHeap, Relation NewHeap,
											 TransactionId OldestXmin, TransactionId FreezeXid,
											 MultiXactId MultiXactCutoff, bool use_wal);
extern void end_zheap_rewrite(RewriteZheapState state);
extern void reform_and_rewrite_ztuple(TupleDesc oldTupDesc,
						  TupleDesc newTupDesc, Datum *values, bool *isnull,
						  RewriteZheapState rwstate);
extern void rewrite_zheap_tuple(RewriteZheapState state,
					ZHeapTuple newTuple);

#endif							/* REWRITE_ZHEAP_H */
