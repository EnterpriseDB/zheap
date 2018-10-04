/*-------------------------------------------------------------------------
 *
 * rewritezheap.h
 *	  Declarations for zheap rewrite support functions
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * src/include/access/rewritezheap.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef REWRITE_ZHEAP_H
#define REWRITE_ZHEAP_H

#include "access/zhtup.h"
/*
 * Fixme: We should not include rewriteheap.h here.  It will be removed once we
 * move common datastructures like RewriteState to some common header file
 * (which will be done as part of pluggable storage).
 */
#include "access/rewriteheap.h"
#include "utils/relcache.h"

extern RewriteState begin_zheap_rewrite(Relation OldHeap, Relation NewHeap,
				   TransactionId OldestXmin, TransactionId FreezeXid,
				   MultiXactId MultiXactCutoff, bool use_wal);
extern void end_zheap_rewrite(RewriteState state);
extern void reform_and_rewrite_ztuple(ZHeapTuple tuple, TupleDesc oldTupDesc,
	TupleDesc newTupDesc, Datum *values, bool *isnull,
	bool newRelHasOids, RewriteState rwstate);
extern void rewrite_zheap_tuple(RewriteState state, ZHeapTuple oldTuple,
				   ZHeapTuple newTuple);

#endif							/* REWRITE_ZHEAP_H */
