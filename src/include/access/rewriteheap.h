/*-------------------------------------------------------------------------
 *
 * rewriteheap.h
 *	  Declarations for heap rewrite support functions
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * src/include/access/rewriteheap.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef REWRITE_HEAP_H
#define REWRITE_HEAP_H

#include "access/htup.h"
#include "storage/bufpage.h"
#include "storage/itemptr.h"
#include "storage/relfilenode.h"
#include "utils/hsearch.h"
#include "utils/relcache.h"

/*
 * State associated with a rewrite operation. This is opaque to the user
 * of the rewrite facility.
 */
typedef struct RewriteStateData
{
	Relation	rs_old_rel;		/* source heap */
	Relation	rs_new_rel;		/* destination heap */
	Page		rs_buffer;		/* page currently being built */
	BlockNumber rs_blockno;		/* block where page will go */
	bool		rs_buffer_valid;	/* T if any tuples in buffer */
	bool		rs_use_wal;		/* must we WAL-log inserts? */
	bool		rs_logical_rewrite; /* do we need to do logical rewriting */
	TransactionId rs_oldest_xmin;	/* oldest xmin used by caller to determine
									 * tuple visibility */
	TransactionId rs_freeze_xid;	/* Xid that will be used as freeze cutoff
									 * point */
	TransactionId rs_logical_xmin;	/* Xid that will be used as cutoff point
									 * for logical rewrites */
	MultiXactId rs_cutoff_multi;	/* MultiXactId that will be used as cutoff
									 * point for multixacts */
	MemoryContext rs_cxt;		/* for hash tables and entries and tuples in
								 * them */
	XLogRecPtr	rs_begin_lsn;	/* XLogInsertLsn when starting the rewrite */
	HTAB	   *rs_unresolved_tups; /* unmatched A tuples */
	HTAB	   *rs_old_new_tid_map; /* unmatched B tuples */
	HTAB	   *rs_logical_mappings;	/* logical remapping files */
	uint32		rs_num_rewrite_mappings;	/* # in memory mappings */
}			RewriteStateData;

typedef RewriteStateData *RewriteState;

extern RewriteState begin_heap_rewrite(Relation OldHeap, Relation NewHeap,
				   TransactionId OldestXmin, TransactionId FreezeXid,
				   MultiXactId MultiXactCutoff, bool use_wal);
extern void end_heap_rewrite(RewriteState state);
extern void rewrite_heap_tuple(RewriteState state, HeapTuple oldTuple,
				   HeapTuple newTuple);
extern bool rewrite_heap_dead_tuple(RewriteState state, HeapTuple oldTuple);

/*
 * On-Disk data format for an individual logical rewrite mapping.
 */
typedef struct LogicalRewriteMappingData
{
	RelFileNode old_node;
	RelFileNode new_node;
	ItemPointerData old_tid;
	ItemPointerData new_tid;
} LogicalRewriteMappingData;

/* ---
 * The filename consists of the following, dash separated,
 * components:
 * 1) database oid or InvalidOid for shared relations
 * 2) the oid of the relation
 * 3) upper 32bit of the LSN at which a rewrite started
 * 4) lower 32bit of the LSN at which a rewrite started
 * 5) xid we are mapping for
 * 6) xid of the xact performing the mapping
 * ---
 */
#define LOGICAL_REWRITE_FORMAT "map-%x-%x-%X_%X-%x-%x"
void		CheckPointLogicalRewriteHeap(void);

#endif							/* REWRITE_HEAP_H */
