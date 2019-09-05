/*-------------------------------------------------------------------------
 *
 * zheapscan.h
 *	  POSTGRES table scan definitions
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheapscan.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef ZHEAPSCAN_H
#define ZHEAPSCAN_H

#include "access/relscan.h"
#include "access/skey.h"
#include "access/zheap.h"

typedef struct ZHeapScanDescData
{
	/* scan parameters */
	TableScanDescData rs_base;	/* */

	/* state set up at initscan time */
	BlockNumber rs_nblocks;		/* total number of blocks in rel */
	BlockNumber rs_startblock;	/* block # to start at */
	BlockNumber rs_numblocks;	/* max number of blocks to scan */
	/* rs_numblocks is usually InvalidBlockNumber, meaning "scan whole rel" */

	/* scan current state */
	bool		rs_inited;		/* false = scan not initialized yet */
	BlockNumber rs_cblock;		/* current block # in scan, if any */
	Buffer		rs_cbuf;		/* current buffer in scan, if any */


	/* rs_numblocks is usually InvalidBlockNumber, meaning "scan whole rel" */
	BufferAccessStrategy rs_strategy;	/* access strategy for reads */

	ZHeapTuple	rs_cztup;		/* current tuple in scan, if any */

	int			rs_cindex;		/* current tuple's index in visztuples */
	int			rs_ntuples;		/* number of visible tuples on page */

	ZHeapTuple	rs_visztuples[MaxZHeapTuplesPerPage];
} ZHeapScanDescData;

typedef struct ZHeapScanDescData *ZHeapScanDesc;

extern TableScanDesc zheap_beginscan(Relation relation, Snapshot snapshot,
									 int nkeys, ScanKey key, ParallelTableScanDesc parallel_scan,
									 uint32 flags);
extern void zheap_endscan(TableScanDesc sscan);
extern void zheap_rescan(TableScanDesc scan, ScanKey key, bool set_params,
						 bool allow_strat, bool allow_sync, bool allow_pagemode);
extern void zheap_setscanlimits(TableScanDesc scan, BlockNumber startBlk,
								BlockNumber endBlk);
extern bool zheapgetpage(TableScanDesc scan, BlockNumber page);
extern bool zheap_getnextslot(TableScanDesc scan, ScanDirection direction,
							  struct TupleTableSlot *slot);

struct TBMIterateResult;
extern bool zheap_scan_bitmap_next_block(TableScanDesc sscan, struct TBMIterateResult *tbmres);
extern bool zheap_scan_bitmap_next_tuple(TableScanDesc sscan, struct TBMIterateResult *tbmres, struct TupleTableSlot *slot);

extern ZHeapTuple zheap_search_buffer(ItemPointer tid, Relation relation,
									  Buffer buffer, Snapshot snapshot, bool *all_dead);
extern bool zheap_fetch(Relation relation, Snapshot snapshot,
						ItemPointer tid, ZHeapTuple *tuple, Buffer *userbuf,
						bool keep_buf, bool keep_tup);

#endif							/* ZHEAPSCAN_H */
