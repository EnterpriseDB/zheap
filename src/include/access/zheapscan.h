/*-------------------------------------------------------------------------
 *
 * zheapscan.h
 *	  POSTGRES table scan definitions
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheapscan.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef ZHEAPSCAN_H
#define ZHEAPSCAN_H

#include "access/relscan.h"
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
	bool		rs_inited;		/* false = scan not init'd yet */
	BlockNumber rs_cblock;		/* current block # in scan, if any */
	Buffer		rs_cbuf;		/* current buffer in scan, if any */


	/* rs_numblocks is usually InvalidBlockNumber, meaning "scan whole rel" */
	BufferAccessStrategy rs_strategy;	/* access strategy for reads */

	ZHeapTuple rs_cztup;		/* current tuple in scan, if any */

	int			rs_cindex;		/* current tuple's index in vistuples */
	int			rs_ntuples;		/* number of visible tuples on page */

	ZHeapTuple      rs_visztuples[MaxZHeapTuplesPerPage];
}			ZHeapScanDescData;

typedef struct ZHeapScanDescData *ZHeapScanDesc;

#endif /* ZHEAPSCAN_H */
