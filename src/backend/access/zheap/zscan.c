/*-------------------------------------------------------------------------
 *
 * zscan.c
 *	  Routines to scan zheap data pages.
 *
 * This file provides API's to scan the zheap page and get the tuples.  Zheap
 * contains different kind of meta pages (like meta and tpd pages) which
 * doesn't have tuples, so we need to always skip them during scan.
 *
 * Unlike heap, we always need to make a copy of zheap tuple before releasing
 * the containing buffer as an in-place update can change the tuple.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zscan.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/tableam.h"
#include "access/tpd.h"
#include "access/visibilitymap.h"
#include "access/zheapscan.h"
#include "miscadmin.h"
#include "nodes/tidbitmap.h"
#include "pgstat.h"
#include "storage/predicate.h"
#include "utils/ztqual.h"

/*
 * ZBORKED: don't want to include heapam.h to avoid mistakes - the syncscan
 * stuff should probably be moved to a different header.
 */
extern BlockNumber ss_get_location(Relation rel, BlockNumber relnblocks);
extern void ss_report_location(Relation rel, BlockNumber location);

/*
 * zinitscan - same as initscan except for tuple initialization
 */
static void
zinitscan(ZHeapScanDesc scan, ScanKey key, bool keep_startblock)
{
	ParallelBlockTableScanDesc bpscan = NULL;
	bool		allow_strat;
	bool		allow_sync;

	/*
	 * Determine the number of blocks we have to scan.
	 *
	 * It is sufficient to do this once at scan start, since any tuples added
	 * while the scan is in progress will be invisible to my snapshot anyway.
	 * (That is not true when using a non-MVCC snapshot.  However, we couldn't
	 * guarantee to return tuples added after scan start anyway, since they
	 * might go into pages we already scanned.  To guarantee consistent
	 * results for a non-MVCC snapshot, the caller must hold some higher-level
	 * lock that ensures the interesting tuple(s) won't change.)
	 */
	if (scan->rs_base.rs_parallel != NULL)
	{
		bpscan = (ParallelBlockTableScanDesc) scan->rs_base.rs_parallel;
		scan->rs_nblocks = bpscan->phs_nblocks;
	}
	else
		scan->rs_nblocks = RelationGetNumberOfBlocks(scan->rs_base.rs_rd);

	/*
	 * If the table is large relative to NBuffers, use a bulk-read access
	 * strategy and enable synchronized scanning (see syncscan.c).  Although
	 * the thresholds for these features could be different, we make them the
	 * same so that there are only two behaviors to tune rather than four.
	 * (However, some callers need to be able to disable one or both of these
	 * behaviors, independently of the size of the table; also there is a GUC
	 * variable that can disable synchronized scanning.)
	 *
	 * Note that heap_parallelscan_initialize has a very similar test; if you
	 * change this, consider changing that one, too.
	 */
	if (!RelationUsesLocalBuffers(scan->rs_base.rs_rd) &&
		scan->rs_nblocks > NBuffers / 4)
	{
		allow_strat = scan->rs_base.rs_allow_strat;
		allow_sync = scan->rs_base.rs_allow_sync;
	}
	else
		allow_strat = allow_sync = false;

	if (allow_strat)
	{
		/* During a rescan, keep the previous strategy object. */
		if (scan->rs_strategy == NULL)
			scan->rs_strategy = GetAccessStrategy(BAS_BULKREAD);
	}
	else
	{
		if (scan->rs_strategy != NULL)
			FreeAccessStrategy(scan->rs_strategy);
		scan->rs_strategy = NULL;
	}

	if (scan->rs_base.rs_parallel != NULL)
	{
		/* For parallel scan, believe whatever ParallelHeapScanDesc says. */
		scan->rs_base.rs_syncscan = scan->rs_base.rs_parallel->phs_syncscan;
	}
	else if (keep_startblock)
	{
		/*
		 * When rescanning, we want to keep the previous startblock setting,
		 * so that rewinding a cursor doesn't generate surprising results.
		 * Reset the active syncscan setting, though.
		 */
		scan->rs_base.rs_syncscan = (allow_sync && synchronize_seqscans);
	}
	else if (allow_sync && synchronize_seqscans)
	{
		scan->rs_base.rs_syncscan = true;
		scan->rs_startblock = ss_get_location(scan->rs_base.rs_rd, scan->rs_nblocks);
		/* Skip metapage */
		if (scan->rs_startblock == ZHEAP_METAPAGE)
			scan->rs_startblock = ZHEAP_METAPAGE + 1;
	}
	else
	{
		scan->rs_base.rs_syncscan = false;
		scan->rs_startblock = ZHEAP_METAPAGE + 1;
	}

	scan->rs_numblocks = InvalidBlockNumber;
	scan->rs_inited = false;
	scan->rs_cbuf = InvalidBuffer;
	scan->rs_cblock = InvalidBlockNumber;

	/* page-at-a-time fields are always invalid when not rs_inited */

	/*
	 * copy the scan key, if appropriate
	 */
	if (key != NULL)
		memcpy(scan->rs_base.rs_key, key, scan->rs_base.rs_nkeys * sizeof(ScanKeyData));

	/*
	 * Currently, we don't have a stats counter for bitmap heap scans (but the
	 * underlying bitmap index scans will be counted) or sample scans (we only
	 * update stats for tuple fetches there)
	 */
	if (!scan->rs_base.rs_bitmapscan && !scan->rs_base.rs_samplescan)
		pgstat_count_heap_scan(scan->rs_base.rs_rd);
}

/*
 * zheap_beginscan - same as heap_beginscan except for tuple initialization
 */
TableScanDesc
zheap_beginscan(Relation relation, Snapshot snapshot,
				int nkeys, ScanKey key,
				ParallelTableScanDesc parallel_scan,
				bool allow_strat,
				bool allow_sync,
				bool allow_pagemode,
				bool is_bitmapscan,
				bool is_samplescan,
				bool temp_snap)
{
	ZHeapScanDesc scan;

	/*
	 * increment relation ref count while scanning relation
	 *
	 * This is just to make really sure the relcache entry won't go away while
	 * the scan has a pointer to it.  Caller should be holding the rel open
	 * anyway, so this is redundant in all normal scenarios...
	 */
	RelationIncrementReferenceCount(relation);

	/*
	 * allocate and initialize scan descriptor
	 */
	scan = (ZHeapScanDesc) palloc(sizeof(ZHeapScanDescData));

	scan->rs_base.rs_rd = relation;
	scan->rs_base.rs_snapshot = snapshot;
	scan->rs_base.rs_nkeys = nkeys;
	scan->rs_base.rs_bitmapscan = is_bitmapscan;
	scan->rs_base.rs_samplescan = is_samplescan;
	scan->rs_strategy = NULL;	/* set in zinitscan */
	scan->rs_startblock = 0;	/* set in initscan */
	scan->rs_base.rs_allow_strat = allow_strat;
	scan->rs_base.rs_allow_sync = allow_sync;
	scan->rs_base.rs_temp_snap = temp_snap;
	scan->rs_base.rs_parallel = parallel_scan;
	scan->rs_ntuples = 0;

	/*
	 * we can use page-at-a-time mode if it's an MVCC-safe snapshot
	 */
	scan->rs_base.rs_pageatatime = allow_pagemode && snapshot && IsMVCCSnapshot(snapshot);

	/*
	 * For a seqscan in a serializable transaction, acquire a predicate lock
	 * on the entire relation. This is required not only to lock all the
	 * matching tuples, but also to conflict with new insertions into the
	 * table. In an indexscan, we take page locks on the index pages covering
	 * the range specified in the scan qual, but in a heap scan there is
	 * nothing more fine-grained to lock. A bitmap scan is a different story,
	 * there we have already scanned the index and locked the index pages
	 * covering the predicate. But in that case we still have to lock any
	 * matching heap tuples.
	 */
	if (!is_bitmapscan && snapshot)
		PredicateLockRelation(relation, snapshot);

	scan->rs_cztup = NULL;


	/*
	 * we do this here instead of in initscan() because heap_rescan also calls
	 * initscan() and we don't want to allocate memory again
	 */
	if (nkeys > 0)
		scan->rs_base.rs_key = (ScanKey) palloc(sizeof(ScanKeyData) * nkeys);
	else
		scan->rs_base.rs_key = NULL;

	zinitscan(scan, key, false);

	return (TableScanDesc) scan;
}

void
zheap_endscan(TableScanDesc sscan)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;

	/* Note: no locking manipulations needed */

	/*
	 * unpin scan buffers
	 */
	if (BufferIsValid(scan->rs_cbuf))
		ReleaseBuffer(scan->rs_cbuf);

	/*
	 * decrement relation reference count and free scan descriptor storage
	 */
	RelationDecrementReferenceCount(scan->rs_base.rs_rd);

	if (scan->rs_base.rs_key)
		pfree(scan->rs_base.rs_key);

	if (scan->rs_strategy != NULL)
		FreeAccessStrategy(scan->rs_strategy);

	if (scan->rs_base.rs_temp_snap)
		UnregisterSnapshot(scan->rs_base.rs_snapshot);

	pfree(scan);
}

/* ----------------
 *		zheap_rescan		- similar to heap_rescan
 * ----------------
 */
void
zheap_rescan(TableScanDesc sscan, ScanKey key, bool set_params,
			bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;

	if (set_params)
	{
		scan->rs_base.rs_allow_strat = allow_strat;
		scan->rs_base.rs_allow_sync = allow_sync;
		scan->rs_base.rs_pageatatime = allow_pagemode && IsMVCCSnapshot(scan->rs_base.rs_snapshot);
	}

	/*
	 * unpin scan buffers
	 */
	if (BufferIsValid(scan->rs_cbuf))
		ReleaseBuffer(scan->rs_cbuf);

	/*
	 * reinitialize scan descriptor
	 */
	zinitscan(scan, key, true);
}

/*
 * zheap_setscanlimits - restrict range of a zheapscan
 *
 * startBlk is the page to start at
 * numBlks is number of pages to scan (InvalidBlockNumber means "all")
 */
void
zheap_setscanlimits(TableScanDesc sscan, BlockNumber startBlk, BlockNumber numBlks)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;

	Assert(!scan->rs_inited);	/* else too late to change */
	Assert(!scan->rs_base.rs_syncscan); /* else rs_startblock is
											 * significant */

	/*
	 * Check startBlk is valid (but allow case of zero blocks...).
	 * Consider meta-page as well.
	 */
	Assert(startBlk == 0 || startBlk < scan->rs_nblocks ||
			startBlk == ZHEAP_METAPAGE + 1);

	scan->rs_startblock = startBlk;
	scan->rs_numblocks = numBlks;
}

/* ----------------
 *		zheap_update_snapshot
 *
 *		Update snapshot info in zheap scan descriptor.
 * ----------------
 */
void
zheap_update_snapshot(TableScanDesc sscan, Snapshot snapshot)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;

	Assert(IsMVCCSnapshot(snapshot));

	RegisterSnapshot(snapshot);
	scan->rs_base.rs_snapshot = snapshot;
	scan->rs_base.rs_temp_snap = true;
}

/*
 * zheapgetpage - Same as heapgetpage, but operate on zheap page and
 * in page-at-a-time mode, visible tuples are stored in rs_visztuples.
 *
 * It returns false, if we can't scan the page (like in case of TPD page),
 * otherwise, return true.
 */
bool
zheapgetpage(TableScanDesc sscan, BlockNumber page)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;
	Buffer		buffer;
	Snapshot	snapshot;
	Page		dp;
	int			lines;
	int			ntup;
	OffsetNumber lineoff;
	ItemId		lpp;
	bool		all_visible;
	uint8		vmstatus;
	Buffer		vmbuffer = InvalidBuffer;

	Assert(page < scan->rs_nblocks);

	/* release previous scan buffer, if any */
	if (BufferIsValid(scan->rs_cbuf))
	{
		ReleaseBuffer(scan->rs_cbuf);
		scan->rs_cbuf = InvalidBuffer;
	}

	if (page == ZHEAP_METAPAGE)
	{
		/* needs to be updated to keep track of scan position */
		scan->rs_cblock = page;
		return false;
	}

	/*
	 * Be sure to check for interrupts at least once per page.  Checks at
	 * higher code levels won't be able to stop a seqscan that encounters many
	 * pages' worth of consecutive dead tuples.
	 */
	CHECK_FOR_INTERRUPTS();

	/* read page using selected strategy */
	buffer = ReadBufferExtended(scan->rs_base.rs_rd, MAIN_FORKNUM, page,
								RBM_NORMAL, scan->rs_strategy);
	scan->rs_cblock = page;

	/*
	 * We must hold share lock on the buffer content while examining tuple
	 * visibility.  Afterwards, however, the tuples we have found to be
	 * visible are guaranteed good as long as we hold the buffer pin.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = BufferGetPage(buffer);

	/*
	 * Skip TPD pages. As of now, the size of special space in TPD pages is
	 * different from other zheap pages like metapage and regular zheap page,
	 * however, if that changes, we might need to explicitly store pagetype
	 * flag somewhere.
	 *
	 * Fixme - As an exception, the size of special space for zheap page
	 * with one transaction slot will match with TPD page's special size.
	 */
	if (PageGetSpecialSize(dp) == MAXALIGN(sizeof(TPDPageOpaqueData)))
	{
		UnlockReleaseBuffer(buffer);
		return false;
	}
	else if (!scan->rs_base.rs_pageatatime)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		scan->rs_cbuf = buffer;
		return true;
	}

	snapshot = scan->rs_base.rs_snapshot;

	TestForOldSnapshot(snapshot, scan->rs_base.rs_rd, dp);
	lines = PageGetMaxOffsetNumber(dp);
	ntup = 0;

	/*
	 * If the all-visible flag indicates that all tuples on the page are
	 * visible to everyone, we can skip the per-tuple visibility tests.
	 *
	 * Note: In hot standby, a tuple that's already visible to all
	 * transactions in the master might still be invisible to a read-only
	 * transaction in the standby. We partly handle this problem by tracking
	 * the minimum xmin of visible tuples as the cut-off XID while marking a
	 * page all-visible on master and WAL log that along with the visibility
	 * map SET operation. In hot standby, we wait for (or abort) all
	 * transactions that can potentially may not see one or more tuples on the
	 * page. That's how index-only scans work fine in hot standby.
	 */

	vmstatus = visibilitymap_get_status(scan->rs_base.rs_rd, page, &vmbuffer);

	all_visible = (vmstatus & VISIBILITYMAP_ALL_VISIBLE) &&
				  !snapshot->takenDuringRecovery;

	if (BufferIsValid(vmbuffer))
	{
		ReleaseBuffer(vmbuffer);
		vmbuffer = InvalidBuffer;
	}

	for (lineoff = FirstOffsetNumber, lpp = PageGetItemId(dp, lineoff);
		 lineoff <= lines;
		 lineoff++, lpp++)
	{
		if (ItemIdIsNormal(lpp) || ItemIdIsDeleted(lpp))
		{
			ZHeapTuple	loctup = NULL;
			ZHeapTuple	resulttup = NULL;
			Size		loctup_len;
			bool		valid = false;
			ItemPointerData	tid;

			ItemPointerSet(&tid, page, lineoff);

			if (ItemIdIsDeleted(lpp))
			{
				if (all_visible)
				{
					valid = false;
					resulttup = NULL;
				}
				else
				{
					resulttup = ZHeapGetVisibleTuple(lineoff, snapshot, buffer,
													 NULL);
					valid = resulttup ? true : false;
				}
			}
			else
			{
				loctup_len = ItemIdGetLength(lpp);

				loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
				loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

				loctup->t_tableOid = RelationGetRelid(scan->rs_base.rs_rd);
				loctup->t_len = loctup_len;
				loctup->t_self = tid;

				/*
				 * We always need to make a copy of zheap tuple as once we
				 * release the buffer, an in-place update can change the tuple.
				 */
				memcpy(loctup->t_data,
					   ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)),
					   loctup->t_len);

				if (all_visible)
				{
					valid = true;
					resulttup = loctup;
				}
				else
				{
					resulttup = ZHeapTupleSatisfies(loctup, snapshot,
													buffer, NULL);
					valid = resulttup ? true : false;
				}
			}

			/*
			 * If any prior version is visible, we pass latest visible as
			 * true. The state of latest version of tuple is determined by
			 * the called function.
			 *
			 * Note that, it's possible that tuple is updated in-place and
			 * we're seeing some prior version of that. We handle that case
			 * in ZHeapTupleHasSerializableConflictOut.
			 */
			CheckForSerializableConflictOut(valid, scan->rs_base.rs_rd, (void *) &tid,
											buffer, snapshot);

			if (valid)
				scan->rs_visztuples[ntup++] = resulttup;
		}
	}

	UnlockReleaseBuffer(buffer);

	Assert(ntup <= MaxZHeapTuplesPerPage);
	scan->rs_ntuples = ntup;

	return true;
}

/* ----------------
 *		zheapgettup_pagemode - fetch next zheap tuple in page-at-a-time mode
 *
 * Note that here we process only regular zheap pages, meta and tpd pages are
 * skipped.
 * ----------------
 */
static ZHeapTuple
zheapgettup_pagemode(ZHeapScanDesc scan,
					 ScanDirection dir)
{
	ZHeapTuple	tuple = scan->rs_cztup;
	bool		backward = ScanDirectionIsBackward(dir);
	BlockNumber page;
	bool		finished;
	bool		valid;
	int			lines;
	int			lineindex;
	int			linesleft;
	int			i = 0;

	/*
	 * calculate next starting lineindex, given scan direction
	 */
	if (ScanDirectionIsForward(dir))
	{
		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				tuple = NULL;
				return tuple;
			}
			if (scan->rs_base.rs_parallel != NULL)
			{
				ParallelBlockTableScanDesc pbscan =
				(ParallelBlockTableScanDesc) scan->rs_base.rs_parallel;

				table_block_parallelscan_startblock_init(scan->rs_base.rs_rd,
														 pbscan);

				page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
														 pbscan);

				/* Skip metapage */
				if (page == ZHEAP_METAPAGE)
					page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
															 pbscan);

				/* Other processes might have already finished the scan. */
				if (page == InvalidBlockNumber)
				{
					Assert(!BufferIsValid(scan->rs_cbuf));
					tuple = NULL;
					return tuple;
				}
			}
			else
				page = scan->rs_startblock;		/* first page */
			valid = zheapgetpage(&scan->rs_base, page);
			if (!valid)
				goto get_next_page;

			lineindex = 0;
			scan->rs_inited = true;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
			lineindex = scan->rs_cindex + 1;
		}

		lines = scan->rs_ntuples;
		/* page and lineindex now reference the next visible tid */

		linesleft = lines - lineindex;
	}
	else if (backward)
	{
		/* backward parallel scan not supported */
		Assert(scan->rs_base.rs_parallel == NULL);

		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				tuple = NULL;
				return tuple;
			}

			/*
			 * Disable reporting to syncscan logic in a backwards scan; it's
			 * not very likely anyone else is doing the same thing at the same
			 * time, and much more likely that we'll just bollix things for
			 * forward scanners.
			 */
			scan->rs_base.rs_syncscan = false;
			/* start from last page of the scan */
			if (scan->rs_startblock > ZHEAP_METAPAGE + 1)
				page = scan->rs_startblock - 1;
			else
				page = scan->rs_nblocks - 1;
			valid = zheapgetpage(&scan->rs_base, page);
			if (!valid)
				goto get_next_page;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
		}

		lines = scan->rs_ntuples;

		if (!scan->rs_inited)
		{
			lineindex = lines - 1;
			scan->rs_inited = true;
		}
		else
		{
			lineindex = scan->rs_cindex - 1;
		}
		/* page and lineindex now reference the previous visible tid */

		linesleft = lineindex + 1;
	}
	else
	{
		/*
		 * In executor it seems NoMovementScanDirection is nothing but
		 * do-nothing flag so we should not be here. The else part is still
		 * here to keep the code as in heapgettup_pagemode.
		 */
		Assert(false);
		return NULL;
	}

get_next_tuple:
	/*
	 * advance the scan until we find a qualifying tuple or run out of stuff
	 * to scan
	 */
	while (linesleft > 0)
	{
		tuple = scan->rs_visztuples[lineindex];
		scan->rs_cindex = lineindex;
		return tuple;
	}

	/*
	 * if we get here, it means we've exhausted the items on this page and
	 * it's time to move to the next.
	 * For now we shall free all of the zheap tuples stored in rs_visztuples.
	 * Later a better memory management is required.
	 */
	for (i = 0; i < scan->rs_ntuples; i++)
		zheap_freetuple(scan->rs_visztuples[i]);
	scan->rs_ntuples = 0;

get_next_page:
	for (;;)
	{
		if (backward)
		{
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);
			if (page == ZHEAP_METAPAGE + 1)
				page = scan->rs_nblocks;
			page--;
		}
		else if (scan->rs_base.rs_parallel != NULL)
		{
			ParallelBlockTableScanDesc pbscan =
			(ParallelBlockTableScanDesc) scan->rs_base.rs_parallel;

			page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
													 pbscan);
			/* Skip metapage */
			if (page == ZHEAP_METAPAGE)
				page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
														 pbscan);
			finished = (page == InvalidBlockNumber);
		}
		else
		{
			page++;
			if (page >= scan->rs_nblocks)
				page = 0;

			if (page == ZHEAP_METAPAGE)
			{
				/*
				 * Since we're skipping the metapage, we should update the
				 * scan location if sync scan is enabled.
				 */
				if (scan->rs_base.rs_syncscan)
					ss_report_location(scan->rs_base.rs_rd, page);
				page++;
			}

			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);

			/*
			 * Report our new scan position for synchronization purposes. We
			 * don't do that when moving backwards, however. That would just
			 * mess up any other forward-moving scanners.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_base.rs_syncscan)
				ss_report_location(scan->rs_base.rs_rd, page);
		}

		/*
		 * return NULL if we've exhausted all the pages
		 */
		if (finished)
		{
			if (BufferIsValid(scan->rs_cbuf))
				ReleaseBuffer(scan->rs_cbuf);
			scan->rs_cbuf = InvalidBuffer;
			scan->rs_cblock = InvalidBlockNumber;
			tuple = NULL;
			scan->rs_inited = false;
			return tuple;
		}

		valid = zheapgetpage(&scan->rs_base, page);
		if (!valid)
			continue;

		if (!scan->rs_inited)
			scan->rs_inited = true;
		lines = scan->rs_ntuples;
		linesleft = lines;
		if (backward)
			lineindex = lines - 1;
		else
			lineindex = 0;

		goto get_next_tuple;
	}
}

/*
 * Similar to heapgettup, but for fetching zheap tuple.
 *
 * Note that here we process only regular zheap pages, meta and tpd pages are
 * skipped.
 */
static ZHeapTuple
zheapgettup(ZHeapScanDesc scan,
		   ScanDirection dir)
{
	ZHeapTuple	tuple = scan->rs_cztup;
	Snapshot	snapshot = scan->rs_base.rs_snapshot;
	bool		backward = ScanDirectionIsBackward(dir);
	BlockNumber page;
	bool		finished;
	bool		valid;
	Page		dp;
	int			lines;
	OffsetNumber lineoff;
	int			linesleft;
	ItemId		lpp;

	/*
	 * calculate next starting lineoff, given scan direction
	 */
	if (ScanDirectionIsForward(dir))
	{
		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				return NULL;
			}
			if (scan->rs_base.rs_parallel != NULL)
			{
				ParallelBlockTableScanDesc pbscan =
				(ParallelBlockTableScanDesc) scan->rs_base.rs_parallel;

				table_block_parallelscan_startblock_init(scan->rs_base.rs_rd,
														 pbscan);

				page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
														 pbscan);

				/* Skip metapage */
				if (page == ZHEAP_METAPAGE)
					page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
															 pbscan);

				/* Other processes might have already finished the scan. */
				if (page == InvalidBlockNumber)
				{
					Assert(!BufferIsValid(scan->rs_cbuf));
					return NULL;
				}
			}
			else
				page = scan->rs_startblock;		/* first page */
			valid = zheapgetpage(&scan->rs_base, page);
			if (!valid)
				goto get_next_page;
			lineoff = FirstOffsetNumber;		/* first offnum */
			scan->rs_inited = true;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
			lineoff =			/* next offnum */
				OffsetNumberNext(ItemPointerGetOffsetNumber(&(tuple->t_self)));
		}

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_base.rs_rd, dp);
		lines = PageGetMaxOffsetNumber(dp);
		/* page and lineoff now reference the physically next tid */

		linesleft = lines - lineoff + 1;
	}
	else if (backward)
	{
		/* backward parallel scan not supported */
		Assert(scan->rs_base.rs_parallel == NULL);

		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				return NULL;
			}

			/*
			 * Disable reporting to syncscan logic in a backwards scan; it's
			 * not very likely anyone else is doing the same thing at the same
			 * time, and much more likely that we'll just bollix things for
			 * forward scanners.
			 */
			scan->rs_base.rs_syncscan = false;
			/* start from last page of the scan */
			if (scan->rs_startblock > ZHEAP_METAPAGE + 1)
				page = scan->rs_startblock - 1;
			else
				page = scan->rs_nblocks - 1;
			valid = zheapgetpage(&scan->rs_base, page);
			if (!valid)
				goto get_next_page;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
		}

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_base.rs_rd, dp);
		lines = PageGetMaxOffsetNumber(dp);

		if (!scan->rs_inited)
		{
			lineoff = lines;	/* final offnum */
			scan->rs_inited = true;
		}
		else
		{
			lineoff =			/* previous offnum */
				OffsetNumberPrev(ItemPointerGetOffsetNumber(&(tuple->t_self)));
		}
		/* page and lineoff now reference the physically previous tid */

		linesleft = lineoff;
	}
	else
	{
		/*
		 * In executor it seems NoMovementScanDirection is nothing but
		 * do-nothing flag so we should not be here. The else part is still
		 * here to keep the code as in heapgettup_pagemode.
		 */
		Assert(false);

		return NULL;
	}

	/*
	 * advance the scan until we find a qualifying tuple or run out of stuff
	 * to scan
	 */
	lpp = PageGetItemId(dp, lineoff);

get_next_tuple:
	while (linesleft > 0)
	{
		if (ItemIdIsNormal(lpp))
		{
			ZHeapTuple	tuple = NULL;
			ZHeapTuple loctup = NULL;
			Size		loctup_len;
			bool		valid = false;
			ItemPointerData	tid;

			ItemPointerSet(&tid, page, lineoff);

			loctup_len = ItemIdGetLength(lpp);

			loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
			loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

			loctup->t_tableOid = RelationGetRelid(scan->rs_base.rs_rd);
			loctup->t_len = loctup_len;
			loctup->t_self = tid;

			/*
			 * We always need to make a copy of zheap tuple as once we release
			 * the buffer an in-place update can change the tuple.
			 */
			memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)), loctup->t_len);

			tuple = ZHeapTupleSatisfies(loctup, snapshot, scan->rs_cbuf, NULL);
			valid = tuple ? true : false;

			/*
			 * If any prior version is visible, we pass latest visible as
			 * true. The state of latest version of tuple is determined by
			 * the called function.
			 *
			 * Note that, it's possible that tuple is updated in-place and
			 * we're seeing some prior version of that. We handle that case
			 * in ZHeapTupleHasSerializableConflictOut.
			 */
			CheckForSerializableConflictOut(valid, scan->rs_base.rs_rd, (void *) &tid,
											scan->rs_cbuf, snapshot);

			if (valid)
			{
				LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
				return tuple;
			}
		}

		/*
		 * otherwise move to the next item on the page
		 */
		--linesleft;
		if (backward)
		{
			--lpp;			/* move back in this page's ItemId array */
			--lineoff;
		}
		else
		{
			++lpp;			/* move forward in this page's ItemId array */
			++lineoff;
		}
	}

	/*
	 * if we get here, it means we've exhausted the items on this page and
	 * it's time to move to the next.
	 */
	LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

get_next_page:
	for (;;)
	{
		/*
		 * advance to next/prior page and detect end of scan
		 */
		if (backward)
		{
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);
			if (page == ZHEAP_METAPAGE + 1)
				page = scan->rs_nblocks;
			page--;
		}
		else if (scan->rs_base.rs_parallel != NULL)
		{
			ParallelBlockTableScanDesc pbscan =
			(ParallelBlockTableScanDesc) scan->rs_base.rs_parallel;

			page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
													 pbscan);
			/* Skip metapage */
			if (page == ZHEAP_METAPAGE)
				page = table_block_parallelscan_nextpage(scan->rs_base.rs_rd,
														 pbscan);
			finished = (page == InvalidBlockNumber);
		}
		else
		{
			page++;
			if (page >= scan->rs_nblocks)
				page = 0;

			if (page == ZHEAP_METAPAGE)
			{
				/*
				 * Since we're skipping the metapage, we should update the
				 * scan location if sync scan is enabled.
				 */
				if (scan->rs_base.rs_syncscan)
					ss_report_location(scan->rs_base.rs_rd, page);
				page++;
			}

			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);

			/*
			 * Report our new scan position for synchronization purposes. We
			 * don't do that when moving backwards, however. That would just
			 * mess up any other forward-moving scanners.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_base.rs_syncscan)
				ss_report_location(scan->rs_base.rs_rd, page);
		}

		/*
		 * return NULL if we've exhausted all the pages
		 */
		if (finished)
		{
			if (BufferIsValid(scan->rs_cbuf))
				ReleaseBuffer(scan->rs_cbuf);
			scan->rs_cbuf = InvalidBuffer;
			scan->rs_cblock = InvalidBlockNumber;
			scan->rs_inited = false;
			return NULL;
		}

		valid = zheapgetpage(&scan->rs_base, page);
		if (!valid)
			continue;

		if (!scan->rs_inited)
			scan->rs_inited = true;

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_base.rs_rd, dp);
		lines = PageGetMaxOffsetNumber((Page) dp);
		linesleft = lines;
		if (backward)
		{
			lineoff = lines;
			lpp = PageGetItemId(dp, lines);
		}
		else
		{
			lineoff = FirstOffsetNumber;
			lpp = PageGetItemId(dp, FirstOffsetNumber);
		}

		goto get_next_tuple;
	}
}
#ifdef ZHEAPDEBUGALL
#define ZHEAPDEBUG_1 \
	elog(DEBUG2, "zheap_getnext([%s,nkeys=%d],dir=%d) called", \
		 RelationGetRelationName(scan->rs_rd), scan->rs_nkeys, (int) direction)
#define ZHEAPDEBUG_2 \
	elog(DEBUG2, "zheap_getnext returning EOS")
#define ZHEAPDEBUG_3 \
	elog(DEBUG2, "zheap_getnext returning tuple")
#else
#define ZHEAPDEBUG_1
#define ZHEAPDEBUG_2
#define ZHEAPDEBUG_3
#endif   /* !defined(ZHEAPDEBUGALL) */


ZHeapTuple
zheap_getnext(TableScanDesc sscan, ScanDirection direction)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;
	ZHeapTuple	zhtup = NULL;

	/* Skip metapage */
	if (scan->rs_startblock == ZHEAP_METAPAGE)
		scan->rs_startblock = ZHEAP_METAPAGE + 1;

	/* Note: no locking manipulations needed */

	ZHEAPDEBUG_1;				/* zheap_getnext( info ) */

	/*
	 * The key will be passed only for catalog table scans and catalog tables
	 * are always a heap table!. So in case of zheap it should be set to NULL.
	 */
	Assert (scan->rs_base.rs_key == NULL);

	if (scan->rs_base.rs_pageatatime)
		zhtup = zheapgettup_pagemode(scan, direction);
	else
		zhtup = zheapgettup(scan, direction);

	if (zhtup == NULL)
	{
		ZHEAPDEBUG_2;			/* zheap_getnext returning EOS */
		return NULL;
	}

	scan->rs_cztup = zhtup;

	/*
	 * if we get here it means we have a new current scan tuple, so point to
	 * the proper return buffer and return the tuple.
	 */
	ZHEAPDEBUG_3;				/* zheap_getnext returning tuple */

	pgstat_count_heap_getnext(scan->rs_base.rs_rd);

	return zhtup;
}

bool
zheap_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;
	ZHeapTuple	zhtup = NULL;

	/* Skip metapage */
	if (scan->rs_startblock == ZHEAP_METAPAGE)
		scan->rs_startblock = ZHEAP_METAPAGE + 1;

	ZHEAPDEBUG_1;				/* zheap_getnext( info ) */

	/*
	 * The key will be passed only for catalog table scans and catalog tables
	 * are always a heap table!. So in case of zheap it should be set to NULL.
	 */
	Assert (scan->rs_base.rs_key == NULL);

	if (scan->rs_base.rs_pageatatime)
		zhtup = zheapgettup_pagemode(scan, direction);
	else
		zhtup = zheapgettup(scan, direction);

	if (zhtup == NULL)
	{
		ZHEAPDEBUG_2;			/* zheap_getnext returning EOS */
		ExecClearTuple(slot);
		return false;
	}

	scan->rs_cztup = zhtup;

	/*
	 * if we get here it means we have a new current scan tuple, so point to
	 * the proper return buffer and return the tuple.
	 */
	ZHEAPDEBUG_3;				/* zheap_getnext returning tuple */

	pgstat_count_heap_getnext(scan->rs_base.rs_rd);

	ExecStoreZHeapTuple(zhtup, slot,
						scan->rs_base.rs_pageatatime ? false : true);

	return true;
}

bool
zheap_scan_bitmap_next_block(TableScanDesc sscan,
							 TBMIterateResult *tbmres)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;
	BlockNumber page = tbmres->blockno;
	Page        dp;
	Buffer		buffer;
	Snapshot	snapshot;
	int			ntup;

	scan->rs_cindex = 0;
	scan->rs_ntuples = 0;

	/*
	 * Ignore any claimed entries past what we think is the end of the
	 * relation.  (This is probably not necessary given that we got at
	 * least AccessShareLock on the table before performing any of the
	 * indexscans, but let's be safe.)
	 */
	if (page >= scan->rs_nblocks)
		return false;

	if (page == ZHEAP_METAPAGE)
		return false;

	scan->rs_cbuf = ReleaseAndReadBuffer(scan->rs_cbuf,
												 scan->rs_base.rs_rd,
												 page);
	buffer = scan->rs_cbuf;
	snapshot = scan->rs_base.rs_snapshot;

	ntup = 0;

	/*
	 * We must hold share lock on the buffer content while examining tuple
	 * visibility.  Afterwards, however, the tuples we have found to be
	 * visible are guaranteed good as long as we hold the buffer pin.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);
	dp = (Page) BufferGetPage(buffer);

	/*
	 * Skip TPD pages. As of now, the size of special space in TPD pages is
	 * different from other zheap pages like metapage and regular zheap page,
	 * however, if that changes, we might need to explicitly store pagetype
	 * flag somewhere.
	 *
	 * Fixme - As an exception, the size of special space for zheap page
	 * with one transaction slot will match with TPD page's special size.
	 */
	if (PageGetSpecialSize(dp) == MAXALIGN(sizeof(TPDPageOpaqueData)))
	{
		UnlockReleaseBuffer(buffer);
		return false;
	}
	/*
	 * We need two separate strategies for lossy and non-lossy cases.
	 */
	if (tbmres->ntuples >= 0)
	{
		/*
		 * Bitmap is non-lossy, so we just look through the offsets listed in
		 * tbmres;
		 */
		int			curslot;

		for (curslot = 0; curslot < tbmres->ntuples; curslot++)
		{
			OffsetNumber offnum = tbmres->offsets[curslot];
			ItemPointerData tid;
			ZHeapTuple ztuple;

			ItemPointerSet(&tid, page, offnum);
			ztuple = zheap_search_buffer(&tid, scan->rs_base.rs_rd, buffer, snapshot, NULL);
			if (ztuple != NULL)
				scan->rs_visztuples[ntup++] = ztuple;
		}
	}
	else
	{
		/*
		 * Bitmap is lossy, so we must examine each item pointer on the page.
		 */
		OffsetNumber maxoff = PageGetMaxOffsetNumber(dp);
		OffsetNumber offnum;

		for (offnum = FirstOffsetNumber; offnum <= maxoff; offnum = OffsetNumberNext(offnum))
		{
			ItemId		lpp;
			ZHeapTuple	loctup = NULL;
			ZHeapTuple	resulttup = NULL;
			Size		loctup_len;
			bool		valid = false;
			ItemPointerData tid;

			lpp = PageGetItemId(dp, offnum);
			if (!ItemIdIsNormal(lpp))
				continue;

			ItemPointerSet(&tid, page, offnum);
			loctup_len = ItemIdGetLength(lpp);

			loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
			loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

			loctup->t_tableOid = RelationGetRelid(scan->rs_base.rs_rd);
			loctup->t_len = loctup_len;
			loctup->t_self = tid;

			/*
			 * We always need to make a copy of zheap tuple as once we release
			 * the buffer an in-place update can change the tuple.
			 */
			memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)), loctup->t_len);

			resulttup = ZHeapTupleSatisfies(loctup, snapshot, buffer, NULL);
			valid = resulttup ? true : false;

			if (valid)
			{
				PredicateLockTid(scan->rs_base.rs_rd, &(resulttup->t_self), snapshot,
								 IsSerializableXact() ?
								 zheap_fetchinsertxid(resulttup, buffer) :
								 InvalidTransactionId);
			}

			/*
			 * If any prior version is visible, we pass latest visible as
			 * true. The state of latest version of tuple is determined by
			 * the called function.
			 *
			 * Note that, it's possible that tuple is updated in-place and
			 * we're seeing some prior version of that. We handle that case
			 * in ZHeapTupleHasSerializableConflictOut.
			 */
			CheckForSerializableConflictOut(valid, scan->rs_base.rs_rd, (void *) &tid,
											buffer, snapshot);

			if (valid)
				scan->rs_visztuples[ntup++] = resulttup;
		}
	}

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	Assert(ntup <= MaxZHeapTuplesPerPage);
	scan->rs_ntuples = ntup;
	return true;
}

bool
zheap_scan_bitmap_next_tuple(TableScanDesc sscan, TBMIterateResult *tbmres, struct TupleTableSlot *slot)
{
	ZHeapScanDesc scan = (ZHeapScanDesc) sscan;

	if (scan->rs_cindex < 0 || scan->rs_cindex >= scan->rs_ntuples)
		return false;

	scan->rs_cztup = scan->rs_visztuples[scan->rs_cindex];

	/*
	 * Set up the result slot to point to this tuple. We don't need
	 * to keep the pin on the buffer, since we only scan tuples in page
	 * mode.
	 */
	ExecStoreZHeapTuple(scan->rs_cztup, slot, true);

	scan->rs_cindex++;

	return true;
}

/*
 *	zheap_search_buffer - search tuple satisfying snapshot
 *
 * On entry, *tid is the TID of a tuple, and buffer is the buffer holding
 * this tuple.  We search for the first visible member satisfying the given
 * snapshot. If one is found, we return the tuple, in addition to updating
 * *tid. Return NULL otherwise.
 *
 * The caller must already have pin and (at least) share lock on the buffer;
 * it is still pinned/locked at exit.  Also, We do not report any pgstats
 * count; caller may do so if wanted.
 */
ZHeapTuple
zheap_search_buffer(ItemPointer tid, Relation relation, Buffer buffer,
					Snapshot snapshot, bool *all_dead)
{
	Page		dp = (Page) BufferGetPage(buffer);
	ItemId		lp;
	OffsetNumber offnum;
	ZHeapTuple	loctup = NULL;
	ZHeapTupleData	loctup_tmp;
	ZHeapTuple	resulttup = NULL;
	Size		loctup_len;

	if (all_dead)
		*all_dead = false;

	Assert(ItemPointerGetBlockNumber(tid) == BufferGetBlockNumber(buffer));
	offnum = ItemPointerGetOffsetNumber(tid);
	/* check for bogus TID */
	if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(dp))
		return NULL;

	lp = PageGetItemId(dp, offnum);

	/* check for unused or dead items */
	if (!(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp)))
	{
		if (all_dead)
			*all_dead = true;
		return NULL;
	}

	/*
	 * If the record is deleted, its place in the page might have been taken
	 * by another of its kind. Try to get it from the UNDO if it is still
	 * visible.
	 */
	if (ItemIdIsDeleted(lp))
	{
		resulttup = ZHeapGetVisibleTuple(offnum, snapshot, buffer, all_dead);
		if (resulttup)
			PredicateLockTid(relation, &(resulttup->t_self), snapshot,
							 IsSerializableXact() ?
							 zheap_fetchinsertxid(resulttup, buffer) :
							 InvalidTransactionId);
	}
	else
	{
		loctup_len = ItemIdGetLength(lp);

		loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
		loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

		loctup->t_tableOid = RelationGetRelid(relation);
		loctup->t_len = loctup_len;
		loctup->t_self = *tid;

		/*
		 * We always need to make a copy of zheap tuple as once we release the
		 * buffer an in-place update can change the tuple.
		 */
		memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lp)), loctup->t_len);

		/* If it's visible per the snapshot, we must return it */
		resulttup = ZHeapTupleSatisfies(loctup, snapshot, buffer, NULL);

		if (resulttup)
		{
			/*
			 * To fetch the xmin (aka transaction that has inserted the
			 * tuple), we need to use the transaction slot of the tuple in the
			 * page instead of the tuple from undo, otherwise, it might
			 * traverse the wrong chain.
			 */
			loctup_tmp.t_tableOid = RelationGetRelid(relation);
			loctup_tmp.t_data = (ZHeapTupleHeader) PageGetItem((Page) dp, lp);
			loctup_tmp.t_len = ItemIdGetLength(lp);
			loctup_tmp.t_self = *tid;

			PredicateLockTid(relation, &(loctup_tmp.t_self), snapshot,
							 IsSerializableXact() ?
							 zheap_fetchinsertxid(&loctup_tmp, buffer) :
							 InvalidTransactionId);
		}
	}

	/*
	 * If any prior version is visible, we pass latest visible as
	 * true. The state of latest version of tuple is determined by
	 * the called function.
	 *
	 * Note that, it's possible that tuple is updated in-place and
	 * we're seeing some prior version of that. We handle that case
	 * in ZHeapTupleHasSerializableConflictOut.
	 */
	CheckForSerializableConflictOut((resulttup != NULL), relation, (void *) tid,
									buffer, snapshot);

	if (resulttup)
	{
		/* set the tid */
		*tid = resulttup->t_self;
	}
	else if (!ItemIdIsDeleted(lp))
	{
		/*
		 * Temporarily get the copy of tuple from page to check if tuple is
		 * surely dead.  We can't rely on the copy of local tuple (loctup)
		 * that is prepared for the visibility test as that would have been
		 * freed.
		 */
		loctup_tmp.t_tableOid = RelationGetRelid(relation);
		loctup_tmp.t_data = (ZHeapTupleHeader) PageGetItem((Page) dp, lp);
		loctup_tmp.t_len = ItemIdGetLength(lp);
		loctup_tmp.t_self = *tid;

		/*
		 * If we can't see it, maybe no one else can either.  At caller
		 * request, check whether tuple is dead to all transactions.
		 */
		if (!resulttup && all_dead &&
			ZHeapTupleIsSurelyDead(&loctup_tmp,
								   pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo),
								   buffer))
			*all_dead = true;
	}
	else
	{
		/* For deleted item pointers, we've already set the value for all_dead. */
		return NULL;
	}

	return resulttup;
}

/*
 * zheap_fetch - Fetch a tuple based on TID.
 *
 *	This function is quite similar to heap_fetch with few differences like
 *	it will always allocate the memory for tuple and do a memcpy of the tuple
 *	instead of pointing it to disk tuple.  It is the responsibility of the
 *	caller to free the tuple.
 */
bool
zheap_fetch(Relation relation,
			Snapshot snapshot,
			ItemPointer tid,
			ZHeapTuple *tuple,
			Buffer *userbuf,
			bool keep_buf)
{
	ZHeapTuple	resulttup;
	ItemId		lp;
	Buffer		buffer;
	Page		page;
	Size		tup_len;
	OffsetNumber offnum;
	bool		valid;
	ItemPointerData	ctid;

	/*
	 * Fetch and pin the appropriate page of the relation.
	 */
	buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

	/*
	 * Need share lock on buffer to examine tuple commit status.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);
	page = BufferGetPage(buffer);

	/*
	 * We'd better check for out-of-range offnum in case of VACUUM since the
	 * TID was obtained. Exit if this is metapage.
	 */
	offnum = ItemPointerGetOffsetNumber(tid);
	if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(page) ||
		BufferGetBlockNumber(buffer) == ZHEAP_METAPAGE)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		if (keep_buf)
			*userbuf = buffer;
		else
		{
			ReleaseBuffer(buffer);
			*userbuf = InvalidBuffer;
		}
		*tuple = NULL;
		return false;
	}

	/*
	 * get the item line pointer corresponding to the requested tid
	 */
	lp = PageGetItemId(page, offnum);

	/*
	 * Must check for dead and unused items.
	 */
	if (!ItemIdIsNormal(lp) && !ItemIdIsDeleted(lp))
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		if (keep_buf)
			*userbuf = buffer;
		else
		{
			ReleaseBuffer(buffer);
			*userbuf = InvalidBuffer;
		}
		*tuple = NULL;
		return false;
	}

	*tuple = NULL;
	if (ItemIdIsDeleted(lp))
	{
		CommandId		tup_cid;
		TransactionId	tup_xid;

		resulttup = ZHeapGetVisibleTuple(offnum, snapshot, buffer, NULL);
		ctid = *tid;
		ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
		valid = resulttup ? true : false;
	}
	else
	{
		/*
		 * fill in *tuple fields
		 */
		tup_len = ItemIdGetLength(lp);

		*tuple = palloc(ZHEAPTUPLESIZE + tup_len);
		(*tuple)->t_data = (ZHeapTupleHeader) ((char *) (*tuple) + ZHEAPTUPLESIZE);

		(*tuple)->t_tableOid = RelationGetRelid(relation);
		(*tuple)->t_len = tup_len;
		(*tuple)->t_self = *tid;

		/*
		 * We always need to make a copy of zheap tuple as once we release
		 * the lock on buffer an in-place update can change the tuple.
		 */
		memcpy((*tuple)->t_data, ((ZHeapTupleHeader) PageGetItem(page, lp)), tup_len);
		ItemPointerSetInvalid(&ctid);

		/*
		 * check time qualification of tuple, then release lock
		 */
		resulttup = ZHeapTupleSatisfies(*tuple, snapshot, buffer, &ctid);
		valid = resulttup ? true : false;
	}

	if (valid)
		PredicateLockTid(relation, &((resulttup)->t_self), snapshot,
						 IsSerializableXact() ?
						 zheap_fetchinsertxid(resulttup, buffer) :
						 InvalidTransactionId);

	/*
	 * If any prior version is visible, we pass latest visible as
	 * true. The state of latest version of tuple is determined by
	 * the called function.
	 *
	 * Note that, it's possible that tuple is updated in-place and
	 * we're seeing some prior version of that. We handle that case
	 * in ZHeapTupleHasSerializableConflictOut.
	 */
	CheckForSerializableConflictOut(valid, relation, (void *) tid,
									buffer, snapshot);

	/*
	 * Pass back the ctid if the tuple is invisible because it was updated.
	 * Apart from SnapshotAny, ctid must be changed only when current
	 * tuple in not visible.
	 */
	if (ItemPointerIsValid(&ctid))
	{
		if (snapshot == SnapshotAny || !valid)
		{
			*tid = ctid;
		}
	}

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	if (valid)
	{
		/*
		 * All checks passed, so return the tuple as valid. Caller is now
		 * responsible for releasing the buffer.
		 */
		*userbuf = buffer;
		*tuple = resulttup;

		return true;
	}

	/* Tuple failed time qual, but maybe caller wants to see it anyway. */
	if (keep_buf)
		*userbuf = buffer;
	else
	{
		ReleaseBuffer(buffer);
		*userbuf = InvalidBuffer;
	}

	return false;
}
