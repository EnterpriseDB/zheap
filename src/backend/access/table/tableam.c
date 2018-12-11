/*----------------------------------------------------------------------
 *
 * tableam.c
 *		Table access method routines too big to be inline functions.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/table/tableam.c
 *----------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/tableam.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"

/* GUC variable */
bool		synchronize_seqscans = true;

char *default_table_access_method = DEFAULT_TABLE_ACCESS_METHOD;


/* ----------------
 *		table_parallelscan_estimate - estimate storage for ParallelTableScanDesc
 *
 *		Sadly, this doesn't reduce to a constant, because the size required
 *		to serialize the snapshot can vary.
 * ----------------
 */
Size
table_parallelscan_estimate(Snapshot snapshot)
{
	return add_size(offsetof(ParallelTableScanDescData, phs_snapshot_data),
					EstimateSnapshotSpace(snapshot));
}

/* ----------------
 *		table_parallelscan_initialize - initialize ParallelTableScanDesc
 *
 *		Must allow as many bytes of shared memory as returned by
 *		table_parallelscan_estimate.  Call this just once in the leader
 *		process; then, individual workers attach via table_beginscan_parallel.
 * ----------------
 */
void
table_parallelscan_initialize(ParallelTableScanDesc target, Relation relation,
							 Snapshot snapshot)
{
	target->phs_relid = RelationGetRelid(relation);
	target->phs_nblocks = RelationGetNumberOfBlocks(relation);
	/* compare phs_syncscan initialization to similar logic in initscan */
	target->phs_syncscan = synchronize_seqscans &&
		!RelationUsesLocalBuffers(relation) &&
		target->phs_nblocks > NBuffers / 4;
	SpinLockInit(&target->phs_mutex);
	target->phs_startblock = InvalidBlockNumber;
	pg_atomic_init_u64(&target->phs_nallocated, 0);
	if (IsMVCCSnapshot(snapshot))
	{
		SerializeSnapshot(snapshot, target->phs_snapshot_data);
		target->phs_snapshot_any = false;
	}
	else
	{
		Assert(snapshot == SnapshotAny);
		target->phs_snapshot_any = true;
	}
}

/* ----------------
 *		table_parallelscan_reinitialize - reset a parallel scan
 *
 *		Call this in the leader process.  Caller is responsible for
 *		making sure that all workers have finished the scan beforehand.
 * ----------------
 */
void
table_parallelscan_reinitialize(ParallelTableScanDesc parallel_scan)
{
	pg_atomic_write_u64(&parallel_scan->phs_nallocated, 0);
}

/* ----------------
 *		table_parallelscan_startblock_init - find and set the scan's startblock
 *
 *		Determine where the parallel seq scan should start.  This function may
 *		be called many times, once by each parallel worker.  We must be careful
 *		only to set the startblock once.
 * ----------------
 */
void
table_parallelscan_startblock_init(TableScanDesc scan)
{
	BlockNumber sync_startpage = InvalidBlockNumber;
	ParallelTableScanDesc parallel_scan;

	Assert(scan->rs_parallel);
	parallel_scan = scan->rs_parallel;

retry:
	/* Grab the spinlock. */
	SpinLockAcquire(&parallel_scan->phs_mutex);

	/*
	 * If the scan's startblock has not yet been initialized, we must do so
	 * now.  If this is not a synchronized scan, we just start at block 0, but
	 * if it is a synchronized scan, we must get the starting position from
	 * the synchronized scan machinery.  We can't hold the spinlock while
	 * doing that, though, so release the spinlock, get the information we
	 * need, and retry.  If nobody else has initialized the scan in the
	 * meantime, we'll fill in the value we fetched on the second time
	 * through.
	 */
	if (parallel_scan->phs_startblock == InvalidBlockNumber)
	{
		if (!parallel_scan->phs_syncscan)
			parallel_scan->phs_startblock = 0;
		else if (sync_startpage != InvalidBlockNumber)
			parallel_scan->phs_startblock = sync_startpage;
		else
		{
			SpinLockRelease(&parallel_scan->phs_mutex);
			sync_startpage = ss_get_location(scan->rs_rd, scan->rs_nblocks);
			goto retry;
		}
	}
	SpinLockRelease(&parallel_scan->phs_mutex);
}

/* ----------------
 *		table_parallelscan_nextpage - get the next page to scan
 *
 *		Get the next page to scan.  Even if there are no pages left to scan,
 *		another backend could have grabbed a page to scan and not yet finished
 *		looking at it, so it doesn't follow that the scan is done when the
 *		first backend gets an InvalidBlockNumber return.
 * ----------------
 */
BlockNumber
table_parallelscan_nextpage(TableScanDesc scan)
{
	BlockNumber page;
	ParallelTableScanDesc parallel_scan;
	uint64		nallocated;

	Assert(scan->rs_parallel);
	parallel_scan = scan->rs_parallel;

	/*
	 * phs_nallocated tracks how many pages have been allocated to workers
	 * already.  When phs_nallocated >= rs_nblocks, all blocks have been
	 * allocated.
	 *
	 * Because we use an atomic fetch-and-add to fetch the current value, the
	 * phs_nallocated counter will exceed rs_nblocks, because workers will
	 * still increment the value, when they try to allocate the next block but
	 * all blocks have been allocated already. The counter must be 64 bits
	 * wide because of that, to avoid wrapping around when rs_nblocks is close
	 * to 2^32.
	 *
	 * The actual page to return is calculated by adding the counter to the
	 * starting block number, modulo nblocks.
	 */
	nallocated = pg_atomic_fetch_add_u64(&parallel_scan->phs_nallocated, 1);
	if (nallocated >= scan->rs_nblocks)
		page = InvalidBlockNumber;	/* all blocks have been allocated */
	else
		page = (nallocated + parallel_scan->phs_startblock) % scan->rs_nblocks;

	/*
	 * Report scan location.  Normally, we report the current page number.
	 * When we reach the end of the scan, though, we report the starting page,
	 * not the ending page, just so the starting positions for later scans
	 * doesn't slew backwards.  We only report the position at the end of the
	 * scan once, though: subsequent callers will report nothing.
	 */
	if (scan->rs_syncscan)
	{
		if (page != InvalidBlockNumber)
			ss_report_location(scan->rs_rd, page);
		else if (nallocated == scan->rs_nblocks)
			ss_report_location(scan->rs_rd, parallel_scan->phs_startblock);
	}

	return page;
}
