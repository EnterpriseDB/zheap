/*-------------------------------------------------------------------------
 *
 * vacuumblk.c
 *	  The postgres block level functions.
 *
 * This file contains the commons functions for block level vacuum that
 * can be used by different storage engines.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/commands/vacuumblk.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/multixact.h"
#include "access/vacuumblk.h"
#include "catalog/storage.h"
#include "commands/progress.h"
#include "commands/vacuum.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "utils/pg_rusage.h"

/*
 * Space/time tradeoff parameters: do these need to be user-tunable?
 *
 * To consider truncating the relation, we want there to be at least
 * REL_TRUNCATE_MINIMUM or (relsize / REL_TRUNCATE_FRACTION) (whichever
 * is less) potentially-freeable pages.
 */
#define REL_TRUNCATE_MINIMUM	1000
#define REL_TRUNCATE_FRACTION	16

/*
 * Timing parameters for truncate locking heuristics.
 *
 * These were not exposed as user tunable GUC values because it didn't seem
 * that the potential for improvement was great enough to merit the cost of
 * supporting them.
 */
#define VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL		20	/* ms */
#define VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL		50	/* ms */
#define VACUUM_TRUNCATE_LOCK_TIMEOUT			5000	/* ms */

/*
 * Size of the prefetch window for lazy vacuum backwards truncation scan.
 * Needs to be a power of 2.
 */
#define PREFETCH_SIZE			((BlockNumber) 32)

static bool lazy_tid_reaped(ItemPointer itemptr, void *state);
static int	vac_cmp_itemptr(const void *left, const void *right);
static BlockNumber count_nondeletable_pages(Relation onerel,
						 LVRelStats *vacrelstats,
						 BufferAccessStrategy vac_strategy,
						 int elevel);

/*
 *	lazy_vacuum_index() -- vacuum one index relation.
 *
 *		Delete all the index entries pointing to tuples listed in
 *		vacrelstats->dead_tuples, and update running statistics.
 */
void
lazy_vacuum_index(Relation indrel,
				  IndexBulkDeleteResult **stats,
				  LVRelStats *vacrelstats,
				  BufferAccessStrategy vac_strategy,
				  int elevel)
{
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.analyze_only = false;
	ivinfo.estimated_count = true;
	ivinfo.message_level = elevel;
	/* We can only provide an approximate value of num_heap_tuples here */
	ivinfo.num_heap_tuples = vacrelstats->old_live_tuples;
	ivinfo.strategy = vac_strategy;

	/* Do bulk deletion */
	*stats = index_bulk_delete(&ivinfo, *stats,
							   lazy_tid_reaped, (void *) vacrelstats);

	ereport(elevel,
			(errmsg("scanned index \"%s\" to remove %d row versions",
					RelationGetRelationName(indrel),
					vacrelstats->num_dead_tuples),
			 errdetail_internal("%s", pg_rusage_show(&ru0))));
}

/*
 *	lazy_cleanup_index() -- do post-vacuum cleanup for one index relation.
 */
void
lazy_cleanup_index(Relation indrel,
				   IndexBulkDeleteResult *stats,
				   LVRelStats *vacrelstats,
				   BufferAccessStrategy vac_strategy,
				   int elevel)
{
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.analyze_only = false;
	ivinfo.report_progress = false;
	ivinfo.estimated_count = (vacrelstats->tupcount_pages < vacrelstats->rel_pages);
	ivinfo.message_level = elevel;

	/*
	 * Now we can provide a better estimate of total number of surviving
	 * tuples (we assume indexes are more interested in that than in the
	 * number of nominally live tuples).
	 */
	ivinfo.num_heap_tuples = vacrelstats->new_rel_tuples;
	ivinfo.strategy = vac_strategy;

	stats = index_vacuum_cleanup(&ivinfo, stats);

	if (!stats)
		return;

	/*
	 * Now update statistics in pg_class, but only if the index says the count
	 * is accurate.
	 */
	if (!stats->estimated_count)
		vac_update_relstats(indrel,
							stats->num_pages,
							stats->num_index_tuples,
							0,
							false,
							InvalidTransactionId,
							InvalidMultiXactId,
							false);

	ereport(elevel,
			(errmsg("index \"%s\" now contains %.0f row versions in %u pages",
					RelationGetRelationName(indrel),
					stats->num_index_tuples,
					stats->num_pages),
			 errdetail("%.0f index row versions were removed.\n"
					   "%u index pages have been deleted, %u are currently reusable.\n"
					   "%s.",
					   stats->tuples_removed,
					   stats->pages_deleted, stats->pages_free,
					   pg_rusage_show(&ru0))));

	pfree(stats);
}

/*
 * should_attempt_truncation - should we attempt to truncate the heap?
 *
 * Don't even think about it unless we have a shot at releasing a goodly
 * number of pages.  Otherwise, the time taken isn't worth it.
 *
 * Also don't attempt it if we are doing early pruning/vacuuming, because a
 * scan which cannot find a truncated heap page cannot determine that the
 * snapshot is too old to read that page.  We might be able to get away with
 * truncating all except one of the pages, setting its LSN to (at least) the
 * maximum of the truncated range if we also treated an index leaf tuple
 * pointing to a missing heap page as something to trigger the "snapshot too
 * old" error, but that seems fragile and seems like it deserves its own patch
 * if we consider it.
 *
 * This is split out so that we can test whether truncation is going to be
 * called for before we actually do it.  If you change the logic here, be
 * careful to depend only on fields that lazy_scan_heap updates on-the-fly.
 */
bool
should_attempt_truncation(Relation rel, LVRelStats *vacrelstats)
{
	BlockNumber possibly_freeable;

	if (rel->rd_options != NULL &&
		((StdRdOptions *) rel->rd_options)->vacuum_truncate == false)
		return false;

	possibly_freeable = vacrelstats->rel_pages - vacrelstats->nonempty_pages;
	if (possibly_freeable > 0 &&
		(possibly_freeable >= REL_TRUNCATE_MINIMUM ||
		 possibly_freeable >= vacrelstats->rel_pages / REL_TRUNCATE_FRACTION) &&
		old_snapshot_threshold < 0)
		return true;
	else
		return false;
}

/*
 * lazy_truncate_heap - try to truncate off any empty pages at the end
 */
void
lazy_truncate_heap(Relation onerel, LVRelStats *vacrelstats,
				   BufferAccessStrategy vac_strategy, int elevel)
{
	BlockNumber old_rel_pages = vacrelstats->rel_pages;
	BlockNumber new_rel_pages;
	PGRUsage	ru0;
	int			lock_retry;

	pg_rusage_init(&ru0);

	/* Report that we are now truncating */
	pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
								 PROGRESS_VACUUM_PHASE_TRUNCATE);

	/*
	 * Loop until no more truncating can be done.
	 */
	do
	{
		/*
		 * We need full exclusive lock on the relation in order to do
		 * truncation. If we can't get it, give up rather than waiting --- we
		 * don't want to block other backends, and we don't want to deadlock
		 * (which is quite possible considering we already hold a lower-grade
		 * lock).
		 */
		vacrelstats->lock_waiter_detected = false;
		lock_retry = 0;
		while (true)
		{
			if (ConditionalLockRelation(onerel, AccessExclusiveLock))
				break;

			/*
			 * Check for interrupts while trying to (re-)acquire the exclusive
			 * lock.
			 */
			CHECK_FOR_INTERRUPTS();

			if (++lock_retry > (VACUUM_TRUNCATE_LOCK_TIMEOUT /
								VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL))
			{
				/*
				 * We failed to establish the lock in the specified number of
				 * retries. This means we give up truncating.
				 */
				vacrelstats->lock_waiter_detected = true;
				ereport(elevel,
						(errmsg("\"%s\": stopping truncate due to conflicting lock request",
								RelationGetRelationName(onerel))));
				return;
			}

			pg_usleep(VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL * 1000L);
		}

		/*
		 * Now that we have exclusive lock, look to see if the rel has grown
		 * whilst we were vacuuming with non-exclusive lock.  If so, give up;
		 * the newly added pages presumably contain non-deletable tuples.
		 */
		new_rel_pages = RelationGetNumberOfBlocks(onerel);
		if (new_rel_pages != old_rel_pages)
		{
			/*
			 * Note: we intentionally don't update vacrelstats->rel_pages with
			 * the new rel size here.  If we did, it would amount to assuming
			 * that the new pages are empty, which is unlikely. Leaving the
			 * numbers alone amounts to assuming that the new pages have the
			 * same tuple density as existing ones, which is less unlikely.
			 */
			UnlockRelation(onerel, AccessExclusiveLock);
			return;
		}

		/*
		 * Scan backwards from the end to verify that the end pages actually
		 * contain no tuples.  This is *necessary*, not optional, because
		 * other backends could have added tuples to these pages whilst we
		 * were vacuuming.
		 */
		new_rel_pages = count_nondeletable_pages(onerel, vacrelstats,
												 vac_strategy, elevel);

		if (new_rel_pages >= old_rel_pages)
		{
			/* can't do anything after all */
			UnlockRelation(onerel, AccessExclusiveLock);
			return;
		}

		/*
		 * Okay to truncate.
		 */

		/* make sure it's not the metapage */
		if (RelationStorageIsZHeap(onerel))
			Assert(new_rel_pages > 0);

		RelationTruncate(onerel, new_rel_pages);

		/*
		 * We can release the exclusive lock as soon as we have truncated.
		 * Other backends can't safely access the relation until they have
		 * processed the smgr invalidation that smgrtruncate sent out ... but
		 * that should happen as part of standard invalidation processing once
		 * they acquire lock on the relation.
		 */
		UnlockRelation(onerel, AccessExclusiveLock);

		/*
		 * Update statistics.  Here, it *is* correct to adjust rel_pages
		 * without also touching reltuples, since the tuple count wasn't
		 * changed by the truncation.
		 */
		vacrelstats->pages_removed += old_rel_pages - new_rel_pages;
		vacrelstats->rel_pages = new_rel_pages;

		ereport(elevel,
				(errmsg("\"%s\": truncated %u to %u pages",
						RelationGetRelationName(onerel),
						old_rel_pages, new_rel_pages),
				 errdetail_internal("%s",
									pg_rusage_show(&ru0))));
		old_rel_pages = new_rel_pages;
	} while (new_rel_pages > vacrelstats->nonempty_pages &&
			 vacrelstats->lock_waiter_detected);
}

/*
 * lazy_record_dead_tuple - remember one deletable tuple
 */
void
lazy_record_dead_tuple(LVRelStats *vacrelstats,
					   ItemPointer itemptr)
{
	/*
	 * The array shouldn't overflow under normal behavior, but perhaps it
	 * could if we are given a really small maintenance_work_mem. In that
	 * case, just forget the last few tuples (we'll get 'em next time).
	 */
	if (vacrelstats->num_dead_tuples < vacrelstats->max_dead_tuples)
	{
		vacrelstats->dead_tuples[vacrelstats->num_dead_tuples] = *itemptr;
		vacrelstats->num_dead_tuples++;
		pgstat_progress_update_param(PROGRESS_VACUUM_NUM_DEAD_TUPLES,
									 vacrelstats->num_dead_tuples);
	}
}

/*
 *	lazy_tid_reaped() -- is a particular tid deletable?
 *
 *		This has the right signature to be an IndexBulkDeleteCallback.
 *
 *		Assumes dead_tuples array is in sorted order.
 */
static bool
lazy_tid_reaped(ItemPointer itemptr, void *state)
{
	LVRelStats *vacrelstats = (LVRelStats *) state;
	ItemPointer res;

	res = (ItemPointer) bsearch((void *) itemptr,
								(void *) vacrelstats->dead_tuples,
								vacrelstats->num_dead_tuples,
								sizeof(ItemPointerData),
								vac_cmp_itemptr);

	return (res != NULL);
}

/*
 * Comparator routines for use with qsort() and bsearch().
 */
static int
vac_cmp_itemptr(const void *left, const void *right)
{
	BlockNumber lblk,
				rblk;
	OffsetNumber loff,
				roff;

	lblk = ItemPointerGetBlockNumber((ItemPointer) left);
	rblk = ItemPointerGetBlockNumber((ItemPointer) right);

	if (lblk < rblk)
		return -1;
	if (lblk > rblk)
		return 1;

	loff = ItemPointerGetOffsetNumber((ItemPointer) left);
	roff = ItemPointerGetOffsetNumber((ItemPointer) right);

	if (loff < roff)
		return -1;
	if (loff > roff)
		return 1;

	return 0;
}

/*
 * Rescan end pages to verify that they are (still) empty of tuples.
 *
 * Returns number of nondeletable pages (last nonempty page + 1).
 */
static BlockNumber
count_nondeletable_pages(Relation onerel, LVRelStats *vacrelstats,
						 BufferAccessStrategy vac_strategy, int elevel)
{
	BlockNumber blkno;
	BlockNumber prefetchedUntil;
	instr_time	starttime;

	/* Initialize the starttime if we check for conflicting lock requests */
	INSTR_TIME_SET_CURRENT(starttime);

	/*
	 * Start checking blocks at what we believe relation end to be and move
	 * backwards.  (Strange coding of loop control is needed because blkno is
	 * unsigned.)  To make the scan faster, we prefetch a few blocks at a time
	 * in forward direction, so that OS-level readahead can kick in.
	 */
	blkno = vacrelstats->rel_pages;
	StaticAssertStmt((PREFETCH_SIZE & (PREFETCH_SIZE - 1)) == 0,
					 "prefetch size must be power of 2");
	prefetchedUntil = InvalidBlockNumber;
	while (blkno > vacrelstats->nonempty_pages)
	{
		Buffer		buf;
		Page		page;
		OffsetNumber offnum,
					maxoff;
		bool		hastup;

		/*
		 * Check if another process requests a lock on our relation. We are
		 * holding an AccessExclusiveLock here, so they will be waiting. We
		 * only do this once per VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL, and we
		 * only check if that interval has elapsed once every 32 blocks to
		 * keep the number of system calls and actual shared lock table
		 * lookups to a minimum.
		 */
		if ((blkno % 32) == 0)
		{
			instr_time	currenttime;
			instr_time	elapsed;

			INSTR_TIME_SET_CURRENT(currenttime);
			elapsed = currenttime;
			INSTR_TIME_SUBTRACT(elapsed, starttime);
			if ((INSTR_TIME_GET_MICROSEC(elapsed) / 1000)
				>= VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL)
			{
				if (LockHasWaitersRelation(onerel, AccessExclusiveLock))
				{
					ereport(elevel,
							(errmsg("\"%s\": suspending truncate due to conflicting lock request",
									RelationGetRelationName(onerel))));

					vacrelstats->lock_waiter_detected = true;
					return blkno;
				}
				starttime = currenttime;
			}
		}

		/*
		 * We don't insert a vacuum delay point here, because we have an
		 * exclusive lock on the table which we want to hold for as short a
		 * time as possible.  We still need to check for interrupts however.
		 */
		CHECK_FOR_INTERRUPTS();

		blkno--;

		/* If we haven't prefetched this lot yet, do so now. */
		if (prefetchedUntil > blkno)
		{
			BlockNumber prefetchStart;
			BlockNumber pblkno;

			prefetchStart = blkno & ~(PREFETCH_SIZE - 1);
			for (pblkno = prefetchStart; pblkno <= blkno; pblkno++)
			{
				PrefetchBuffer(onerel, MAIN_FORKNUM, pblkno);
				CHECK_FOR_INTERRUPTS();
			}
			prefetchedUntil = prefetchStart;
		}

		buf = ReadBufferExtended(onerel, MAIN_FORKNUM, blkno,
								 RBM_NORMAL, vac_strategy);

		/* In this phase we only need shared access to the buffer */
		LockBuffer(buf, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buf);

		if (PageIsNew(page) || PageIsEmpty(page))
		{
			UnlockReleaseBuffer(buf);
			continue;
		}

		hastup = false;
		maxoff = PageGetMaxOffsetNumber(page);
		for (offnum = FirstOffsetNumber;
			 offnum <= maxoff;
			 offnum = OffsetNumberNext(offnum))
		{
			ItemId		itemid;

			itemid = PageGetItemId(page, offnum);

			/*
			 * Note: any non-unused item should be taken as a reason to keep
			 * this page.  We formerly thought that DEAD tuples could be
			 * thrown away, but that's not so, because we'd not have cleaned
			 * out their index entries.
			 *
			 * XXX - This function is used by both heap and zheap and the
			 * behavior must be same in both the cases.  However, for zheap,
			 * there could be some unused items that contain pending xact
			 * information for the current transaction.  It is okay to
			 * truncate such pages as even if the transaction rolled back
			 * after this point, we won't be reclaiming the truncated pages or
			 * making the unused items back to dead.  We can add Assert to
			 * check if the pending xact is the current transaction, but to do
			 * that we need some storage engine specific check which seems too
			 * much for the purpose for which it is required.
			 */
			if (ItemIdIsUsed(itemid))
			{
				hastup = true;
				break;			/* can stop scanning */
			}
		}						/* scan along page */

		UnlockReleaseBuffer(buf);

		/* Done scanning if we found a tuple here */
		if (hastup)
			return blkno + 1;
	}

	/*
	 * If we fall out of the loop, all the previously-thought-to-be-empty
	 * pages still are; we need not bother to look at the last known-nonempty
	 * page.
	 */
	return vacrelstats->nonempty_pages;
}
