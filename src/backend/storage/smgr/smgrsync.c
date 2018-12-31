/*-------------------------------------------------------------------------
 *
 * smgrsync.c
 *	  management of file synchronization.
 *
 * This modules tracks which files need to be fsynced or unlinked at the
 * next checkpoint, and performs those actions.  Normally the work is done
 * when called by the checkpointer, but it is also done in standalone mode
 * and startup.
 *
 * Originally this logic was inside md.c, but it is now made more general,
 * for reuse by other SMGR implementations that work with files.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/smgr/smgrsync.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <unistd.h>

#include "access/xlog.h"
#include "miscadmin.h"
#include "nodes/pg_list.h"
#include "pgstat.h"
#include "portability/instr_time.h"
#include "postmaster/bgwriter.h"
#include "postmaster/checkpointer.h"
#include "storage/relfilenode.h"
#include "storage/smgrsync.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"

static MemoryContext pendingOpsCxt; /* context for the pending ops state  */

#define SV_PREFIX segnum_vector
#define SV_DECLARE
#define SV_DEFINE
#define SV_ELEMENT_TYPE BlockNumber
#define SV_SCOPE static inline
#define SV_GLOBAL_MEMORY_CONTEXT pendingOpsCxt
#include "lib/simplevector.h"

#define SA_PREFIX segnum_array
#define SA_COMPARE(a,b) (*a < *b ? -1 : *a == *b ? 0 : 1)
#define SA_DECLARE
#define SA_DEFINE
#define SA_ELEMENT_TYPE SV_ELEMENT_TYPE
#define SA_SCOPE static inline
#include "lib/sort_utils.h"

/*
 * In some contexts (currently, standalone backends and the checkpointer)
 * we keep track of pending fsync operations: we need to remember all relation
 * segments that have been written since the last checkpoint, so that we can
 * fsync them down to disk before completing the next checkpoint.  A hash
 * table remembers the pending operations.  We use a hash table mostly as
 * a convenient way of merging duplicate requests.
 *
 * We use a similar mechanism to remember no-longer-needed files that can
 * be deleted after the next checkpoint, but we use a linked list instead of
 * a hash table, because we don't expect there to be any duplicate requests.
 *
 * These mechanisms are only used for non-temp relations; we never fsync
 * temp rels, nor do we need to postpone their deletion (see comments in
 * mdunlink).
 *
 * (Regular backends do not track pending operations locally, but forward
 * them to the checkpointer.)
 */

typedef uint32 CycleCtr;		/* can be any convenient integer size */

/*
 * Values for the "type" member of CheckpointerRequest.
 *
 * Note that CompactCheckpointerRequestQueue assumes that it's OK to remove an
 * fsync request from the queue if an identical, subsequent request is found.
 * See comments there before making changes here.
 */
#define FSYNC_SEGMENT_REQUEST	1
#define FORGET_SEGMENT_FSYNC	2
#define FORGET_RELATION_FSYNC	3
#define FORGET_DATABASE_FSYNC	4
#define UNLINK_RELATION_REQUEST 5
#define UNLINK_SEGMENT_REQUEST	6

/* intervals for calling AbsorbFsyncRequests in smgrsync and smgrpostckpt */
#define FSYNCS_PER_ABSORB		10
#define UNLINKS_PER_ABSORB		10

/*
 * An entry in the hash table of files that need to be flushed for the next
 * checkpoint.
 */
typedef struct PendingFsyncEntry
{
	RelFileNode	rnode;
	segnum_vector requests[MAX_FORKNUM + 1];
	segnum_vector requests_in_progress[MAX_FORKNUM + 1];
	CycleCtr	cycle_ctr;
} PendingFsyncEntry;

typedef struct PendingUnlinkEntry
{
	RelFileNode rnode;			/* the dead relation to delete */
	CycleCtr	cycle_ctr;		/* ckpt_cycle_ctr when request was made */
} PendingUnlinkEntry;

static bool sync_in_progress = false;
static CycleCtr sync_cycle_ctr = 0;
static CycleCtr ckpt_cycle_ctr = 0;

static HTAB *pendingFsyncTable = NULL;
static List *pendingUnlinks = NIL;

/*
 * Initialize the pending operations state, if necessary.
 */
void
smgrsync_init(void)
{
	/*
	 * Create pending-operations hashtable if we need it.  Currently, we need
	 * it if we are standalone (not under a postmaster) or if we are a startup
	 * or checkpointer auxiliary process.
	 */
	if (!IsUnderPostmaster || AmStartupProcess() || AmCheckpointerProcess())
	{
		HASHCTL		hash_ctl;

		/*
		 * XXX: The checkpointer needs to add entries to the pending ops table
		 * when absorbing fsync requests.  That is done within a critical
		 * section, which isn't usually allowed, but we make an exception. It
		 * means that there's a theoretical possibility that you run out of
		 * memory while absorbing fsync requests, which leads to a PANIC.
		 * Fortunately the hash table is small so that's unlikely to happen in
		 * practice.
		 */
		pendingOpsCxt = AllocSetContextCreate(TopMemoryContext,
											  "Pending ops context",
											  ALLOCSET_DEFAULT_SIZES);
		MemoryContextAllowInCriticalSection(pendingOpsCxt, true);

		MemSet(&hash_ctl, 0, sizeof(hash_ctl));
		hash_ctl.keysize = sizeof(RelFileNode);
		hash_ctl.entrysize = sizeof(PendingFsyncEntry);
		hash_ctl.hcxt = pendingOpsCxt;
		pendingFsyncTable = hash_create("Pending Ops Table",
									  100L,
									  &hash_ctl,
									  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
		pendingUnlinks = NIL;
	}
}

/*
 * Do pre-checkpoint work.
 *
 * To distinguish unlink requests that arrived before this checkpoint
 * started from those that arrived during the checkpoint, we use a cycle
 * counter similar to the one we use for fsync requests. That cycle
 * counter is incremented here.
 *
 * This must be called *before* the checkpoint REDO point is determined.
 * That ensures that we won't delete files too soon.
 *
 * Note that we can't do anything here that depends on the assumption
 * that the checkpoint will be completed.
 */
void
smgrpreckpt(void)
{
	/*
	 * Any unlink requests arriving after this point will be assigned the next
	 * cycle counter, and won't be unlinked until next checkpoint.
	 */
	ckpt_cycle_ctr++;
}

/*
 * Sync previous writes to stable storage.
 */
void
smgrsync(void)
{
	HASH_SEQ_STATUS hstat;
	PendingFsyncEntry *entry;
	int			absorb_counter;

	/* Statistics on sync times */
	instr_time	sync_start,
				sync_end,
				sync_diff;
	uint64		elapsed;
	int			processed = CheckpointStats.ckpt_sync_rels;
	uint64		longest = CheckpointStats.ckpt_longest_sync;
	uint64		total_elapsed = CheckpointStats.ckpt_agg_sync_time;

	/*
	 * This is only called during checkpoints, and checkpoints should only
	 * occur in processes that have created a pendingFsyncTable.
	 */
	if (!pendingFsyncTable)
		elog(ERROR, "cannot sync without a pendingFsyncTable");

	/*
	 * If we are in the checkpointer, the sync had better include all fsync
	 * requests that were queued by backends up to this point.  The tightest
	 * race condition that could occur is that a buffer that must be written
	 * and fsync'd for the checkpoint could have been dumped by a backend just
	 * before it was visited by BufferSync().  We know the backend will have
	 * queued an fsync request before clearing the buffer's dirtybit, so we
	 * are safe as long as we do an Absorb after completing BufferSync().
	 */
	AbsorbFsyncRequests();

	/*
	 * To avoid excess fsync'ing (in the worst case, maybe a never-terminating
	 * checkpoint), we want to ignore fsync requests that are entered into the
	 * hashtable after this point --- they should be processed next time,
	 * instead.  We use sync_cycle_ctr to tell old entries apart from new
	 * ones: new ones will have cycle_ctr equal to the incremented value of
	 * sync_cycle_ctr.
	 *
	 * In normal circumstances, all entries present in the table at this point
	 * will have cycle_ctr exactly equal to the current (about to be old)
	 * value of sync_cycle_ctr.  However, if we fail partway through the
	 * fsync'ing loop, then older values of cycle_ctr might remain when we
	 * come back here to try again.  Repeated checkpoint failures would
	 * eventually wrap the counter around to the point where an old entry
	 * might appear new, causing us to skip it, possibly allowing a checkpoint
	 * to succeed that should not have.  To forestall wraparound, any time the
	 * previous smgrsync() failed to complete, run through the table and
	 * forcibly set cycle_ctr = sync_cycle_ctr.
	 *
	 * Think not to merge this loop with the main loop, as the problem is
	 * exactly that that loop may fail before having visited all the entries.
	 * From a performance point of view it doesn't matter anyway, as this path
	 * will never be taken in a system that's functioning normally.
	 */
	if (sync_in_progress)
	{
		/* prior try failed, so update any stale cycle_ctr values */
		hash_seq_init(&hstat, pendingFsyncTable);
		while ((entry = (PendingFsyncEntry *) hash_seq_search(&hstat)) != NULL)
		{
			ForkNumber		forknum;

			entry->cycle_ctr = sync_cycle_ctr;

			/*
			 * If any requests remain unprocessed, they need to be merged with
			 * the segment numbers that have arrived since.
			 */
			for (forknum = 0; forknum <= MAX_FORKNUM; forknum++)
			{
				segnum_vector *requests = &entry->requests[forknum];
				segnum_vector *requests_in_progress =
					&entry->requests_in_progress[forknum];

				if (!segnum_vector_empty(requests_in_progress))
				{
					/* Append the unfinished requests that were not yet handled. */
					segnum_vector_append_n(requests,
										   segnum_vector_data(requests_in_progress),
										   segnum_vector_size(requests_in_progress));
					segnum_vector_reset(requests_in_progress);

					/* Sort and make unique. */
					segnum_array_sort(segnum_vector_begin(requests),
									  segnum_vector_end(requests));
					segnum_vector_resize(requests,
									 segnum_array_unique(segnum_vector_begin(requests),
														 segnum_vector_end(requests)) -
										 segnum_vector_begin(requests));
				}
			}
		}
	}

	/* Advance counter so that new hashtable entries are distinguishable */
	sync_cycle_ctr++;

	/* Set flag to detect failure if we don't reach the end of the loop */
	sync_in_progress = true;

	/* Now scan the hashtable for fsync requests to process */
	absorb_counter = FSYNCS_PER_ABSORB;
	hash_seq_init(&hstat, pendingFsyncTable);
	while ((entry = (PendingFsyncEntry *) hash_seq_search(&hstat)))
	{
		ForkNumber forknum;
		SMgrRelation reln;

		/*
		 * If the entry is new then don't process it this time; it might
		 * contain multiple fsync requests, but they are all new.  Note
		 * "continue" bypasses the hash-remove call at the bottom of the loop.
		 */
		if (entry->cycle_ctr == sync_cycle_ctr)
			continue;

		/* Else assert we haven't missed it */
		Assert((CycleCtr) (entry->cycle_ctr + 1) == sync_cycle_ctr);

		/*
		 * Scan over the forks and segments represented by the entry.
		 *
		 * The vector manipulations are slightly tricky, because we can call
		 * AbsorbFsyncRequests() inside the loop and that could result in new
		 * segment numbers being added.  So we swap the contents of "requests"
		 * with "requests_in_progress", and if we fail we'll merge it with any
		 * new requests that have arrived in the meantime.
		 */
		for (forknum = 0; forknum <= MAX_FORKNUM; forknum++)
		{
			segnum_vector *requests_in_progress =
				&entry->requests_in_progress[forknum];

			/*
			 * Transfer the current set of segment numbers into the "in
			 * progress" vector (which must be empty initially).
			 */
			Assert(segnum_vector_empty(requests_in_progress));
			segnum_vector_swap(&entry->requests[forknum], requests_in_progress);

			/*
			 * If fsync is off then we don't have to bother opening the
			 * files at all.  (We delay checking until this point so that
			 * changing fsync on the fly behaves sensibly.)
			 */
			if (!enableFsync)
				segnum_vector_clear(requests_in_progress);

			/* Loop until all requests have been handled. */
			while (!segnum_vector_empty(requests_in_progress))
			{
				SegmentNumber	segno = *segnum_vector_back(requests_in_progress);

				INSTR_TIME_SET_CURRENT(sync_start);

				reln = smgropen(entry->rnode, InvalidBackendId);
				if (!smgrimmedsync(reln, forknum, segno))
				{
					/*
					 * The underlying file couldn't be found.  Check if a
					 * later message in the queue reports that it has been
					 * unlinked; if so it will be removed from the vector,
					 * indicating that we can safely skip it.
					 */
					AbsorbFsyncRequests();
					if (!segnum_array_binary_search(segnum_vector_begin(requests_in_progress),
													segnum_vector_end(requests_in_progress),
													&segno))
						continue;

					/* Otherwise it's an unexpectedly missing file. */
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not open backing file to fsync: %u/%u/%u",
									entry->rnode.dbNode,
									entry->rnode.relNode,
									segno)));
				}

				/* Success; update statistics about sync timing */
				INSTR_TIME_SET_CURRENT(sync_end);
				sync_diff = sync_end;
				INSTR_TIME_SUBTRACT(sync_diff, sync_start);
				elapsed = INSTR_TIME_GET_MICROSEC(sync_diff);
				if (elapsed > longest)
					longest = elapsed;
				total_elapsed += elapsed;
				processed++;

				/* Remove this segment number. */
				Assert(segno == *segnum_vector_back(requests_in_progress));
				segnum_vector_pop_back(requests_in_progress);

				if (log_checkpoints)
					ereport(DEBUG1,
							(errmsg("checkpoint sync: number=%d db=%u rel=%u seg=%u time=%.3f msec",
									processed,
									entry->rnode.dbNode,
									entry->rnode.relNode,
									segno,
									(double) elapsed / 1000),
							 errhidestmt(true),
							 errhidecontext(true)));

				/*
				 * If in checkpointer, we want to absorb pending requests
				 * every so often to prevent overflow of the fsync request
				 * queue.  It is unspecified whether newly-added entries will
				 * be visited by hash_seq_search, but we don't care since we
				 * don't need to process them anyway.
				 */
				if (--absorb_counter <= 0)
				{
					AbsorbFsyncRequests();
					absorb_counter = FSYNCS_PER_ABSORB;
				}
			}
		}

		/*
		 * We've finished everything that was requested before we started to
		 * scan the entry.  If no new requests have been inserted meanwhile,
		 * remove the entry.  Otherwise, update its cycle counter, as all the
		 * requests now in it must have arrived during this cycle.
		 */
		for (forknum = 0; forknum <= MAX_FORKNUM; forknum++)
		{
			Assert(segnum_vector_empty(&entry->requests_in_progress[forknum]));
			if (!segnum_vector_empty(&entry->requests[forknum]))
				break;
			segnum_vector_reset(&entry->requests[forknum]);
		}
		if (forknum <= MAX_FORKNUM)
			entry->cycle_ctr = sync_cycle_ctr;
		else
		{
			/* Okay to remove it */
			if (hash_search(pendingFsyncTable, &entry->rnode,
							HASH_REMOVE, NULL) == NULL)
				elog(ERROR, "pendingOpsTable corrupted");
		}
	}							/* end loop over hashtable entries */

	/* Maintain sync performance metrics for report at checkpoint end */
	CheckpointStats.ckpt_sync_rels = processed;
	CheckpointStats.ckpt_longest_sync = longest;
	CheckpointStats.ckpt_agg_sync_time = total_elapsed;

	/* Flag successful completion of smgrsync */
	sync_in_progress = false;
}

/*
 * Do post-checkpoint work.
 *
 * Remove any lingering files that can now be safely removed.
 */
void
smgrpostckpt(void)
{
	int			absorb_counter;

	absorb_counter = UNLINKS_PER_ABSORB;
	while (pendingUnlinks != NIL)
	{
		PendingUnlinkEntry *entry = (PendingUnlinkEntry *) linitial(pendingUnlinks);
		char	   *path;

		/*
		 * New entries are appended to the end, so if the entry is new we've
		 * reached the end of old entries.
		 *
		 * Note: if just the right number of consecutive checkpoints fail, we
		 * could be fooled here by cycle_ctr wraparound.  However, the only
		 * consequence is that we'd delay unlinking for one more checkpoint,
		 * which is perfectly tolerable.
		 */
		if (entry->cycle_ctr == ckpt_cycle_ctr)
			break;

		/* Unlink the file */
		path = relpathperm(entry->rnode, MAIN_FORKNUM);
		if (unlink(path) < 0)
		{
			/*
			 * There's a race condition, when the database is dropped at the
			 * same time that we process the pending unlink requests. If the
			 * DROP DATABASE deletes the file before we do, we will get ENOENT
			 * here. rmtree() also has to ignore ENOENT errors, to deal with
			 * the possibility that we delete the file first.
			 */
			if (errno != ENOENT)
				ereport(WARNING,
						(errcode_for_file_access(),
						 errmsg("could not remove file \"%s\": %m", path)));
		}
		pfree(path);

		/* And remove the list entry */
		pendingUnlinks = list_delete_first(pendingUnlinks);
		pfree(entry);

		/*
		 * As in smgrsync, we don't want to stop absorbing fsync requests for a
		 * long time when there are many deletions to be done.  We can safely
		 * call AbsorbFsyncRequests() at this point in the loop (note it might
		 * try to delete list entries).
		 */
		if (--absorb_counter <= 0)
		{
			AbsorbFsyncRequests();
			absorb_counter = UNLINKS_PER_ABSORB;
		}
	}
}


/*
 * Mark a file as needing fsync.
 *
 * If there is a local pending-ops table, just make an entry in it for
 * smgrsync to process later.  Otherwise, try to pass off the fsync request to
 * the checkpointer process.
 *
 * Returns true on success, but false if the queue was full and we couldn't
 * pass the request to the the checkpointer, meaning that the caller must
 * perform the fsync.
 */
bool
FsyncAtCheckpoint(RelFileNode rnode, ForkNumber forknum, SegmentNumber segno)
{
	if (pendingFsyncTable)
	{
		RememberFsyncRequest(FSYNC_SEGMENT_REQUEST, rnode, forknum, segno);
		return true;
	}
	else
		return ForwardFsyncRequest(FSYNC_SEGMENT_REQUEST, rnode, forknum,
								   segno);
}

/*
 * Schedule a file to be deleted after next checkpoint.
 *
 * As with FsyncAtCheckpoint, this could involve either a local or a remote
 * pending-ops table.
 */
void
UnlinkAfterCheckpoint(RelFileNodeBackend rnode)
{
	/* Should never be used with temp relations */
	Assert(!RelFileNodeBackendIsTemp(rnode));

	if (pendingFsyncTable)
	{
		/* push it into local pending-ops table */
		RememberFsyncRequest(UNLINK_RELATION_REQUEST,
							 rnode.node,
							 MAIN_FORKNUM,
							 InvalidSegmentNumber);
	}
	else
	{
		/* Notify the checkpointer about it. */
		Assert(IsUnderPostmaster);

		ForwardFsyncRequest(UNLINK_RELATION_REQUEST,
							rnode.node,
							MAIN_FORKNUM,
							InvalidSegmentNumber);
	}
}

/*
 * In archive recovery, we rely on checkpointer to do fsyncs, but we will have
 * already created the pendingFsyncTable during initialization of the startup
 * process.  Calling this function drops the local pendingFsyncTable so that
 * subsequent requests will be forwarded to checkpointer.
 */
void
SetForwardFsyncRequests(void)
{
	/* Perform any pending fsyncs we may have queued up, then drop table */
	if (pendingFsyncTable)
	{
		smgrsync();
		hash_destroy(pendingFsyncTable);
	}
	pendingFsyncTable = NULL;

	/*
	 * We should not have any pending unlink requests, since mdunlink doesn't
	 * queue unlink requests when isRedo.
	 */
	Assert(pendingUnlinks == NIL);
}

/*
 * Find and remove a segment number by binary search.
 */
static inline void
delete_segno(segnum_vector *vec, SegmentNumber segno)
{
	SegmentNumber *position =
		segnum_array_lower_bound(segnum_vector_begin(vec),
								 segnum_vector_end(vec),
								 &segno);

	if (position != segnum_vector_end(vec) &&
		*position == segno)
		segnum_vector_erase(vec, position);
}

/*
 * Add a segment number by binary search.  Hopefully these tend to be added a
 * the high end, which is cheap.
 */
static inline void
insert_segno(segnum_vector *vec, SegmentNumber segno)
{
	segnum_vector_insert(vec,
						 segnum_array_lower_bound(segnum_vector_begin(vec),
												  segnum_vector_end(vec),
												  &segno),
						 &segno);
}

/*
 * RememberFsyncRequest() -- callback from checkpointer side of fsync request
 *
 * We stuff fsync requests into the local hash table for execution
 * during the checkpointer's next checkpoint.  UNLINK requests go into a
 * separate linked list, however, because they get processed separately.
 *
 * Valid valid values for 'type':
 * - FSYNC_SEGMENT_REQUEST means to schedule an fsync
 * - FORGET_SEGMENT_FSYNC means to cancel pending fsyncs for one segment
 * - FORGET_RELATION_FSYNC means to cancel pending fsyncs for a relation,
 *	 either for one fork, or all forks if forknum is InvalidForkNumber
 * - FORGET_DATABASE_FSYNC means to cancel pending fsyncs for a whole database
 * - UNLINK_RELATION_REQUEST is a request to delete the file after the next
 *	 checkpoint.
 * Note also that we're assuming real segment numbers don't exceed INT_MAX.
 *
 * (Handling FORGET_DATABASE_FSYNC requests is a tad slow because the hash
 * table has to be searched linearly, but dropping a database is a pretty
 * heavyweight operation anyhow, so we'll live with it.)
 */
void
RememberFsyncRequest(int type, RelFileNode rnode, ForkNumber forknum,
					 SegmentNumber segno)
{
	Assert(pendingFsyncTable);

	if (type == FORGET_SEGMENT_FSYNC || type == FORGET_RELATION_FSYNC)
	{
		PendingFsyncEntry *entry;

		entry = hash_search(pendingFsyncTable, &rnode, HASH_FIND, NULL);
		if (entry)
		{
			if (type == FORGET_SEGMENT_FSYNC)
			{
				delete_segno(&entry->requests[forknum], segno);
				delete_segno(&entry->requests_in_progress[forknum], segno);
			}
			else if (forknum == InvalidForkNumber)
			{
				/* Remove requests for all forks. */
				for (forknum = 0; forknum <= MAX_FORKNUM; forknum++)
				{
					segnum_vector_reset(&entry->requests[forknum]);
					segnum_vector_reset(&entry->requests_in_progress[forknum]);
				}
			}
			else
			{
				/* Forget about all segments for one fork. */
				segnum_vector_reset(&entry->requests[forknum]);
				segnum_vector_reset(&entry->requests_in_progress[forknum]);
			}
		}
	}
	else if (type == FORGET_DATABASE_FSYNC)
	{
		HASH_SEQ_STATUS hstat;
		PendingFsyncEntry *entry;

		/* Remove fsync requests */
		hash_seq_init(&hstat, pendingFsyncTable);
		while ((entry = (PendingFsyncEntry *) hash_seq_search(&hstat)) != NULL)
		{
			if (rnode.dbNode == entry->rnode.dbNode)
			{
				/* Remove requests for all forks. */
				for (forknum = 0; forknum <= MAX_FORKNUM; forknum++)
				{
					segnum_vector_reset(&entry->requests[forknum]);
					segnum_vector_reset(&entry->requests_in_progress[forknum]);
				}
			}
		}

		/* Remove unlink requests */
		if (segno == FORGET_DATABASE_FSYNC)
		{
			ListCell   *cell,
					   *next,
					   *prev;

			prev = NULL;
			for (cell = list_head(pendingUnlinks); cell; cell = next)
			{
				PendingUnlinkEntry *entry = (PendingUnlinkEntry *) lfirst(cell);

				next = lnext(cell);
				if (rnode.dbNode == entry->rnode.dbNode)
				{
					pendingUnlinks = list_delete_cell(pendingUnlinks, cell,
													  prev);
					pfree(entry);
				}
				else
					prev = cell;
			}
		}
	}
	else if (type == UNLINK_RELATION_REQUEST)
	{
		/* Unlink request: put it in the linked list */
		MemoryContext oldcxt = MemoryContextSwitchTo(pendingOpsCxt);
		PendingUnlinkEntry *entry;

		/* PendingUnlinkEntry doesn't store forknum, since it's always MAIN */
		Assert(forknum == MAIN_FORKNUM);

		entry = palloc(sizeof(PendingUnlinkEntry));
		entry->rnode = rnode;
		entry->cycle_ctr = ckpt_cycle_ctr;

		pendingUnlinks = lappend(pendingUnlinks, entry);

		MemoryContextSwitchTo(oldcxt);
	}
	else if (type == FSYNC_SEGMENT_REQUEST)
	{
		/* Normal case: enter a request to fsync this segment */
		PendingFsyncEntry *entry;
		bool		found;

		entry = (PendingFsyncEntry *) hash_search(pendingFsyncTable,
												  &rnode,
												  HASH_ENTER,
												  &found);
		/* if new entry, initialize it */
		if (!found)
		{
			ForkNumber	f;

			entry->cycle_ctr = ckpt_cycle_ctr;
			for (f = 0; f <= MAX_FORKNUM; f++)
			{
				segnum_vector_init(&entry->requests[f]);
				segnum_vector_init(&entry->requests_in_progress[f]);
			}
		}

		/*
		 * NB: it's intentional that we don't change cycle_ctr if the entry
		 * already exists.  The cycle_ctr must represent the oldest fsync
		 * request that could be in the entry.
		 */

		insert_segno(&entry->requests[forknum], segno);
	}
}

/*
 * ForgetSegmentFsyncRequests -- forget any fsyncs for one segment of a
 * relation fork
 *
 * forknum == InvalidForkNumber means all forks, although this code doesn't
 * actually know that, since it's just forwarding the request elsewhere.
 */
void
ForgetSegmentFsyncRequests(RelFileNode rnode, ForkNumber forknum,
						   SegmentNumber segno)
{
	if (pendingFsyncTable)
	{
		/* standalone backend or startup process: fsync state is local */
		RememberFsyncRequest(FORGET_SEGMENT_FSYNC, rnode, forknum, segno);
	}
	else if (IsUnderPostmaster)
	{
		/* Notify the checkpointer about it. */
		while (!ForwardFsyncRequest(FORGET_SEGMENT_FSYNC, rnode, forknum,
									segno))
			pg_usleep(10000L);	/* 10 msec seems a good number */

		/*
		 * Note we don't wait for the checkpointer to actually absorb the
		 * cancel message; see smgrsync() for the implications.
		 */
	}
}

/*
 * ForgetRelationFsyncRequests -- forget any fsyncs for a relation fork
 *
 * forknum == InvalidForkNumber means all forks, although this code doesn't
 * actually know that, since it's just forwarding the request elsewhere.
 */
void
ForgetRelationFsyncRequests(RelFileNode rnode, ForkNumber forknum)
{
	if (pendingFsyncTable)
	{
		/* standalone backend or startup process: fsync state is local */
		RememberFsyncRequest(FORGET_RELATION_FSYNC, rnode, forknum,
							 InvalidSegmentNumber);
	}
	else if (IsUnderPostmaster)
	{
		/* Notify the checkpointer about it. */
		while (!ForwardFsyncRequest(FORGET_RELATION_FSYNC, rnode, forknum,
									InvalidSegmentNumber))
			pg_usleep(10000L);	/* 10 msec seems a good number */

		/*
		 * Note we don't wait for the checkpointer to actually absorb the
		 * cancel message; see smgrsync() for the implications.
		 */
	}
}

/*
 * ForgetDatabaseFsyncRequests -- forget any fsyncs and unlinks for a DB
 */
void
ForgetDatabaseFsyncRequests(Oid dbid)
{
	RelFileNode rnode;

	rnode.dbNode = dbid;
	rnode.spcNode = 0;
	rnode.relNode = 0;

	if (pendingFsyncTable)
	{
		/* standalone backend or startup process: fsync state is local */
		RememberFsyncRequest(FORGET_DATABASE_FSYNC, rnode, 0,
							 InvalidSegmentNumber);
	}
	else if (IsUnderPostmaster)
	{
		/* see notes in ForgetRelationFsyncRequests */
		while (!ForwardFsyncRequest(FORGET_DATABASE_FSYNC, rnode, 0,
									InvalidSegmentNumber))
			pg_usleep(10000L);	/* 10 msec seems a good number */
	}
}
