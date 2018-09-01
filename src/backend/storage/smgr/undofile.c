/*
 * undofile.h
 *
 * PostgreSQL undo file manager.  This module provides SMGR-compatible
 * interface to the files that back undo logs on the filesystem, so that undo
 * log data can use the shared buffer pool.  Other aspects of undo log
 * management are provided by undolog.c, so the SMGR interfaces not directly
 * concerned with reading, writing and flushing data are unimplemented.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/storage/smgr/undofile.c
 */

#include "postgres.h"

#include "access/undolog.h"
#include "access/xlog.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgwriter.h"
#include "storage/fd.h"
#include "storage/undofile.h"
#include "utils/memutils.h"

/* intervals for calling AbsorbFsyncRequests in undofile_sync */
#define FSYNCS_PER_ABSORB		10

/*
 * Special values for the fork arg to undofile_requestsync.
 */
#define FORGET_UNDO_SEGMENT_FSYNC	(InvalidBlockNumber)

/*
 * While md.c expects random access and has a small number of huge
 * segments, undofile.c manages a potentially very large number of smaller
 * segments and has a less random access pattern.  Therefore, instead of
 * keeping a potentially huge array of vfds we'll just keep the most
 * recently accessed N.
 *
 * For now, N == 1, so we just need to hold onto one 'File' handle.
 */
typedef struct UndoFileState
{
	int		mru_segno;
	File	mru_file;
} UndoFileState;

static MemoryContext UndoFileCxt;

typedef uint16 CycleCtr;

/*
 * An entry recording the segments that need to be fsynced by undofile_sync().
 * This is a bit simpler than md.c's version, though it could perhaps be
 * merged into a common struct.  One difference is that we can have much
 * larger segment numbers, so we'll adjust for that to avoid having a lot of
 * leading zero bits.
 */
typedef struct
{
	RelFileNode rnode;
	Bitmapset  *requests;
	CycleCtr	cycle_ctr;
} PendingOperationEntry;

static HTAB *pendingOpsTable = NULL;
static MemoryContext pendingOpsCxt;

static CycleCtr undofile_sync_cycle_ctr = 0;

static File undofile_open_segment_file(Oid relNode, Oid spcNode, int segno,
									   bool missing_ok);
static File undofile_get_segment_file(SMgrRelation reln, int segno);

void
undofile_init(void)
{
	UndoFileCxt = AllocSetContextCreate(TopMemoryContext,
										"UndoFileSmgr",
										ALLOCSET_DEFAULT_SIZES);

	if (!IsUnderPostmaster || AmStartupProcess() || AmCheckpointerProcess())
	{
		HASHCTL		hash_ctl;

		pendingOpsCxt = AllocSetContextCreate(UndoFileCxt,
											  "Pending ops context",
											  ALLOCSET_DEFAULT_SIZES);
		MemoryContextAllowInCriticalSection(pendingOpsCxt, true);

		MemSet(&hash_ctl, 0, sizeof(hash_ctl));
		hash_ctl.keysize = sizeof(RelFileNode);
		hash_ctl.entrysize = sizeof(PendingOperationEntry);
		hash_ctl.hcxt = pendingOpsCxt;
		pendingOpsTable = hash_create("Pending Ops Table",
									  100L,
									  &hash_ctl,
									  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	}
}

void
undofile_shutdown(void)
{
}

void
undofile_close(SMgrRelation reln, ForkNumber forknum)
{
}

void
undofile_create(SMgrRelation reln, ForkNumber forknum, bool isRedo)
{
	elog(ERROR, "undofile_create is not supported");
}

bool
undofile_exists(SMgrRelation reln, ForkNumber forknum)
{
	elog(ERROR, "undofile_exists is not supported");
}

void
undofile_unlink(RelFileNodeBackend rnode, ForkNumber forknum, bool isRedo)
{
	elog(ERROR, "undofile_unlink is not supported");
}

void
undofile_extend(SMgrRelation reln, ForkNumber forknum,
				BlockNumber blocknum, char *buffer,
				bool skipFsync)
{
	elog(ERROR, "undofile_extend is not supported");
}

void
undofile_prefetch(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum)
{
	elog(ERROR, "undofile_prefetch is not supported");
}

void
undofile_read(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
			  char *buffer)
{
	File		file;
	off_t		seekpos;
	int			nbytes;

	Assert(forknum == MAIN_FORKNUM);
	file = undofile_get_segment_file(reln, blocknum / UNDOSEG_SIZE);
	seekpos = (off_t) BLCKSZ * (blocknum % ((BlockNumber) UNDOSEG_SIZE));
	Assert(seekpos < (off_t) BLCKSZ * UNDOSEG_SIZE);
	if (FileSeek(file, seekpos, SEEK_SET) != seekpos)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not seek to block %u in file \"%s\": %m",
						blocknum, FilePathName(file))));
	nbytes = FileRead(file, buffer, BLCKSZ, WAIT_EVENT_UNDO_FILE_READ);
	if (nbytes != BLCKSZ)
	{
		if (nbytes < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not read block %u in file \"%s\": %m",
							blocknum, FilePathName(file))));
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("could not read block %u in file \"%s\": read only %d of %d bytes",
						blocknum, FilePathName(file),
						nbytes, BLCKSZ)));
	}
}

static void
register_dirty_segment(SMgrRelation reln, ForkNumber forknum, int segno, File file)
{
	/* Temp relations should never be fsync'd */
	Assert(!SmgrIsTemp(reln));

	if (pendingOpsTable)
	{
		/* push it into local pending-ops table */
		undofile_requestsync(reln->smgr_rnode.node, forknum, segno);
	}
	else
	{
		if (ForwardFsyncRequest(reln->smgr_rnode.node, forknum, segno))
			return;				/* passed it off successfully */

		ereport(DEBUG1,
				(errmsg("could not forward fsync request because request queue is full")));

		if (FileSync(file, WAIT_EVENT_DATA_FILE_SYNC) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not fsync file \"%s\": %m",
							FilePathName(file))));
	}
}

void
undofile_write(SMgrRelation reln, ForkNumber forknum,
			   BlockNumber blocknum, char *buffer,
			   bool skipFsync)
{
	File		file;
	off_t		seekpos;
	int			nbytes;

	Assert(forknum == MAIN_FORKNUM);
	file = undofile_get_segment_file(reln, blocknum / UNDOSEG_SIZE);
	seekpos = (off_t) BLCKSZ * (blocknum % ((BlockNumber) UNDOSEG_SIZE));
	Assert(seekpos < (off_t) BLCKSZ * UNDOSEG_SIZE);
	if (FileSeek(file, seekpos, SEEK_SET) != seekpos)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not seek to block %u in file \"%s\": %m",
						blocknum, FilePathName(file))));
	nbytes = FileWrite(file, buffer, BLCKSZ, WAIT_EVENT_UNDO_FILE_WRITE);
	if (nbytes != BLCKSZ)
	{
		if (nbytes < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write block %u in file \"%s\": %m",
							blocknum, FilePathName(file))));
		/*
		 * short write: unexpected, because this should be overwriting an
		 * entirely pre-allocated segment file
		 */
		ereport(ERROR,
				(errcode(ERRCODE_DISK_FULL),
				 errmsg("could not write block %u in file \"%s\": wrote only %d of %d bytes",
						blocknum, FilePathName(file),
						nbytes, BLCKSZ)));
	}

	if (!skipFsync && !SmgrIsTemp(reln))
		register_dirty_segment(reln, forknum, blocknum / UNDOSEG_SIZE, file);
}

void
undofile_writeback(SMgrRelation reln, ForkNumber forknum,
				   BlockNumber blocknum, BlockNumber nblocks)
{
	while (nblocks > 0)
	{
		File	file;
		int		nflush;

		file = undofile_get_segment_file(reln, blocknum / UNDOSEG_SIZE);

		/* compute number of desired writes within the current segment */
		nflush = Min(nblocks,
					 1 + UNDOSEG_SIZE - (blocknum % UNDOSEG_SIZE));

		FileWriteback(file,
					  (blocknum % UNDOSEG_SIZE) * BLCKSZ,
					  nflush * BLCKSZ, WAIT_EVENT_UNDO_FILE_FLUSH);

		nblocks -= nflush;
		blocknum += nflush;
	}
}

BlockNumber
undofile_nblocks(SMgrRelation reln, ForkNumber forknum)
{
	elog(ERROR, "undofile_nblocks is not supported");
	return 0;
}

void
undofile_truncate(SMgrRelation reln, ForkNumber forknum, BlockNumber nblocks)
{
	elog(ERROR, "undofile_truncate is not supported");
}

void
undofile_immedsync(SMgrRelation reln, ForkNumber forknum)
{
	elog(ERROR, "undofile_immedsync is not supported");
}

void
undofile_preckpt(void)
{
}

void
undofile_requestsync(RelFileNode rnode, ForkNumber forknum, int segno)
{
	MemoryContext oldcxt = MemoryContextSwitchTo(pendingOpsCxt);
	PendingOperationEntry *entry;
	bool		found;

	Assert(pendingOpsTable);

	if (forknum == FORGET_UNDO_SEGMENT_FSYNC)
	{
		entry = (PendingOperationEntry *) hash_search(pendingOpsTable,
													  &rnode,
													  HASH_FIND,
													  NULL);
		if (entry)
			entry->requests = bms_del_member(entry->requests, segno);
	}
	else
	{
		entry = (PendingOperationEntry *) hash_search(pendingOpsTable,
													  &rnode,
													  HASH_ENTER,
													  &found);
		if (!found)
		{
			entry->cycle_ctr = undofile_sync_cycle_ctr;
			entry->requests = bms_make_singleton(segno);
		}
		else
			entry->requests = bms_add_member(entry->requests, segno);
	}

	MemoryContextSwitchTo(oldcxt);
}

void
undofile_forgetsync(Oid logno, Oid tablespace, int segno)
{
	RelFileNode rnode;

	rnode.dbNode = 9;
	rnode.spcNode = tablespace;
	rnode.relNode = logno;

	if (pendingOpsTable)
		undofile_requestsync(rnode, FORGET_UNDO_SEGMENT_FSYNC, segno);
	else if (IsUnderPostmaster)
	{
		while (!ForwardFsyncRequest(rnode, FORGET_UNDO_SEGMENT_FSYNC, segno))
			pg_usleep(10000L);
	}
}

void
undofile_sync(void)
{
	static bool undofile_sync_in_progress = false;

	HASH_SEQ_STATUS hstat;
	PendingOperationEntry *entry;
	int			absorb_counter;
	int			segno;

	if (!pendingOpsTable)
		elog(ERROR, "cannot sync without a pendingOpsTable");

	AbsorbFsyncRequests();

	if (undofile_sync_in_progress)
	{
		/* prior try failed, so update any stale cycle_ctr values */
		hash_seq_init(&hstat, pendingOpsTable);
		while ((entry = (PendingOperationEntry *) hash_seq_search(&hstat)) != NULL)
			entry->cycle_ctr = undofile_sync_cycle_ctr;
	}

	undofile_sync_cycle_ctr++;
	undofile_sync_in_progress = true;

	absorb_counter = FSYNCS_PER_ABSORB;
	hash_seq_init(&hstat, pendingOpsTable);
	while ((entry = (PendingOperationEntry *) hash_seq_search(&hstat)) != NULL)
	{
		Bitmapset	   *requests;

		/* Skip entries that arrived after we arrived. */
		if (entry->cycle_ctr == undofile_sync_cycle_ctr)
			continue;

		Assert((CycleCtr) (entry->cycle_ctr + 1) == undofile_sync_cycle_ctr);

		if (!enableFsync)
			continue;

		requests = entry->requests;
		entry->requests = NULL;

		segno = -1;
		while ((segno = bms_next_member(requests, segno)) >= 0)
		{
			File		file;

			if (!enableFsync)
				continue;

			file = undofile_open_segment_file(entry->rnode.relNode,
											  entry->rnode.spcNode,
											  segno, true /* missing_ok */);

			/*
			 * The file may be gone due to concurrent discard.  We'll ignore
			 * that, but only if we find a cancel request for this segment in
			 * the queue.
			 *
			 * It's also possible that we succeed in opening a segment file
			 * that is subsequently recycled (renamed to represent a new range
			 * of undo log), in which case we'll fsync that later file
			 * instead.  That is rare and harmless.
			 */
			if (file <= 0)
			{
				char		name[MAXPGPATH];

				/*
				 * Put the request back into the bitset in a way that can't
				 * fail due to memory allocation.
				 */
				entry->requests = bms_join(entry->requests, requests);
				/*
				 * Check if a forgetsync request has arrived to delete that
				 * segment.
				 */
				AbsorbFsyncRequests();
				if (bms_is_member(segno, entry->requests))
				{
					UndoLogSegmentPath(entry->rnode.relNode,
									   segno,
									   entry->rnode.spcNode,
									   name);
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not fsync file \"%s\": %m", name)));
				}
				/* It must have been removed, so we can safely skip it. */
				continue;
			}

			elog(LOG, "fsync()ing %s", FilePathName(file));	/* TODO: remove me */
			if (FileSync(file, WAIT_EVENT_UNDO_FILE_SYNC) < 0)
			{
				char		name[MAXPGPATH];

				strcpy(name, FilePathName(file));
				FileClose(file);

				/*
				 * Keep the failed requests, but merge with any new ones.  The
				 * requirement to be able to do this without risk of failure
				 * prevents us from using a smaller bitmap that doesn't bother
				 * tracking leading zeros.  Perhaps another data structure
				 * would be better.
				 */
				entry->requests = bms_join(entry->requests, requests);
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not fsync file \"%s\": %m", name)));
			}
			requests = bms_del_member(requests, segno);
			FileClose(file);

			if (--absorb_counter <= 0)
			{
				AbsorbFsyncRequests();
				absorb_counter = FSYNCS_PER_ABSORB;
			}
		}

		bms_free(requests);
	}

	undofile_sync_in_progress = true;
}

void undofile_postckpt(void)
{
}

static File undofile_open_segment_file(Oid relNode, Oid spcNode, int segno,
									   bool missing_ok)
{
	File		file;
	char		path[MAXPGPATH];

	UndoLogSegmentPath(relNode, segno, spcNode, path);
	file = PathNameOpenFile(path, O_RDWR | PG_BINARY);

	if (file <= 0 && (!missing_ok || errno != ENOENT))
		elog(ERROR, "cannot open undo segment file '%s': %m", path);

	return file;
}

/*
 * Get a File for a particular segment of a SMgrRelation representing an undo
 * log.
 */
static File undofile_get_segment_file(SMgrRelation reln, int segno)
{
	UndoFileState *state;


	/*
	 * Create private state space on demand.
	 *
	 * XXX There should probably be a smgr 'open' or 'init' interface that
	 * would do this.  smgr.c currently initializes reln->md_XXX stuff
	 * directly...
	 */
	state = (UndoFileState *) reln->private_data;
	if (unlikely(state == NULL))
	{
		state = MemoryContextAllocZero(UndoFileCxt, sizeof(UndoFileState));
		reln->private_data = state;
	}

	/* If we have a file open already, check if we need to close it. */
	if (state->mru_file > 0 && state->mru_segno != segno)
	{
		/* These are not the blocks we're looking for. */
		FileClose(state->mru_file);
		state->mru_file = 0;
	}

	/* Check if we need to open a new file. */
	if (state->mru_file <= 0)
	{
		state->mru_file =
			undofile_open_segment_file(reln->smgr_rnode.node.relNode,
									   reln->smgr_rnode.node.spcNode,
									   segno, InRecovery);
		if (InRecovery && state->mru_file <= 0)
		{
			/*
			 * If in recovery, we may be trying to access a file that will
			 * later be unlinked.  Tolerate missing files, creating a new
			 * zero-filled file as required.
			 */
			UndoLogNewSegment(reln->smgr_rnode.node.relNode,
							  reln->smgr_rnode.node.spcNode,
							  segno);
			state->mru_file =
				undofile_open_segment_file(reln->smgr_rnode.node.relNode,
										   reln->smgr_rnode.node.spcNode,
										   segno, false);
			Assert(state->mru_file > 0);
		}
		state->mru_segno = segno;
	}

	return state->mru_file;
}
