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
#include "storage/smgr.h"
#include "storage/smgrsync.h"
#include "utils/memutils.h"

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

static File undofile_open_segment_file(Oid relNode, Oid spcNode,
									   SegmentNumber segno, bool missing_ok);
static File undofile_get_segment_file(SMgrRelation reln, SegmentNumber segno);

void
undofile_init(void)
{
	UndoFileCxt = AllocSetContextCreate(TopMemoryContext,
										"UndoFileSmgr",
										ALLOCSET_DEFAULT_SIZES);
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
	/*
	 * File creation is managed by undolog.c, but xlogutils.c likes to call
	 * this just in case.  Ignore.
	 */
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
	nbytes = FileRead(file, buffer, BLCKSZ, seekpos, WAIT_EVENT_UNDO_FILE_READ);
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
register_dirty_segment(SMgrRelation reln, ForkNumber forknum, SegmentNumber segno,
					   File file)
{
	/* Temp relations should never be fsync'd */
	Assert(!SmgrIsTemp(reln));

	if (!FsyncAtCheckpoint(reln->smgr_rnode.node, forknum, segno))
	{
		ereport(DEBUG1,
				(errmsg("could not forward fsync request because request queue is full")));

		if (FileSync(file, WAIT_EVENT_DATA_FILE_SYNC) < 0)
			ereport(data_sync_elevel(ERROR),
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
	nbytes = FileWrite(file, buffer, BLCKSZ, seekpos, WAIT_EVENT_UNDO_FILE_WRITE);
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
	/*
	 * xlogutils.c likes to call this to decide whether to read or extend; for
	 * now we lie and say the relation is big as possible.
	 */
	return UndoLogMaxSize / BLCKSZ;
}

void
undofile_truncate(SMgrRelation reln, ForkNumber forknum, BlockNumber nblocks)
{
	elog(ERROR, "undofile_truncate is not supported");
}

bool
undofile_immedsync(SMgrRelation reln, ForkNumber forknum, SegmentNumber segno)
{
	File file = undofile_get_segment_file(reln, segno);

	if (file <= 0)
		return false;

	if (FileSync(file, WAIT_EVENT_UNDO_FILE_SYNC) < 0)
		ereport(data_sync_elevel(ERROR),
				(errcode_for_file_access(),
				 errmsg("could not fsync file \"%s\": %m",
						FilePathName(file))));

	return true;
}

static File undofile_open_segment_file(Oid relNode, Oid spcNode,
									   SegmentNumber segno, bool missing_ok)
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
static File undofile_get_segment_file(SMgrRelation reln, SegmentNumber segno)
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
