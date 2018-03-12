/*
 * undofile.h
 *
 * PostgreSQL undo file manager.  This module provides SMGR-compatible
 * interface to the files that back undo logs on the filesystem, so that undo
 * log data can use the shared buffer pool.  Other aspects of undo log
 * management are provided by undolog.c, so the SMGR interfaces not directly
 * concerned with reading, writing and flushing data are unimplemented.
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/storage/smgr/undofile.c
 */

#include "postgres.h"

#include "access/undolog.h"
#include "pgstat.h"
#include "storage/fd.h"
#include "storage/undofile.h"
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

static File undofile_open_segment_file(Oid relNode, Oid spcNode, int segno);
static File undofile_get_segment_file(SMgrRelation reln, int segno);

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
	nbytes = FileRead(file, buffer, BLCKSZ, seekpos, WAIT_EVENT_UNDO_FILE_READ);
	if (nbytes != BLCKSZ)
	{
		if (nbytes < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not read block %u in file \"%s\": %m",
							blocknum, FilePathName(file))));
		/* TODO think about whether we have to tolerate short reads like mdread */
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("could not read block %u in file \"%s\": read only %d of %d bytes",
						blocknum, FilePathName(file),
						nbytes, BLCKSZ)));
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

	/* TODO: Mark this segment dirty in shared memory, so we sync it. */
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

		/* TODO handle case where segment doesn't exist? */
		Assert(file > 0);

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
	/*
	 * XXX This will probably be needed for copying zheap tables, in code
	 * paths that don't go through shared buffers?
	 */
	elog(ERROR, "undofile_immedsync is not yet implemented");
}

void undofile_preckpt(void)
{
}

void undofile_sync(void)
{
	UndoLogControl *log = NULL;

	/*
	 * XXX For now we just track the range of segments in each undo log that
	 * could possibly be dirty.  This means that we always fsync at least the
	 * final segment of every active log.  We probably need something smarter,
	 * involving some IPC like md.c's queue machinery.
	 */

	/* TODO: this is being rewritten completely -- watch this space */

	while ((log = UndoLogNext(log)))
	{
		int		low_segno = 0,
				high_segno = 0,
				segno = 0;

		UndoLogGetDirtySegmentRange(log->logno, &low_segno, &high_segno);
		for (segno = low_segno; segno < high_segno; ++segno)
		{
			File		file;

			file = undofile_open_segment_file(log->logno, log->meta.tablespace, segno);

			/* The file may be gone due to concurrent discard. */
			if (file == 0)
				continue;

			/* Try to sync the file, making sure to close it either way. */
			if (FileSync(file, WAIT_EVENT_UNDO_FILE_SYNC) < 0)
			{
				FileClose(file);
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not fsync file \"%s\": %m",
								FilePathName(file))));
			}
			FileClose(file);

			/* Remember that we've fsync this far. */
			UndoLogSetHighestSyncedSegment(log->logno, segno);
		}
	}
}

void undofile_postckpt(void)
{
}

static File undofile_open_segment_file(Oid relNode, Oid spcNode, int segno)
{
	File		file;
	char		path[MAXPGPATH];

	UndoLogSegmentPath(relNode, segno, spcNode, path);
	file = PathNameOpenFile(path, O_RDWR | PG_BINARY);

	if (file <= 0)
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
	 * XXX SMgrRelationData has a couple of members for md.c-specific state.
	 * They should probably be replaced with a void private state pointer for
	 * use by any implementation to store whatever it wants.  For now, we'll
	 * just jam a square UndoFileState pointer into the round md_seg_fds[0].
	 * Not beautiful.  To be fixed later.
	 */
	state = (UndoFileState *) reln->md_seg_fds[0];

	/*
	 * Create private state space on demand.
	 *
	 * XXX There should probably be a smgr 'open' interface that would do
	 * this.  smgr.c currently initializes reln->md_XXX stuff directly but
	 * md.c should get a chance to do that!  And undofile.c should do
	 * similarly.
	 */
	if (unlikely(state == NULL))
	{
		state = MemoryContextAllocZero(UndoFileCxt, sizeof(UndoFileState));
		reln->md_seg_fds[0] = (struct _MdfdVec *) state;
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
									   segno);
		state->mru_segno = segno;
	}

	return state->mru_file;
}
