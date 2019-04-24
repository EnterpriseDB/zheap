/*
 * undofile.h
 *
 * PostgreSQL undo file manager.  This module provides SMGR-compatible
 * interface to the files that back undo logs on the filesystem, so that undo
 * log data can use the shared buffer pool.  Other aspects of undo log
 * management are provided by undolog.c, so the SMGR interfaces not directly
 * concerned with reading, writing and flushing data are unimplemented.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/storage/smgr/undofile.c
 */

#include "postgres.h"

#include "access/undolog.h"
#include "access/xlog.h"
#include "catalog/database_internal.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgwriter.h"
#include "storage/fd.h"
#include "storage/smgr.h"
#include "storage/undofile.h"
#include "utils/memutils.h"

/* Populate a file tag describing an undo segment file. */
#define INIT_UNDOFILETAG(a,xx_logno,xx_tbspc,xx_segno) \
( \
	memset(&(a), 0, sizeof(FileTag)), \
	(a).handler = SYNC_HANDLER_UNDO, \
	(a).rnode.dbNode = UndoDbOid, \
	(a).rnode.spcNode = (xx_tbspc), \
	(a).rnode.relNode = (xx_logno), \
	(a).segno = (xx_segno) \
)

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
									   BlockNumber segno, bool missing_ok);
static File undofile_get_segment_file(SMgrRelation reln, BlockNumber segno);

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
undofile_open(SMgrRelation reln)
{
	UndoFileState *state;

	state = MemoryContextAllocZero(UndoFileCxt, sizeof(UndoFileState));
	reln->private_data = state;
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

	return false;		/* not reached */
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
#ifdef USE_PREFETCH
	File		file;
	off_t		seekpos;

	Assert(forknum == MAIN_FORKNUM);
	file = undofile_get_segment_file(reln, blocknum / UNDOSEG_SIZE);
	seekpos = (off_t) BLCKSZ * (blocknum % ((BlockNumber) UNDOSEG_SIZE));

	Assert(seekpos < (off_t) BLCKSZ * UNDOSEG_SIZE);

	(void) FilePrefetch(file, seekpos, BLCKSZ, WAIT_EVENT_UNDO_FILE_PREFETCH);
#endif							/* USE_PREFETCH */
}

bool
undofile_read(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
			  char *buffer)
{
	File		file;
	off_t		seekpos;
	int			nbytes;

	Assert(forknum == MAIN_FORKNUM);

	/* Check if the block has been discarded. */
	if (UndoRecPtrIsDiscarded(MakeUndoRecPtr(reln->smgr_rnode.node.relNode,
											 BLCKSZ * (blocknum + 1))))
		return false;

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

	return true;
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

	/* Tell checkpointer this file is dirty. */
	if (!skipFsync && !SmgrIsTemp(reln))
	{
		undofile_request_sync(reln->smgr_rnode.node.relNode,
							  blocknum / UNDOSEG_SIZE,
							  reln->smgr_rnode.node.spcNode);
	}
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

void
undofile_immedsync(SMgrRelation reln, ForkNumber forknum)
{
	elog(ERROR, "undofile_immedsync is not supported");
}

static File undofile_open_segment_file(Oid relNode, Oid spcNode,
									   BlockNumber segno, bool missing_ok)
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
static File undofile_get_segment_file(SMgrRelation reln, BlockNumber segno)
{
	UndoFileState *state = (UndoFileState *) reln->private_data;

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

/*
 * Callback to handle a queued sync request.
 */
int
undofile_syncfiletag(const FileTag *tag, char *path)
{
	SMgrRelation reln = smgropen(tag->rnode, InvalidBackendId);
	File		file;

	if (tag->rnode.relNode == (Oid) InvalidUndoLogNumber)
	{
		/* Sync parent directory for this tablespace. */
		UndoLogDirectory(tag->rnode.spcNode, path);

		/* The caller (sync.c) will do appropriate error reporting. */
		return fsync_fname_ext(path, true, false, WARNING);
	}
	else
	{
		/* Sync a segment file. */
		UndoLogSegmentPath(tag->rnode.relNode, tag->segno, tag->rnode.spcNode,
						   path);

		file = undofile_get_segment_file(reln, tag->segno);
		if (file <= 0)
		{
			/* errno set by undofile_get_segment_file() */
			return -1;
		}

		return FileSync(file, WAIT_EVENT_UNDO_FILE_SYNC);
	}
}

/*
 * Filtering callback used by SYNC_FILTER_REQUEST to forget some requests.
 */
bool
undofile_filetagmatches(const FileTag *tag, const FileTag *candidate)
{
	/*
	 * We use SYNC_FILTER_REQUEST to forget requests for a given tablespace,
	 * before removing all undo files in the tablespace.
	 */
	return tag->rnode.spcNode == candidate->rnode.spcNode;
}

/*
 * Tell the checkpointer to sync a segment file.
 */
void
undofile_request_sync(UndoLogNumber logno, BlockNumber segno, Oid tablespace)
{
	char		path[MAXPGPATH];
	FileTag		tag;

	INIT_UNDOFILETAG(tag, logno, tablespace, segno);

	/* Try to send to the checkpointer, but if out of space, do it here. */
	if (!RegisterSyncRequest(&tag, SYNC_REQUEST, false))
	{
		if (undofile_syncfiletag(&tag, path) < 0)
			ereport(data_sync_elevel(ERROR),
					(errmsg("could not fsync file \"%s\": %m", path)));
	}
}

/*
 * Tell the checkpointer to forget about any sync requests for a given segment
 * file, because it's about to go away.
 */
void
undofile_forget_sync(UndoLogNumber logno, BlockNumber segno, Oid tablespace)
{
	FileTag		tag;

	INIT_UNDOFILETAG(tag, logno, tablespace, segno);

	/* Send, and keep retrying if out of space. */
	(void) RegisterSyncRequest(&tag, SYNC_FORGET_REQUEST, true);
}

/*
 * Tell the checkpointer to fsync the undo directory in a given tablespace,
 * because we have created or renamed files inside it.
 */
void
undofile_request_sync_dir(Oid tablespace)
{
	char		path[MAXPGPATH];
	FileTag		tag;

	/* We use a special logno and segno to mean "the directory". */
	INIT_UNDOFILETAG(tag, (Oid) InvalidUndoLogNumber, tablespace,
					 InvalidBlockNumber);

	/* Try to send to the checkpointer, but if out of space, do it here. */
	if (!RegisterSyncRequest(&tag, SYNC_REQUEST, false))
	{
		if (undofile_syncfiletag(&tag, path) < 0)
			ereport(data_sync_elevel(ERROR),
					(errmsg("could not fsync directory \"%s\": %m", path)));
	}
}

/*
 * Tell the checkpointer to forget about all sync requests for a given
 * tablespace, because it's about to go away.
 */
void
undofile_forget_sync_tablespace(Oid tablespace)
{
	FileTag		tag;

	INIT_UNDOFILETAG(tag, (Oid) InvalidUndoLogNumber, tablespace,
					 InvalidBlockNumber);

	/*
	 * Tell checkpointer to forget about any request for this tag, and keep
	 * waiting if there is not enough space.
	 */
	(void) RegisterSyncRequest(&tag, SYNC_FILTER_REQUEST, true);
}
