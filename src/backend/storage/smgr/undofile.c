/*
 * undofile.c
 *
 * PostgreSQL undo file manager.  This module provides SMGR-compatible
 * interface to the files that back undo logs on the file system, so that undo
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
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgwriter.h"
#include "storage/fd.h"
#include "storage/undofile.h"
#include "utils/memutils.h"

/* Populate a file tag describing an undofile.c segment file. */
#define INIT_UNDOFILETAG(a,xx_logno,xx_tbspc,xx_segno) \
( \
   memset(&(a), 0, sizeof(FileTag)), \
   (a).handler = SYNC_HANDLER_UNDO, \
   (a).rnode.spcNode = (xx_tbspc), \
   (a).rnode.relNode = (xx_logno), \
   (a).segno = (xx_segno) \
)

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

void
undofile_write(SMgrRelation reln, ForkNumber forknum,
			   BlockNumber blocknum, char *buffer,
			   bool skipFsync)
{
	FileTag     tag;
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
		INIT_UNDOFILETAG(tag,
						 reln->smgr_rnode.node.relNode,
						 reln->smgr_rnode.node.spcNode,
						 blocknum / UNDOSEG_SIZE);

		if (!RegisterSyncRequest(&tag, SYNC_REQUEST, false /*retryOnError*/))
		{
			if (FileSync(file, WAIT_EVENT_DATA_FILE_SYNC) < 0)
				ereport(data_sync_elevel(ERROR),
						(errcode_for_file_access(),
						 errmsg("could not fsync file \"%s\": %m",
								FilePathName(file))));
		}
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

int
undofile_syncfiletag(const FileTag *tag, char *path)
{
	SMgrRelation reln = smgropen(tag->rnode, InvalidBackendId);
	File        file;

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

void
undofile_forget_sync(UndoLogNumber logno, BlockNumber segno, Oid tablespace)
{
	FileTag     tag;

	INIT_UNDOFILETAG(tag, logno, tablespace, segno);

	(void) RegisterSyncRequest(&tag, SYNC_FORGET_REQUEST, true /*retryOnError*/);
}
