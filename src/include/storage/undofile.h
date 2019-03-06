/*-------------------------------------------------------------------------
 *
 * undofile.h
 *	  undo storage manager public interface declarations.
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/undofile.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOFILE_H
#define UNDOFILE_H

#include "access/undolog.h"
#include "storage/block.h"
#include "storage/relfilenode.h"
#include "storage/smgr.h"
#include "storage/sync.h"

extern void undofile_init(void);
extern void undofile_shutdown(void);
extern void undofile_open(SMgrRelation reln);
extern void undofile_close(SMgrRelation reln, ForkNumber forknum);
extern void undofile_create(SMgrRelation reln, ForkNumber forknum,
							bool isRedo);
extern bool undofile_exists(SMgrRelation reln, ForkNumber forknum);
extern void undofile_unlink(RelFileNodeBackend rnode, ForkNumber forknum,
							bool isRedo);
extern void undofile_extend(SMgrRelation reln, ForkNumber forknum,
		 BlockNumber blocknum, char *buffer, bool skipFsync);
extern void undofile_prefetch(SMgrRelation reln, ForkNumber forknum,
		   BlockNumber blocknum);
extern void undofile_read(SMgrRelation reln, ForkNumber forknum,
						  BlockNumber blocknum, char *buffer);
extern void undofile_write(SMgrRelation reln, ForkNumber forknum,
		BlockNumber blocknum, char *buffer, bool skipFsync);
extern void undofile_writeback(SMgrRelation reln, ForkNumber forknum,
			BlockNumber blocknum, BlockNumber nblocks);
extern BlockNumber undofile_nblocks(SMgrRelation reln, ForkNumber forknum);
extern void undofile_truncate(SMgrRelation reln, ForkNumber forknum,
		   BlockNumber nblocks);
extern void undofile_immedsync(SMgrRelation reln, ForkNumber forknum);

/* Callbacks used by sync.c. */
extern int undofile_syncfiletag(const FileTag *tag, char *path);
extern bool undofile_filetagmatches(const FileTag *tag, const FileTag *candidate);

/* Management of checkpointer requests. */
extern void undofile_request_sync(UndoLogNumber logno, BlockNumber segno,
								  Oid tablespace);
extern void undofile_forget_sync(UndoLogNumber logno, BlockNumber segno,
								 Oid tablespace);
extern void undofile_forget_sync_tablespace(Oid tablespace);
extern void undofile_request_sync_dir(Oid tablespace);

#endif							/* UNDOFILE_H */
