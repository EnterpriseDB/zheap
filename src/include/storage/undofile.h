/*
 * undofile.h
 *
 * PostgreSQL undo file manager.  This module manages the files that back undo
 * logs on the filesystem.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/undofile.h
 */

#ifndef UNDOFILE_H
#define UNDOFILE_H

#include "storage/smgr.h"

/* Prototypes of functions exposed to SMgr. */
extern void undofile_init(void);
extern void undofile_shutdown(void);
extern void undofile_close(SMgrRelation reln, ForkNumber forknum);
extern void undofile_create(SMgrRelation reln, ForkNumber forknum,
							bool isRedo);
extern bool undofile_exists(SMgrRelation reln, ForkNumber forknum);
extern void undofile_unlink(RelFileNodeBackend rnode, ForkNumber forknum,
							bool isRedo);
extern void undofile_extend(SMgrRelation reln, ForkNumber forknum,
							BlockNumber blocknum, char *buffer,
							bool skipFsync);
extern void undofile_prefetch(SMgrRelation reln, ForkNumber forknum,
							  BlockNumber blocknum);
extern void undofile_read(SMgrRelation reln, ForkNumber forknum,
						  BlockNumber blocknum, char *buffer);
extern void undofile_write(SMgrRelation reln, ForkNumber forknum,
						   BlockNumber blocknum, char *buffer,
						   bool skipFsync);
extern void undofile_writeback(SMgrRelation reln, ForkNumber forknum,
							   BlockNumber blocknum, BlockNumber nblocks);
extern BlockNumber undofile_nblocks(SMgrRelation reln, ForkNumber forknum);
extern void undofile_truncate(SMgrRelation reln, ForkNumber forknum,
							  BlockNumber nblocks);
extern void undofile_immedsync(SMgrRelation reln, ForkNumber forknum);
extern void undofile_pre_ckpt(void);
extern void undofile_sync(void);
extern void undofile_post_ckpt(void);

/* Functions used by undolog.c. */
extern void undofile_forgetsync(Oid logno, Oid tablespace, int segno);

#endif
