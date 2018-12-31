/*-------------------------------------------------------------------------
 *
 * smgrsync.h
 *	  management of file synchronization
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/smgrpending.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef SMGRSYNC_H
#define SMGRSYNC_H

#include "storage/smgr.h"

extern void smgrsync_init(void);
extern void smgrpreckpt(void);
extern void smgrsync(void);
extern void smgrpostckpt(void);

extern void UnlinkAfterCheckpoint(RelFileNodeBackend rnode);
extern bool FsyncAtCheckpoint(RelFileNode rnode, ForkNumber forknum,
							  SegmentNumber segno);
extern void RememberFsyncRequest(int type, RelFileNode rnode,
								 ForkNumber forknum, SegmentNumber segno);
extern void SetForwardFsyncRequests(void);
extern void ForgetSegmentFsyncRequests(RelFileNode rnode, ForkNumber forknum,
									   SegmentNumber segno);
extern void ForgetRelationFsyncRequests(RelFileNode rnode, ForkNumber forknum);
extern void ForgetDatabaseFsyncRequests(Oid dbid);


#endif
