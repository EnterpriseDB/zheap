/*-------------------------------------------------------------------------
 *
 * vacuumblk.h
 *	  header file for postgres block level vacuum routines
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/vacuumblk.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef VACUUMBLK_H
#define VACUUMBLK_H

#include "commands/vacuum.h"
#include "storage/buf.h"

extern void lazy_vacuum_index(Relation indrel, IndexBulkDeleteResult **stats,
				  LVRelStats *vacrelstats,
				  BufferAccessStrategy vac_strategy, int elevel);
extern void lazy_cleanup_index(Relation indrel, IndexBulkDeleteResult *stats,
				   LVRelStats *vacrelstats,
				   BufferAccessStrategy vac_strategy, int elevel);
extern bool should_attempt_truncation(Relation rel, LVRelStats *vacrelstats);
extern void lazy_truncate_heap(Relation onerel, LVRelStats *vacrelstats,
				   BufferAccessStrategy vac_strategy, int elevel);
extern void lazy_record_dead_tuple(LVRelStats *vacrelstats,
					   ItemPointer itemptr);

#endif							/* VACUUMBLK_H */
