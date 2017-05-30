/*-------------------------------------------------------------------------
 *
 * genham.h
 *	  POSTGRES generalized heap access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/genham.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef GENHAM_H
#define GENHAM_H

#include "access/sdir.h"
#include "access/skey.h"

extern bool	enable_zheap;
extern int	data_alignment;
extern PGDLLIMPORT int	data_alignment_zheap;

/* struct definitions appear in relscan.h */
typedef struct HeapScanDescData *HeapScanDesc;
typedef struct ParallelHeapScanDescData *ParallelHeapScanDesc;

#endif   /* GENHAM_H */
