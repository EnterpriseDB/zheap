/*-------------------------------------------------------------------------
 *
 * zheap.h
 *	  POSTGRES zheap header definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheap.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHEAP_H
#define ZHEAP_H

#include "postgres.h"

#include "access/undoinsert.h"

extern bool	enable_zheap;
extern int	data_alignment;
extern PGDLLIMPORT int	data_alignment_zheap;

typedef struct ZHeapPageOpaqueData
{
	TransactionId	xid;
	UndoRecPtr	urec_ptr;
} ZHeapPageOpaqueData;

typedef ZHeapPageOpaqueData *ZHeapPageOpaque;

/*
 * macros for access to zheap page's special space. (Beware multiple evaluation
 * of the arguments!)
 */
#define PageGetUNDO(opaque) \
	((opaque)->urec_ptr)
#define PageSetUNDO(opaque, xid, undo) \
	((opaque)->xid = xid, (opaque)->urec_ptr = undo)

/* WAL Stuff */

/*
 * WAL record definitions for zheapam.c's WAL operations
 */
#define XLOG_ZHEAP_INSERT		0x00
#define XLOG_ZHEAP_DELETE		0x10
#define XLOG_ZHEAP_UPDATE		0x20
/*
 * When we insert 1st item on new page in INSERT, UPDATE, HOT_UPDATE,
 * or MULTI_INSERT, we can (and we do) restore entire page in redo
 */
#define XLOG_ZHEAP_INIT_PAGE		0x30

/*
 * xl_zheap_insert/xl_zheap_multi_insert flag values, 8 bits are available.
 */
#define XLZ_INSERT_ALL_VISIBLE_CLEARED			(1<<0)
#define XLZ_INSERT_LAST_IN_MULTI				(1<<1)
#define XLZ_INSERT_IS_SPECULATIVE				(1<<2)
#define XLZ_INSERT_CONTAINS_NEW_TUPLE			(1<<3)

/*
 * NOTE: t_hoff could be recomputed, but we may as well store it because
 * it will come for free due to alignment considerations.
 */
typedef struct xl_zheap_header
{
	uint8		t_numattrs;
	uint8		t_infomask;
	uint8		t_hoff;
} xl_zheap_header;

#define SizeOfZHeapHeader	(offsetof(xl_zheap_header, t_hoff) + sizeof(uint8))

/* This is what we need to know about insert */
typedef struct xl_zheap_insert
{
	/* undo record related info */
	UndoRecPtr	urec_ptr;	/* undo location for undo tuple */
	uint64		uur_blkprev;	/* byte offset of previous undo for block */

	/* heap record related info */
	OffsetNumber offnum;		/* inserted tuple's offset */
	uint8		flags;

	/* xl_zheap_header & TUPLE DATA in backup block 0 */
} xl_zheap_insert;

#define SizeOfZHeapInsert	(offsetof(xl_zheap_insert, flags) + sizeof(uint8))

#endif   /* ZHEAP_H */
