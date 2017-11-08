/*-------------------------------------------------------------------------
 *
 * zheapam_xlog.h
 *	  POSTGRES zheap access XLOG definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheapam_xlog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHEAP_XLOG_H
#define ZHEAP_XLOG_H

#include "postgres.h"

#include "access/genham.h"
#include "access/hio.h"
#include "access/xlogreader.h"
#include "access/undoinsert.h"
#include "access/zhtup.h"
#include "utils/rel.h"
#include "utils/snapshot.h"

/*
 * WAL record definitions for zheapam.c's WAL operations
 *
 * XLOG allows to store some information in high 4 bits of log
 * record xl_info field.  We use 3 for opcode and one for init bit.
 */
#define XLOG_ZHEAP_INSERT			0x00
#define XLOG_ZHEAP_DELETE			0x10
#define XLOG_ZHEAP_UPDATE			0x20
#define XLOG_ZHEAP_MULTI_INSERT		0x30

#define	XLOG_ZHEAP_OPMASK			0x70

/*
 * When we insert 1st item on new page in INSERT, NON-INPLACE-UPDATE,
 * or MULTI_INSERT, we can (and we do) restore entire page in redo
 */
#define XLOG_ZHEAP_INIT_PAGE		0x80

/* common undo record related info */
typedef struct xl_undo_header
{
	Oid			relfilenode;	/* relfilenode for relation */
	Oid			tsid;	/* tablespace OID */
	uint64		blkprev;	/* byte offset of previous undo for block */
	UndoRecPtr	urec_ptr;	/* undo location for undo tuple */
} xl_undo_header;

#define SizeOfUndoHeader	(offsetof(xl_undo_header, urec_ptr) + sizeof(UndoRecPtr))

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
	uint16		t_infomask2;
	uint16		t_infomask;
	uint8		t_hoff;
} xl_zheap_header;

#define SizeOfZHeapHeader	(offsetof(xl_zheap_header, t_hoff) + sizeof(uint8))

/* This is what we need to know about insert */
typedef struct xl_zheap_insert
{
	/* heap record related info */
	OffsetNumber offnum;		/* inserted tuple's offset */
	uint8		flags;

	/* xl_zheap_header & TUPLE DATA in backup block 0 */
} xl_zheap_insert;

#define SizeOfZHeapInsert	(offsetof(xl_zheap_insert, flags) + sizeof(uint8))

/*
 * xl_zheap_delete flag values, 8 bits are available.
 */
/* PD_ALL_VISIBLE was cleared */
#define XLZ_DELETE_ALL_VISIBLE_CLEARED			(1<<0)
/* undo tuple is present in xlog record? */
#define XLZ_HAS_DELETE_UNDOTUPLE				(1<<1)

/* This is what we need to know about delete */
typedef struct xl_zheap_delete
{
	/* info related to undo record */
	TransactionId prevxid;			/* transaction id that has modified the tuple
									 * written in undo record for delete operation */

	/* zheap related info */
	OffsetNumber offnum;		/* deleted tuple's offset */
	uint8		trans_slot_id;	/* transaction slot id */
	uint8		flags;
} xl_zheap_delete;

#define SizeOfZHeapDelete	(offsetof(xl_zheap_delete, flags) + sizeof(uint8))

extern void zheap_redo(XLogReaderState *record);
extern void zheap_desc(StringInfo buf, XLogReaderState *record);
extern const char *zheap_identify(uint8 info);

#endif   /* ZHEAP_XLOG_H */
