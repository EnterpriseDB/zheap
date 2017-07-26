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

#include "access/genham.h"
#include "access/undoinsert.h"
#include "access/zhtup.h"
#include "utils/rel.h"
#include "utils/snapshot.h"

#define MAX_PAGE_TRANS_INFO_SLOTS	4

/*
 * We need tansactionid and undo pointer to retrieve the undo information
 * for a particular transaction.
 */
typedef struct TransInfo
{
	TransactionId	xid;
	UndoRecPtr	urec_ptr;
} TransInfo;

typedef struct ZHeapPageOpaqueData
{
	TransInfo	transinfo[MAX_PAGE_TRANS_INFO_SLOTS];
} ZHeapPageOpaqueData;

typedef ZHeapPageOpaqueData *ZHeapPageOpaque;

extern Oid zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options);
extern HTSU_Result zheap_delete(Relation relation, ItemPointer tid,
						CommandId cid, Snapshot crosscheck, bool wait,
						HeapUpdateFailureData *hufd);
extern HTSU_Result zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
					CommandId cid, Snapshot crosscheck, bool wait,
					HeapUpdateFailureData *hufd, LockTupleMode *lockmode);
extern HTSU_Result zheap_lock_tuple(Relation relation, ZHeapTuple tuple,
					CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
					bool follow_updates, bool eval, Buffer *buffer,
					HeapUpdateFailureData *hufd);
extern void ZheapInitPage(Page page, Size pageSize);

/* Zheap scan related API's */
extern HeapScanDesc zheap_beginscan(Relation relation, Snapshot snapshot,
				int nkeys, ScanKey key);
extern HeapScanDesc zheap_beginscan_strat(Relation relation, Snapshot snapshot,
					int nkeys, ScanKey key,
					bool allow_strat, bool allow_sync);
extern ZHeapTuple zheap_getnext(HeapScanDesc scan, ScanDirection direction);
extern ZHeapTuple zheap_search_buffer(ItemPointer tid, Relation relation,
									  Buffer buffer, Snapshot snapshot,
									  bool *all_dead);

extern bool zheap_fetch(Relation relation, Snapshot snapshot,
				ItemPointer tid, ZHeapTuple *tuple, Buffer *userbuf,
				bool keep_buf, Relation stats_relation);

/* Zheap and undo record interaction related API's */
extern ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						bool free_zhtup);

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
	uint16		t_infomask2;
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
