/*-------------------------------------------------------------------------
 *
 * rewritezheap.c
 *	  Support functions to rewrite zheap tables.
 *
 * These functions provide a facility to completely rewrite a heap.
 *
 * INTERFACE
 *
 * The caller is responsible for creating the new heap, all catalog
 * changes, supplying the tuples to be written to the new heap, and
 * rebuilding indexes.  The caller must hold AccessExclusiveLock on the
 * target table, because we assume no one else is writing into it.
 *
 * To use the facility:
 *
 * begin_heap_rewrite
 * while (fetch next tuple)
 * {
 *	   if (tuple is dead)
 *		   rewrite_heap_dead_tuple
 *	   else
 *	   {
 *		   // do any transformations here if required
 *		   rewrite_heap_tuple
 *	   }
 * }
 * end_zheap_rewrite
 *
 * The contents of the new relation shouldn't be relied on until after
 * end_zheap_rewrite is called.
 *
 *
 * IMPLEMENTATION
 *
 * As of now, this layer gets only LIVE tuples and we freeze them before
 * storing in new heap.  This is not a good idea as we lose all the
 * visibility information of tuples, but OTOH, the same can't be copied
 * from the original tuple as that is maintained in undo and we don't have
 * facility to modify undo records.
 *
 * One idea to capture the visibility information is that we should write a
 * special undo record such that it stores previous version's visibility
 * information and later if the current version is not visible as per latest
 * xid (which is of cluster/vacuum full command), then we should get previous
 * xid information from undo.  It seems along with previous versions xid, we
 * need to write previous version tuples as well and somehow need to fix the
 * ctid information in the undo records.
 *
 * We can't use the normal zheap_insert function to insert into the new
 * heap, because heap_insert overwrites the visibility information and
 * it uses buffer management layer to process the tuples which is bit
 * slower.  We use a special-purpose raw_zheap_insert function instead, which
 * is optimized for bulk inserting a lot of tuples, knowing that we have
 * exclusive access to the heap.  raw_zheap_insert builds new pages in
 * local storage.  When a page is full, or at the end of the process,
 * we insert it to WAL as a single record and then write it to disk
 * directly through smgr.  Note, however, that any data sent to the new
 * heap's TOAST table will go through the normal bufmgr.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994-5, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/rewritezheap.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/stat.h>
#include <unistd.h>

#include "access/heapam.h"	/* for heap_sync() */
#include "access/rewritezheap.h"
#include "access/tuptoaster.h"
#include "access/zheap.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "storage/smgr.h"
#include "storage/procarray.h"
#include "utils/memutils.h"


/*
 * State associated with a rewrite operation. This is opaque to the user
 * of the rewrite facility.
 */
typedef struct RewriteZheapStateData
{
	Relation	rs_new_rel;		/* destination heap */
	Page		rs_buffer;		/* page currently being built */
	BlockNumber rs_blockno;		/* block where page will go */
	bool		rs_buffer_valid;	/* T if any tuples in buffer */
	bool		rs_use_wal;		/* must we WAL-log inserts? */
	MemoryContext rs_cxt;		/* for hash tables and entries and tuples in
								 * them */
}			RewriteZheapStateData;


/* prototypes for internal functions */
static void raw_zheap_insert(RewriteZheapState state, ZHeapTuple tup);

/*
 * Begin a rewrite of a table
 *
 * old_heap		old, locked heap relation tuples will be read from
 * new_heap		new, locked heap relation to insert tuples to
 * oldest_xmin	xid used by the caller to determine which tuples are dead
 * freeze_xid	this is kept for API compatability with heap, it's value will
 *				be InvalidTransactionId.
 * min_multi	this is kept for API compatability with heap, it's value will
 *				will be InvalidMultiXactId
 * use_wal		should the inserts to the new heap be WAL-logged?
 *
 * Returns an opaque RewriteState, allocated in current memory context,
 * to be used in subsequent calls to the other functions.
 */
RewriteZheapState
begin_zheap_rewrite(Relation old_heap, Relation new_heap,
					TransactionId oldest_xmin, TransactionId freeze_xid,
					MultiXactId cutoff_multi, bool use_wal)
{
	RewriteZheapState state;
	MemoryContext rw_cxt;
	MemoryContext old_cxt;

	/*
	 * To ease cleanup, make a separate context that will contain the
	 * RewriteState struct itself plus all subsidiary data.
	 */
	rw_cxt = AllocSetContextCreate(CurrentMemoryContext,
								   "Table rewrite",
								   ALLOCSET_DEFAULT_SIZES);
	old_cxt = MemoryContextSwitchTo(rw_cxt);

	/* Create and fill in the state struct */
	state = palloc0(sizeof(RewriteZheapStateData));

	state->rs_new_rel = new_heap;
	state->rs_buffer = (Page) palloc(BLCKSZ);
	/* new_heap needn't be empty, just locked */
	state->rs_blockno = RelationGetNumberOfBlocks(new_heap);
	state->rs_buffer_valid = false;
	state->rs_use_wal = use_wal;
	state->rs_cxt = rw_cxt;

	MemoryContextSwitchTo(old_cxt);

	return state;
}

/*
 * End a rewrite.
 *
 * state and any other resources are freed.
 */
void
end_zheap_rewrite(RewriteZheapState state)
{
	/* Write the last page, if any */
	if (state->rs_buffer_valid)
	{
		if (state->rs_use_wal)
			log_newpage(&state->rs_new_rel->rd_node,
						MAIN_FORKNUM,
						state->rs_blockno,
						state->rs_buffer,
						true);
		RelationOpenSmgr(state->rs_new_rel);

		PageSetChecksumInplace(state->rs_buffer, state->rs_blockno);

		smgrextend(state->rs_new_rel->rd_smgr, MAIN_FORKNUM, state->rs_blockno,
				   (char *) state->rs_buffer, true);
	}

	/*
	 * If the rel is WAL-logged, must fsync before commit.  We use heap_sync
	 * to ensure that the toast table gets fsync'd too.
	 *
	 * It's obvious that we must do this when not WAL-logging. It's less
	 * obvious that we have to do it even if we did WAL-log the pages. The
	 * reason is the same as in tablecmds.c's copy_relation_data(): we're
	 * writing data that's not in shared buffers, and so a CHECKPOINT
	 * occurring during the rewritezheap operation won't have fsync'd data we
	 * wrote before the checkpoint.
	 */
	if (RelationNeedsWAL(state->rs_new_rel))
		heap_sync(state->rs_new_rel);

	/* Deleting the context frees everything */
	MemoryContextDelete(state->rs_cxt);
}

/*
 * Reconstruct and rewrite the given tuple
 *
 * We cannot simply copy the tuple as-is, see reform_and_rewrite_tuple for
 * reasons.
 */
void
reform_and_rewrite_ztuple(ZHeapTuple tuple, TupleDesc oldTupDesc,
						  TupleDesc newTupDesc, Datum *values, bool *isnull,
						  RewriteZheapState rwstate)
{
	ZHeapTuple	copiedTuple;
	int			i;

	zheap_deform_tuple(tuple, oldTupDesc, values, isnull);

	/* Be sure to null out any dropped columns */
	for (i = 0; i < newTupDesc->natts; i++)
	{
		if (TupleDescAttr(newTupDesc, i)->attisdropped)
			isnull[i] = true;
	}

	copiedTuple = zheap_form_tuple(newTupDesc, values, isnull);

	rewrite_zheap_tuple(rwstate, tuple, copiedTuple);

	zheap_freetuple(copiedTuple);
}

/*
 * Add a tuple to the new heap.
 *
 * Maintaining previous version's visibility information needs much more work
 * (see atop of this file), so for now, we freeze all the tuples.  We only get
 * LIVE versions of the tuple as input.
 *
 * Note that since we scribble on new_tuple, it had better be temp storage
 * not a pointer to the original tuple.
 *
 * state		opaque state as returned by begin_heap_rewrite
 * old_tuple	original tuple in the old heap
 * new_tuple	new, rewritten tuple to be inserted to new heap
 */
void
rewrite_zheap_tuple(RewriteZheapState state, ZHeapTuple old_tuple,
					ZHeapTuple new_tuple)
{
	MemoryContext old_cxt;

	old_cxt = MemoryContextSwitchTo(state->rs_cxt);

	/*
	 * As of now, we copy only LIVE tuples in zheap, so we can mark them as
	 * frozen.
	 */
	new_tuple->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	new_tuple->t_data->t_infomask2 &= ~ZHEAP_XACT_SLOT;
	ZHeapTupleHeaderSetXactSlot(new_tuple->t_data, ZHTUP_SLOT_FROZEN);

	raw_zheap_insert(state, new_tuple);

	MemoryContextSwitchTo(old_cxt);
}

/*
 * Insert a tuple to the new relation.  This has to track zheap_insert
 * and its subsidiary functions!
 *
 * t_self of the tuple is set to the new TID of the tuple.
 */
static void
raw_zheap_insert(RewriteZheapState state, ZHeapTuple tup)
{
	Page		page = state->rs_buffer;
	Size		pageFreeSpace,
				saveFreeSpace;
	Size		len;
	OffsetNumber newoff;
	ZHeapTuple	heaptup;

	/*
	 * If the new tuple is too big for storage or contains already toasted
	 * out-of-line attributes from some other relation, invoke the toaster.
	 *
	 * Note: below this point, heaptup is the data we actually intend to store
	 * into the relation; tup is the caller's original untoasted data.
	 */
	if (state->rs_new_rel->rd_rel->relkind == RELKIND_TOASTVALUE)
	{
		/* toast table entries should never be recursively toasted */
		Assert(!ZHeapTupleHasExternal(tup));
		heaptup = tup;
	}
	else if (ZHeapTupleHasExternal(tup) || tup->t_len > TOAST_TUPLE_THRESHOLD)
	{
		/*
		 * As of now, we copy only LIVE tuples in zheap, so we can mark them
		 * as frozen.
		 */
		heaptup = ztoast_insert_or_update(state->rs_new_rel, tup, NULL,
										  ZHEAP_INSERT_FROZEN |
										  ZHEAP_INSERT_SKIP_FSM |
										  (state->rs_use_wal ?
										   0 : ZHEAP_INSERT_SKIP_WAL));
	}
	else
		heaptup = tup;

	len = SHORTALIGN(heaptup->t_len);

	/*
	 * If we're gonna fail for oversize tuple, do it right away
	 */
	if (len > MaxZHeapTupleSize)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("row is too big: size %zu, maximum size %zu",
						len, MaxZHeapTupleSize)));

	/* Compute desired extra freespace due to fillfactor option */
	saveFreeSpace = RelationGetTargetPageFreeSpace(state->rs_new_rel,
												   HEAP_DEFAULT_FILLFACTOR);

	/* Now we can check to see if there's enough free space already. */
	if (state->rs_buffer_valid)
	{
		pageFreeSpace = PageGetHeapFreeSpace(page);

		if (len + saveFreeSpace > pageFreeSpace)
		{
			/* Doesn't fit, so write out the existing page */

			/* XLOG stuff */
			if (state->rs_use_wal)
				log_newpage(&state->rs_new_rel->rd_node,
							MAIN_FORKNUM,
							state->rs_blockno,
							page,
							true);

			/*
			 * Now write the page. We say isTemp = true even if it's not a
			 * temp table, because there's no need for smgr to schedule an
			 * fsync for this write; we'll do it ourselves in
			 * end_zheap_rewrite.
			 */
			RelationOpenSmgr(state->rs_new_rel);

			PageSetChecksumInplace(page, state->rs_blockno);

			smgrextend(state->rs_new_rel->rd_smgr, MAIN_FORKNUM,
					   state->rs_blockno, (char *) page, true);

			state->rs_blockno++;
			state->rs_buffer_valid = false;
		}
	}

	if (!state->rs_buffer_valid)
	{
		/* Initialize a new empty page */
		ZheapInitPage(page, BLCKSZ);
		state->rs_buffer_valid = true;
	}

	/* And now we can insert the tuple into the page */
	newoff = ZPageAddItem(InvalidBuffer, page, (Item) heaptup->t_data,
						  heaptup->t_len, InvalidOffsetNumber, false, true,
						  true);
	if (newoff == InvalidOffsetNumber)
		elog(ERROR, "failed to add tuple");

	/* Update caller's t_self to the actual position where it was stored */
	ItemPointerSet(&(tup->t_self), state->rs_blockno, newoff);

	/* If heaptup is a private copy, release it. */
	if (heaptup != tup)
		zheap_freetuple(heaptup);
}
