/*-------------------------------------------------------------------------
 *
 * execTuples.c
 *	  Routines dealing with TupleTableSlots.  These are used for resource
 *	  management associated with tuples (eg, releasing buffer pins for
 *	  tuples in disk buffers, or freeing the memory occupied by transient
 *	  tuples).  Slots also provide access abstraction that lets us implement
 *	  "virtual" tuples to reduce data-copying overhead.
 *
 *	  Routines dealing with the type information for tuples. Currently,
 *	  the type information for a tuple is an array of FormData_pg_attribute.
 *	  This information is needed by routines manipulating tuples
 *	  (getattribute, formtuple, etc.).
 *
 *
 *	 EXAMPLE OF HOW TABLE ROUTINES WORK
 *		Suppose we have a query such as SELECT emp.name FROM emp and we have
 *		a single SeqScan node in the query plan.
 *
 *		At ExecutorStart()
 *		----------------

 *		- ExecInitSeqScan() calls ExecInitScanTupleSlot() to construct a
 *		  TupleTableSlots for the tuples returned by the access method, and
 *		  ExecInitResultTypeTL() to define the node's return
 *		  type. ExecAssignScanProjectionInfo() will, if necessary, create
 *		  another TupleTableSlot for the tuples resulting from performing
 *		  target list projections.
 *
 *		During ExecutorRun()
 *		----------------
 *		- SeqNext() calls ExecStoreBufferHeapTuple() to place the tuple
 *		  returned by the access method into the scan tuple slot.
 *
 *		- ExecSeqScan() (via ExecScan), if necessary, calls ExecProject(),
 *		  putting the result of the projection in the result tuple slot. If
 *		  not necessary, it directly returns the slot returned by SeqNext().
 *
 *		- ExecutePlan() calls the output function.
 *
 *		The important thing to watch in the executor code is how pointers
 *		to the slots containing tuples are passed instead of the tuples
 *		themselves.  This facilitates the communication of related information
 *		(such as whether or not a tuple should be pfreed, what buffer contains
 *		this tuple, the tuple's tuple descriptor, etc).  It also allows us
 *		to avoid physically constructing projection tuples in many cases.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/execTuples.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/tupdesc_details.h"
#include "access/tuptoaster.h"
#include "access/zheap.h"
#include "access/zhtup.h"
#include "funcapi.h"
#include "catalog/pg_type.h"
#include "nodes/nodeFuncs.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/typcache.h"


static TupleDesc ExecTypeFromTLInternal(List *targetList,
					   bool hasoid, bool skipjunk);


/* ----------------------------------------------------------------
 *				  tuple table create/delete functions
 * ----------------------------------------------------------------
 */

/* --------------------------------
 *		MakeTupleTableSlot
 *
 *		Basic routine to make an empty TupleTableSlot. If tupleDesc is
 *		specified the slot's descriptor is fixed for it's lifetime, gaining
 *		some efficiency. If that's undesirable, pass NULL.
 * --------------------------------
 */
TupleTableSlot *
MakeTupleTableSlot(TupleDesc tupleDesc)
{
	Size		sz;
	TupleTableSlot *slot;

	/*
	 * When a fixed descriptor is specified, we can reduce overhead by
	 * allocating the entire slot in one go.
	 */
	if (tupleDesc)
		sz = MAXALIGN(sizeof(TupleTableSlot)) +
			MAXALIGN(tupleDesc->natts * sizeof(Datum)) +
			MAXALIGN(tupleDesc->natts * sizeof(bool));
	else
		sz = sizeof(TupleTableSlot);

	slot = palloc0(sz);
	slot->type = T_TupleTableSlot;
	slot->tts_flags |= TTS_FLAG_EMPTY;
	if (tupleDesc != NULL)
		slot->tts_flags |= TTS_FLAG_FIXED;
	slot->tts_tuple = NULL;
	slot->tts_tupleDescriptor = tupleDesc;
	slot->tts_mcxt = CurrentMemoryContext;
	slot->tts_buffer = InvalidBuffer;
	slot->tts_nvalid = 0;
	slot->tts_values = NULL;
	slot->tts_isnull = NULL;
	slot->tts_mintuple = NULL;

	if (tupleDesc != NULL)
	{
		slot->tts_values = (Datum *)
			(((char *) slot)
			 + MAXALIGN(sizeof(TupleTableSlot)));
		slot->tts_isnull = (bool *)
			(((char *) slot)
			 + MAXALIGN(sizeof(TupleTableSlot))
			 + MAXALIGN(tupleDesc->natts * sizeof(Datum)));

		PinTupleDesc(tupleDesc);
	}

	return slot;
}

/* --------------------------------
 *		ExecAllocTableSlot
 *
 *		Create a tuple table slot within a tuple table (which is just a List).
 * --------------------------------
 */
TupleTableSlot *
ExecAllocTableSlot(List **tupleTable, TupleDesc desc)
{
	TupleTableSlot *slot = MakeTupleTableSlot(desc);

	*tupleTable = lappend(*tupleTable, slot);

	return slot;
}

/* --------------------------------
 *		ExecResetTupleTable
 *
 *		This releases any resources (buffer pins, tupdesc refcounts)
 *		held by the tuple table, and optionally releases the memory
 *		occupied by the tuple table data structure.
 *		It is expected that this routine be called by EndPlan().
 * --------------------------------
 */
void
ExecResetTupleTable(List *tupleTable,	/* tuple table */
					bool shouldFree)	/* true if we should free memory */
{
	ListCell   *lc;

	foreach(lc, tupleTable)
	{
		TupleTableSlot *slot = lfirst_node(TupleTableSlot, lc);

		/* Always release resources and reset the slot to empty */
		ExecClearTuple(slot);
		if (slot->tts_tupleDescriptor)
		{
			ReleaseTupleDesc(slot->tts_tupleDescriptor);
			slot->tts_tupleDescriptor = NULL;
		}

		/* If shouldFree, release memory occupied by the slot itself */
		if (shouldFree)
		{
			if (!TTS_FIXED(slot))
			{
				if (slot->tts_values)
					pfree(slot->tts_values);
				if (slot->tts_isnull)
					pfree(slot->tts_isnull);
			}
			pfree(slot);
		}
	}

	/* If shouldFree, release the list structure */
	if (shouldFree)
		list_free(tupleTable);
}

/* --------------------------------
 *		MakeSingleTupleTableSlot
 *
 *		This is a convenience routine for operations that need a
 *		standalone TupleTableSlot not gotten from the main executor
 *		tuple table.  It makes a single slot and initializes it
 *		to use the given tuple descriptor.
 * --------------------------------
 */
TupleTableSlot *
MakeSingleTupleTableSlot(TupleDesc tupdesc)
{
	TupleTableSlot *slot = MakeTupleTableSlot(tupdesc);

	return slot;
}

/* --------------------------------
 *		ExecDropSingleTupleTableSlot
 *
 *		Release a TupleTableSlot made with MakeSingleTupleTableSlot.
 *		DON'T use this on a slot that's part of a tuple table list!
 * --------------------------------
 */
void
ExecDropSingleTupleTableSlot(TupleTableSlot *slot)
{
	/* This should match ExecResetTupleTable's processing of one slot */
	Assert(IsA(slot, TupleTableSlot));
	ExecClearTuple(slot);
	if (slot->tts_tupleDescriptor)
		ReleaseTupleDesc(slot->tts_tupleDescriptor);
	if (!TTS_FIXED(slot))
	{
		if (slot->tts_values)
			pfree(slot->tts_values);
		if (slot->tts_isnull)
			pfree(slot->tts_isnull);
	}
	pfree(slot);
}


/* ----------------------------------------------------------------
 *				  tuple table slot accessor functions
 * ----------------------------------------------------------------
 */

/* --------------------------------
 *		ExecSetSlotDescriptor
 *
 *		This function is used to set the tuple descriptor associated
 *		with the slot's tuple.  The passed descriptor must have lifespan
 *		at least equal to the slot's.  If it is a reference-counted descriptor
 *		then the reference count is incremented for as long as the slot holds
 *		a reference.
 * --------------------------------
 */
void
ExecSetSlotDescriptor(TupleTableSlot *slot, /* slot to change */
					  TupleDesc tupdesc)	/* new tuple descriptor */
{
	Assert(!TTS_FIXED(slot));

	/* For safety, make sure slot is empty before changing it */
	ExecClearTuple(slot);

	/*
	 * Release any old descriptor.  Also release old Datum/isnull arrays if
	 * present (we don't bother to check if they could be re-used).
	 */
	if (slot->tts_tupleDescriptor)
		ReleaseTupleDesc(slot->tts_tupleDescriptor);

	if (slot->tts_values)
		pfree(slot->tts_values);
	if (slot->tts_isnull)
		pfree(slot->tts_isnull);

	/*
	 * Install the new descriptor; if it's refcounted, bump its refcount.
	 */
	slot->tts_tupleDescriptor = tupdesc;
	PinTupleDesc(tupdesc);

	/*
	 * Allocate Datum/isnull arrays of the appropriate size.  These must have
	 * the same lifetime as the slot, so allocate in the slot's own context.
	 */
	slot->tts_values = (Datum *)
		MemoryContextAlloc(slot->tts_mcxt, tupdesc->natts * sizeof(Datum));
	slot->tts_isnull = (bool *)
		MemoryContextAlloc(slot->tts_mcxt, tupdesc->natts * sizeof(bool));
}

/* --------------------------------
 *		ExecStoreHeapTuple
 *
 *		This function is used to store an on-the-fly physical tuple into a specified
 *		slot in the tuple table.
 *
 *		tuple:	tuple to store
 *		slot:	slot to store it in
 *		shouldFree: true if ExecClearTuple should pfree() the tuple
 *					when done with it
 *
 * shouldFree is normally set 'true' for tuples constructed on-the-fly.  But it
 * can be 'false' when the referenced tuple is held in a tuple table slot
 * belonging to a lower-level executor Proc node.  In this case the lower-level
 * slot retains ownership and responsibility for eventually releasing the
 * tuple.  When this method is used, we must be certain that the upper-level
 * Proc node will lose interest in the tuple sooner than the lower-level one
 * does!  If you're not certain, copy the lower-level tuple with heap_copytuple
 * and let the upper-level table slot assume ownership of the copy!
 *
 * Return value is just the passed-in slot pointer.
 * --------------------------------
 */
TupleTableSlot *
ExecStoreHeapTuple(HeapTuple tuple,
				   TupleTableSlot *slot,
				   bool shouldFree)
{
	/*
	 * sanity checks
	 */
	Assert(tuple != NULL);
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);

	/*
	 * Free any old physical tuple belonging to the slot.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		heap_freetuple(slot->tts_tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}
	if (TTS_SHOULDZFREE(slot))
	{
		zheap_freetuple(slot->tts_ztuple);
		slot->tts_ztuple = NULL;
		slot->tts_flags &= ~TTS_FLAG_SHOULDZFREE;
	}	
	if (TTS_SHOULDFREEMIN(slot))
	{
		heap_free_minimal_tuple(slot->tts_mintuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREEMIN;
	}

	/*
	 * Store the new tuple into the specified slot.
	 */
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	if (shouldFree)
		slot->tts_flags |= TTS_FLAG_SHOULDFREE;
	slot->tts_tuple = tuple;
	slot->tts_mintuple = NULL;

	/* Mark extracted state invalid */
	slot->tts_nvalid = 0;

	/* Unpin any buffer pinned by the slot. */
	if (BufferIsValid(slot->tts_buffer))
		ReleaseBuffer(slot->tts_buffer);
	slot->tts_buffer = InvalidBuffer;

	return slot;
}

/* --------------------------------
 *		ExecStoreBufferHeapTuple
 *
 *		This function is used to store an on-disk physical tuple from a buffer
 *		into a specified slot in the tuple table.
 *
 *		tuple:	tuple to store
 *		slot:	slot to store it in
 *		buffer: disk buffer if tuple is in a disk page, else InvalidBuffer
 *
 * The tuple table code acquires a pin on the buffer which is held until the
 * slot is cleared, so that the tuple won't go away on us.
 *
 * Return value is just the passed-in slot pointer.
 * --------------------------------
 */
TupleTableSlot *
ExecStoreBufferHeapTuple(HeapTuple tuple,
						 TupleTableSlot *slot,
						 Buffer buffer)
{
	/*
	 * sanity checks
	 */
	Assert(tuple != NULL);
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);
	Assert(BufferIsValid(buffer));

	/*
	 * Free any old physical tuple belonging to the slot.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		heap_freetuple(slot->tts_tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}
	if (TTS_SHOULDZFREE(slot))
	{
		zheap_freetuple(slot->tts_ztuple);
		slot->tts_ztuple = NULL;
		slot->tts_flags &= ~TTS_FLAG_SHOULDZFREE;
	}	
	if (TTS_SHOULDFREEMIN(slot))
	{
		heap_free_minimal_tuple(slot->tts_mintuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREEMIN;
	}

	/*
	 * Store the new tuple into the specified slot.
	 */
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	slot->tts_tuple = tuple;
	slot->tts_ztuple = NULL;
	slot->tts_mintuple = NULL;

	/* Mark extracted state invalid */
	slot->tts_nvalid = 0;

	/*
	 * Keep the disk page containing the given tuple pinned as long as we hold
	 * a pointer into it.  We assume the caller already has such a pin.
	 *
	 * This is coded to optimize the case where the slot previously held a
	 * tuple on the same disk page: in that case releasing and re-acquiring the
	 * pin is a waste of cycles.  This is a common situation during seqscans,
	 * so it's worth troubling over.
	 */
	if (slot->tts_buffer != buffer)
	{
		if (BufferIsValid(slot->tts_buffer))
			ReleaseBuffer(slot->tts_buffer);
		slot->tts_buffer = buffer;
		IncrBufferRefCount(buffer);
	}

	return slot;
}

/* --------------------------------
 *		ExecStoreZTuple
 *
 *		This function is same as ExecStoreTuple except that it used to store a
 *		physical zheap tuple into a specified slot in the tuple table.
 *
 *		NOTE: Unlike ExecStoreTuple, it's possible that buffer is valid and
 *		should_free is true. Because, slot->tts_ztuple may be a copy of the
 *		tuple allocated locally. So, we want to free the tuple even after
 *		keeping a pin/lock to the previously valid buffer.
 */
TupleTableSlot *
ExecStoreZTuple(ZHeapTuple tuple,
				TupleTableSlot *slot,
				Buffer buffer,
				bool shouldFree)
{
	/*
	 * sanity checks
	 */
	Assert(tuple != NULL);
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);

	/*
	 * Free any old physical tuple belonging to the slot.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		heap_freetuple(slot->tts_tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}
	if (TTS_SHOULDZFREE(slot))
	{
		zheap_freetuple(slot->tts_ztuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDZFREE;
	}
	if (TTS_SHOULDFREEMIN(slot))
	{
		heap_free_minimal_tuple(slot->tts_mintuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREEMIN;
	}

	/*
	 * Store the new tuple into the specified slot.
	 */
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	if (shouldFree)
		slot->tts_flags |= TTS_FLAG_SHOULDZFREE;
	slot->tts_ztuple = tuple;
	slot->tts_tuple = NULL;
	slot->tts_mintuple = NULL;

	/* Mark extracted state invalid */
	slot->tts_nvalid = 0;

	/*
	 * If tuple is on a disk page, keep the page pinned as long as we hold a
	 * pointer into it.  We assume the caller already has such a pin.
	 *
	 * This is coded to optimize the case where the slot previously held a
	 * tuple on the same disk page: in that case releasing and re-acquiring
	 * the pin is a waste of cycles.  This is a common situation during
	 * seqscans, so it's worth troubling over.
	 */
	if (slot->tts_buffer != buffer)
	{
		if (BufferIsValid(slot->tts_buffer))
			ReleaseBuffer(slot->tts_buffer);
		slot->tts_buffer = buffer;
		if (BufferIsValid(buffer))
			IncrBufferRefCount(buffer);
	}

	return slot;
}

/* --------------------------------
 *		ExecStoreMinimalTuple
 *
 *		Like ExecStoreHeapTuple, but insert a "minimal" tuple into the slot.
 *
 * No 'buffer' parameter since minimal tuples are never stored in relations.
 * --------------------------------
 */
TupleTableSlot *
ExecStoreMinimalTuple(MinimalTuple mtup,
					  TupleTableSlot *slot,
					  bool shouldFree)
{
	/*
	 * sanity checks
	 */
	Assert(mtup != NULL);
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);

	/*
	 * Free any old physical tuple belonging to the slot.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		heap_freetuple(slot->tts_tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}
	if (TTS_SHOULDZFREE(slot))
	{
		zheap_freetuple(slot->tts_ztuple);
		slot->tts_ztuple = NULL;
		slot->tts_flags &= ~TTS_FLAG_SHOULDZFREE;
	}
	if (TTS_SHOULDFREEMIN(slot))
	{
		heap_free_minimal_tuple(slot->tts_mintuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREEMIN;
	}

	/*
	 * Drop the pin on the referenced buffer, if there is one.
	 */
	if (BufferIsValid(slot->tts_buffer))
		ReleaseBuffer(slot->tts_buffer);

	slot->tts_buffer = InvalidBuffer;

	/*
	 * Store the new tuple into the specified slot.
	 */
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	if (shouldFree)
		slot->tts_flags |= TTS_FLAG_SHOULDFREEMIN;

	slot->tts_tuple = &slot->tts_minhdr;
	slot->tts_mintuple = mtup;

	slot->tts_minhdr.t_len = mtup->t_len + MINIMAL_TUPLE_OFFSET;
	slot->tts_minhdr.t_data = (HeapTupleHeader) ((char *) mtup - MINIMAL_TUPLE_OFFSET);
	/* no need to set t_self or t_tableOid since we won't allow access */

	/* Mark extracted state invalid */
	slot->tts_nvalid = 0;

	return slot;
}

/* --------------------------------
 *		ExecClearTuple
 *
 *		This function is used to clear out a slot in the tuple table.
 *
 *		NB: only the tuple is cleared, not the tuple descriptor (if any).
 * --------------------------------
 */
TupleTableSlot *				/* return: slot passed */
ExecClearTuple(TupleTableSlot *slot)	/* slot in which to store tuple */
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);

	/*
	 * Free the old physical tuple if necessary.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		heap_freetuple(slot->tts_tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}
	if (TTS_SHOULDZFREE(slot))
	{
		zheap_freetuple(slot->tts_ztuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDZFREE;
	}
	if (TTS_SHOULDFREEMIN(slot))
	{
		heap_free_minimal_tuple(slot->tts_mintuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREEMIN;
	}	
	

	slot->tts_ztuple = NULL;
	slot->tts_tuple = NULL;
	slot->tts_mintuple = NULL;

	/*
	 * Drop the pin on the referenced buffer, if there is one.
	 */
	if (BufferIsValid(slot->tts_buffer))
		ReleaseBuffer(slot->tts_buffer);

	slot->tts_buffer = InvalidBuffer;

	/*
	 * Mark it empty.
	 */
	slot->tts_flags |= TTS_FLAG_EMPTY;
	slot->tts_nvalid = 0;

	return slot;
}

/* --------------------------------
 *		ExecStoreVirtualTuple
 *			Mark a slot as containing a virtual tuple.
 *
 * The protocol for loading a slot with virtual tuple data is:
 *		* Call ExecClearTuple to mark the slot empty.
 *		* Store data into the Datum/isnull arrays.
 *		* Call ExecStoreVirtualTuple to mark the slot valid.
 * This is a bit unclean but it avoids one round of data copying.
 * --------------------------------
 */
TupleTableSlot *
ExecStoreVirtualTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);
	Assert(TTS_EMPTY(slot));

	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	slot->tts_nvalid = slot->tts_tupleDescriptor->natts;

	return slot;
}

/* --------------------------------
 *		ExecStoreAllNullTuple
 *			Set up the slot to contain a null in every column.
 *
 * At first glance this might sound just like ExecClearTuple, but it's
 * entirely different: the slot ends up full, not empty.
 * --------------------------------
 */
TupleTableSlot *
ExecStoreAllNullTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(slot->tts_tupleDescriptor != NULL);

	/* Clear any old contents */
	ExecClearTuple(slot);

	/*
	 * Fill all the columns of the virtual tuple with nulls
	 */
	MemSet(slot->tts_values, 0,
		   slot->tts_tupleDescriptor->natts * sizeof(Datum));
	memset(slot->tts_isnull, true,
		   slot->tts_tupleDescriptor->natts * sizeof(bool));

	return ExecStoreVirtualTuple(slot);
}

/* --------------------------------
 *		ExecCopySlotTuple
 *			Obtain a copy of a slot's regular physical tuple.  The copy is
 *			palloc'd in the current memory context.
 *			The slot itself is undisturbed.
 *
 *		This works even if the slot contains a virtual or minimal tuple;
 *		however the "system columns" of the result will not be meaningful.
 * --------------------------------
 */
HeapTuple
ExecCopySlotTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a physical tuple (either format) then just copy it.
	 */
	if (TTS_HAS_PHYSICAL_TUPLE(slot))
		return heap_copytuple(slot->tts_tuple);
	if (slot->tts_mintuple)
		return heap_tuple_from_minimal_tuple(slot->tts_mintuple);

	/*
	 * FIXME: Executor nodes don't recognize zheap tuples as of now. If it's
	 * a zheap tuple, deform it.
	 */
	if (slot->tts_ztuple != NULL)
		zheap_deform_tuple(slot->tts_ztuple, slot->tts_tupleDescriptor,
						  slot->tts_values, slot->tts_isnull);
	/*
	 * Otherwise we need to build a tuple from the Datum array.
	 */
	return heap_form_tuple(slot->tts_tupleDescriptor,
						   slot->tts_values,
						   slot->tts_isnull);
}

/* --------------------------------
 *		ExecCopySlotZTuple
 *
 *		Similar to ExecCopySlotTuple. Notice that physical tuple and minimal
 *		tuple only works with heap tuple. Hence, we convert this to heap tuple
 *		and subsequently convert this to zheap tuple.
 * --------------------------------
 */
ZHeapTuple
ExecCopySlotZTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a physical tuple (either format) then just copy it.
	 */
	if (TTS_HAS_PHYSICAL_TUPLE(slot))
		slot->tts_tuple = heap_copytuple(slot->tts_tuple);
	else if (slot->tts_mintuple)
		slot->tts_tuple = heap_tuple_from_minimal_tuple(slot->tts_mintuple);

	if (slot->tts_tuple != NULL)
		heap_deform_tuple(slot->tts_tuple, slot->tts_tupleDescriptor,
						  slot->tts_values, slot->tts_isnull);

	return zheap_form_tuple(slot->tts_tupleDescriptor,
						   slot->tts_values,
						   slot->tts_isnull);
}

/* --------------------------------
 *		ExecCopySlotMinimalTuple
 *			Obtain a copy of a slot's minimal physical tuple.  The copy is
 *			palloc'd in the current memory context.
 *			The slot itself is undisturbed.
 * --------------------------------
 */
MinimalTuple
ExecCopySlotMinimalTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a physical tuple then just copy it.  Prefer to copy
	 * tts_mintuple since that's a tad cheaper.
	 */
	if (slot->tts_mintuple)
		return heap_copy_minimal_tuple(slot->tts_mintuple);
	if (slot->tts_tuple)
	{
		if (HeapTupleHeaderGetNatts(slot->tts_tuple->t_data)
			< slot->tts_tupleDescriptor->natts)
			return minimal_expand_tuple(slot->tts_tuple,
										slot->tts_tupleDescriptor);
		else
			return minimal_tuple_from_heap_tuple(slot->tts_tuple);
	}

	/*
	 * FIXME: Executor nodes don't recognize zheap tuples as of now. If it's
	 * a zheap tuple, deform it.
	 */
	if (slot->tts_ztuple != NULL)
		zheap_deform_tuple(slot->tts_ztuple, slot->tts_tupleDescriptor,
						  slot->tts_values, slot->tts_isnull);

	/*
	 * Otherwise we need to build a tuple from the Datum array.
	 */
	return heap_form_minimal_tuple(slot->tts_tupleDescriptor,
								   slot->tts_values,
								   slot->tts_isnull);
}

/* --------------------------------
 *		ExecFetchSlotTuple
 *			Fetch the slot's regular physical tuple.
 *
 *		If the slot contains a virtual tuple, we convert it to physical
 *		form.  The slot retains ownership of the physical tuple.
 *		If it contains a minimal tuple we convert to regular form and store
 *		that in addition to the minimal tuple (not instead of, because
 *		callers may hold pointers to Datums within the minimal tuple).
 *
 * The main difference between this and ExecMaterializeSlot() is that this
 * does not guarantee that the contained tuple is local storage.
 * Hence, the result must be treated as read-only.
 * --------------------------------
 */
HeapTuple
ExecFetchSlotTuple(TupleTableSlot *slot)
{
	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a regular physical tuple then just return it.
	 */
	if (TTS_HAS_PHYSICAL_TUPLE(slot))
	{
		if (HeapTupleHeaderGetNatts(slot->tts_tuple->t_data) <
			slot->tts_tupleDescriptor->natts)
		{
			HeapTuple	tuple;
			MemoryContext oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

			tuple = heap_expand_tuple(slot->tts_tuple,
									  slot->tts_tupleDescriptor);
			MemoryContextSwitchTo(oldContext);
			slot = ExecStoreHeapTuple(tuple, slot, true);
		}
		return slot->tts_tuple;
	}

	/*
	 * Otherwise materialize the slot...
	 */
	return ExecMaterializeSlot(slot);
}

/* --------------------------------
 *		ExecFetchSlotMinimalTuple
 *			Fetch the slot's minimal physical tuple.
 *
 *		If the slot contains a virtual tuple, we convert it to minimal
 *		physical form.  The slot retains ownership of the minimal tuple.
 *		If it contains a regular tuple we convert to minimal form and store
 *		that in addition to the regular tuple (not instead of, because
 *		callers may hold pointers to Datums within the regular tuple).
 *
 * As above, the result must be treated as read-only.
 * --------------------------------
 */
MinimalTuple
ExecFetchSlotMinimalTuple(TupleTableSlot *slot)
{
	MemoryContext oldContext;

	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));


	/*
	 * If we have a minimal physical tuple (local or not) then just return it.
	 */
	if (slot->tts_mintuple)
		return slot->tts_mintuple;

	/*
	 * Otherwise, copy or build a minimal tuple, and store it into the slot.
	 *
	 * We may be called in a context that is shorter-lived than the tuple
	 * slot, but we have to ensure that the materialized tuple will survive
	 * anyway.
	 */
	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);
	slot->tts_mintuple = ExecCopySlotMinimalTuple(slot);
	slot->tts_flags |= TTS_FLAG_SHOULDFREEMIN;
	MemoryContextSwitchTo(oldContext);

	/*
	 * Note: we may now have a situation where we have a local minimal tuple
	 * attached to a virtual or non-local physical tuple.  There seems no harm
	 * in that at the moment, but if any materializes, we should change this
	 * function to force the slot into minimal-tuple-only state.
	 */

	return slot->tts_mintuple;
}

/* --------------------------------
 *		ExecFetchSlotTupleDatum
 *			Fetch the slot's tuple as a composite-type Datum.
 *
 *		The result is always freshly palloc'd in the caller's memory context.
 * --------------------------------
 */
Datum
ExecFetchSlotTupleDatum(TupleTableSlot *slot)
{
	HeapTuple	tup;
	TupleDesc	tupdesc;

	/* Fetch slot's contents in regular-physical-tuple form */
	tup = ExecFetchSlotTuple(slot);
	tupdesc = slot->tts_tupleDescriptor;

	/* Convert to Datum form */
	return heap_copy_tuple_as_datum(tup, tupdesc);
}

/* --------------------------------
 *		ExecMaterializeSlot
 *			Force a slot into the "materialized" state.
 *
 *		This causes the slot's tuple to be a local copy not dependent on
 *		any external storage.  A pointer to the contained tuple is returned.
 *
 *		A typical use for this operation is to prepare a computed tuple
 *		for being stored on disk.  The original data may or may not be
 *		virtual, but in any case we need a private copy for heap_insert
 *		to scribble on.
 * --------------------------------
 */
HeapTuple
ExecMaterializeSlot(TupleTableSlot *slot)
{
	MemoryContext oldContext;

	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a regular physical tuple, and it's locally palloc'd, we have
	 * nothing to do.
	 */
	if (slot->tts_tuple && TTS_SHOULDFREE(slot))
		return slot->tts_tuple;

	/*
	 * Otherwise, copy or build a physical tuple, and store it into the slot.
	 *
	 * We may be called in a context that is shorter-lived than the tuple
	 * slot, but we have to ensure that the materialized tuple will survive
	 * anyway.
	 */
	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);
	slot->tts_tuple = ExecCopySlotTuple(slot);
	slot->tts_flags |= TTS_FLAG_SHOULDFREE;
	MemoryContextSwitchTo(oldContext);

	/*
	 * Drop the pin on the referenced buffer, if there is one.
	 */
	if (BufferIsValid(slot->tts_buffer))
		ReleaseBuffer(slot->tts_buffer);

	slot->tts_buffer = InvalidBuffer;

	/*
	 * Mark extracted state invalid.  This is important because the slot is
	 * not supposed to depend any more on the previous external data; we
	 * mustn't leave any dangling pass-by-reference datums in tts_values.
	 * However, we have not actually invalidated any such datums, if there
	 * happen to be any previously fetched from the slot.  (Note in particular
	 * that we have not pfree'd tts_mintuple, if there is one.)
	 */
	slot->tts_nvalid = 0;

	/*
	 * On the same principle of not depending on previous remote storage,
	 * forget the mintuple if it's not local storage.  (If it is local
	 * storage, we must not pfree it now, since callers might have already
	 * fetched datum pointers referencing it.)
	 */
	if (!TTS_SHOULDFREEMIN(slot))
		slot->tts_mintuple = NULL;

	return slot->tts_tuple;
}

/* --------------------------------
 *		ExecMaterializeZSlot
 *			This is same as ExecMaterializeSlot except for tuple type.
 * --------------------------------
 */
ZHeapTuple
ExecMaterializeZSlot(TupleTableSlot *slot)
{
	MemoryContext oldContext;

	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(!TTS_EMPTY(slot));

	/*
	 * If we have a regular physical tuple, and it's locally palloc'd (which
	 * is always true in case of zheap), we have  nothing to do.
	 */
	if (slot->tts_ztuple)
		return slot->tts_ztuple;

	/*
	 * Otherwise, copy or build a physical tuple, and store it into the slot.
	 *
	 * We may be called in a context that is shorter-lived than the tuple
	 * slot, but we have to ensure that the materialized tuple will survive
	 * anyway.
	 */
	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);
	slot->tts_ztuple = ExecCopySlotZTuple(slot);
	slot->tts_flags |= TTS_FLAG_SHOULDZFREE;
	MemoryContextSwitchTo(oldContext);

	/*
	 * Drop the pin on the referenced buffer, if there is one.
	 */
	if (BufferIsValid(slot->tts_buffer))
		ReleaseBuffer(slot->tts_buffer);

	slot->tts_buffer = InvalidBuffer;

	/*
	 * Mark extracted state invalid.  This is important because the slot is
	 * not supposed to depend any more on the previous external data; we
	 * mustn't leave any dangling pass-by-reference datums in tts_values.
	 * However, we have not actually invalidated any such datums, if there
	 * happen to be any previously fetched from the slot.  (Note in particular
	 * that we have not pfree'd tts_mintuple, if there is one.)
	 */
	slot->tts_nvalid = 0;

	/*
	 * On the same principle of not depending on previous remote storage,
	 * forget the mintuple if it's not local storage.  (If it is local
	 * storage, we must not pfree it now, since callers might have already
	 * fetched datum pointers referencing it.)
	 */
	if (!TTS_SHOULDFREEMIN(slot))
		slot->tts_mintuple = NULL;

	return slot->tts_ztuple;
}

/* --------------------------------
 *		ExecCopySlot
 *			Copy the source slot's contents into the destination slot.
 *
 *		The destination acquires a private copy that will not go away
 *		if the source is cleared.
 *
 *		The caller must ensure the slots have compatible tupdescs.
 * --------------------------------
 */
TupleTableSlot *
ExecCopySlot(TupleTableSlot *dstslot, TupleTableSlot *srcslot)
{
	HeapTuple	newTuple;
	MemoryContext oldContext;

	/*
	 * There might be ways to optimize this when the source is virtual, but
	 * for now just always build a physical copy.  Make sure it is in the
	 * right context.
	 */
	oldContext = MemoryContextSwitchTo(dstslot->tts_mcxt);
	newTuple = ExecCopySlotTuple(srcslot);
	MemoryContextSwitchTo(oldContext);

	return ExecStoreHeapTuple(newTuple, dstslot, true);
}


/* ----------------------------------------------------------------
 *				convenience initialization routines
 * ----------------------------------------------------------------
 */

/* ----------------
 *		ExecInitResultTypeTL
 *
 *		Initialize result type, using the plan node's targetlist.
 * ----------------
 */
void
ExecInitResultTypeTL(PlanState *planstate)
{
	bool		hasoid;
	TupleDesc	tupDesc;

	if (ExecContextForcesOids(planstate, &hasoid))
	{
		/* context forces OID choice; hasoid is now set correctly */
	}
	else
	{
		/* given free choice, don't leave space for OIDs in result tuples */
		hasoid = false;
	}

	tupDesc = ExecTypeFromTL(planstate->plan->targetlist, hasoid);
	planstate->ps_ResultTupleDesc = tupDesc;
}

/* --------------------------------
 *		ExecInit{Result,Scan,Extra}TupleSlot[TL]
 *
 *		These are convenience routines to initialize the specified slot
 *		in nodes inheriting the appropriate state.  ExecInitExtraTupleSlot
 *		is used for initializing special-purpose slots.
 * --------------------------------
 */

/* ----------------
 *		ExecInitResultTupleSlotTL
 *
 *		Initialize result tuple slot, using the tuple descriptor previously
 *		computed with ExecInitResultTypeTL().
 * ----------------
 */
void
ExecInitResultSlot(PlanState *planstate)
{
	TupleTableSlot *slot;

	slot = ExecAllocTableSlot(&planstate->state->es_tupleTable,
							  planstate->ps_ResultTupleDesc);
	planstate->ps_ResultTupleSlot = slot;
}

/* ----------------
 *		ExecInitResultTupleSlotTL
 *
 *		Initialize result tuple slot, using the plan node's targetlist.
 * ----------------
 */
void
ExecInitResultTupleSlotTL(PlanState *planstate)
{
	ExecInitResultTypeTL(planstate);
	ExecInitResultSlot(planstate);
}

/* ----------------
 *		ExecInitScanTupleSlot
 * ----------------
 */
void
ExecInitScanTupleSlot(EState *estate, ScanState *scanstate, TupleDesc tupledesc)
{
	scanstate->ss_ScanTupleSlot = ExecAllocTableSlot(&estate->es_tupleTable,
													 tupledesc);
	scanstate->ps.scandesc = tupledesc;
}

/* ----------------
 *		ExecInitExtraTupleSlot
 *
 * Return a newly created slot. If tupledesc is non-NULL the slot will have
 * that as its fixed tupledesc. Otherwise the caller needs to use
 * ExecSetSlotDescriptor() to set the descriptor before use.
 * ----------------
 */
TupleTableSlot *
ExecInitExtraTupleSlot(EState *estate, TupleDesc tupledesc)
{
	return ExecAllocTableSlot(&estate->es_tupleTable, tupledesc);
}

/* ----------------
 *		ExecInitNullTupleSlot
 *
 * Build a slot containing an all-nulls tuple of the given type.
 * This is used as a substitute for an input tuple when performing an
 * outer join.
 * ----------------
 */
TupleTableSlot *
ExecInitNullTupleSlot(EState *estate, TupleDesc tupType)
{
	TupleTableSlot *slot = ExecInitExtraTupleSlot(estate, tupType);

	return ExecStoreAllNullTuple(slot);
}

/* ---------------------------------------------------------------
 *      Routines for setting/accessing attributes in a slot.
 * ---------------------------------------------------------------
 */

/*
 * Fill in missing values for a TupleTableSlot.
 *
 * This is only exposed because it's needed for JIT compiled tuple
 * deforming. That exception aside, there should be no callers outside of this
 * file.
 */
void
slot_getmissingattrs(TupleTableSlot *slot, int startAttNum, int lastAttNum)
{
	AttrMissing *attrmiss = NULL;
	int			missattnum;

	if (slot->tts_tupleDescriptor->constr)
		attrmiss = slot->tts_tupleDescriptor->constr->missing;

	if (!attrmiss)
	{
		/* no missing values array at all, so just fill everything in as NULL */
		memset(slot->tts_values + startAttNum, 0,
			   (lastAttNum - startAttNum) * sizeof(Datum));
		memset(slot->tts_isnull + startAttNum, 1,
			   (lastAttNum - startAttNum) * sizeof(bool));
	}
	else
	{
		/* if there is a missing values array we must process them one by one */
		for (missattnum = startAttNum;
			 missattnum < lastAttNum;
			 missattnum++)
		{
			slot->tts_values[missattnum] = attrmiss[missattnum].am_value;
			slot->tts_isnull[missattnum] = !attrmiss[missattnum].am_present;
		}
	}
}

/*
 * slot_getattr
 *		This function fetches an attribute of the slot's current tuple.
 *		It is functionally equivalent to heap_getattr, but fetches of
 *		multiple attributes of the same tuple will be optimized better,
 *		because we avoid O(N^2) behavior from multiple calls of
 *		nocachegetattr(), even when attcacheoff isn't usable.
 *
 *		A difference from raw heap_getattr is that attnums beyond the
 *		slot's tupdesc's last attribute will be considered NULL even
 *		when the physical tuple is longer than the tupdesc.
 */
Datum
slot_getattr(TupleTableSlot *slot, int attnum, bool *isnull)
{
	TupleDesc	tupleDesc = slot->tts_tupleDescriptor;
	HeapTupleHeader tup;
	ZHeapTupleHeader ztup;
	HeapTuple	tuple = NULL;
	ZHeapTuple	ztuple = NULL;

	/*
	 * Tuple can be either a heap tuple or a zheap tuple.
	 */
	if (slot->tts_ztuple)
		ztuple = slot->tts_ztuple;
	else
		tuple = slot->tts_tuple;

	/*
	 * system attributes are handled by heap_getsysattr
	 */
	if (attnum <= 0)
	{
		if (tuple == NULL && ztuple == NULL)		/* internal error */
			elog(ERROR, "cannot extract system attribute from virtual tuple");
		if (tuple == &(slot->tts_minhdr))	/* internal error */
			elog(ERROR, "cannot extract system attribute from minimal tuple");

		if (ztuple)
			return zheap_getsysattr(ztuple, slot->tts_buffer, attnum, tupleDesc, isnull);
		else
			return heap_getsysattr(tuple, attnum, tupleDesc, isnull);
	}

	/*
	 * fast path if desired attribute already cached
	 */
	if (attnum <= slot->tts_nvalid)
	{
		*isnull = slot->tts_isnull[attnum - 1];
		return slot->tts_values[attnum - 1];
	}

	/*
	 * return NULL if attnum is out of range according to the tupdesc
	 */
	if (attnum > tupleDesc->natts)
	{
		*isnull = true;
		return (Datum) 0;
	}

	/*
	 * otherwise we had better have a physical tuple (tts_nvalid should equal
	 * natts in all virtual-tuple cases)
	 */
	if (ztuple == NULL && tuple == NULL)			/* internal error */
		elog(ERROR, "cannot extract attribute from empty tuple slot");

	/*
	 * return NULL or missing value if attnum is out of range according to the
	 * tuple
	 *
	 * (We have to check this separately because of various inheritance and
	 * table-alteration scenarios: the tuple could be either longer or shorter
	 * than the tupdesc.)
	 */
	if (ztuple)
		ztup = ztuple->t_data;
	else
		tup = tuple->t_data;

	if (ztuple)
	{
		if (attnum > ZHeapTupleHeaderGetNatts(ztup))
			return getmissingattr(slot->tts_tupleDescriptor, attnum, isnull);
	}
	else if (attnum > HeapTupleHeaderGetNatts(tup))
		return getmissingattr(slot->tts_tupleDescriptor, attnum, isnull);

	/*
	 * check if target attribute is null: no point in groveling through tuple
	 */
	if (ztuple)
	{
		if (ZHeapTupleHasNulls(ztuple) && att_isnull(attnum - 1, ztup->t_bits))
		{
			*isnull = true;
			return (Datum) 0;
		}
	}
	else if (HeapTupleHasNulls(tuple) && att_isnull(attnum - 1, tup->t_bits))
	{
		*isnull = true;
		return (Datum) 0;
	}

	/*
	 * Extract the attribute, along with any preceding attributes.
	 */
	slot_deform_tuple(slot, attnum);

	/*
	 * The result is acquired from tts_values array.
	 */
	*isnull = slot->tts_isnull[attnum - 1];
	return slot->tts_values[attnum - 1];
}

/*
 * slot_getsomeattrs
 *		This function forces the entries of the slot's Datum/isnull
 *		arrays to be valid at least up through the attnum'th entry.
 */
void
slot_getsomeattrs(TupleTableSlot *slot, int attnum)
{
	HeapTuple	tuple = NULL;
	ZHeapTuple	ztuple = NULL;
	int			attno;

	/*
	 * Tuple can be either a heap tuple or a zheap tuple.
	 */
	if (slot->tts_ztuple)
		ztuple = slot->tts_ztuple;
	else
		tuple = slot->tts_tuple;

	/* Quick out if we have 'em all already */
	if (slot->tts_nvalid >= attnum)
		return;

	/* Check for caller error */
	if (attnum <= 0 || attnum > slot->tts_tupleDescriptor->natts)
		elog(ERROR, "invalid attribute number %d", attnum);

	/*
	 * otherwise we had better have a physical tuple (tts_nvalid should equal
	 * natts in all virtual-tuple cases)
	 */
	if (ztuple == NULL && tuple == NULL)			/* internal error */
		elog(ERROR, "cannot extract attribute from empty tuple slot");

	/*
	 * load up any slots available from physical tuple
	 */
	if (ztuple)
		attno = ZHeapTupleHeaderGetNatts(ztuple->t_data);
	else
		attno = HeapTupleHeaderGetNatts(tuple->t_data);

	attno = Min(attno, attnum);

	slot_deform_tuple(slot, attno);

	attno = slot->tts_nvalid;

	/*
	 * If tuple doesn't have all the atts indicated by attnum, read the rest
	 * as NULLs or missing values
	 */
	if (attno < attnum)
		slot_getmissingattrs(slot, attno, attnum);

	slot->tts_nvalid = attnum;
}

/* ----------------------------------------------------------------
 *		ExecTypeFromTL
 *
 *		Generate a tuple descriptor for the result tuple of a targetlist.
 *		(A parse/plan tlist must be passed, not an ExprState tlist.)
 *		Note that resjunk columns, if any, are included in the result.
 *
 *		Currently there are about 4 different places where we create
 *		TupleDescriptors.  They should all be merged, or perhaps
 *		be rewritten to call BuildDesc().
 * ----------------------------------------------------------------
 */
TupleDesc
ExecTypeFromTL(List *targetList, bool hasoid)
{
	return ExecTypeFromTLInternal(targetList, hasoid, false);
}

/* ----------------------------------------------------------------
 *		ExecCleanTypeFromTL
 *
 *		Same as above, but resjunk columns are omitted from the result.
 * ----------------------------------------------------------------
 */
TupleDesc
ExecCleanTypeFromTL(List *targetList, bool hasoid)
{
	return ExecTypeFromTLInternal(targetList, hasoid, true);
}

static TupleDesc
ExecTypeFromTLInternal(List *targetList, bool hasoid, bool skipjunk)
{
	TupleDesc	typeInfo;
	ListCell   *l;
	int			len;
	int			cur_resno = 1;

	if (skipjunk)
		len = ExecCleanTargetListLength(targetList);
	else
		len = ExecTargetListLength(targetList);
	typeInfo = CreateTemplateTupleDesc(len, hasoid);

	foreach(l, targetList)
	{
		TargetEntry *tle = lfirst(l);

		if (skipjunk && tle->resjunk)
			continue;
		TupleDescInitEntry(typeInfo,
						   cur_resno,
						   tle->resname,
						   exprType((Node *) tle->expr),
						   exprTypmod((Node *) tle->expr),
						   0);
		TupleDescInitEntryCollation(typeInfo,
									cur_resno,
									exprCollation((Node *) tle->expr));
		cur_resno++;
	}

	return typeInfo;
}

/*
 * ExecTypeFromExprList - build a tuple descriptor from a list of Exprs
 *
 * This is roughly like ExecTypeFromTL, but we work from bare expressions
 * not TargetEntrys.  No names are attached to the tupledesc's columns.
 */
TupleDesc
ExecTypeFromExprList(List *exprList)
{
	TupleDesc	typeInfo;
	ListCell   *lc;
	int			cur_resno = 1;

	typeInfo = CreateTemplateTupleDesc(list_length(exprList), false);

	foreach(lc, exprList)
	{
		Node	   *e = lfirst(lc);

		TupleDescInitEntry(typeInfo,
						   cur_resno,
						   NULL,
						   exprType(e),
						   exprTypmod(e),
						   0);
		TupleDescInitEntryCollation(typeInfo,
									cur_resno,
									exprCollation(e));
		cur_resno++;
	}

	return typeInfo;
}

/*
 * ExecTypeSetColNames - set column names in a TupleDesc
 *
 * Column names must be provided as an alias list (list of String nodes).
 *
 * For some callers, the supplied tupdesc has a named rowtype (not RECORD)
 * and it is moderately likely that the alias list matches the column names
 * already present in the tupdesc.  If we do change any column names then
 * we must reset the tupdesc's type to anonymous RECORD; but we avoid doing
 * so if no names change.
 */
void
ExecTypeSetColNames(TupleDesc typeInfo, List *namesList)
{
	bool		modified = false;
	int			colno = 0;
	ListCell   *lc;

	foreach(lc, namesList)
	{
		char	   *cname = strVal(lfirst(lc));
		Form_pg_attribute attr;

		/* Guard against too-long names list */
		if (colno >= typeInfo->natts)
			break;
		attr = TupleDescAttr(typeInfo, colno);
		colno++;

		/* Ignore empty aliases (these must be for dropped columns) */
		if (cname[0] == '\0')
			continue;

		/* Change tupdesc only if alias is actually different */
		if (strcmp(cname, NameStr(attr->attname)) != 0)
		{
			namestrcpy(&(attr->attname), cname);
			modified = true;
		}
	}

	/* If we modified the tupdesc, it's now a new record type */
	if (modified)
	{
		typeInfo->tdtypeid = RECORDOID;
		typeInfo->tdtypmod = -1;
	}
}

/*
 * BlessTupleDesc - make a completed tuple descriptor useful for SRFs
 *
 * Rowtype Datums returned by a function must contain valid type information.
 * This happens "for free" if the tupdesc came from a relcache entry, but
 * not if we have manufactured a tupdesc for a transient RECORD datatype.
 * In that case we have to notify typcache.c of the existence of the type.
 */
TupleDesc
BlessTupleDesc(TupleDesc tupdesc)
{
	if (tupdesc->tdtypeid == RECORDOID &&
		tupdesc->tdtypmod < 0)
		assign_record_type_typmod(tupdesc);

	return tupdesc;				/* just for notational convenience */
}

/*
 * TupleDescGetAttInMetadata - Build an AttInMetadata structure based on the
 * supplied TupleDesc. AttInMetadata can be used in conjunction with C strings
 * to produce a properly formed tuple.
 */
AttInMetadata *
TupleDescGetAttInMetadata(TupleDesc tupdesc)
{
	int			natts = tupdesc->natts;
	int			i;
	Oid			atttypeid;
	Oid			attinfuncid;
	FmgrInfo   *attinfuncinfo;
	Oid		   *attioparams;
	int32	   *atttypmods;
	AttInMetadata *attinmeta;

	attinmeta = (AttInMetadata *) palloc(sizeof(AttInMetadata));

	/* "Bless" the tupledesc so that we can make rowtype datums with it */
	attinmeta->tupdesc = BlessTupleDesc(tupdesc);

	/*
	 * Gather info needed later to call the "in" function for each attribute
	 */
	attinfuncinfo = (FmgrInfo *) palloc0(natts * sizeof(FmgrInfo));
	attioparams = (Oid *) palloc0(natts * sizeof(Oid));
	atttypmods = (int32 *) palloc0(natts * sizeof(int32));

	for (i = 0; i < natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);

		/* Ignore dropped attributes */
		if (!att->attisdropped)
		{
			atttypeid = att->atttypid;
			getTypeInputInfo(atttypeid, &attinfuncid, &attioparams[i]);
			fmgr_info(attinfuncid, &attinfuncinfo[i]);
			atttypmods[i] = att->atttypmod;
		}
	}
	attinmeta->attinfuncs = attinfuncinfo;
	attinmeta->attioparams = attioparams;
	attinmeta->atttypmods = atttypmods;

	return attinmeta;
}

/*
 * BuildTupleFromCStrings - build a HeapTuple given user data in C string form.
 * values is an array of C strings, one for each attribute of the return tuple.
 * A NULL string pointer indicates we want to create a NULL field.
 */
HeapTuple
BuildTupleFromCStrings(AttInMetadata *attinmeta, char **values)
{
	TupleDesc	tupdesc = attinmeta->tupdesc;
	int			natts = tupdesc->natts;
	Datum	   *dvalues;
	bool	   *nulls;
	int			i;
	HeapTuple	tuple;

	dvalues = (Datum *) palloc(natts * sizeof(Datum));
	nulls = (bool *) palloc(natts * sizeof(bool));

	/*
	 * Call the "in" function for each non-dropped attribute, even for nulls,
	 * to support domains.
	 */
	for (i = 0; i < natts; i++)
	{
		if (!TupleDescAttr(tupdesc, i)->attisdropped)
		{
			/* Non-dropped attributes */
			dvalues[i] = InputFunctionCall(&attinmeta->attinfuncs[i],
										   values[i],
										   attinmeta->attioparams[i],
										   attinmeta->atttypmods[i]);
			if (values[i] != NULL)
				nulls[i] = false;
			else
				nulls[i] = true;
		}
		else
		{
			/* Handle dropped attributes by setting to NULL */
			dvalues[i] = (Datum) 0;
			nulls[i] = true;
		}
	}

	/*
	 * Form a tuple
	 */
	tuple = heap_form_tuple(tupdesc, dvalues, nulls);

	/*
	 * Release locally palloc'd space.  XXX would probably be good to pfree
	 * values of pass-by-reference datums, as well.
	 */
	pfree(dvalues);
	pfree(nulls);

	return tuple;
}

/*
 * HeapTupleHeaderGetDatum - convert a HeapTupleHeader pointer to a Datum.
 *
 * This must *not* get applied to an on-disk tuple; the tuple should be
 * freshly made by heap_form_tuple or some wrapper routine for it (such as
 * BuildTupleFromCStrings).  Be sure also that the tupledesc used to build
 * the tuple has a properly "blessed" rowtype.
 *
 * Formerly this was a macro equivalent to PointerGetDatum, relying on the
 * fact that heap_form_tuple fills in the appropriate tuple header fields
 * for a composite Datum.  However, we now require that composite Datums not
 * contain any external TOAST pointers.  We do not want heap_form_tuple itself
 * to enforce that; more specifically, the rule applies only to actual Datums
 * and not to HeapTuple structures.  Therefore, HeapTupleHeaderGetDatum is
 * now a function that detects whether there are externally-toasted fields
 * and constructs a new tuple with inlined fields if so.  We still need
 * heap_form_tuple to insert the Datum header fields, because otherwise this
 * code would have no way to obtain a tupledesc for the tuple.
 *
 * Note that if we do build a new tuple, it's palloc'd in the current
 * memory context.  Beware of code that changes context between the initial
 * heap_form_tuple/etc call and calling HeapTuple(Header)GetDatum.
 *
 * For performance-critical callers, it could be worthwhile to take extra
 * steps to ensure that there aren't TOAST pointers in the output of
 * heap_form_tuple to begin with.  It's likely however that the costs of the
 * typcache lookup and tuple disassembly/reassembly are swamped by TOAST
 * dereference costs, so that the benefits of such extra effort would be
 * minimal.
 *
 * XXX it would likely be better to create wrapper functions that produce
 * a composite Datum from the field values in one step.  However, there's
 * enough code using the existing APIs that we couldn't get rid of this
 * hack anytime soon.
 */
Datum
HeapTupleHeaderGetDatum(HeapTupleHeader tuple)
{
	Datum		result;
	TupleDesc	tupDesc;

	/* No work if there are no external TOAST pointers in the tuple */
	if (!HeapTupleHeaderHasExternal(tuple))
		return PointerGetDatum(tuple);

	/* Use the type data saved by heap_form_tuple to look up the rowtype */
	tupDesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(tuple),
									 HeapTupleHeaderGetTypMod(tuple));

	/* And do the flattening */
	result = toast_flatten_tuple_to_datum(tuple,
										  HeapTupleHeaderGetDatumLength(tuple),
										  tupDesc);

	ReleaseTupleDesc(tupDesc);

	return result;
}


/*
 * Functions for sending tuples to the frontend (or other specified destination)
 * as though it is a SELECT result. These are used by utility commands that
 * need to project directly to the destination and don't need or want full
 * table function capability. Currently used by EXPLAIN and SHOW ALL.
 */
TupOutputState *
begin_tup_output_tupdesc(DestReceiver *dest, TupleDesc tupdesc)
{
	TupOutputState *tstate;

	tstate = (TupOutputState *) palloc(sizeof(TupOutputState));

	tstate->slot = MakeSingleTupleTableSlot(tupdesc);
	tstate->dest = dest;

	tstate->dest->rStartup(tstate->dest, (int) CMD_SELECT, tupdesc);

	return tstate;
}

/*
 * write a single tuple
 */
void
do_tup_output(TupOutputState *tstate, Datum *values, bool *isnull)
{
	TupleTableSlot *slot = tstate->slot;
	int			natts = slot->tts_tupleDescriptor->natts;

	/* make sure the slot is clear */
	ExecClearTuple(slot);

	/* insert data */
	memcpy(slot->tts_values, values, natts * sizeof(Datum));
	memcpy(slot->tts_isnull, isnull, natts * sizeof(bool));

	/* mark slot as containing a virtual tuple */
	ExecStoreVirtualTuple(slot);

	/* send the tuple to the receiver */
	(void) tstate->dest->receiveSlot(slot, tstate->dest);

	/* clean up */
	ExecClearTuple(slot);
}

/*
 * write a chunk of text, breaking at newline characters
 *
 * Should only be used with a single-TEXT-attribute tupdesc.
 */
void
do_text_output_multiline(TupOutputState *tstate, const char *txt)
{
	Datum		values[1];
	bool		isnull[1] = {false};

	while (*txt)
	{
		const char *eol;
		int			len;

		eol = strchr(txt, '\n');
		if (eol)
		{
			len = eol - txt;
			eol++;
		}
		else
		{
			len = strlen(txt);
			eol = txt + len;
		}

		values[0] = PointerGetDatum(cstring_to_text_with_len(txt, len));
		do_tup_output(tstate, values, isnull);
		pfree(DatumGetPointer(values[0]));
		txt = eol;
	}
}

void
end_tup_output(TupOutputState *tstate)
{
	tstate->dest->rShutdown(tstate->dest);
	/* note that destroying the dest is not ours to do */
	ExecDropSingleTupleTableSlot(tstate->slot);
	pfree(tstate);
}
