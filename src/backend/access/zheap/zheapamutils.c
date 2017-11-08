/*-------------------------------------------------------------------------
 *
 * zheapamutils.c
 *	  zheap utility method code
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zheapamutils.c
 *
 *
 * INTERFACE ROUTINES
 *		zheap_to_heap	- convert zheap tuple to heap tuple
 *
 * NOTES
 *	  This file contains utility functions for the zheap
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/xact.h"
#include "access/zheap.h"
#include "access/zheaputils.h"
#include "storage/bufmgr.h"

/*
 * zheap_to_heap
 *
 * convert zheap tuple to heap tuple
 */
HeapTuple
zheap_to_heap(ZHeapTuple ztuple, TupleDesc tupDesc)
{
	HeapTuple tuple;
	Datum	*values = palloc0(sizeof(Datum) * ZHeapTupleHeaderGetNatts(ztuple->t_data));
	bool	*nulls = palloc0(sizeof(bool) * ZHeapTupleHeaderGetNatts(ztuple->t_data));

	zheap_deform_tuple(ztuple, tupDesc, values, nulls);
	tuple = heap_form_tuple(tupDesc, values, nulls);
	tuple->t_self = ztuple->t_self;

	pfree(values);
	pfree(nulls);

	return tuple;
}

/*
 * heap_to_zheap
 *
 * convert heap tuple to zheap tuple
 */
ZHeapTuple
heap_to_zheap(HeapTuple tuple, TupleDesc tupDesc)
{
	ZHeapTuple ztuple;
	Datum	*values = palloc0(sizeof(Datum) * HeapTupleHeaderGetNatts(tuple->t_data));
	bool	*nulls = palloc0(sizeof(bool) * HeapTupleHeaderGetNatts(tuple->t_data));

	heap_deform_tuple(tuple, tupDesc, values, nulls);
	ztuple = zheap_form_tuple(tupDesc, values, nulls);
	ztuple->t_self = tuple->t_self;

	pfree(values);
	pfree(nulls);

	return ztuple;
}

/*
 * XXX this function may need to move to some other file may be trigger.c
 * but currently kept here so that the coverage of zheap can be tracked easily.
 */
HeapTuple
GetZTupleForTrigger(EState *estate,
				   EPQState *epqstate,
				   ResultRelInfo *relinfo,
				   ItemPointer tid,
				   LockTupleMode lockmode,
				   TupleTableSlot **newSlot,
				   ItemPointer newtid)
{
	Relation	relation = relinfo->ri_RelationDesc;
	ZHeapTupleData ztuple = {0};
	HeapTuple	result;
	Buffer		buffer;
	Page		page;
	ItemId		lp;

	if (newSlot != NULL)
	{
		HTSU_Result test;
		HeapUpdateFailureData hufd;

		*newSlot = NULL;

		/* caller must pass an epqstate if EvalPlanQual is possible */
		Assert(epqstate != NULL);

		/*
		 * lock tuple for update
		 */
ltrmark:;
		/*
		 * FIXME Only for getting the tuple length we need to take the buffer
		 * lock and get the length.
		 * another possibility here is that we can pass a flag to
		 * zheap_lock_tuple, saying that it need to allocate the memory for
		 * ztuple.t_data, but that will make zheap_lock_tuple API incompatible
		 * with heap_lock_tuple.
		 */
		buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));
		LockBuffer(buffer, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buffer);
		lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));

		Assert(ItemIdIsNormal(lp));
		ztuple.t_len = ItemIdGetLength(lp);
		UnlockReleaseBuffer(buffer);

		ztuple.t_self = *tid;

		if (ztuple.t_data)
			pfree(ztuple.t_data);

		ztuple.t_data = palloc0(ztuple.t_len);
		test = zheap_lock_tuple(relation, &ztuple,
								estate->es_output_cid,
								lockmode, LockWaitBlock,
								false, true, NULL, &buffer, &hufd);
		switch (test)
		{
			case HeapTupleSelfUpdated:

				/*
				 * The target tuple was already updated or deleted by the
				 * current command, or by a later command in the current
				 * transaction.  We ignore the tuple in the former case, and
				 * throw error in the latter case, for the same reasons
				 * enumerated in ExecUpdate and ExecDelete in
				 * nodeModifyTable.c.
				 */
				if (hufd.cmax != estate->es_output_cid)
					ereport(ERROR,
							(errcode(ERRCODE_TRIGGERED_DATA_CHANGE_VIOLATION),
							 errmsg("tuple to be updated was already modified by an operation triggered by the current command"),
							 errhint("Consider using an AFTER trigger instead of a BEFORE trigger to propagate changes to other rows.")));

				/* treat it as deleted; do not process */
				ReleaseBuffer(buffer);
				return NULL;

			case HeapTupleMayBeUpdated:
				result = zheap_to_heap(&ztuple, relation->rd_att);
				break;

			case HeapTupleUpdated:
				ReleaseBuffer(buffer);
				if (IsolationUsesXactSnapshot())
					ereport(ERROR,
							(errcode(ERRCODE_T_R_SERIALIZATION_FAILURE),
							 errmsg("could not serialize access due to concurrent update")));
				if (!ItemPointerEquals(&hufd.ctid, &ztuple.t_self))
				{
					/* it was updated, so look at the updated version */
					TupleTableSlot *epqslot;

					epqslot = EvalPlanQual(estate,
										   epqstate,
										   relation,
										   relinfo->ri_RangeTableIndex,
										   lockmode,
										   &hufd.ctid,
										   hufd.xmax);
					if (!TupIsNull(epqslot))
					{
						*tid = hufd.ctid;
						*newSlot = epqslot;

						/*
						 * EvalPlanQual already locked the tuple, but we
						 * re-call heap_lock_tuple anyway as an easy way of
						 * re-fetching the correct tuple.  Speed is hardly a
						 * criterion in this path anyhow.
						 */
						goto ltrmark;
					}
				}

				/*
				 * if tuple was deleted or PlanQual failed for updated tuple -
				 * we must not process this tuple!
				 */
				return NULL;

			case HeapTupleInvisible:
				elog(ERROR, "attempted to lock invisible tuple");

			default:
				ReleaseBuffer(buffer);
				elog(ERROR, "unrecognized heap_lock_tuple status: %u", test);
				return NULL;	/* keep compiler quiet */
		}
	}
	else
	{
		buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

		/*
		 * Although we already know this tuple is valid, we must lock the
		 * buffer to ensure that no one has a buffer cleanup lock; otherwise
		 * they might move the tuple while we try to copy it.  But we can
		 * release the lock before actually doing the heap_copytuple call,
		 * since holding pin is sufficient to prevent anyone from getting a
		 * cleanup lock they don't already hold.
		 */
		LockBuffer(buffer, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buffer);
		lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));
		Assert(ItemIdIsNormal(lp));
		ztuple.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);

		/* If tid is same as newtid then fetch the oldtuple from the undo. */
		if (ItemPointerIsValid(newtid) && ItemPointerEquals(newtid, tid))
		{
			ZHeapTuple	undo_tup;

			undo_tup = zheap_fetch_undo_guts(&ztuple, buffer, newtid);
			result = zheap_to_heap(undo_tup, relation->rd_att);
			zheap_freetuple(undo_tup);
		}
		else
		{
			ztuple.t_len = ItemIdGetLength(lp);
			ztuple.t_self = *tid;
			ztuple.t_tableOid = RelationGetRelid(relation);
			result = zheap_to_heap(&ztuple, relation->rd_att);
		}

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	}

	ReleaseBuffer(buffer);

	return result;
}
