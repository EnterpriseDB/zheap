/*-------------------------------------------------------------------------
 *
 * undoinspect.c
 *	  functions for inspecting undo logs, primarily for debugging
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * contrib/undoinspect/undoinspect.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undoaccess.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/undorequest.h"
#include "access/xlog_internal.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "utils/builtins.h"


PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(undoinspect);

Datum
undoinspect(PG_FUNCTION_ARGS)
{
	Oid			logno = PG_GETARG_OID(0);
	int			size = PG_GETARG_INT32(1);
	UndoRecPtr	insert;
	UndoRecPtr	record_ptr;
	UndoRecPtr	oldest_record_ptr;
	UndoLogCategory category;
	UndoLogSlot *slot;
	bool		empty;
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;

	/*
	 * For now this is superuser-only.  Later we could considering allowing
	 * regular users to see records belonging to their own transaction (by
	 * skipping to the transaction header to find its xid).
	 */
	if (!superuser())
		elog(ERROR, "must be superuser to inspect undo log contents");

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;
	MemoryContextSwitchTo(oldcontext);

	slot = UndoLogGetSlot(logno, false);

	LWLockAcquire(&slot->meta_lock, LW_SHARED);
	empty = true;
	if (slot->logno == logno)
	{
		empty = slot->meta.unlogged.insert == slot->meta.discard;
		insert = MakeUndoRecPtr(slot->logno, slot->meta.unlogged.insert);
		category = slot->meta.category;
		oldest_record_ptr = MakeUndoRecPtr(slot->logno, slot->meta.discard);
	}
	LWLockRelease(&slot->meta_lock);

	/* Now walk back record-by-record dumping description data. */
	if (!empty)
	{
		StringInfoData sb;
		UndoRecInfo *record_info;
		int			nrecords;
		int			i;

		record_ptr = UndoGetPrevUrp(NULL, insert, InvalidBuffer, category);
		record_info = UndoBulkFetchRecord(&record_ptr,
										  oldest_record_ptr,
										  size,
										  &nrecords);

		initStringInfo(&sb);
		for (i = 0; i < nrecords; ++i)
		{
#define PG_STAT_GET_UNDO_RECORDS_COLS 5
			Datum		values[PG_STAT_GET_UNDO_RECORDS_COLS];
			bool		nulls[PG_STAT_GET_UNDO_RECORDS_COLS];
			char		buffer[17];
			UndoRecPtr	urp = record_info[i].urp;
			UnpackedUndoRecord *uur = record_info[i].uur;

			snprintf(buffer, sizeof(buffer), UndoRecPtrFormat, urp);
			values[0] = CStringGetTextDatum(buffer);
			nulls[0] = false;

			values[1] = CStringGetTextDatum(RmgrTable[uur->uur_rmid].rm_name);
			nulls[1] = false;

			resetStringInfo(&sb);
			if (uur->uur_info & UREC_INFO_BLOCK)
				appendStringInfoString(&sb, sb.len > 0 ? ",B" : "B");
			if (uur->uur_info & UREC_INFO_PAYLOAD)
				appendStringInfoString(&sb, sb.len > 0 ? ",P" : "P");
			if (uur->uur_info & UREC_INFO_GROUP)
			{
				appendStringInfoString(&sb, sb.len > 0 ? ",G" : "G");
				if (IsXactApplyProgressCompleted(uur->uur_group->urec_progress))
					appendStringInfoString(&sb, sb.len > 0 ? ",AC" : "AC");
				else if (!IsXactApplyProgressNotStarted(uur->uur_group->urec_progress))
					appendStringInfoString(&sb, sb.len > 0 ? ",AS" : "AS");
			}

			values[2] = CStringGetTextDatum(sb.data);
			nulls[2] = false;

			if (uur->uur_info & UREC_INFO_GROUP)
			{
				values[3] = XidFromFullTransactionId(uur->uur_fxid); /* XXX */
				nulls[3] = false;
			}
			else
				nulls[3] = true;

			resetStringInfo(&sb);
			RmgrTable[uur->uur_rmid].rm_undo_desc(&sb, uur);
			values[4] = CStringGetTextDatum(sb.data);
			nulls[4] = false;

			tuplestore_putvalues(tupstore, tupdesc, values, nulls);
		}
		pfree(sb.data);
	}

	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}
