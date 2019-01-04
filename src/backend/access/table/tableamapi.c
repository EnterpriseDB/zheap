/*----------------------------------------------------------------------
 *
 * tableamapi.c
 *		Support routines for API for Postgres table access methods
 *
 * FIXME: looks like this should be in amapi.c.
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * src/backend/access/table/tableamapi.c
 *----------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/tableam.h"
#include "access/xact.h"
#include "catalog/pg_am.h"
#include "catalog/pg_proc.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/memutils.h"

static Oid get_table_am_oid(const char *tableamname, bool missing_ok);

TupleTableSlot*
table_gimmegimmeslot(Relation relation, List **reglist)
{
	const TupleTableSlotOps *tts_cb;
	TupleTableSlot *slot;

	tts_cb = table_slot_callbacks(relation);
	slot = MakeSingleTupleTableSlot(RelationGetDescr(relation), tts_cb);

	if (reglist)
		*reglist = lappend(*reglist, slot);

	return slot;
}


/*
 * GetTableAmRoutine
 *		Call the specified access method handler routine to get its
 *		TableAmRoutine struct, which will be palloc'd in the caller's
 *		memory context.
 */
const TableAmRoutine *
GetTableAmRoutine(Oid amhandler)
{
	Datum		datum;
	const TableAmRoutine *routine;

	datum = OidFunctionCall0(amhandler);
	routine = (TableAmRoutine *) DatumGetPointer(datum);

	if (routine == NULL || !IsA(routine, TableAmRoutine))
		elog(ERROR, "Table access method handler %u did not return a TableAmRoutine struct",
			 amhandler);

	return routine;
}

/*
 * GetTableAmRoutineByAmId - look up the handler of the table access
 * method with the given OID, and get its TableAmRoutine struct.
 */
const TableAmRoutine *
GetTableAmRoutineByAmId(Oid amoid)
{
	regproc		amhandler;
	HeapTuple	tuple;
	Form_pg_am	amform;

	/* Get handler function OID for the access method */
	tuple = SearchSysCache1(AMOID, ObjectIdGetDatum(amoid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for access method %u",
			 amoid);
	amform = (Form_pg_am) GETSTRUCT(tuple);

	/* Check that it is a table access method */
	if (amform->amtype != AMTYPE_TABLE)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("access method \"%s\" is not of type %s",
						NameStr(amform->amname), "TABLE")));

	amhandler = amform->amhandler;

	/* Complain if handler OID is invalid */
	if (!RegProcedureIsValid(amhandler))
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("table access method \"%s\" does not have a handler",
						NameStr(amform->amname))));

	ReleaseSysCache(tuple);

	/* And finally, call the handler function to get the API struct. */
	return GetTableAmRoutine(amhandler);
}

/*
 * get_table_am_oid - given a table access method name, look up the OID
 *
 * If missing_ok is false, throw an error if table access method name not
 * found. If true, just return InvalidOid.
 */
static Oid
get_table_am_oid(const char *tableamname, bool missing_ok)
{
	Oid			result;
	Relation	rel;
	TableScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	/*
	 * Search pg_tablespace.  We use a heapscan here even though there is an
	 * index on name, on the theory that pg_tablespace will usually have just
	 * a few entries and so an indexed lookup is a waste of effort.
	 */
	rel = heap_open(AccessMethodRelationId, AccessShareLock);

	ScanKeyInit(&entry[0],
				Anum_pg_am_amname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(tableamname));
	scandesc = table_beginscan_catalog(rel, 1, entry);
	tuple = heap_scan_getnext(scandesc, ForwardScanDirection);

	/* We assume that there can be at most one matching tuple */
	if (HeapTupleIsValid(tuple) &&
			((Form_pg_am) GETSTRUCT(tuple))->amtype == AMTYPE_TABLE)
		result = ((Form_pg_am) GETSTRUCT(tuple))->oid;
	else
		result = InvalidOid;

	table_endscan(scandesc);
	heap_close(rel, AccessShareLock);

	if (!OidIsValid(result) && !missing_ok)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("table access method \"%s\" does not exist",
						 tableamname)));

	return result;
}

/* check_hook: validate new default_table_access_method */
bool
check_default_table_access_method(char **newval, void **extra, GucSource source)
{
	/*
	 * If we aren't inside a transaction, we cannot do database access so
	 * cannot verify the name.  Must accept the value on faith.
	 */
	if (IsTransactionState())
	{
		if (**newval != '\0' &&
			!OidIsValid(get_table_am_oid(*newval, true)))
		{
			/*
			 * When source == PGC_S_TEST, don't throw a hard error for a
			 * nonexistent table access method, only a NOTICE.
			 * See comments in guc.h.
			 */
			if (source == PGC_S_TEST)
			{
				ereport(NOTICE,
						(errcode(ERRCODE_UNDEFINED_OBJECT),
						 errmsg("Table access method \"%s\" does not exist",
								*newval)));
			}
			else
			{
				GUC_check_errdetail("Table access method \"%s\" does not exist.",
									*newval);
				return false;
			}
		}
	}

	return true;
}
