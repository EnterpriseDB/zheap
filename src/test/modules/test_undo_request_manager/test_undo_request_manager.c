/*--------------------------------------------------------------------------
 *
 * test_undo_request_manager.c
 *		Test undo request manager.
 *
 * Copyright (c) 2013-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		src/test/modules/test_undo_request_manager/undo_request_manager.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undorequest.h"
#include "catalog/pg_type_d.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/proc.h"
#include "utils/array.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(urm_simple_test);

/*
 * SQL-callable test function.  We create an UndoRequestManager in
 * backend-private memory here and exercise it a bit to see if it breaks.
 *
 * The first argument is the capacity of the UndoRequestManager as an integer.
 *
 * The second argument is 1-dimensional bigint array, where each subarray
 * contains a hypothetical undo size.
 *
 * This function registers and inserts all the requests (failing if space is
 * exhausted) with fake, sequentially assigned transaction IDs, and then
 * fetches them back one by one. The return value is an array of fake
 * transaction IDs in the order they were returned.
 *
 * This test doesn't simulate undo failure, multi-database operation, or
 * prepared transactions.
 */
Datum
urm_simple_test(PG_FUNCTION_ARGS)
{
	int64	capacity = PG_GETARG_INT32(0);
	ArrayType *array = PG_GETARG_ARRAYTYPE_P(1);
	Datum	  *darray;
	int			nentries;
	Datum	  *dresult;
	ArrayType *result;
	UndoRequestManager *urm;
	const UndoRecPtr SomeValidUndoRecPtr = InvalidUndoRecPtr + 1;
	int			i;
	FullTransactionId fake_fxid = FullTransactionIdFromEpochAndXid(0, 1000);

	/* Require positive capacity. */
	if (capacity <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("undo request manager capacity must be a positive integer")));

	/* Sanity-check and deconstruct array. */
	if (ARR_NDIM(array) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_ELEMENT_ERROR),
				 errmsg("array must have exactly 1 dimension")));
	if (array_contains_nulls(array))
		ereport(ERROR,
				(errcode(ERRCODE_ARRAY_ELEMENT_ERROR),
				 errmsg("cannot work with arrays containing NULLs")));
	deconstruct_array(array, INT8OID, 8, FLOAT8PASSBYVAL, 'd',
					  &darray, NULL, &nentries);

	/*
	 * Initialize UndoRequestManager. We have to supply an LWLock; rather than
	 * creating a new one somewhere, just use our own backendLock. These locks
	 * aren't that heavily trafficked and we won't have any reason to take it
	 * for any other purpose while the UndoRequstManager holds it, so this
	 * should be safe enough.
	 *
	 * We make the soft limit equal to the full capacity here for testing
	 * purposes, which means that we should always succeed in dispatching to
	 * the background.
	 */
	urm = palloc(EstimateUndoRequestManagerSize(capacity));
	InitializeUndoRequestManager(urm, &MyProc->backendLock,
								 capacity, capacity);

	/* Insert entries as provided by caller. */
	for (i = 0; i < nentries; ++i)
	{
		int64	size = DatumGetInt64(darray[i]);
		UndoRequest *req;

		FullTransactionIdAdvance(&fake_fxid);

		req = RegisterUndoRequest(urm, fake_fxid, MyDatabaseId);
		if (req == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("unable to register undo request #%d", i + 1)));
		FinalizeUndoRequest(urm, req, size,
							SomeValidUndoRecPtr,
							InvalidUndoRecPtr,
							SomeValidUndoRecPtr,
							InvalidUndoRecPtr,
							false);
		if (!PerformUndoInBackground(urm, req, false))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("unable to background undo request #%d", i + 1)));
	}

	/* Now get the entries back. */
	dresult = palloc(nentries * sizeof(Datum));
	for (i = 0; true; ++i)
	{
		UndoRequest *req;
		UndoRecPtr	p[4];
		Oid			out_dbid;

		/* Get some work. */
		req = GetNextUndoRequest(urm, MyDatabaseId, true, &out_dbid,
								 &fake_fxid, &p[0], &p[1], &p[2], &p[3]);
		if (req == NULL)
			break;
		if (i >= nentries)
			elog(ERROR, "found more undo requests than were inserted");

		/* Save the fake FXID. */
		dresult[i] =
			Int64GetDatum((int64) U64FromFullTransactionId(fake_fxid));

		/* Report that we successfully processed the imaginary undo. */
		UnregisterUndoRequest(urm, req);
	}

	/* Put result into array form. */
	result = construct_array(dresult, i, INT8OID, 8, FLOAT8PASSBYVAL, 'd');
	PG_RETURN_ARRAYTYPE_P(result);
}
