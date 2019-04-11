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
	Datum	*values = palloc0(sizeof(Datum) * tupDesc->natts);
	bool	*nulls = palloc0(sizeof(bool) * tupDesc->natts);

	zheap_deform_tuple(ztuple, tupDesc, values, nulls);
	tuple = heap_form_tuple(tupDesc, values, nulls);
	tuple->t_self = ztuple->t_self;
	tuple->t_tableOid = ztuple->t_tableOid;

	pfree(values);
	pfree(nulls);

	return tuple;
}

/*
 * zheap_to_heap
 *
 * convert zheap tuple to a minimal tuple
 */
MinimalTuple
zheap_to_minimal(ZHeapTuple ztuple, TupleDesc tupDesc)
{
	MinimalTuple tuple;
	Datum	*values = palloc0(sizeof(Datum) * tupDesc->natts);
	bool	*nulls = palloc0(sizeof(bool) * tupDesc->natts);

	zheap_deform_tuple(ztuple, tupDesc, values, nulls);
	tuple = heap_form_minimal_tuple(tupDesc, values, nulls);

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
	Datum	*values = palloc0(sizeof(Datum) * tupDesc->natts);
	bool	*nulls = palloc0(sizeof(bool) * tupDesc->natts);

	heap_deform_tuple(tuple, tupDesc, values, nulls);
	ztuple = zheap_form_tuple(tupDesc, values, nulls);
	ztuple->t_self = tuple->t_self;
	ztuple->t_tableOid = tuple->t_tableOid;

	pfree(values);
	pfree(nulls);

	return ztuple;
}

/* ----------------
 *		zheap_copytuple
 *
 *		returns a copy of an entire tuple
 *
 * The ZHeapTuple struct, tuple header, and tuple data are all allocated
 * as a single palloc() block.
 * ----------------
 */
ZHeapTuple
zheap_copytuple(ZHeapTuple tuple)
{
	ZHeapTuple	newTuple;

	if (!ZHeapTupleIsValid(tuple) || tuple->t_data == NULL)
		return NULL;

	newTuple = (ZHeapTuple) palloc(ZHEAPTUPLESIZE + tuple->t_len);
	newTuple->t_len = tuple->t_len;
	newTuple->t_self = tuple->t_self;
	newTuple->t_tableOid = tuple->t_tableOid;
	newTuple->t_data = (ZHeapTupleHeader) ((char *) newTuple + ZHEAPTUPLESIZE);
	memcpy((char *) newTuple->t_data, (char *) tuple->t_data, tuple->t_len);
	return newTuple;
}
