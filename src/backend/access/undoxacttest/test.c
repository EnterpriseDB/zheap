#include "postgres.h"

#include "access/heapam.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/undoxacttest.h"
#include "access/xactundo.h"
#include "catalog/pg_am_d.h"
#include "catalog/pg_class.h"
#include "catalog/pg_type_d.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/fmgrprotos.h"
#include "utils/snapmgr.h"

static char* undoxacttest_fetch(Relation rel, Buffer *buf, bool is_undo);
static void sanity_check_undoxacttest_rel(Relation rel, bool init, bool is_undo);


Datum
undoxacttest_init_rel(PG_FUNCTION_ARGS)
{
	Oid			reloid = PG_GETARG_OID(0);
	Relation	rel;
	bytea	   *data;
	Datum		values[1];
	bool		isnull[1];
	HeapTuple	tuple;

	rel = table_open(reloid, AccessExclusiveLock);

	sanity_check_undoxacttest_rel(rel, true,  /* is_undo = */ false);

	data = palloc0(VARHDRSZ + 100);
	SET_VARSIZE(data, VARHDRSZ + 100);

	values[0] = PointerGetDatum(data);
	isnull[0] = false;

	tuple = heap_form_tuple(RelationGetDescr(rel),
							values, isnull);
	simple_heap_insert(rel, tuple);

	table_close(rel, NoLock);

	PG_RETURN_VOID();
}

static Datum
undoxacttest_mod_impl(Oid reloid, int64 mod)
{
	Relation	rel;
	Buffer		buf;
	char	   *data;
	int64	   *counter;
	int64		oldval;

	rel = table_open(reloid, RowExclusiveLock);

	sanity_check_undoxacttest_rel(rel, false,  /* is_undo = */ false);

	data = undoxacttest_fetch(rel, &buf, /* is_undo = */ false);
	counter = ((int64 *) &data[0]);

	oldval = undoxacttest_log_execute_mod(rel, buf, counter, mod, /* is_undo = */ false);

	UnlockReleaseBuffer(buf);

	table_close(rel, NoLock);

	PG_RETURN_INT64(oldval);
}

Datum
undoxacttest_fetch_and_inc(PG_FUNCTION_ARGS)
{
	Oid reloid = PG_GETARG_OID(0);
	int64 value = PG_GETARG_INT64(1);

	return undoxacttest_mod_impl(reloid, value);
}

Datum
undoxacttest_fetch_and_dec(PG_FUNCTION_ARGS)
{
	Oid reloid = PG_GETARG_OID(0);
	int64 value = PG_GETARG_INT64(1);

	return undoxacttest_mod_impl(reloid, -value);
}

Datum
undoxacttest_read(PG_FUNCTION_ARGS)
{
	Oid reloid = PG_GETARG_OID(0);
	Relation rel;
	Buffer buf;
	char *data;
	int64 *counter;
	int64 value;

	rel = table_open(reloid, AccessShareLock);

	sanity_check_undoxacttest_rel(rel, false,  /* is_undo = */ false);

	data = undoxacttest_fetch(rel, &buf, /* is_undo = */ false);

	LockBuffer(buf, BUFFER_LOCK_SHARE);

	counter = ((int64 *) &data[0]);
	value = *counter;

	UnlockReleaseBuffer(buf);

	table_close(rel, NoLock);

	PG_RETURN_INT64(value);
}

void
undoxacttest_undo_mod(const xu_undoxactest_mod *uxt_r)
{
	Relation	rel;
	Buffer		buf;
	char	   *data;
	int64	   *counter;

	rel = table_open(uxt_r->reloid, RowExclusiveLock);

	sanity_check_undoxacttest_rel(rel, false, /* is_undo = */ true);

	data = undoxacttest_fetch(rel, &buf, /* is_undo = */ true);
	counter = ((int64 *) &data[0]);

	undoxacttest_log_execute_mod(rel, buf, counter, -uxt_r->mod, /* is_undo = */ true);

	UnlockReleaseBuffer(buf);

	table_close(rel, NoLock);
}

/*
 * Check that we actually can use the relation for tests.
 */
static void
sanity_check_undoxacttest_rel(Relation rel, bool init, bool is_undo)
{
	uint64 relsize;
	TupleDesc desc = RelationGetDescr(rel);
	Form_pg_class relform = rel->rd_rel;
	Form_pg_attribute attr;

	if (!superuser())
		elog(ERROR, "undoxacttest: only superuser is allowed to test, who are you???");

	if (relform->relkind != RELKIND_RELATION ||
		relform->relam != HEAP_TABLE_AM_OID)
		elog(ERROR, "undoxacttest: only a heap relation may be used");

	if (desc->natts != 1)
		elog(ERROR, "undoxacttest: 1 column expected");

	attr = TupleDescAttr(desc, 0);

	if (attr->atttypid != BYTEAOID ||
		!attr->attnotnull ||
		attr->attstorage != 'p')
		elog(ERROR, "undoxacttest: column needs to be type bytea, not null, and plain storage ");

	if (namestrcmp(&attr->attname, "data") != 0)
		elog(ERROR, "undoxacttest: expected column to be named data");

	relsize = table_block_relation_size(rel, MAIN_FORKNUM);

	if (init)
	{
		if (relsize != 0)
			elog(ERROR, "undoxacttest: can only initialize empty relation");
	}
	else
	{
		Buffer buf;

		if (relsize != BLCKSZ)
			elog(ERROR, "undoxacttest: can only test single page relation");

		/* verify that the test tuple we expect is present */
		undoxacttest_fetch(rel, &buf, is_undo);

		ReleaseBuffer(buf);
	}
}

/*
 * Fetch test data. Assumes that preconditions checked by
 * sanity_check_undoxacttest_rel(init = false) are fulfilled.
 */
static char*
undoxacttest_fetch(Relation rel, Buffer *buf, bool is_undo)
{
	Page		page;
	HeapTupleData tuple = {0};
	bool		isnull;
	Datum		datum;
	bytea	   *data;
	size_t		data_size;
	ItemId		lp;

	ItemPointerSet(&tuple.t_self, 0, 1);

	*buf = ReadBuffer(rel, 0);
	LockBuffer(*buf, BUFFER_LOCK_SHARE);
	page = BufferGetPage(*buf);

	if (PageGetMaxOffsetNumber(page) != 1)
		elog(ERROR, "undoxacttest: expected exactly one tuple");

	lp = PageGetItemId(page, 1);

	if (!ItemIdIsNormal(lp))
		elog(ERROR, "undoxacttest: expected normal line pointer");

	tuple.t_data = (HeapTupleHeader) PageGetItem(page, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_tableOid = RelationGetRelid(rel);

	/* don't have a snapshot while executing undo currently */
	if (!is_undo &&
		!HeapTupleSatisfiesVisibility(&tuple, GetActiveSnapshot(), *buf))
		elog(ERROR, "undoxacttest: expected visible tuple");

	LockBuffer(*buf, BUFFER_LOCK_UNLOCK);

	datum = heap_getattr(&tuple, 1, RelationGetDescr(rel), &isnull);
	data = (bytea *) DatumGetPointer(datum);
	data_size = VARSIZE_ANY_EXHDR(data);

	if (data_size != 100)
		elog(ERROR, "undoxacttest: unexpected size %zu instead of %zu",
			 data_size, (size_t) 100);

	return VARDATA(data);
}
