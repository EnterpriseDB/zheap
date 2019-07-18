/*-------------------------------------------------------------------------
 *
 * zheapfuncs.c
 *	  Functions to investigate zheap pages
 *
 * We check the input to these functions for corrupt pointers etc. that
 * might cause crashes, but at the same time we try to print out as much
 * information as possible, even if it's nonsense. That's because if a
 * page is corrupt, we don't know why and how exactly it is corrupt, so we
 * let the user judge it.
 *
 * These functions are restricted to superusers for the fear of introducing
 * security holes if the input checking isn't as water-tight as it should be.
 * You'd need to be superuser to obtain a raw page image anyway, so
 * there's hardly any use case for using these without superuser-rights
 * anyway.
 *
 * Copyright (c) 2007-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/pageinspect/zheapfuncs.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "pageinspect.h"

#include "access/htup_details.h"
#include "access/zheap.h"
#include "funcapi.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/rel.h"

static void decode_infomask(ZHeapTupleHeader ztuphdr, Datum *values, bool *nulls);

/*
 * bits_to_text
 *
 * Converts a bits8-array of 'len' bits to a human-readable
 * c-string representation.
 */
static char *
bits_to_text(bits8 *bits, int len)
{
	int			i;
	char	   *str;

	str = palloc(len + 1);

	for (i = 0; i < len; i++)
		str[i] = (bits[(i / 8)] & (1 << (i % 8))) ? '1' : '0';

	str[i] = '\0';

	return str;
}

/*
 * decode_infomask
 *
 * Converts tuple infomask into an array describing the flags marked in
 * tuple infomask.
 */
static void
decode_infomask(ZHeapTupleHeader ztuphdr, Datum *values, bool *nulls)
{
	ArrayBuildState *raw_attrs;

	raw_attrs = initArrayResult(TEXTOID, CurrentMemoryContext, false);
	if (ZHeapTupleHasMultiLockers(ztuphdr->t_infomask) ||
		IsZHeapTupleModified(ztuphdr->t_infomask) ||
		ZHeapTupleHasInvalidXact(ztuphdr->t_infomask))
	{
		if (ZHeapTupleHasInvalidXact(ztuphdr->t_infomask))
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("slot-reused"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if (ZHeapTupleHasMultiLockers(ztuphdr->t_infomask))
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("multilock"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if (ztuphdr->t_infomask & ZHEAP_DELETED)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("deleted"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if (ztuphdr->t_infomask & ZHEAP_UPDATED)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("updated"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if (ztuphdr->t_infomask & ZHEAP_INPLACE_UPDATED)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("in-updated"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if ((ztuphdr->t_infomask & ZHEAP_XID_SHR_LOCK) == ZHEAP_XID_SHR_LOCK)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("l-share"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		else if (ztuphdr->t_infomask & ZHEAP_XID_NOKEY_EXCL_LOCK)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("l-nokey-ex"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		else if (ztuphdr->t_infomask & ZHEAP_XID_KEYSHR_LOCK)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("l-keyshare"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		if (ztuphdr->t_infomask & ZHEAP_XID_EXCL_LOCK)
		{
			raw_attrs = accumArrayResult(raw_attrs, CStringGetTextDatum("l-ex"),
										 false, TEXTOID, CurrentMemoryContext);
		}
		*values = makeArrayResult(raw_attrs, CurrentMemoryContext);
	}
	else
		*nulls = true;
}

/*
 * zheap_page_items
 *
 * Allows inspection of line pointers and tuple headers of a zheap page.
 */
PG_FUNCTION_INFO_V1(zheap_page_items);

typedef struct zheap_page_items_state
{
	TupleDesc	tupd;
	Page		page;
	uint16		offset;
} zheap_page_items_state;

Datum
zheap_page_items(PG_FUNCTION_ARGS)
{
	bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
	zheap_page_items_state *inter_call_data = NULL;
	FuncCallContext *fctx;
	int			raw_page_size;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 (errmsg("must be superuser to use raw page functions"))));

	raw_page_size = VARSIZE(raw_page) - VARHDRSZ;

	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc	tupdesc;
		MemoryContext mctx;
		int			num_trans_slots;

		if (raw_page_size < SizeOfPageHeaderData)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("input page too small (%d bytes)", raw_page_size)));

		fctx = SRF_FIRSTCALL_INIT();
		mctx = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		inter_call_data = palloc(sizeof(zheap_page_items_state));

		/* Build a tuple descriptor for our result type */
		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		inter_call_data->tupd = tupdesc;

		inter_call_data->offset = FirstOffsetNumber;
		inter_call_data->page = VARDATA(raw_page);

		fctx->max_calls = PageGetMaxOffsetNumber(inter_call_data->page);
		fctx->user_fctx = inter_call_data;

		/*
		 * We cannot check whether this is a zheap page or not. But, we can
		 * check whether pd_special is set correctly so that it contains the
		 * expected number of transaction slots in the special space.
		 */
		num_trans_slots = (raw_page_size - ((PageHeader)
											(inter_call_data->page))->pd_special)
			/ sizeof(ZHeapPageOpaqueData);

		if (num_trans_slots != ZHEAP_PAGE_TRANS_SLOTS)
			elog(ERROR, "zheap page contains unexpected number of transaction"
				 "slots: %d, expecting %d", num_trans_slots, ZHEAP_PAGE_TRANS_SLOTS);

		MemoryContextSwitchTo(mctx);
	}

	fctx = SRF_PERCALL_SETUP();
	inter_call_data = fctx->user_fctx;

	if (fctx->call_cntr < fctx->max_calls)
	{
		Page		page = inter_call_data->page;
		HeapTuple	resultTuple;
		Datum		result;
		ItemId		id;
		Datum		values[11];
		bool		nulls[11];
		uint16		lp_offset;
		uint16		lp_flags;
		uint16		lp_len;

		memset(nulls, 0, sizeof(nulls));

		/* Extract information from the line pointer */

		id = PageGetItemId(page, inter_call_data->offset);

		lp_offset = ItemIdGetOffset(id);
		lp_flags = ItemIdGetFlags(id);
		lp_len = ItemIdGetLength(id);

		values[0] = UInt16GetDatum(inter_call_data->offset);
		values[1] = UInt16GetDatum(lp_offset);
		values[2] = UInt16GetDatum(lp_flags);
		values[3] = UInt16GetDatum(lp_len);

		/*
		 * We do just enough validity checking to make sure we don't reference
		 * data outside the page passed to us. The page could be corrupt in
		 * many other ways, but at least we won't crash.
		 */
		if (ItemIdHasStorage(id) &&
			lp_len >= MinZHeapTupleSize &&
			lp_offset + lp_len <= raw_page_size)
		{
			ZHeapTupleHeader ztuphdr;
			bytea	   *tuple_data_bytea;
			int			tuple_data_len;

			/* Extract information from the tuple header */
			ztuphdr = (ZHeapTupleHeader) PageGetItem(page, id);

			values[4] = UInt16GetDatum(ZHeapTupleHeaderGetXactSlot(ztuphdr));

			values[5] = UInt32GetDatum(ztuphdr->t_infomask2);
			values[6] = UInt32GetDatum(ztuphdr->t_infomask);
			values[7] = UInt8GetDatum(ztuphdr->t_hoff);

			/*
			 * We already checked that the item is completely within the raw
			 * page passed to us, with the length given in the line pointer.
			 * Let's check that t_hoff doesn't point over lp_len, before using
			 * it to access t_bits and oid.
			 */
			if (ztuphdr->t_hoff >= SizeofZHeapTupleHeader &&
				ztuphdr->t_hoff <= lp_len)
			{
				if (ztuphdr->t_infomask & ZHEAP_HASNULL)
				{
					int			bits_len;

					bits_len =
						BITMAPLEN(ZHeapTupleHeaderGetNatts(ztuphdr)) * BITS_PER_BYTE;
					values[8] = CStringGetTextDatum(
													bits_to_text(ztuphdr->t_bits, bits_len));
				}
				else
					nulls[8] = true;

			}
			else
			{
				nulls[8] = true;
			}

			/* Copy raw tuple data into bytea attribute */
			tuple_data_len = lp_len - ztuphdr->t_hoff;
			tuple_data_bytea = (bytea *) palloc(tuple_data_len + VARHDRSZ);
			SET_VARSIZE(tuple_data_bytea, tuple_data_len + VARHDRSZ);
			memcpy(VARDATA(tuple_data_bytea), (char *) ztuphdr + ztuphdr->t_hoff,
				   tuple_data_len);
			values[9] = PointerGetDatum(tuple_data_bytea);

			decode_infomask(ztuphdr, &values[10], &nulls[10]);
		}
		else
		{
			/*
			 * The line pointer is not used, or it's invalid. Set the rest of
			 * the fields to NULL
			 */
			int			i;

			for (i = 4; i <= 11; i++)
				nulls[i] = true;
		}

		/* Build and return the result tuple. */
		resultTuple = heap_form_tuple(inter_call_data->tupd, values, nulls);
		result = HeapTupleGetDatum(resultTuple);

		inter_call_data->offset++;

		SRF_RETURN_NEXT(fctx, result);
	}
	else
		SRF_RETURN_DONE(fctx);
}

/*
 * zheap_page_slots
 *
 * Allows inspection of transaction slots of a zheap page.
 */
PG_FUNCTION_INFO_V1(zheap_page_slots);

typedef struct zheap_page_slots_state
{
	TupleDesc	tupd;
	Page		page;
	uint16		slot_id;
} zheap_page_slots_state;

Datum
zheap_page_slots(PG_FUNCTION_ARGS)
{
	bytea	   *raw_page = PG_GETARG_BYTEA_P(0);
	zheap_page_slots_state *inter_call_data = NULL;
	FuncCallContext *fctx;
	int			raw_page_size;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 (errmsg("must be superuser to use raw page functions"))));

	raw_page_size = VARSIZE(raw_page) - VARHDRSZ;

	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc	tupdesc;
		MemoryContext mctx;
		int			num_trans_slots;

		if (raw_page_size < SizeOfPageHeaderData)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("input page too small (%d bytes)", raw_page_size)));

		fctx = SRF_FIRSTCALL_INIT();
		mctx = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		inter_call_data = palloc(sizeof(zheap_page_slots_state));

		/* Build a tuple descriptor for our result type */
		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			elog(ERROR, "return type must be a row type");

		inter_call_data->tupd = tupdesc;

		inter_call_data->slot_id = 0;
		inter_call_data->page = VARDATA(raw_page);

		fctx->user_fctx = inter_call_data;

		/*
		 * We cannot check whether this is a zheap page or not. But, we can
		 * check whether pd_special is set correctly so that it contains the
		 * expected number of transaction slots in the special space.
		 */
		num_trans_slots = (raw_page_size - ((PageHeader)
											(inter_call_data->page))->pd_special)
			/ sizeof(ZHeapPageOpaqueData);

		if (num_trans_slots != ZHEAP_PAGE_TRANS_SLOTS)
			elog(ERROR, "zheap page contains unexpected number of transaction"
				 "slots: %d, expecting %d", num_trans_slots, ZHEAP_PAGE_TRANS_SLOTS);

		/*
		 * If the page has tpd slot, last slot is used as tpd slot. In that
		 * case, it will not have any informations about transaction.
		 */
		if (ZHeapPageHasTPDSlot((PageHeader) inter_call_data->page))
			num_trans_slots--;
		fctx->max_calls = num_trans_slots;

		MemoryContextSwitchTo(mctx);
	}

	fctx = SRF_PERCALL_SETUP();
	inter_call_data = fctx->user_fctx;

	if (fctx->call_cntr < fctx->max_calls)
	{
		Page		page = inter_call_data->page;
		HeapTuple	resultTuple;
		Datum		result;
		Datum		values[4];
		bool		nulls[4];
		ZHeapPageOpaque opaque;
		TransInfo	transinfo;

		memset(nulls, 0, sizeof(nulls));

		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
		transinfo = opaque->transinfo[inter_call_data->slot_id];

		/* Fetch transaction and undo information from slot */
		values[0] = UInt16GetDatum(inter_call_data->slot_id + 1);
		/* FIXME: should probably be represented as a single value? */
		values[1] = UInt32GetDatum(EpochFromFullTransactionId(transinfo.fxid));
		values[2] = UInt32GetDatum(XidFromFullTransactionId(transinfo.fxid));
		values[3] = UInt64GetDatum(transinfo.urec_ptr);

		/* Build and return the result tuple. */
		resultTuple = heap_form_tuple(inter_call_data->tupd, values, nulls);
		result = HeapTupleGetDatum(resultTuple);

		inter_call_data->slot_id++;

		SRF_RETURN_NEXT(fctx, result);
	}
	else
		SRF_RETURN_DONE(fctx);
}
