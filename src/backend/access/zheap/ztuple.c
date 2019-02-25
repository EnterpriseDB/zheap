/*-------------------------------------------------------------------------
 *
 * ztuple.c
 *	  Routines to form and deform zheap tuples.
 *
 * Tuple header in zheap is 5 bytes as compared to 24 bytes in heap.  All
 * transactional information is stored in undo, so fields that store such
 * information are not needed here.
 *
 * We omit all alignment padding for pass-by-value types.  Pass-by-reference
 * types will work as they do in the heap.  We don’t need alignment padding
 * between the tuple header and the tuple data as we always make a copy of the
 * tuple to support in-place updates.  Likewise, we ideally don't need any
 * alignment padding between tuples. However, there are places in zheap code
 * where we access tuple header directly from the page (ex. zheap_delete,
 * zheap_update, etc.) for which we want them to be aligned at two-byte
 * boundary).
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/ztuple.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/relation.h"
#include "access/tpd.h"
#include "access/zheaputils.h"
#include "storage/proc.h"
#include "utils/datum.h"
#include "utils/ztqual.h"

/*
 * zheap_compute_data_size
 *		Determine size of the data area of a tuple to be constructed.
 *
 * We can't start with zero offset for first attribute as that has a
 * hidden assumption that tuple header is MAXALIGNED which is not true
 * for zheap.  For example, if the first attribute requires alignment
 * (say it is four-byte varlena), then the code would assume the offset
 * is aligned incase we start with zero offset for first attribute.  So,
 * always start with the actual byte from where the first attribute starts.
 */
Size
zheap_compute_data_size(TupleDesc tupleDesc, Datum *values, bool *isnull,
						int t_hoff)
{
	Size		data_length = t_hoff;
	int			i;
	int			numberOfAttributes = tupleDesc->natts;

	for (i = 0; i < numberOfAttributes; i++)
	{
		Datum		val;
		Form_pg_attribute atti;

		if (isnull[i])
			continue;

		val = values[i];
		atti = TupleDescAttr(tupleDesc, i);

		if (atti->attbyval)
		{
			/* byval attributes are stored unaligned in zheap. */
			data_length += atti->attlen;
		}
		else if (ATT_IS_PACKABLE(atti) &&
				 VARATT_CAN_MAKE_SHORT(DatumGetPointer(val)))
		{
			/*
			 * we're anticipating converting to a short varlena header, so
			 * adjust length and don't count any alignment
			 */
			data_length += VARATT_CONVERTED_SHORT_SIZE(DatumGetPointer(val));
		}
		else if (atti->attlen == -1 &&
				 VARATT_IS_EXTERNAL_EXPANDED(DatumGetPointer(val)))
		{
			/*
			 * we want to flatten the expanded value so that the constructed
			 * tuple doesn't depend on it
			 */
			data_length = att_align_nominal(data_length, atti->attalign);
			data_length += EOH_get_flat_size(DatumGetEOHP(val));
		}
		else
		{
			data_length = att_align_datum(data_length, atti->attalign,
										  atti->attlen, val);
			data_length = att_addlength_datum(data_length, atti->attlen,
											  val);
		}
	}

	return data_length - t_hoff;
}

/*
 * zheap_fill_tuple
 *		Load data portion of a tuple from values/isnull arrays
 *
 * We also fill the null bitmap (if any) and set the infomask bits
 * that reflect the tuple's data contents.
 *
 * This function is same as heap_fill_tuple except for datatype of infomask
 * parameter.
 *
 * NOTE: it is now REQUIRED that the caller have pre-zeroed the data area.
 */
void
zheap_fill_tuple(TupleDesc tupleDesc,
				 Datum *values, bool *isnull,
				 char *data, Size data_size,
				 uint16 *infomask, bits8 *bit)
{
	bits8	   *bitP;
	int			bitmask;
	int			i;
	int			numberOfAttributes = tupleDesc->natts;

#ifdef USE_ASSERT_CHECKING
	char	   *start = data;
#endif

	if (bit != NULL)
	{
		bitP = &bit[-1];
		bitmask = HIGHBIT;
	}
	else
	{
		/* just to keep compiler quiet */
		bitP = NULL;
		bitmask = 0;
	}

	*infomask &= ~(ZHEAP_HASNULL | ZHEAP_HASVARWIDTH | ZHEAP_HASEXTERNAL);

	for (i = 0; i < numberOfAttributes; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);
		Size		data_length;

		if (bit != NULL)
		{
			if (bitmask != HIGHBIT)
				bitmask <<= 1;
			else
			{
				bitP += 1;
				*bitP = 0x0;
				bitmask = 1;
			}

			if (isnull[i])
			{
				*infomask |= ZHEAP_HASNULL;
				continue;
			}

			*bitP |= bitmask;
		}

		/*
		 * XXX we use the att_align macros on the pointer value itself, not on
		 * an offset.  This is a bit of a hack.
		 */

		if (att->attbyval)
		{
			/* pass-by-value */
			/* data = (char *) att_align_nominal(data, att->attalign); */
			/* store_att_byval(data, values[i], att->attlen); */
			memcpy(data, (char *) &values[i], att->attlen);
			data_length = att->attlen;
		}
		else if (att->attlen == -1)
		{
			/* varlena */
			Pointer		val = DatumGetPointer(values[i]);

			*infomask |= ZHEAP_HASVARWIDTH;
			if (VARATT_IS_EXTERNAL(val))
			{
				if (VARATT_IS_EXTERNAL_EXPANDED(val))
				{
					/*
					 * we want to flatten the expanded value so that the
					 * constructed tuple doesn't depend on it
					 */
					ExpandedObjectHeader *eoh = DatumGetEOHP(values[i]);

					data = (char *) att_align_nominal(data,
													  att->attalign);
					data_length = EOH_get_flat_size(eoh);
					EOH_flatten_into(eoh, data, data_length);
				}
				else
				{
					*infomask |= ZHEAP_HASEXTERNAL;
					/* no alignment, since it's short by definition */
					data_length = VARSIZE_EXTERNAL(val);
					memcpy(data, val, data_length);
				}
			}
			else if (VARATT_IS_SHORT(val))
			{
				/* no alignment for short varlenas */
				data_length = VARSIZE_SHORT(val);
				memcpy(data, val, data_length);
			}
			else if (VARLENA_ATT_IS_PACKABLE(att) &&
					 VARATT_CAN_MAKE_SHORT(val))
			{
				/* convert to short varlena -- no alignment */
				data_length = VARATT_CONVERTED_SHORT_SIZE(val);
				SET_VARSIZE_SHORT(data, data_length);
				memcpy(data + 1, VARDATA(val), data_length - 1);
			}
			else
			{
				/* full 4-byte header varlena */
				data = (char *) att_align_nominal(data,
												  att->attalign);
				data_length = VARSIZE(val);
				memcpy(data, val, data_length);
			}
		}
		else if (att->attlen == -2)
		{
			/* cstring ... never needs alignment */
			*infomask |= ZHEAP_HASVARWIDTH;
			Assert(att->attalign == 'c');
			data_length = strlen(DatumGetCString(values[i])) + 1;
			memcpy(data, DatumGetPointer(values[i]), data_length);
		}
		else
		{
			/* fixed-length pass-by-reference */
			data = (char *) att_align_nominal(data, att->attalign);
			Assert(att->attlen > 0);
			data_length = att->attlen;
			memcpy(data, DatumGetPointer(values[i]), data_length);
		}

		data += data_length;
	}

	Assert((data - start) == data_size);
}

/*
 * zheap_form_tuple
 *		construct a tuple from the given values[] and isnull[] arrays.
 *
 *	This is similar to heap_form_tuple except for tuple header.  Currently,
 *	we don't do anything special for Datum tuples, but eventually we need
 *	to do something about it.
 */
ZHeapTuple
zheap_form_tuple(TupleDesc tupleDescriptor,
				 Datum *values,
				 bool *isnull)
{
	ZHeapTuple	tuple;			/* return tuple */
	ZHeapTupleHeader td;		/* tuple data */
	Size		len,
				data_len;
	int			hoff;
	bool		hasnull = false;
	int			numberOfAttributes = tupleDescriptor->natts;
	int			i;

	if (numberOfAttributes > MaxTupleAttributeNumber)
		ereport(ERROR,
				(errcode(ERRCODE_TOO_MANY_COLUMNS),
				 errmsg("number of columns (%d) exceeds limit (%d)",
						numberOfAttributes, MaxTupleAttributeNumber)));

	/*
	 * Check for nulls
	 */
	for (i = 0; i < numberOfAttributes; i++)
	{
		if (isnull[i])
		{
			hasnull = true;
			break;
		}
	}

	/*
	 * Determine total space needed
	 */
	len = offsetof(ZHeapTupleHeaderData, t_bits);

	if (hasnull)
		len += BITMAPLEN(numberOfAttributes);

	/*
	 * We don't MAXALIGN the tuple headers as we always make the copy of tuple
	 * to support in-place updates.
	 */
	hoff = len;

	data_len = zheap_compute_data_size(tupleDescriptor, values, isnull, hoff);

	len += data_len;

	/*
	 * Allocate and zero the space needed.  Note that the tuple body and
	 * ZHeapTupleData management structure are allocated in one chunk.
	 */
	tuple = MemoryContextAllocExtended(CurrentMemoryContext,
									   ZHEAPTUPLESIZE + len,
									   MCXT_ALLOC_HUGE | MCXT_ALLOC_ZERO);
	tuple->t_data = td = (ZHeapTupleHeader) ((char *) tuple + ZHEAPTUPLESIZE);

	/*
	 * And fill in the information.  Note we fill the Datum fields even though
	 * this tuple may never become a Datum.  This lets HeapTupleHeaderGetDatum
	 * identify the tuple type if needed.
	 */
	tuple->t_len = len;
	ItemPointerSetInvalid(&(tuple->t_self));
	tuple->t_tableOid = InvalidOid;

	ZHeapTupleHeaderSetNatts(td, numberOfAttributes);
	td->t_hoff = hoff;

	zheap_fill_tuple(tupleDescriptor,
					 values,
					 isnull,
					 (char *) td + hoff,
					 data_len,
					 &td->t_infomask,
					 (hasnull ? td->t_bits : NULL));

	return tuple;
}

/*
 * zheap_deform_tuple - similar to heap_deform_tuple, but for zheap tuples.
 *
 * Note that for zheap, cached offsets are not used and we always start
 * deforming with the actual byte from where the first attribute starts.  See
 * atop zheap_compute_data_size.
 */
void
zheap_deform_tuple(ZHeapTuple tuple, TupleDesc tupleDesc,
				   Datum *values, bool *isnull)
{
	ZHeapTupleHeader tup = tuple->t_data;
	bool		hasnulls = ZHeapTupleHasNulls(tuple);
	int			tdesc_natts = tupleDesc->natts;
	int			natts;			/* number of atts to extract */
	int			attnum;
	char	   *tp;				/* ptr to tuple data */
	long		off;			/* offset in tuple data */
	bits8	   *bp = tup->t_bits;	/* ptr to null bitmap in tuple */

	natts = ZHeapTupleHeaderGetNatts(tup);

	/*
	 * In inheritance situations, it is possible that the given tuple actually
	 * has more fields than the caller is expecting.  Don't run off the end of
	 * the caller's arrays.
	 */
	natts = Min(natts, tdesc_natts);

	tp = (char *) tup;

	off = tup->t_hoff;

	for (attnum = 0; attnum < natts; attnum++)
	{
		Form_pg_attribute thisatt = TupleDescAttr(tupleDesc, attnum);

		if (hasnulls && att_isnull(attnum, bp))
		{
			values[attnum] = (Datum) 0;
			isnull[attnum] = true;
			continue;
		}

		isnull[attnum] = false;

		if (thisatt->attlen == -1)
		{
			off = att_align_pointer(off, thisatt->attalign, -1,
									tp + off);
		}
		else if (!thisatt->attbyval)
		{
			/* not varlena, so safe to use att_align_nominal */
			off = att_align_nominal(off, thisatt->attalign);
		}

		/*
		 * Support fetching attributes for zheap.  The main difference as
		 * compare to heap tuples is that we don't align passbyval attributes.
		 * To compensate that we use memcpy to fetch passbyval attributes.
		 */
		if (thisatt->attbyval)
		{
			Datum		datum;

			memcpy(&datum, tp + off, thisatt->attlen);

			/*
			 * We use fetch_att to set the other uninitialized bytes in datum
			 * field as zero.  We could achieve that by just initializing
			 * datum with zero, but this helps us to keep the code in sync
			 * with heap.
			 */
			values[attnum] = fetch_att(&datum, true, thisatt->attlen);
		}
		else
			values[attnum] = PointerGetDatum((char *) (tp + off));

		off = att_addlength_pointer(off, thisatt->attlen, tp + off);
	}

	/*
	 * If tuple doesn't have all the atts indicated by tupleDesc, read the
	 * rest as nulls or missing values as appropriate.
	 */
	for (; attnum < tdesc_natts; attnum++)
		values[attnum] = getmissingattr(tupleDesc, attnum + 1, &isnull[attnum]);
}

/*
 * zheap_freetuple
 */
void
zheap_freetuple(ZHeapTuple zhtup)
{
	pfree(zhtup);
}

/*
 * znocachegetattr - This is same as nocachegetattr except that it takes
 * ZHeapTuple as input.
 *
 * Note that for zheap, cached offsets are not used and we always start
 * deforming with the actual byte from where the first attribute starts.  See
 * atop zheap_compute_data_size.
 */
Datum
znocachegetattr(ZHeapTuple tuple,
				int attnum,
				TupleDesc tupleDesc)
{
	ZHeapTupleHeader tup = tuple->t_data;
	Form_pg_attribute thisatt;
	Datum		ret_datum = (Datum) 0;
	char	   *tp;				/* ptr to data part of tuple */
	bits8	   *bp = tup->t_bits;	/* ptr to null bitmap in tuple */
	int			off;			/* current offset within data */
	int			i;

	attnum--;
	tp = (char *) tup;

	/*
	 * For each non-null attribute, we have to first account for alignment
	 * padding before the attr, then advance over the attr based on its
	 * length.  Nulls have no storage and no alignment padding either.
	 */
	off = tup->t_hoff;

	for (i = 0;; i++)			/* loop exit is at "break" */
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

		if (ZHeapTupleHasNulls(tuple) && att_isnull(i, bp))
		{
			continue;			/* this cannot be the target att */
		}

		if (att->attlen == -1)
		{
			off = att_align_pointer(off, att->attalign, -1,
									tp + off);
		}
		else if (!att->attbyval)
		{
			/* not varlena, so safe to use att_align_nominal */
			off = att_align_nominal(off, att->attalign);
		}

		if (i == attnum)
			break;

		off = att_addlength_pointer(off, att->attlen, tp + off);
	}

	thisatt = TupleDescAttr(tupleDesc, attnum);
	if (thisatt->attbyval)
	{
		Datum		datum;

		memcpy(&datum, tp + off, thisatt->attlen);

		/*
		 * We use fetch_att to set the other uninitialized bytes in datum
		 * field as zero.  We could achieve that by just initializing datum
		 * with zero, but this helps us to keep the code in sync with heap.
		 */
		ret_datum = fetch_att(&datum, true, thisatt->attlen);
	}
	else
		ret_datum = PointerGetDatum((char *) (tp + off));

	return ret_datum;
}

/* ----------------
 *		zheap_getsysattr
 *
 *		Fetch the value of a system attribute for a tuple.
 *
 * This provides same information as heap_getsysattr, but for zheap tuple.
 * ----------------
 */
Datum
zheap_getsysattr(ZHeapTuple zhtup, Buffer buf, int attnum,
				 TupleDesc tupleDesc, bool *isnull)
{
	Datum		result;
	TransactionId xid = InvalidTransactionId;
	bool		release_buf = false;

	Assert(zhtup);

	/*
	 * For xmin,xmax,cmin and cmax we may need to fetch the information from
	 * the undo record, so ensure we have the valid buffer.
	 */
	if (!BufferIsValid(buf) &&
		((attnum == MinTransactionIdAttributeNumber) ||
		 (attnum == MaxTransactionIdAttributeNumber) ||
		 (attnum == MinCommandIdAttributeNumber) ||
		 (attnum == MaxCommandIdAttributeNumber)))
	{
		Relation	rel = relation_open(zhtup->t_tableOid, NoLock);

		buf = ReadBuffer(rel, ItemPointerGetBlockNumber(&(zhtup->t_self)));
		relation_close(rel, NoLock);
		release_buf = true;
	}

	/* Currently, no sys attribute ever reads as NULL. */
	*isnull = false;

	switch (attnum)
	{
		case SelfItemPointerAttributeNumber:
			/* pass-by-reference datatype */
			result = PointerGetDatum(&(zhtup->t_self));
			break;
		case MinTransactionIdAttributeNumber:
			{
				/*
				 * Fixme - Need to check whether we need any handling of epoch
				 * here.
				 */
				uint64		epoch_xid;

				ZHeapTupleGetTransInfo(zhtup, buf, NULL, &epoch_xid, &xid,
									   NULL, NULL, false, InvalidSnapshot);

				if (!TransactionIdIsValid(xid) || epoch_xid <
					pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
					xid = FrozenTransactionId;

				result = TransactionIdGetDatum(xid);
			}
			break;
		case MaxTransactionIdAttributeNumber:
		case MinCommandIdAttributeNumber:
		case MaxCommandIdAttributeNumber:
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("xmax, cmin, and cmax are not supported for zheap tuples")));
			break;
		case TableOidAttributeNumber:
			result = ObjectIdGetDatum(zhtup->t_tableOid);
			break;
		default:
			elog(ERROR, "invalid attnum: %d", attnum);
			result = 0;			/* keep compiler quiet */
			break;
	}

	if (release_buf)
		ReleaseBuffer(buf);

	return result;
}

/* ---------------------
 *		zheap_attisnull  - returns TRUE if zheap tuple attribute is not present
 * ---------------------
 */
bool
zheap_attisnull(ZHeapTuple tup, int attnum, TupleDesc tupleDesc)
{
	if (attnum > (int) ZHeapTupleHeaderGetNatts(tup->t_data))
		return true;

	/*
	 * We allow a NULL tupledesc for relations not expected to have missing
	 * values, such as catalog relations and indexes.
	 */
	Assert(!tupleDesc || attnum <= tupleDesc->natts);
	if (attnum > (int) ZHeapTupleHeaderGetNatts(tup->t_data))
	{
		if (tupleDesc && TupleDescAttr(tupleDesc, attnum - 1)->atthasmissing)
			return false;
		else
			return true;
	}

	if (attnum > 0)
	{
		if (ZHeapTupleNoNulls(tup))
			return false;
		return att_isnull(attnum - 1, tup->t_data->t_bits);
	}

	switch (attnum)
	{
		case TableOidAttributeNumber:
		case SelfItemPointerAttributeNumber:
		case MinTransactionIdAttributeNumber:
		case MinCommandIdAttributeNumber:
		case MaxTransactionIdAttributeNumber:
		case MaxCommandIdAttributeNumber:
			/* these are never null */
			break;
		default:
			elog(ERROR, "invalid attnum: %d", attnum);
	}

	return false;
}

/*
 * Check if the specified attribute's value is same in both given tuples.
 * Subroutine for ZHeapDetermineModifiedColumns.
 */
bool
zheap_tuple_attr_equals(TupleDesc tupdesc, int attrnum,
						ZHeapTuple tup1, ZHeapTuple tup2)
{
	Datum		value1,
				value2;
	bool		isnull1,
				isnull2;
	Form_pg_attribute att;

	/*
	 * If it's a whole-tuple reference, say "not equal".  It's not really
	 * worth supporting this case, since it could only succeed after a no-op
	 * update, which is hardly a case worth optimizing for.
	 */
	if (attrnum == 0)
		return false;

	/*
	 * Likewise, automatically say "not equal" for any system attribute other
	 * than OID and tableOID; we cannot expect these to be consistent in a HOT
	 * chain, or even to be set correctly yet in the new tuple.
	 */
	if (attrnum < 0)
	{
		if (attrnum != TableOidAttributeNumber)
			return false;
	}

	/*
	 * Extract the corresponding values.  XXX this is pretty inefficient if
	 * there are many indexed columns.  Should HeapDetermineModifiedColumns do
	 * a single heap_deform_tuple call on each tuple, instead?	But that
	 * doesn't work for system columns ...
	 */
	value1 = zheap_getattr(tup1, attrnum, tupdesc, &isnull1);
	value2 = zheap_getattr(tup2, attrnum, tupdesc, &isnull2);

	/*
	 * If one value is NULL and other is not, then they are certainly not
	 * equal
	 */
	if (isnull1 != isnull2)
		return false;

	/*
	 * If both are NULL, they can be considered equal.
	 */
	if (isnull1)
		return true;

	/*
	 * We do simple binary comparison of the two datums.  This may be overly
	 * strict because there can be multiple binary representations for the
	 * same logical value.  But we should be OK as long as there are no false
	 * positives.  Using a type-specific equality operator is messy because
	 * there could be multiple notions of equality in different operator
	 * classes; furthermore, we cannot safely invoke user-defined functions
	 * while holding exclusive buffer lock.
	 */
	if (attrnum <= 0)
	{
		/* The only allowed system columns are OIDs, so do this */
		return (DatumGetObjectId(value1) == DatumGetObjectId(value2));
	}
	else
	{
		Assert(attrnum <= tupdesc->natts);
		att = TupleDescAttr(tupdesc, attrnum - 1);
		return datumIsEqual(value1, value2, att->attbyval, att->attlen);
	}
}

/*
 * TupleTableSlotOps implementation for ZheapHeapTupleTableSlot.
 */

static void
tts_zheap_init(TupleTableSlot *slot)
{
}

static void
tts_zheap_release(TupleTableSlot *slot)
{
}

static void
tts_zheap_clear(TupleTableSlot *slot)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	/*
	 * Free the memory for heap tuple if allowed. A tuple coming from zheap
	 * can never be freed. But we may have materialized a tuple from zheap.
	 * Such a tuple can be freed.
	 */
	if (TTS_SHOULDFREE(slot))
	{
		zheap_freetuple(zslot->tuple);
		slot->tts_flags &= ~TTS_FLAG_SHOULDFREE;
	}

#if 0
	if (ZheapIsValid(bslot->zheap))
		ReleaseZheap(bslot->zheap);
#endif

	slot->tts_nvalid = 0;
	slot->tts_flags |= TTS_FLAG_EMPTY;
	zslot->tuple = NULL;
}

static void
tts_zheap_getsomeattrs(TupleTableSlot *slot, int natts)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	Assert(!TTS_EMPTY(slot));
	slot_deform_ztuple(slot, zslot->tuple, &zslot->off, natts);
}

static Datum
tts_zheap_getsysattr(TupleTableSlot *slot, int attnum, bool *isnull)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	return zheap_getsysattr(zslot->tuple, InvalidBuffer, attnum,
							slot->tts_tupleDescriptor, isnull);
}

/*
 * Materialize the heap tuple contained in the given slot into its own memory
 * context.
 */
static void
tts_zheap_materialize(TupleTableSlot *slot)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;
	MemoryContext oldContext;

	Assert(!TTS_EMPTY(slot));

	/* If already materialized nothing to do. */
	if (TTS_SHOULDFREE(slot))
		return;

	slot->tts_flags |= TTS_FLAG_SHOULDFREE;

	oldContext = MemoryContextSwitchTo(slot->tts_mcxt);

	if (zslot->tuple)
		zslot->tuple = zheap_copytuple(zslot->tuple);
	else
	{
		/*
		 * The tuple contained in this slot is not allocated in the memory
		 * context of the given slot (else it would have TTS_SHOULDFREE set).
		 * Copy the tuple into the given slot's memory context.
		 */
		zslot->tuple = zheap_form_tuple(slot->tts_tupleDescriptor,
										slot->tts_values,
										slot->tts_isnull);
	}
	MemoryContextSwitchTo(oldContext);

#if 0

	/*
	 * TODO: I expect a ZheapHeapTupleTableSlot to always have a zheap to be
	 * associated with it OR the tuple is materialized. In the later case we
	 * won't come here. So, we should always see a valid zheap here to be
	 * unpinned.
	 */
	if (zslot->tuple)
	{
		ReleaseZheap(bslot->zheap);
		bslot->zheap = InvalidZheap;
	}
#endif

	/*
	 * Have to deform from scratch, otherwise tts_values[] entries could point
	 * into the non-materialized tuple (which might be gone when accessed).
	 */
	slot->tts_nvalid = 0;
	zslot->off = 0;
}

static void
tts_zheap_copyslot(TupleTableSlot *dstslot, TupleTableSlot *srcslot)
{
	HeapTuple	tuple;
	MemoryContext oldcontext;

	/* ZBORKED: This is a horrible implementation */

	oldcontext = MemoryContextSwitchTo(dstslot->tts_mcxt);
	tuple = ExecCopySlotHeapTuple(srcslot);
	MemoryContextSwitchTo(oldcontext);

	ExecForceStoreHeapTuple(tuple, dstslot);
	ExecMaterializeSlot(dstslot);

	pfree(tuple);
}

static HeapTuple
tts_zheap_copy_heap_tuple(TupleTableSlot *slot)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	Assert(!TTS_EMPTY(slot));

	if (!zslot->tuple)
		tts_zheap_materialize(slot);

	return zheap_to_heap(zslot->tuple, slot->tts_tupleDescriptor);
}

/*
 * Return a minimal tuple constructed from the contents of the slot.
 *
 * We always return a new minimal tuple so no copy, per say, is needed.
 *
 * TODO:
 * This function is exact copy of tts_zheap_get_minimal_tuple() and thus the
 * callback should point to that one instead of a new implementation. But
 * there's one TODO there which might change tts_heap_get_minimal_tuple().
 */
static MinimalTuple
tts_zheap_copy_minimal_tuple(TupleTableSlot *slot)
{
	slot_getallattrs(slot);

	return heap_form_minimal_tuple(slot->tts_tupleDescriptor,
								   slot->tts_values, slot->tts_isnull);
}

const		TupleTableSlotOps TTSOpsZHeapTuple = {
	.base_slot_size = sizeof(ZHeapTupleTableSlot),
	.init = tts_zheap_init,
	.release = tts_zheap_release,
	.clear = tts_zheap_clear,
	.getsomeattrs = tts_zheap_getsomeattrs,
	.getsysattr = tts_zheap_getsysattr,
	.materialize = tts_zheap_materialize,
	.copyslot = tts_zheap_copyslot,

	.get_heap_tuple = NULL,
	.get_minimal_tuple = NULL,

	.copy_heap_tuple = tts_zheap_copy_heap_tuple,
	.copy_minimal_tuple = tts_zheap_copy_minimal_tuple
};

void
slot_deform_ztuple(TupleTableSlot *slot, ZHeapTuple tuple, uint32 *offp, int natts)
{
	TupleDesc	tupleDesc = slot->tts_tupleDescriptor;
	Datum	   *values = slot->tts_values;
	bool	   *isnull = slot->tts_isnull;
	ZHeapTupleHeader tup = tuple->t_data;
	bool		hasnulls = ZHeapTupleHasNulls(tuple);
	int			attnum;
	char	   *tp;				/* ptr to tuple data */
	uint32		off;			/* offset in tuple data */
	bits8	   *bp = tup->t_bits;	/* ptr to null bitmap in tuple */

	/* We can only fetch as many attributes as the tuple has. */
	natts = Min(HeapTupleHeaderGetNatts(tuple->t_data), natts);

	/*
	 * Check whether the first call for this tuple, and initialize or restore
	 * loop state.
	 */
	attnum = slot->tts_nvalid;
	if (attnum == 0)
		off = 0;				/* Start from the first attribute */
	else
		off = *offp;			/* Restore state from previous execution */

	tp = (char *) tup + tup->t_hoff + off;

	for (; attnum < natts; attnum++)
	{
		Form_pg_attribute thisatt = TupleDescAttr(tupleDesc, attnum);

		if (hasnulls && att_isnull(attnum, bp))
		{
			values[attnum] = (Datum) 0;
			isnull[attnum] = true;
			continue;
		}

		isnull[attnum] = false;

		if (thisatt->attlen == -1)
		{
			tp = (char *) att_align_pointer(tp, thisatt->attalign, -1,
											tp);
		}
		else if (!thisatt->attbyval)
		{
			/* not varlena, so safe to use att_align_nominal */
			tp = (char *) att_align_nominal(tp, thisatt->attalign);
		}
		/* XXX: We don't align for byval attributes in zheap. */

		/*
		 * Support fetching attributes for zheap.  The main difference as
		 * compare to heap tuples is that we don't align passbyval attributes.
		 * To compensate that we use memcpy to fetch the source of passbyval
		 * attributes.
		 */
		if (thisatt->attbyval)
		{
			Datum		datum;

			memcpy(&datum, tp, thisatt->attlen);

			/*
			 * We use fetch_att to set the other uninitialized bytes in datum
			 * field as zero.  We could achieve that by just initializing
			 * datum with zero, but this helps us to keep the code in sync
			 * with heap.
			 */
			values[attnum] = fetch_att(&datum, true, thisatt->attlen);
		}
		else
			values[attnum] = PointerGetDatum(tp);

		tp = att_addlength_pointer(tp, thisatt->attlen, tp);
	}

	/*
	 * Save state for next execution
	 */
	slot->tts_nvalid = attnum;
	*offp = tp - ((char *) tup + tup->t_hoff);
}

/*
 * ExecGetZHeapTupleFromSlot - fetch ZHeapTuple repersenting the slot's
 *	content.
 */
ZHeapTuple
ExecGetZHeapTupleFromSlot(TupleTableSlot *slot)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	if (TTS_EMPTY(slot))
		return NULL;

	/*
	 * ZBORKED: to fix the memory management for this, the API should be
	 * like ExecFetchSlotHeapTuple()'s.
	 */
	if (!TTS_IS_ZHEAP(slot))
	{
		slot_getallattrs(slot);
		return zheap_form_tuple(slot->tts_tupleDescriptor,
								slot->tts_values,
								slot->tts_isnull);
	}

	if (!zslot->tuple)
		slot->tts_ops->materialize(slot);

	return zslot->tuple;
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
ExecStoreZTuple(ZHeapTuple tuple, TupleTableSlot *slot, Buffer buffer,
				bool shouldFree)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	/*
	 * sanity checks
	 */
	Assert(slot != NULL);
	Assert(TTS_IS_ZHEAP(slot));
	tts_zheap_clear(slot);

	slot->tts_nvalid = 0;
	zslot->tuple = tuple;
	zslot->off = 0;
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	slot->tts_tid = tuple->t_self;

	if (shouldFree)
		slot->tts_flags |= TTS_FLAG_SHOULDFREE;

	return slot;
}
