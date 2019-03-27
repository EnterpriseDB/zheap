/*-------------------------------------------------------------------------
 *
 * ztuple.c
 *	  Routines to form and deform zheap tuples.
 *
 * zheap implements three separate optimizations which reduce the size of
 * zheap tuples as compared with PostgreSQL's traditional heap tuple
 * format.
 *
 * First, nearly all transactional information is stored in page-level
 * structures or in the undo log rather than on a per-tuple basis.  As
 * a result, tuple headers can be much narrower -- just 5 bytes rather
 * than 23.
 *
 * Second, we omit alignment padding between the tuple header and the
 * tuple data.  Because we support in-place update, we can never return
 * to the executor a pointer directly into the page; instead, every
 * tuple must be copied -- and we can easily copy it into an aligned
 * buffer, whether or not the source data is aligned.
 *
 * Third, we omit all alignment padding for pass-by-value data types.
 * Outside of system catalogs, where it is important for the fixed-width
 * portion of the tuple to match the format of a C "struct", this padding
 * isn't even beneficial in the current heap, although it can't easily be
 * removed for reasons of backward compatibility.  zheap tables can't
 * currently be used for system catalogs, so this doesn't matter at all
 * right now; if it matters someday, we should find a better solution
 * than inserting unnecessary padding into user tables that may contain
 * billions of rows.
 *
 * Unfortunately, zheap cannot take advantage of attcacheoff when
 * forming and deforming tuples, because we still sometimes need to
 * take data from a zheap table and put in the form of a heap tuple,
 * and that code would get confused if the offset had been set according
 * to zheap's weaker alignment rules.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/ztuple.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/relation.h"
#include "access/tpd.h"
#include "storage/proc.h"
#include "utils/datum.h"
#include "utils/ztqual.h"

static void tts_zheap_init(TupleTableSlot *slot);
static void tts_zheap_release(TupleTableSlot *slot);
static void tts_zheap_clear(TupleTableSlot *slot);
static void tts_zheap_getsomeattrs(TupleTableSlot *slot, int natts);
static Datum tts_zheap_getsysattr(TupleTableSlot *slot, int attnum,
					 bool *isnull);
static void tts_zheap_materialize(TupleTableSlot *slot);
static void tts_zheap_copyslot(TupleTableSlot *dstslot,
				   TupleTableSlot *srcslot);
static HeapTuple tts_zheap_copy_heap_tuple(TupleTableSlot *slot);
static MinimalTuple tts_zheap_copy_minimal_tuple(TupleTableSlot *slot);

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

/*
 * zheap_compute_data_size
 *		Determine size of the data area for a zheap tuple.
 *
 * Even the first attribute might require alignment, because in zheap,
 * unlike the regular heap, t_hoff is not necessarily a multiple of
 * MAXIMUM_ALIGNOF.
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
			/* attbyval attributes are stored unaligned in zheap. */
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
			/*
			 * We'll reach this case when storing a varlena that needs a
			 * 4-byte header, a variable-width type that requires alignment
			 * such as a record type, and for fixed-width types that are
			 * not pass-by-value (e.g. aclitem).
			 */
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
 *		Load data portion of a tuple from values/isnull arrays.
 *
 * We also fill the null bitmap (if any) and set the infomask bits
 * that reflect the tuple's data contents.  Note that zheap uses different
 * infomask values than the regular heap, and that the alignment rules
 * are different (see the file header comment for more details).
 *
 * The data area must be pre-zeroed on entry to this function.
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
		 * We use the att_align macros on the pointer value itself, not on
		 * an offset.  This is a bit of a hack.
		 */
		if (att->attbyval)
		{
			/* pass-by-value */
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
			/* cstring never needs alignment */
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
 *		Construct a zheap tuple from the given values[] and isnull[] arrays.
 *
 * The result is allocated in the current memory context.
 */
ZHeapTuple
zheap_form_tuple(TupleDesc tupleDescriptor, Datum *values, bool *isnull)
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

	/* Check for nulls */
	for (i = 0; i < numberOfAttributes; i++)
	{
		if (isnull[i])
		{
			hasnull = true;
			break;
		}
	}

	/* Compute required space.  Note that, in zheap, hoff is not aligned. */
	len = offsetof(ZHeapTupleHeaderData, t_bits);
	if (hasnull)
		len += BITMAPLEN(numberOfAttributes);
	hoff = len;
	data_len = zheap_compute_data_size(tupleDescriptor, values, isnull, hoff);
	len += data_len;

	/* Allocate the require space as a single chunk. */
	tuple = MemoryContextAllocExtended(CurrentMemoryContext,
									   ZHEAPTUPLESIZE + len,
									   MCXT_ALLOC_HUGE | MCXT_ALLOC_ZERO);
	tuple->t_data = td = (ZHeapTupleHeader) ((char *) tuple + ZHEAPTUPLESIZE);

	/*
	 * And fill in the information.  Note we fill the Datum fields even though
	 * this tuple may never become a Datum.  This lets HeapTupleHeaderGetDatum
	 * identify the tuple type if needed.
	 *
	 * ZBORKED: The comment above is false.  Not only do we not set those
	 * fields, but in zheap they don't even exist.  Do we just need to adjust
	 * the comment, or is there something that actually needs to be changed
	 * here?
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
 * zheap_deform_tuple
 * 		Extract data from a zheap tuple into values/isnull arrays.
 *
 * See file header comments for an explanation of why attcacheoff is not
 * used here.  Note that for pass-by-referenced datatypes, the pointer
 * placed in the Datum will point into the given tuple.
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

	/* Loop over attributes one by one. */
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

		/*
		 * If this is a varlena, there might be alignment padding, if it has
		 * a 4-byte header.  Otherwise, there will only be padding if it's
		 * not pass-by-value.
		 */
		if (thisatt->attlen == -1)
			off = att_align_pointer(off, thisatt->attalign, -1,
									tp + off);
		else if (!thisatt->attbyval)
			off = att_align_nominal(off, thisatt->attalign);

		if (thisatt->attbyval)
		{
			Datum		datum;

			/*
			 * Since pass-by-value attributes are not aligned in zheap, use
			 * memcpy to copy the value into adequately-aligned storage.
			 * Since it's pass-by-value, a Datum must be big enough.
			 */
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
 * 		Free memory used to store zheap tuple.
 */
void
zheap_freetuple(ZHeapTuple zhtup)
{
	pfree(zhtup);
}

/*
 * znocachegetattr
 * 		This is same as nocachegetattr except that it takes
 * ZHeapTuple as input.
 *
 * Note that for zheap, cached offsets are not used and we always start
 * deforming with the actual byte from where the first attribute starts.  See
 * atop zheap_compute_data_size.
 *
 * ZBORKED: The comments above more or less contradict each other; the first
 * one says that this is the same as nocachegetattr and the second one
 * describes a second difference between this function and nocachegetattr().
 * Really, this function is misnamed for zheap, because *ALL* attribute
 * fetches in zheap are "nocache", so shouldn't we just rename this to
 * zgetattr or something like that?
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
			continue;			/* this cannot be the target att */

		/*
		 * If this is a varlena, there might be alignment padding, if it has
		 * a 4-byte header.  Otherwise, there will only be padding if it's
		 * not pass-by-value.
		 */
		if (att->attlen == -1)
			off = att_align_pointer(off, att->attalign, -1,
									tp + off);
		else if (!att->attbyval)
			off = att_align_nominal(off, att->attalign);

		if (i == attnum)
			break;

		off = att_addlength_pointer(off, att->attlen, tp + off);
	}

	thisatt = TupleDescAttr(tupleDesc, attnum);
	if (thisatt->attbyval)
	{
		Datum		datum;

		/*
		 * Since pass-by-value attributes are not aligned in zheap, use
		 * memcpy to copy the value into adequately-aligned storage.
		 * Since it's pass-by-value, a Datum must be big enough.
		 */
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

/*
 * zheap_getsysattr
 *		Fetch the value of a system attribute for a tuple.
 */
Datum
zheap_getsysattr(ZHeapTuple zhtup, Buffer buf, int attnum,
				 TupleDesc tupleDesc, bool *isnull)
{
	Datum		result;
	bool		release_buf = false;

	Assert(zhtup);

	/*
	 * For xmin,xmax,cmin and cmax we may need to fetch the information from
	 * the undo record, so ensure we have a valid buffer.
	 *
	 * ZBORKED: It does not seem acceptable to call relation_open() here.
	 * This is a very low-level function which has no business touching the
	 * relcache.
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
				ZHeapTupleTransInfo	zinfo;

				ZHeapTupleGetTransInfo(zhtup, buf, false, false,
									   InvalidSnapshot, &zinfo);

				if (!TransactionIdIsValid(zinfo.xid) || zinfo.epoch_xid <
					pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
					zinfo.xid = FrozenTransactionId;

				result = TransactionIdGetDatum(zinfo.xid);
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

/*
 * zheap_attisnull
 * 		Returns TRUE if zheap tuple attribute is not present.
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
 * zheap_tuple_attr_equals
 * 		Subroutine for ZHeapDetermineModifiedColumns to check if the specified
 *		attribute value is same in both given tuples.
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

	slot->tts_nvalid = 0;
	slot->tts_flags |= TTS_FLAG_EMPTY;
	zslot->tuple = NULL;
	zslot->off = 0;
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
 * tts_zheap_materialize
 * 		Materialize the zheap tuple contained in the given slot into its own
 *		memory context.
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

	/*
	 * Have to deform from scratch, otherwise tts_values[] entries could point
	 * into the non-materialized tuple (which might be gone when accessed).
	 */
	slot->tts_nvalid = 0;
	zslot->off = 0;
}

/*
 * tts_zheap_copyslot
 *
 * ZBORKED: This is extremely inefficient, because it forms a heap tuple
 * for the source slot which we definitely can't store, and must therefore
 * deform again -- only to turn around and build a zheap tuple again.
 * It seems like we should instead do slot_getallattrs() on the source slot
 * and then copy the Datum/isnull arrays.
 */
static void
tts_zheap_copyslot(TupleTableSlot *dstslot, TupleTableSlot *srcslot)
{
	HeapTuple	tuple;
	MemoryContext oldcontext;

	oldcontext = MemoryContextSwitchTo(dstslot->tts_mcxt);
	tuple = ExecCopySlotHeapTuple(srcslot);
	MemoryContextSwitchTo(oldcontext);

	ExecForceStoreHeapTuple(tuple, dstslot);
	ExecMaterializeSlot(dstslot);

	pfree(tuple);
}

/*
 * tts_zheap_copy_heap_tuple
 *		Return a heap tuple constructed from the contents of the slot.
 *
 * heap_form_tuple will always a build a new tuple, so we don't need an
 * explicit copy step.
 */
static HeapTuple
tts_zheap_copy_heap_tuple(TupleTableSlot *slot)
{
	HeapTuple	tuple;

	Assert(!TTS_EMPTY(slot));
	slot_getallattrs(slot);

	tuple = heap_form_tuple(slot->tts_tupleDescriptor,
							slot->tts_values, slot->tts_isnull);
	tuple->t_self = slot->tts_tid;
	tuple->t_tableOid = slot->tts_tableOid;

	return tuple;
}

/*
 * tts_zheap_copy_minimal_tuple
 *		Return a minimal tuple constructed from the contents of the slot.
 *
 * heap_form_minimal_tuple will always a build a new tuple, so we don't
 * need an explicit copy step.
 */
static MinimalTuple
tts_zheap_copy_minimal_tuple(TupleTableSlot *slot)
{
	Assert(!TTS_EMPTY(slot));

	slot_getallattrs(slot);

	return heap_form_minimal_tuple(slot->tts_tupleDescriptor,
								   slot->tts_values, slot->tts_isnull);
}

void
slot_deform_ztuple(TupleTableSlot *slot, ZHeapTuple tuple,
				   uint32 *offp, int natts)
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

		if (thisatt->attbyval)
		{
			Datum		datum;

			/*
			 * Since pass-by-value attributes are not aligned in zheap, use
			 * memcpy to copy the value into adequately-aligned storage.
			 * Since it's pass-by-value, a Datum must be big enough.
			 */
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
 * ExecGetZHeapTupleFromSlot
 *   Fetch ZHeapTuple representing the slot's content.
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

/*
 * ExecStoreZHeapTuple
 *		Store a physical zheap tuple into a TTSOpsZHeapTuple slot.
 */
TupleTableSlot *
ExecStoreZHeapTuple(ZHeapTuple tuple, TupleTableSlot *slot, bool shouldFree)
{
	ZHeapTupleTableSlot *zslot = (ZHeapTupleTableSlot *) slot;

	/* sanity checks */
	Assert(slot != NULL);
	Assert(TTS_IS_ZHEAP(slot));

	/* clear slot and store new tuple */
	tts_zheap_clear(slot);
	zslot->tuple = tuple;
	slot->tts_flags &= ~TTS_FLAG_EMPTY;
	slot->tts_tid = tuple->t_self;

	/* set flag if needed */
	if (shouldFree)
		slot->tts_flags |= TTS_FLAG_SHOULDFREE;

	return slot;
}

/*
 * heap_to_zheap
 *		Convert heap tuple to zheap tuple.
 */
ZHeapTuple
heap_to_zheap(HeapTuple tuple, TupleDesc tupDesc)
{
	ZHeapTuple	ztuple;
	Datum	   *values = palloc0(sizeof(Datum) * tupDesc->natts);
	bool	   *nulls = palloc0(sizeof(bool) * tupDesc->natts);

	heap_deform_tuple(tuple, tupDesc, values, nulls);
	ztuple = zheap_form_tuple(tupDesc, values, nulls);
	ztuple->t_self = tuple->t_self;
	ztuple->t_tableOid = tuple->t_tableOid;

	pfree(values);
	pfree(nulls);

	return ztuple;
}

/*
 * zheap_copytuple
 *		Returns a copy of an entire tuple.
 *
 * The ZHeapTuple struct, tuple header, and tuple data are all allocated
 * as a single palloc() block.
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
