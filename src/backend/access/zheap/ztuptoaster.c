/*-------------------------------------------------------------------------
 *
 * ztuptoaster.c
 *	  Support routines for external and compressed storage of
 *	  variable size attributes.
 *
 *	  This file contains common functionality with tuptoaster except that
 *	  the tuples are of zheap format and stored in zheap storage engine.
 *	  Even if we want to keep it as a separate code for this, the common
 *	  parts needs to be extracted.
 *
 *	  The benefit of storing toast data in zheap is that it avoids bloat in
 *	  toast storage. The tuple space can be immediately reclaimed once the
 *	  deleting transaction is committed.
 *
 * Copyright (c) 2000-2019, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/ztuptoaster.c
 *
 *
 * INTERFACE ROUTINES
 *		ztoast_insert_or_update -
 *			Try to make a given tuple fit into one page by compressing
 *			or moving off attributes
 *
 *		ztoast_delete -
 *			Reclaim toast storage when a tuple is deleted
 *
 *
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <unistd.h>
#include <fcntl.h>

#include "access/genam.h"
#include "access/table.h"
#include "access/tuptoaster.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "common/pg_lzcompress.h"
#include "miscadmin.h"
#include "utils/expandeddatum.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/typcache.h"
#include "access/zheap.h"

static void ztoast_delete_datum(Relation rel, Datum value, bool is_speculative);
static Datum ztoast_save_datum(Relation rel, Datum value,
							   struct varlena *oldexternal, int options, uint32 specToken);

/*
 * ztoast_insert_or_update
 *		Just like toast_insert_or_update but for zheap relations.
 */

ZHeapTuple
ztoast_insert_or_update(Relation rel, ZHeapTuple newtup, ZHeapTuple oldtup,
						int options, uint32 specToken)
{
	ZHeapTuple	result_tuple;
	TupleDesc	tupleDesc;
	int			numAttrs;
	int			i;

	bool		need_change = false;
	bool		need_free = false;
	bool		need_delold = false;
	bool		has_nulls = false;

	Size		maxDataLen;
	Size		hoff;

	char		toast_action[MaxHeapAttributeNumber];
	bool		toast_isnull[MaxHeapAttributeNumber];
	bool		toast_oldisnull[MaxHeapAttributeNumber];
	Datum		toast_values[MaxHeapAttributeNumber];
	Datum		toast_oldvalues[MaxHeapAttributeNumber];
	struct varlena *toast_oldexternal[MaxHeapAttributeNumber];
	int32		toast_sizes[MaxHeapAttributeNumber];
	bool		toast_free[MaxHeapAttributeNumber];
	bool		toast_delold[MaxHeapAttributeNumber];

	/*
	 * We should only ever be called for tuples of plain relations or
	 * materialized views --- recursing on a toast rel is bad news.
	 */
	Assert(rel->rd_rel->relkind == RELKIND_RELATION ||
		   rel->rd_rel->relkind == RELKIND_MATVIEW);

	/*
	 * Get the tuple descriptor and break down the tuple(s) into fields.
	 */
	tupleDesc = rel->rd_att;
	numAttrs = tupleDesc->natts;

	Assert(numAttrs <= MaxHeapAttributeNumber);
	zheap_deform_tuple(newtup, tupleDesc, toast_values, toast_isnull, tupleDesc->natts);
	if (oldtup != NULL)
		zheap_deform_tuple(oldtup, tupleDesc, toast_oldvalues, toast_oldisnull, tupleDesc->natts);

	/* ----------
	 * Then collect information about the values given
	 *
	 * NOTE: toast_action[i] can have these values:
	 *		' '		default handling
	 *		'p'		already processed --- don't touch it
	 *		'x'		incompressible, but OK to move off
	 *
	 * NOTE: toast_sizes[i] is only made valid for varlena attributes with
	 *		toast_action[i] different from 'p'.
	 * ----------
	 */
	memset(toast_action, ' ', numAttrs * sizeof(char));
	memset(toast_oldexternal, 0, numAttrs * sizeof(struct varlena *));
	memset(toast_free, 0, numAttrs * sizeof(bool));
	memset(toast_delold, 0, numAttrs * sizeof(bool));

	for (i = 0; i < numAttrs; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);
		struct varlena *old_value;
		struct varlena *new_value;

		if (oldtup != NULL)
		{
			/*
			 * For UPDATE get the old and new values of this attribute
			 */
			old_value = (struct varlena *) DatumGetPointer(toast_oldvalues[i]);
			new_value = (struct varlena *) DatumGetPointer(toast_values[i]);

			/*
			 * If the old value is stored on disk, check if it has changed so
			 * we have to delete it later.
			 */
			if (att->attlen == -1 && !toast_oldisnull[i] &&
				VARATT_IS_EXTERNAL_ONDISK(old_value))
			{
				if (toast_isnull[i] || !VARATT_IS_EXTERNAL_ONDISK(new_value) ||
					memcmp((char *) old_value, (char *) new_value,
						   VARSIZE_EXTERNAL(old_value)) != 0)
				{
					/*
					 * The old external stored value isn't needed any more
					 * after the update
					 */
					toast_delold[i] = true;
					need_delold = true;
				}
				else
				{
					/*
					 * This attribute isn't changed by this update so we reuse
					 * the original reference to the old value in the new
					 * tuple.
					 */
					toast_action[i] = 'p';
					continue;
				}
			}
		}
		else
		{
			/*
			 * For INSERT simply get the new value
			 */
			new_value = (struct varlena *) DatumGetPointer(toast_values[i]);
		}

		/*
		 * Handle NULL attributes
		 */
		if (toast_isnull[i])
		{
			toast_action[i] = 'p';
			has_nulls = true;
			continue;
		}

		/*
		 * Now look at varlena attributes
		 */
		if (att->attlen == -1)
		{
			/*
			 * If the table's attribute says PLAIN always, force it so.
			 */
			if (att->attstorage == 'p')
				toast_action[i] = 'p';

			/*
			 * We took care of UPDATE above, so any external value we find
			 * still in the tuple must be someone else's that we cannot reuse
			 * (this includes the case of an out-of-line in-memory datum).
			 * Fetch it back (without decompression, unless we are forcing
			 * PLAIN storage).  If necessary, we'll push it out as a new
			 * external value below.
			 */
			if (VARATT_IS_EXTERNAL(new_value))
			{
				toast_oldexternal[i] = new_value;
				if (att->attstorage == 'p')
					new_value = heap_tuple_untoast_attr(new_value);
				else
					new_value = heap_tuple_fetch_attr(new_value);
				toast_values[i] = PointerGetDatum(new_value);
				toast_free[i] = true;
				need_change = true;
				need_free = true;
			}

			/*
			 * Remember the size of this attribute
			 */
			toast_sizes[i] = VARSIZE_ANY(new_value);
		}
		else
		{
			/*
			 * Not a varlena attribute, plain storage always
			 */
			toast_action[i] = 'p';
		}
	}

	/* ----------
	 * Compress and/or save external until data fits into target length
	 *
	 *	1: Inline compress attributes with attstorage 'x', and store very
	 *	   large attributes with attstorage 'x' or 'e' external immediately
	 *	2: Store attributes with attstorage 'x' or 'e' external
	 *	3: Inline compress attributes with attstorage 'm'
	 *	4: Store attributes with attstorage 'm' external
	 * ----------
	 */

	/* compute header overhead --- this should match heap_form_tuple() */
	hoff = SizeofZHeapTupleHeader;
	if (has_nulls)
		hoff += BITMAPLEN(numAttrs);

	/* now convert to a limit on the tuple data size */
	maxDataLen = RelationGetToastTupleTarget(rel, TOAST_TUPLE_TARGET) - hoff;

	/*
	 * Look for attributes with attstorage 'x' to compress.  Also find large
	 * attributes with attstorage 'x' or 'e', and store them external.
	 */
	while (zheap_compute_data_size(tupleDesc,
								   toast_values, toast_isnull, hoff) > maxDataLen)
	{
		int			biggest_attno = -1;
		int32		biggest_size = MAXALIGN(TOAST_POINTER_SIZE);
		Datum		old_value;
		Datum		new_value;

		/*
		 * Search for the biggest yet unprocessed internal attribute
		 */
		for (i = 0; i < numAttrs; i++)
		{
			Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

			if (toast_action[i] != ' ')
				continue;
			if (VARATT_IS_EXTERNAL(DatumGetPointer(toast_values[i])))
				continue;		/* can't happen, toast_action would be 'p' */
			if (VARATT_IS_COMPRESSED(DatumGetPointer(toast_values[i])))
				continue;
			if (att->attstorage != 'x' && att->attstorage != 'e')
				continue;
			if (toast_sizes[i] > biggest_size)
			{
				biggest_attno = i;
				biggest_size = toast_sizes[i];
			}
		}

		if (biggest_attno < 0)
			break;

		/*
		 * Attempt to compress it inline, if it has attstorage 'x'
		 */
		i = biggest_attno;
		if (TupleDescAttr(tupleDesc, i)->attstorage == 'x')
		{
			old_value = toast_values[i];
			new_value = toast_compress_datum(old_value);

			if (DatumGetPointer(new_value) != NULL)
			{
				/* successful compression */
				if (toast_free[i])
					pfree(DatumGetPointer(old_value));
				toast_values[i] = new_value;
				toast_free[i] = true;
				toast_sizes[i] = VARSIZE(DatumGetPointer(toast_values[i]));
				need_change = true;
				need_free = true;
			}
			else
			{
				/* incompressible, ignore on subsequent compression passes */
				toast_action[i] = 'x';
			}
		}
		else
		{
			/* has attstorage 'e', ignore on subsequent compression passes */
			toast_action[i] = 'x';
		}

		/*
		 * If this value is by itself more than maxDataLen (after compression
		 * if any), push it out to the toast table immediately, if possible.
		 * This avoids uselessly compressing other fields in the common case
		 * where we have one long field and several short ones.
		 *
		 * XXX maybe the threshold should be less than maxDataLen?
		 */
		if (toast_sizes[i] > maxDataLen &&
			rel->rd_rel->reltoastrelid != InvalidOid)
		{
			old_value = toast_values[i];
			toast_action[i] = 'p';
			toast_values[i] = ztoast_save_datum(rel, toast_values[i],
												toast_oldexternal[i], options,
												specToken);
			if (toast_free[i])
				pfree(DatumGetPointer(old_value));
			toast_free[i] = true;
			need_change = true;
			need_free = true;
		}
	}

	/*
	 * Second we look for attributes of attstorage 'x' or 'e' that are still
	 * inline.  But skip this if there's no toast table to push them to.
	 */
	while (zheap_compute_data_size(tupleDesc,
								   toast_values, toast_isnull, hoff) > maxDataLen &&
		   rel->rd_rel->reltoastrelid != InvalidOid)
	{
		int			biggest_attno = -1;
		int32		biggest_size = MAXALIGN(TOAST_POINTER_SIZE);
		Datum		old_value;

		/*------
		 * Search for the biggest yet inlined attribute with
		 * attstorage equals 'x' or 'e'
		 *------
		 */
		for (i = 0; i < numAttrs; i++)
		{
			Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

			if (toast_action[i] == 'p')
				continue;
			if (VARATT_IS_EXTERNAL(DatumGetPointer(toast_values[i])))
				continue;		/* can't happen, toast_action would be 'p' */
			if (att->attstorage != 'x' && att->attstorage != 'e')
				continue;
			if (toast_sizes[i] > biggest_size)
			{
				biggest_attno = i;
				biggest_size = toast_sizes[i];
			}
		}

		if (biggest_attno < 0)
			break;

		/*
		 * Store this external
		 */
		i = biggest_attno;
		old_value = toast_values[i];
		toast_action[i] = 'p';
		toast_values[i] = ztoast_save_datum(rel, toast_values[i],
											toast_oldexternal[i], options,
											specToken);
		if (toast_free[i])
			pfree(DatumGetPointer(old_value));
		toast_free[i] = true;

		need_change = true;
		need_free = true;
	}

	/*
	 * Round 3 - this time we take attributes with storage 'm' into
	 * compression
	 */
	while (zheap_compute_data_size(tupleDesc,
								   toast_values, toast_isnull, hoff) > maxDataLen)
	{
		int			biggest_attno = -1;
		int32		biggest_size = MAXALIGN(TOAST_POINTER_SIZE);
		Datum		old_value;
		Datum		new_value;

		/*
		 * Search for the biggest yet uncompressed internal attribute
		 */
		for (i = 0; i < numAttrs; i++)
		{
			if (toast_action[i] != ' ')
				continue;
			if (VARATT_IS_EXTERNAL(DatumGetPointer(toast_values[i])))
				continue;		/* can't happen, toast_action would be 'p' */
			if (VARATT_IS_COMPRESSED(DatumGetPointer(toast_values[i])))
				continue;
			if (TupleDescAttr(tupleDesc, i)->attstorage != 'm')
				continue;
			if (toast_sizes[i] > biggest_size)
			{
				biggest_attno = i;
				biggest_size = toast_sizes[i];
			}
		}

		if (biggest_attno < 0)
			break;

		/*
		 * Attempt to compress it inline
		 */
		i = biggest_attno;
		old_value = toast_values[i];
		new_value = toast_compress_datum(old_value);

		if (DatumGetPointer(new_value) != NULL)
		{
			/* successful compression */
			if (toast_free[i])
				pfree(DatumGetPointer(old_value));
			toast_values[i] = new_value;
			toast_free[i] = true;
			toast_sizes[i] = VARSIZE(DatumGetPointer(toast_values[i]));
			need_change = true;
			need_free = true;
		}
		else
		{
			/* incompressible, ignore on subsequent compression passes */
			toast_action[i] = 'x';
		}
	}

	/*
	 * Finally we store attributes of type 'm' externally.  At this point we
	 * increase the target tuple size, so that 'm' attributes aren't stored
	 * externally unless really necessary.
	 */
	maxDataLen = TOAST_TUPLE_TARGET_MAIN - hoff;

	while (zheap_compute_data_size(tupleDesc,
								   toast_values, toast_isnull, hoff) > maxDataLen &&
		   rel->rd_rel->reltoastrelid != InvalidOid)
	{
		int			biggest_attno = -1;
		int32		biggest_size = MAXALIGN(TOAST_POINTER_SIZE);
		Datum		old_value;

		/*--------
		 * Search for the biggest yet inlined attribute with
		 * attstorage = 'm'
		 *--------
		 */
		for (i = 0; i < numAttrs; i++)
		{
			if (toast_action[i] == 'p')
				continue;
			if (VARATT_IS_EXTERNAL(DatumGetPointer(toast_values[i])))
				continue;		/* can't happen, toast_action would be 'p' */
			if (TupleDescAttr(tupleDesc, i)->attstorage != 'm')
				continue;
			if (toast_sizes[i] > biggest_size)
			{
				biggest_attno = i;
				biggest_size = toast_sizes[i];
			}
		}

		if (biggest_attno < 0)
			break;

		/*
		 * Store this external
		 */
		i = biggest_attno;
		old_value = toast_values[i];
		toast_action[i] = 'p';
		toast_values[i] = ztoast_save_datum(rel, toast_values[i],
											toast_oldexternal[i], options,
											specToken);
		if (toast_free[i])
			pfree(DatumGetPointer(old_value));
		toast_free[i] = true;

		need_change = true;
		need_free = true;
	}

	/*
	 * In the case we toasted any values, we need to build a new heap tuple
	 * with the changed values.
	 */
	if (need_change)
	{
		ZHeapTupleHeader olddata = newtup->t_data;
		ZHeapTupleHeader new_data;
		int32		new_header_len;
		int32		new_data_len;
		int32		new_tuple_len;

		/*
		 * Calculate the new size of the tuple.
		 *
		 * Note: we used to assume here that the old tuple's t_hoff must equal
		 * the new_header_len value, but that was incorrect.  The old tuple
		 * might have a smaller-than-current natts, if there's been an ALTER
		 * TABLE ADD COLUMN since it was stored; and that would lead to a
		 * different conclusion about the size of the null bitmap, or even
		 * whether there needs to be one at all.
		 */
		new_header_len = SizeofZHeapTupleHeader;
		if (has_nulls)
			new_header_len += BITMAPLEN(numAttrs);
		new_data_len = zheap_compute_data_size(tupleDesc,
											   toast_values, toast_isnull, hoff);
		new_tuple_len = new_header_len + new_data_len;

		/*
		 * Allocate and zero the space needed, and fill ZHeapTupleData fields.
		 */
		result_tuple = (ZHeapTuple) palloc0(ZHEAPTUPLESIZE + new_tuple_len);
		result_tuple->t_len = new_tuple_len;
		result_tuple->t_self = newtup->t_self;
		result_tuple->t_tableOid = newtup->t_tableOid;
		new_data = (ZHeapTupleHeader) ((char *) result_tuple + ZHEAPTUPLESIZE);
		result_tuple->t_data = new_data;

		/*
		 * Copy the existing tuple header, but adjust natts and t_hoff.
		 */
		memcpy(new_data, olddata, SizeofZHeapTupleHeader);
		ZHeapTupleHeaderSetNatts(new_data, numAttrs);
		new_data->t_hoff = new_header_len;

		/* Copy over the data, and fill the null bitmap if needed */
		zheap_fill_tuple(tupleDesc,
						 toast_values,
						 toast_isnull,
						 (char *) new_data + new_header_len,
						 new_data_len,
						 &(new_data->t_infomask),
						 has_nulls ? new_data->t_bits : NULL);
	}
	else
		result_tuple = newtup;

	/*
	 * Free allocated temp values
	 */
	if (need_free)
		for (i = 0; i < numAttrs; i++)
			if (toast_free[i])
				pfree(DatumGetPointer(toast_values[i]));

	/*
	 * Delete external values from the old tuple
	 */
	if (need_delold)
		for (i = 0; i < numAttrs; i++)
			if (toast_delold[i])
				ztoast_delete_datum(rel, toast_oldvalues[i], false);

	return result_tuple;
}

/*
 * ztoast_save_datum
 *		Just like toast_save_datum but for zheap relations.
 */
static Datum
ztoast_save_datum(Relation rel, Datum value,
				  struct varlena *oldexternal, int options, uint32 specToken)
{
	Relation	toastrel;
	Relation   *toastidxs;
	ZHeapTuple	toasttup;
	TupleDesc	toasttupDesc;
	Datum		t_values[3];
	bool		t_isnull[3];
	CommandId	mycid = GetCurrentCommandId(true);
	struct varlena *result;
	struct varatt_external toast_pointer;
	union
	{
		struct varlena hdr;
		/* this is to make the union big enough for a chunk: */
		char		data[TOAST_MAX_CHUNK_SIZE + VARHDRSZ];
		/* ensure union is aligned well enough: */
		int32		align_it;
	}			chunk_data;
	int32		chunk_size;
	int32		chunk_seq = 0;
	char	   *data_p;
	int32		data_todo;
	Pointer		dval = DatumGetPointer(value);
	int			num_indexes;
	int			validIndex;

	Assert(!VARATT_IS_EXTERNAL(value));

	/*
	 * Open the toast relation and its indexes.  We can use the index to check
	 * uniqueness of the OID we assign to the toasted item, even though it has
	 * additional columns besides OID.
	 */
	toastrel = heap_open(rel->rd_rel->reltoastrelid, RowExclusiveLock);
	toasttupDesc = toastrel->rd_att;

	/* The toast table of zheap table should also be of zheap type */
	Assert(RelationStorageIsZHeap(toastrel));

	/* Open all the toast indexes and look for the valid one */
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);

	/*
	 * Get the data pointer and length, and compute va_rawsize and va_extsize.
	 *
	 * va_rawsize is the size of the equivalent fully uncompressed datum, so
	 * we have to adjust for short headers.
	 *
	 * va_extsize is the actual size of the data payload in the toast records.
	 */
	if (VARATT_IS_SHORT(dval))
	{
		data_p = VARDATA_SHORT(dval);
		data_todo = VARSIZE_SHORT(dval) - VARHDRSZ_SHORT;
		toast_pointer.va_rawsize = data_todo + VARHDRSZ;	/* as if not short */
		toast_pointer.va_extsize = data_todo;
	}
	else if (VARATT_IS_COMPRESSED(dval))
	{
		data_p = VARDATA(dval);
		data_todo = VARSIZE(dval) - VARHDRSZ;
		/* rawsize in a compressed datum is just the size of the payload */
		toast_pointer.va_rawsize = VARRAWSIZE_4B_C(dval) + VARHDRSZ;
		toast_pointer.va_extsize = data_todo;
		/* Assert that the numbers look like it's compressed */
		Assert(VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer));
	}
	else
	{
		data_p = VARDATA(dval);
		data_todo = VARSIZE(dval) - VARHDRSZ;
		toast_pointer.va_rawsize = VARSIZE(dval);
		toast_pointer.va_extsize = data_todo;
	}

	/*
	 * Insert the correct table OID into the result TOAST pointer.
	 *
	 * Normally this is the actual OID of the target toast table, but during
	 * table-rewriting operations such as CLUSTER, we have to insert the OID
	 * of the table's real permanent toast table instead.  rd_toastoid is set
	 * if we have to substitute such an OID.
	 */
	if (OidIsValid(rel->rd_toastoid))
		toast_pointer.va_toastrelid = rel->rd_toastoid;
	else
		toast_pointer.va_toastrelid = RelationGetRelid(toastrel);

	/*
	 * Choose an OID to use as the value ID for this toast value.
	 *
	 * Normally we just choose an unused OID within the toast table.  But
	 * during table-rewriting operations where we are preserving an existing
	 * toast table OID, we want to preserve toast value OIDs too.  So, if
	 * rd_toastoid is set and we had a prior external value from that same
	 * toast table, re-use its value ID.  If we didn't have a prior external
	 * value (which is a corner case, but possible if the table's attstorage
	 * options have been changed), we have to pick a value ID that doesn't
	 * conflict with either new or existing toast value OIDs.
	 */
	if (!OidIsValid(rel->rd_toastoid))
	{
		/* normal case: just choose an unused OID */
		toast_pointer.va_valueid =
			GetNewOidWithIndex(toastrel,
							   RelationGetRelid(toastidxs[validIndex]),
							   (AttrNumber) 1);
	}
	else
	{
		/* rewrite case: check to see if value was in old toast table */
		toast_pointer.va_valueid = InvalidOid;
		if (oldexternal != NULL)
		{
			struct varatt_external old_toast_pointer;

			Assert(VARATT_IS_EXTERNAL_ONDISK(oldexternal));
			/* Must copy to access aligned fields */
			VARATT_EXTERNAL_GET_POINTER(old_toast_pointer, oldexternal);
			if (old_toast_pointer.va_toastrelid == rel->rd_toastoid)
			{
				/* This value came from the old toast table; reuse its OID */
				toast_pointer.va_valueid = old_toast_pointer.va_valueid;

				/*
				 * There is a corner case here: the table rewrite might have
				 * to copy both live and recently-dead versions of a row, and
				 * those versions could easily reference the same toast value.
				 * When we copy the second or later version of such a row,
				 * reusing the OID will mean we select an OID that's already
				 * in the new toast table.  Check for that, and if so, just
				 * fall through without writing the data again.
				 *
				 * While annoying and ugly-looking, this is a good thing
				 * because it ensures that we wind up with only one copy of
				 * the toast value when there is only one copy in the old
				 * toast table.  Before we detected this case, we'd have made
				 * multiple copies, wasting space; and what's worse, the
				 * copies belonging to already-deleted heap tuples would not
				 * be reclaimed by VACUUM.
				 */
				if (toastrel_valueid_exists(toastrel,
											toast_pointer.va_valueid))
				{
					/* Match, so short-circuit the data storage loop below */
					data_todo = 0;
				}
			}
		}
		if (toast_pointer.va_valueid == InvalidOid)
		{
			/*
			 * new value; must choose an OID that doesn't conflict in either
			 * old or new toast table
			 */
			do
			{
				toast_pointer.va_valueid =
					GetNewOidWithIndex(toastrel,
									   RelationGetRelid(toastidxs[validIndex]),
									   (AttrNumber) 1);
			} while (toastid_valueid_exists(rel->rd_toastoid,
											toast_pointer.va_valueid));
		}
	}

	/*
	 * Initialize constant parts of the tuple data
	 */
	t_values[0] = ObjectIdGetDatum(toast_pointer.va_valueid);
	t_values[2] = PointerGetDatum(&chunk_data);
	t_isnull[0] = false;
	t_isnull[1] = false;
	t_isnull[2] = false;

	/*
	 * Split up the item into chunks
	 */
	while (data_todo > 0)
	{
		int			i;

		CHECK_FOR_INTERRUPTS();

		/*
		 * Calculate the size of this chunk
		 */
		chunk_size = Min(TOAST_MAX_CHUNK_SIZE, data_todo);

		/*
		 * Build a tuple and store it
		 */
		t_values[1] = Int32GetDatum(chunk_seq++);
		SET_VARSIZE(&chunk_data, chunk_size + VARHDRSZ);
		memcpy(VARDATA(&chunk_data), data_p, chunk_size);
		toasttup = zheap_form_tuple(toasttupDesc, t_values, t_isnull);

		zheap_insert(toastrel, toasttup, mycid, options, NULL, specToken);

		/*
		 * Create the index entry.  We cheat a little here by not using
		 * FormIndexDatum: this relies on the knowledge that the index columns
		 * are the same as the initial columns of the table for all the
		 * indexes.  We also cheat by not providing an IndexInfo: this is okay
		 * for now because btree doesn't need one, but we might have to be
		 * more honest someday.
		 *
		 * Note also that there had better not be any user-created index on
		 * the TOAST table, since we don't bother to update anything else.
		 */
		for (i = 0; i < num_indexes; i++)
		{
			/* Only index relations marked as ready can be updated */
			if (toastidxs[i]->rd_index->indisready)
				index_insert(toastidxs[i], t_values, t_isnull,
							 &(toasttup->t_self),
							 toastrel,
							 toastidxs[i]->rd_index->indisunique ?
							 UNIQUE_CHECK_YES : UNIQUE_CHECK_NO,
							 NULL);
		}

		/*
		 * Free memory
		 */
		zheap_freetuple(toasttup);

		/*
		 * Move on to next chunk
		 */
		data_todo -= chunk_size;
		data_p += chunk_size;
	}

	/*
	 * Done - close toast relation and its indexes
	 */
	toast_close_indexes(toastidxs, num_indexes, RowExclusiveLock);
	heap_close(toastrel, RowExclusiveLock);

	/*
	 * Create the TOAST pointer value that we'll return
	 */
	result = (struct varlena *) palloc(TOAST_POINTER_SIZE);
	SET_VARTAG_EXTERNAL(result, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(result), &toast_pointer, sizeof(toast_pointer));

	return PointerGetDatum(result);
}

/*
 * ztoast_delete_datum
 * Just like toast_delete_datum but for zheap relations.
 */
static void
ztoast_delete_datum(Relation rel, Datum value, bool is_speculative)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	struct varatt_external toast_pointer;
	Relation	toastrel;
	Relation   *toastidxs;
	ScanKeyData toastkey;
	SysScanDesc toastscan;
	int			num_indexes;
	int			validIndex;
	SnapshotData SnapshotToast;
	TupleTableSlot *slot;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr))
		return;

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

	/*
	 * Open the toast relation and its indexes
	 */
	toastrel = heap_open(toast_pointer.va_toastrelid, RowExclusiveLock);

	/* The toast table of zheap table should also be of zheap type */
	Assert(RelationStorageIsZHeap(toastrel));

	/* Fetch valid relation used for process */
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);

	/*
	 * Setup a scan key to find chunks with matching va_valueid
	 */
	ScanKeyInit(&toastkey,
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toast_pointer.va_valueid));

	/*
	 * Find all the chunks.  (We don't actually care whether we see them in
	 * sequence or not, but since we've already locked the index we might as
	 * well use systable_beginscan_ordered.)
	 */
	init_toast_snapshot(&SnapshotToast);
	toastscan = systable_beginscan_ordered(toastrel, toastidxs[validIndex],
										   &SnapshotToast, 1, &toastkey);
	while ((slot = systable_getnext_ordered_slot(toastscan, ForwardScanDirection)) != NULL)
	{
		ZHeapTuple	ztuple = ExecGetZHeapTupleFromSlot(slot);

		/*
		 * Have a chunk, delete it
		 */
		if (!is_speculative)
			simple_zheap_delete(toastrel, &ztuple->t_self, &SnapshotToast);
		else
			zheap_abort_speculative(toastrel, &ztuple->t_self);
	}

	/*
	 * End scan and close relations
	 */
	systable_endscan_ordered(toastscan);
	toast_close_indexes(toastidxs, num_indexes, RowExclusiveLock);
	heap_close(toastrel, RowExclusiveLock);
}

/*
 * ztoast_delete
 *		Cascaded delete toast-entries on DELETE
 */
void
ztoast_delete(Relation rel, ZHeapTuple oldtup, bool is_speculative)
{
	TupleDesc	tupleDesc;
	int			numAttrs;
	int			i;
	Datum		toast_values[MaxHeapAttributeNumber];
	bool		toast_isnull[MaxHeapAttributeNumber];

	/*
	 * We should only ever be called for tuples of plain relations or
	 * materialized views --- recursing on a toast rel is bad news.
	 */
	Assert(rel->rd_rel->relkind == RELKIND_RELATION ||
		   rel->rd_rel->relkind == RELKIND_MATVIEW);

	/*
	 * Get the tuple descriptor and break down the tuple into fields.
	 *
	 * NOTE: it's debatable whether to use heap_deform_tuple() here or just
	 * heap_getattr() only the varlena columns.  The latter could win if there
	 * are few varlena columns and many non-varlena ones. However,
	 * heap_deform_tuple costs only O(N) while the heap_getattr way would cost
	 * O(N^2) if there are many varlena columns, so it seems better to err on
	 * the side of linear cost.  (We won't even be here unless there's at
	 * least one varlena column, by the way.)
	 */
	tupleDesc = rel->rd_att;
	numAttrs = tupleDesc->natts;

	Assert(numAttrs <= MaxHeapAttributeNumber);
	zheap_deform_tuple(oldtup, tupleDesc, toast_values, toast_isnull, tupleDesc->natts);

	/*
	 * Check for external stored attributes and delete them from the secondary
	 * relation.
	 */
	for (i = 0; i < numAttrs; i++)
	{
		if (TupleDescAttr(tupleDesc, i)->attlen == -1)
		{
			Datum		value = toast_values[i];

			if (toast_isnull[i])
				continue;
			else if (VARATT_IS_EXTERNAL_ONDISK(PointerGetDatum(value)))
				ztoast_delete_datum(rel, value, is_speculative);
		}
	}
}
