/*-------------------------------------------------------------------------
 *
 * zheapam.c
 *	  zheap access method code
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/zheapam.c
 *
 *
 * INTERFACE ROUTINES
 *		zheap_insert	- insert zheap tuple into a relation
 *
 * NOTES
 *	  This file contains the zheap_ routines which implement
 *	  the POSTGRES zheap access method used for relations backed
 *	  by undo storage.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/hio.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "access/tuptoaster.h"
#include "access/undorecord.h"
#include "access/undoinsert.h"
#include "access/visibilitymap.h"
#include "access/zheap.h"
#include "access/zhtup.h"
#include "catalog/catalog.h"
#include "executor/tuptable.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "storage/predicate.h"
#include "utils/expandeddatum.h"
#include "utils/inval.h"
#include "utils/rel.h"

bool	enable_zheap;

static ZHeapTuple zheap_prepare_insert(Relation relation, ZHeapTuple tup);

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
				 uint8 *infomask, bits8 *bit)
{
	bits8	   *bitP;
	int			bitmask;
	int			i;
	int			numberOfAttributes = tupleDesc->natts;
	Form_pg_attribute *att = tupleDesc->attrs;

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

	*infomask &= ~(HEAP_HASNULL | HEAP_HASVARWIDTH | HEAP_HASEXTERNAL);

	for (i = 0; i < numberOfAttributes; i++)
	{
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
				*infomask |= HEAP_HASNULL;
				continue;
			}

			*bitP |= bitmask;
		}

		/*
		 * XXX we use the att_align macros on the pointer value itself, not on
		 * an offset.  This is a bit of a hack.
		 */

		if (att[i]->attbyval)
		{
			/* pass-by-value */
			data = (char *) att_align_nominal(data, att[i]->attalign);
			store_att_byval(data, values[i], att[i]->attlen);
			data_length = att[i]->attlen;
		}
		else if (att[i]->attlen == -1)
		{
			/* varlena */
			Pointer		val = DatumGetPointer(values[i]);

			*infomask |= HEAP_HASVARWIDTH;
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
													  att[i]->attalign);
					data_length = EOH_get_flat_size(eoh);
					EOH_flatten_into(eoh, data, data_length);
				}
				else
				{
					*infomask |= HEAP_HASEXTERNAL;
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
			else if (VARLENA_ATT_IS_PACKABLE(att[i]) &&
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
												  att[i]->attalign);
				data_length = VARSIZE(val);
				memcpy(data, val, data_length);
			}
		}
		else if (att[i]->attlen == -2)
		{
			/* cstring ... never needs alignment */
			*infomask |= HEAP_HASVARWIDTH;
			Assert(att[i]->attalign == 'c');
			data_length = strlen(DatumGetCString(values[i])) + 1;
			memcpy(data, DatumGetPointer(values[i]), data_length);
		}
		else
		{
			/* fixed-length pass-by-reference */
			data = (char *) att_align_nominal(data, att[i]->attalign);
			Assert(att[i]->attlen > 0);
			data_length = att[i]->attlen;
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
	ZHeapTupleHeader td;			/* tuple data */
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

	if (tupleDescriptor->tdhasoid)
		len += sizeof(Oid);

	hoff = len = MAXALIGN(len); /* align user data safely */

	data_len = heap_compute_data_size(tupleDescriptor, values, isnull);

	len += data_len;

	/*
	 * Allocate and zero the space needed.  Note that the tuple body and
	 * HeapTupleData management structure are allocated in one chunk.
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

	if (tupleDescriptor->tdhasoid)		/* else leave infomask = 0 */
		td->t_infomask = HEAP_HASOID;

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
 * Subroutine for zheap_insert(). Prepares a tuple for insertion.
 *
 * This is similar to heap_prepare_insert except that we don't set
 * information in tuple header as that needs to be either set in
 * TPD entry or undorecord for this tuple.
 */
static ZHeapTuple
zheap_prepare_insert(Relation relation, ZHeapTuple tup)
{
	/*
	 * For now, parallel operations are required to be strictly read-only.
	 * Unlike heap_update() and heap_delete(), an insert should never create a
	 * combo CID, so it might be possible to relax this restriction, but not
	 * without more thought and testing.
	 */
	if (IsInParallelMode())
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TRANSACTION_STATE),
				 errmsg("cannot insert tuples during a parallel operation")));

	if (relation->rd_rel->relhasoids)
	{
#ifdef NOT_USED
		/* this is redundant with an Assert in HeapTupleSetOid */
		Assert(tup->t_data->t_infomask & HEAP_HASOID);
#endif

		/*
		 * If the object id of this tuple has already been assigned, trust the
		 * caller.  There are a couple of ways this can happen.  At initial db
		 * creation, the backend program sets oids for tuples. When we define
		 * an index, we set the oid.  Finally, in the future, we may allow
		 * users to set their own object ids in order to support a persistent
		 * object store (objects need to contain pointers to one another).
		 */
		if (!OidIsValid(HeapTupleGetOid(tup)))
			HeapTupleSetOid(tup, GetNewOid(relation));
	}
	else
	{
		/* check there is not space for an OID */
		Assert(!(tup->t_data->t_infomask & HEAP_HASOID));
	}

	tup->t_tableOid = RelationGetRelid(relation);

	/*
	 * If the new tuple is too big for storage or contains already toasted
	 * out-of-line attributes from some other relation, invoke the toaster.
	 */
	if (relation->rd_rel->relkind != RELKIND_RELATION &&
		relation->rd_rel->relkind != RELKIND_MATVIEW)
	{
		/* toast table entries should never be recursively toasted */
		Assert(!HeapTupleHasExternal(tup));
		return tup;
	}
	else if (HeapTupleHasExternal(tup) || tup->t_len > TOAST_TUPLE_THRESHOLD)
	{
		elog(ERROR, "toast tuple is not supportted for zheap.");
		return NULL;
		/* return toast_insert_or_update(relation, tup, NULL, options); */
	}
	else
		return tup;
}

/*
 * zheap_insert - insert tuple into a zheap
 *
 * There are notable
 * The functionality related to heap is quite similar to heap_insert,
 * additionaly this function inserts an undo record and updates the undo
 * pointer in page header or in TPD entry for this page.
 */
Oid
zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate)
{
	TransactionId xid = GetCurrentTransactionId();
	ZHeapTuple	zheaptup;
	UnpackedUndoRecord	undorecord;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	bool		all_visible_cleared = false;
	BlockNumber	blkno;
	Page		page;
	ZHeapPageOpaque	opaque;
	OffsetNumber offnum;
	UndoRecPtr	urecptr, prev_urecptr;

	/*
	 * Assign an OID, and toast the tuple if necessary.
	 *
	 * Note: below this point, heaptup is the data we actually intend to store
	 * into the relation; tup is the caller's original untoasted data.
	 */
	zheaptup = zheap_prepare_insert(relation, tup);

	/*
	 * Find buffer to insert this tuple into.  If the page is all visible,
	 * this will also pin the requisite visibility map page.
	 */
	buffer = RelationGetBufferForTuple(relation, zheaptup->t_len,
									   InvalidBuffer, options, bistate,
									   &vmbuffer, NULL);

	/*
	 * See heap_insert to know why checking conflicts is important
	 * before actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	/* Add the tuple to the page */
	page = BufferGetPage(buffer);

	offnum = PageAddItem(page, (Item) zheaptup->t_data,
						 zheaptup->t_len, InvalidOffsetNumber, false, true);

	if (offnum == InvalidOffsetNumber)
		elog(PANIC, "failed to add tuple to page");

	blkno = BufferGetBlockNumber(buffer);

	/* Update tuple->t_self to the actual position where it was stored */
	ItemPointerSet(&(zheaptup->t_self), blkno, offnum);

	if (PageIsAllVisible(BufferGetPage(buffer)))
	{
		all_visible_cleared = true;
		PageClearAllVisible(BufferGetPage(buffer));
		visibilitymap_clear(relation,
							ItemPointerGetBlockNumber(&(zheaptup->t_self)),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	MarkBufferDirty(buffer);

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	prev_urecptr = PageGetUNDO(opaque);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_INSERT;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;	/* Fixme - need to figure out how to set this value and then decide whether to WAL log it */
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_tsid = relation->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = offnum;

	initStringInfo(&undorecord.uur_tuple);
	appendBinaryStringInfo(&undorecord.uur_tuple, (char *) &cid, sizeof(cid));

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT);

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	InsertPreparedUndo();
	PageSetUNDO(opaque, xid, urecptr);

	/* XLOG stuff */
	if (!(options & HEAP_INSERT_SKIP_WAL) && RelationNeedsWAL(relation))
	{
		xl_zheap_insert xlrec;
		xl_zheap_header xlhdr;
		XLogRecPtr	recptr;
		Page		page = BufferGetPage(buffer);
		uint8		info = XLOG_ZHEAP_INSERT;
		int			bufflags = 0;

		/*
		 * If this is a catalog, we need to transmit combocids to properly
		 * decode, so log that as well.
		 */
		if (RelationIsAccessibleInLogicalDecoding(relation))
		{
			/*
			 * Fixme: This won't work as it needs to access cmin/cmax which
			 * we probably needs to retrieve from TPD or UNDO.
			 */
			/*log_heap_new_cid(relation, zheaptup);*/
		}

		/*
		 * If this is the single and first tuple on page, we can reinit the
		 * page instead of restoring the whole thing.  Set flag, and hide
		 * buffer references from XLogInsert.
		 */
		if (ItemPointerGetOffsetNumber(&(zheaptup->t_self)) == FirstOffsetNumber &&
			PageGetMaxOffsetNumber(page) == FirstOffsetNumber)
		{
			info |= XLOG_ZHEAP_INIT_PAGE;
			bufflags |= REGBUF_WILL_INIT;
		}

		xlrec.urec_ptr = urecptr;
		xlrec.uur_blkprev = prev_urecptr;
		xlrec.offnum = ItemPointerGetOffsetNumber(&zheaptup->t_self);
		xlrec.flags = 0;
		if (all_visible_cleared)
			xlrec.flags |= XLZ_INSERT_ALL_VISIBLE_CLEARED;
		if (options & HEAP_INSERT_SPECULATIVE)
			xlrec.flags |= XLZ_INSERT_IS_SPECULATIVE;
		Assert(ItemPointerGetBlockNumber(&zheaptup->t_self) == BufferGetBlockNumber(buffer));

		/*
		 * For logical decoding, we need the tuple even if we're doing a full
		 * page write, so make sure it's included even if we take a full-page
		 * image. (XXX We could alternatively store a pointer into the FPW).
		 */
		if (RelationIsLogicallyLogged(relation))
		{
			xlrec.flags |= XLZ_INSERT_CONTAINS_NEW_TUPLE;
			bufflags |= REGBUF_KEEP_DATA;
		}

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfZHeapInsert);

		xlhdr.t_numattrs = zheaptup->t_data->t_numattrs;
		xlhdr.t_infomask = zheaptup->t_data->t_infomask;
		xlhdr.t_hoff = zheaptup->t_data->t_hoff;

		/*
		 * note we mark xlhdr as belonging to buffer; if XLogInsert decides to
		 * write the whole page to the xlog, we don't need to store
		 * xl_heap_header in the xlog.
		 */
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD | bufflags);
		XLogRegisterBufData(0, (char *) &xlhdr, SizeOfZHeapHeader);
		/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
		XLogRegisterBufData(0,
							(char *) zheaptup->t_data + SizeofZHeapTupleHeader,
							zheaptup->t_len - SizeofZHeapTupleHeader);

		/* filtering by origin on a row level is much more efficient */
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

		recptr = XLogInsert(RM_HEAP_ID, info);

		PageSetLSN(page, recptr);
		SetUndoPageLSNs(recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buffer);
	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);
	UnlockReleaseUndoBuffers();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);

	/*
	 * If tuple is cachable, mark it for invalidation from the caches in case
	 * we abort.  Note it is OK to do this after releasing the buffer, because
	 * the zheaptup data structure is all in local memory, not in the shared
	 * buffer.
	 *
	 * Fixme - Cache invalidation API expects HeapTup, so either we need an
	 * eqvivalent API for ZHeapTup or need to teach cache invalidation API's
	 * to work with both the formats.
	 */
	/* CacheInvalidateHeapTuple(relation, zheaptup, NULL); */

	/* Note: speculative insertions are counted too, even if aborted later */
	pgstat_count_heap_insert(relation, 1);

	/*
	 * If zheaptup is a private copy, release it.  Don't forget to copy t_self
	 * back to the caller's image, too.
	 */
	if (zheaptup != tup)
	{
		tup->t_self = zheaptup->t_self;
		pfree(zheaptup);
		/* Fixme - Instead of directly freeing zheaptup, write a new function zheap_freetuple*/
		/*heap_freetuple(zheaptup);*/
	}

	return HeapTupleGetOid(tup);
}
