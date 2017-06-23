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
#include "access/relscan.h"
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
#include "storage/lmgr.h"
#include "storage/predicate.h"
#include "utils/datum.h"
#include "utils/expandeddatum.h"
#include "utils/inval.h"
#include "utils/memdebug.h"
#include "utils/rel.h"
#include "utils/tqual.h"

/*
 * User supplied value for data alignment is captured in data_alignment and
 * then we internally use it only for zheap.
 */
int		data_alignment = 1;
int		data_alignment_zheap = 1;
extern bool synchronize_seqscans;

static ZHeapTuple zheap_prepare_insert(Relation relation, ZHeapTuple tup);
static Bitmapset *
ZHeapDetermineModifiedColumns(Relation relation, Bitmapset *interesting_cols,
							  ZHeapTuple oldtup, ZHeapTuple newtup);
static HeapScanDesc
zheap_beginscan_internal(Relation relation, Snapshot snapshot,
						 int nkeys, ScanKey key,
						 ParallelHeapScanDesc parallel_scan,
						 bool allow_strat,
						 bool allow_sync,
						 bool allow_pagemode,
						 bool is_bitmapscan,
						 bool is_samplescan,
						 bool temp_snap);

static int PageReserveTransactionSlot(Page page, TransactionId xid);
static inline UndoRecPtr PageGetUNDO(Page page, int trans_slot_id);
static inline void PageSetUNDO(Page page, int trans_slot_id, TransactionId xid,
						CommandId cid, UndoRecPtr urecptr);


#include "access/bufmask.h"
#include "access/heapam.h"
#include "access/heapam_xlog.h"
#include "access/hio.h"
#include "access/multixact.h"
#include "access/parallel.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#include "access/transam.h"
#include "access/tuptoaster.h"
#include "access/valid.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "access/xloginsert.h"
#include "access/xlogutils.h"
#include "catalog/catalog.h"
#include "catalog/namespace.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "port/atomics.h"
#include "storage/bufmgr.h"
#include "storage/freespace.h"
#include "storage/lmgr.h"
#include "storage/predicate.h"
#include "storage/procarray.h"
#include "storage/smgr.h"
#include "storage/spin.h"
#include "storage/standby.h"
#include "utils/datum.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/relcache.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

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
			data = (char *) att_align_nominal(data, att->attalign);
			store_att_byval(data, values[i], att->attlen);
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

	/* we want to use user supplied data alignment only for zheap inserts */
	data_alignment_zheap = data_alignment;

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

	if (data_alignment_zheap == 0)
		;	/* no alignment required */
	else if (data_alignment_zheap == 4)
		len = INTALIGN(len);
	else
		len = MAXALIGN(len); /* align user data safely */

	hoff = len;

	data_len = heap_compute_data_size(tupleDescriptor, values, isnull);

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

	if (tupleDescriptor->tdhasoid)		/* else leave infomask = 0 */
		td->t_infomask = ZHEAP_HASOID;

	zheap_fill_tuple(tupleDescriptor,
					 values,
					 isnull,
					 (char *) td + hoff,
					 data_len,
					 &td->t_infomask,
					 (hasnull ? td->t_bits : NULL));

	data_alignment_zheap = 1;

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
		Assert(tup->t_data->t_infomask & ZHEAP_HASOID);
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
		Assert(!(tup->t_data->t_infomask & ZHEAP_HASOID));
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
 * The functionality related to heap is quite similar to heap_insert,
 * additionaly this function inserts an undo record and updates the undo
 * pointer in page header or in TPD entry for this page.
 */
Oid
zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options)
{
	TransactionId xid = GetCurrentTransactionId();
	ZHeapTuple	zheaptup;
	UnpackedUndoRecord	undorecord;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	bool		all_visible_cleared = false;
	int			trans_slot_id;
	BlockNumber	blkno;
	Page		page;
	OffsetNumber offnum;
	UndoRecPtr	urecptr, prev_urecptr;

	data_alignment_zheap = data_alignment;

	/*
	 * Assign an OID, and toast the tuple if necessary.
	 *
	 * Note: below this point, heaptup is the data we actually intend to store
	 * into the relation; tup is the caller's original untoasted data.
	 */
	zheaptup = zheap_prepare_insert(relation, tup);

reacquire_buffer:
	/*
	 * Find buffer to insert this tuple into.  If the page is all visible,
	 * this will also pin the requisite visibility map page.
	 */
	buffer = RelationGetBufferForTuple(relation, zheaptup->t_len,
									   InvalidBuffer, options, NULL,
									   &vmbuffer, NULL);
	page = BufferGetPage(buffer);

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(page, xid);

	if (trans_slot_id == InvalidXactSlotId)
	{
		UnlockReleaseBuffer(buffer);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		goto reacquire_buffer;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, trans_slot_id);

	/*
	 * See heap_insert to know why checking conflicts is important
	 * before actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	/* Add the tuple to the page */
	offnum = ZPageAddItem(page, (Item) zheaptup->t_data,
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

	prev_urecptr = PageGetUNDO(page, trans_slot_id);

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
	undorecord.uur_payload.len = 0;
	undorecord.uur_tuple.len = 0;

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT);

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	InsertPreparedUndo();
	PageSetUNDO(page, trans_slot_id, xid, cid, urecptr);

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

		xlhdr.t_infomask2 = zheaptup->t_data->t_infomask2;
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
		zheap_freetuple(zheaptup);
	}

	data_alignment_zheap = 1;

	return ZHeapTupleGetOid(tup);
}

/*
 * slot_getsyszattr
 *		This function fetches a system attribute of the slot's current tuple.
 *		Unlike slot_getattr, if the slot does not contain system attributes,
 *		this will return false (with a NULL attribute value) instead of
 *		throwing an error.
 */
bool
slot_getsyszattr(TupleTableSlot *slot, int attnum,
				Datum *value, bool *isnull)
{
	ZHeapTuple	tuple = slot->tts_ztuple;

	Assert(attnum < 0);			/* else caller error */
	if (tuple == NULL ||
		tuple == (ZHeapTuple) &(slot->tts_minhdr))
	{
		/* No physical tuple, or minimal tuple, so fail */
		*value = (Datum) 0;
		*isnull = true;
		return false;
	}
	*value = zheap_getsysattr(tuple, slot->tts_buffer, attnum,
							  slot->tts_tupleDescriptor, isnull);
	return true;
}

/*
 * zheap_delete - delete a tuple
 *
 * The functionality related to heap is quite similar to heap_delete,
 * additionaly this function inserts an undo record and updates the undo
 * pointer in page header or in TPD entry for this page.
 */
HTSU_Result
zheap_delete(Relation relation, ItemPointer tid,
			 CommandId cid, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd)
{
	HTSU_Result result;
	TransactionId xid = GetCurrentTransactionId();
	ItemId		lp;
	ZHeapTupleData zheaptup;
	UnpackedUndoRecord	undorecord;
	Page		page;
	BlockNumber blkno;
	OffsetNumber offnum;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	UndoRecPtr	urecptr, prev_urecptr;
	ItemPointerData	ctid;
	ZHeapPageOpaque	opaque;
	int			trans_slot_id;
	bool		have_tuple_lock = false;
	bool		in_place_updated = false;

	Assert(ItemPointerIsValid(tid));

	/*
	 * Forbid this during a parallel operation, lest it allocate a combocid.
	 * Other workers might need that combocid for visibility checks, and we
	 * have no provision for broadcasting it to them.
	 */
	if (IsInParallelMode())
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TRANSACTION_STATE),
				 errmsg("cannot delete tuples during a parallel operation")));

	blkno = ItemPointerGetBlockNumber(tid);
	buffer = ReadBuffer(relation, blkno);
	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Before locking the buffer, pin the visibility map page if it appears to
	 * be necessary.  Since we haven't got the lock yet, someone else might be
	 * in the middle of changing this, so we'll need to recheck after we have
	 * the lock.
	 */
	if (PageIsAllVisible(page))
		visibilitymap_pin(relation, blkno, &vmbuffer);

reacquire_buffer:

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	/*
	 * If we didn't pin the visibility map page and the page has become all
	 * visible while we were busy locking the buffer, we'll have to unlock and
	 * re-lock, to avoid holding the buffer lock across an I/O.  That's a bit
	 * unfortunate, but hopefully shouldn't happen often.
	 */
	if (vmbuffer == InvalidBuffer && PageIsAllVisible(page))
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		visibilitymap_pin(relation, blkno, &vmbuffer);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	}

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(page, xid);

	if (trans_slot_id == InvalidXactSlotId)
	{
		UnlockReleaseBuffer(buffer);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		goto reacquire_buffer;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp));

	zheaptup.t_tableOid = RelationGetRelid(relation);
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);
	zheaptup.t_self = *tid;

	ctid = *tid;

check_tup_satisfies_update:
	result = ZHeapTupleSatisfiesUpdate(&zheaptup, cid, buffer, &ctid, false,
									   &in_place_updated);

	if (result == HeapTupleInvisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to delete invisible tuple")));
	}
	else if (result == HeapTupleBeingUpdated && wait)
	{
		TransactionId xwait;

		/* must copy state data before unlocking buffer */
		xwait = ZHeapTupleHeaderGetRawXid(zheaptup.t_data, opaque);

		/*
		 * Sleep until concurrent transaction ends -- except when there's a
		 * single locker and it's our own transaction.  Note we don't care
		 * which lock mode the locker has, because we need the strongest one.
		 *
		 * Before sleeping, we need to acquire tuple lock to establish our
		 * priority for the tuple (see heap_lock_tuple).  LockTuple will
		 * release us when we are next-in-line for the tuple.
		 *
		 * If we are forced to "start over" below, we keep the tuple lock;
		 * this arranges that we stay at the head of the line while rechecking
		 * tuple state.
		 */
		if (!TransactionIdIsCurrentTransactionId(xwait))
		{
			/*
			 * Wait for regular transaction to end; but first, acquire tuple
			 * lock.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			heap_acquire_tuplock(relation, &(zheaptup.t_self), LockTupleExclusive,
								 LockWaitBlock, &have_tuple_lock);
			XactLockTableWait(xwait, relation, &(zheaptup.t_self), XLTW_Delete);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * xwait is done, but if xwait had just locked the tuple then some
			 * other xact could update this tuple before we get to this point.
			 * Check for xid change, and start over if so.
			 */
			if (!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zheaptup.t_data, opaque),
									 xwait))
				goto check_tup_satisfies_update;
		}

		/*
		 * We may overwrite if previous xid aborted, or if it committed but
		 * only locked the tuple without updating it.
		 */
		if (TransactionIdDidCommit(xwait))
			result = HeapTupleUpdated;
		else
			result = HeapTupleMayBeUpdated;
	}

	if (crosscheck != InvalidSnapshot && result == HeapTupleMayBeUpdated)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleSatisfiesVisibility(&zheaptup, crosscheck, buffer))
			result = HeapTupleUpdated;
	}

	if (result != HeapTupleMayBeUpdated)
	{
		Assert(result == HeapTupleSelfUpdated ||
			   result == HeapTupleUpdated ||
			   result == HeapTupleBeingUpdated);
		Assert(zheaptup.t_data->t_infomask & ZHEAP_DELETED ||
			   zheaptup.t_data->t_infomask & ZHEAP_INPLACE_UPDATED);
		hufd->ctid = ctid;
		hufd->xmax = ZHeapTupleHeaderGetRawXid(zheaptup.t_data, opaque);
		if (result == HeapTupleSelfUpdated)
			hufd->cmax = ZHeapTupleHeaderGetRawCommandId(zheaptup.t_data, opaque);
		else
			hufd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		hufd->in_place_updated = in_place_updated;
		if (have_tuple_lock)
			UnlockTupleTuplock(relation, &(zheaptup.t_self), LockTupleExclusive);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		return result;
	}

	/*
	 * Fixme: Api's for serializable isolation level that take zheaptuple as
	 * input needs to be written.
	 */
	/* CheckForSerializableConflictIn(relation, &tp, buffer); */

	prev_urecptr = PageGetUNDO(page, trans_slot_id);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_DELETE;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;	/* Fixme - need to figure out how to set this value and then decide whether to WAL log it */
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_tsid = relation->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = offnum;
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	/*
	 * Here, we are storing transaction slot id as an integer, but we can optimize
	 * it to just store as two bits as we do in tuple header.
	 *
	 * XXX - The transaction slot id is stored in undo on the assumption that
	 * if the slot got reused or transaction info is removed from page header
	 * (after transaction becomes all-visible), corresponding undo will never
	 * be referred.
	 */
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) zheaptup.t_data,
						   SizeofZHeapTupleHeader);

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT);

	START_CRIT_SECTION();

	if (PageIsAllVisible(page))
	{
		PageClearAllVisible(page);
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, trans_slot_id);

	InsertPreparedUndo();
	PageSetUNDO(page, trans_slot_id, xid, cid, urecptr);

	zheaptup.t_data->t_infomask |= ZHEAP_DELETED;

	MarkBufferDirty(buffer);

	/*
	 * Fixme - Do xlog stuff
	 */

	END_CRIT_SECTION();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);

	/*
	 * Fixme - Delete from toast table before releasing the buffer pin.
	 */

	/* Now we can release the buffer */
	ReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();

	pgstat_count_heap_delete(relation);

	return HeapTupleMayBeUpdated;
}

/*
 * zheap_update - update a tuple
 *
 * This function either updates the tuple in-place or it deletes the old
 * tuple and new tuple for non-in-place updates.  Additionaly this function
 * inserts an undo record and updates the undo pointer in page header or in
 * TPD entry for this page.
 *
 * For input and output values, see heap_update.
 */
HTSU_Result
zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
			 CommandId cid, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd, LockTupleMode *lockmode)
{
	HTSU_Result result;
	TransactionId xid = GetCurrentTransactionId();
	Bitmapset  *inplace_upd_attrs;
	Bitmapset  *interesting_attrs;
	Bitmapset  *modified_attrs;
	ItemId		lp;
	ZHeapTupleData oldtup;
	ZHeapPageOpaque	opaque;
	UndoRecPtr	urecptr, prev_urecptr;
	UnpackedUndoRecord	undorecord;
	Page		page;
	BlockNumber block;
	ItemPointerData	ctid;
	Buffer		buffer,
				vmbuffer = InvalidBuffer;
	int			trans_slot_id;
	bool		have_tuple_lock = false;
	bool		inplace_upd_attrs_checked = false;
	bool		use_inplace_update = false;
	bool		in_place_updated = false;

	Assert(ItemPointerIsValid(otid));

	/*
	 * Forbid this during a parallel operation, lest it allocate a combocid.
	 * Other workers might need that combocid for visibility checks, and we
	 * have no provision for broadcasting it to them.
	 */
	if (IsInParallelMode())
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TRANSACTION_STATE),
				 errmsg("cannot update tuples during a parallel operation")));

	/*
	 * Fetch the list of attributes to be checked for in-place update.  This is
	 * wasted effort if we fail to update or have to put the new tuple on a
	 * different page.  But we must compute the list before obtaining buffer
	 * lock --- in the worst case, if we are doing an update on one of the
	 * relevant system catalogs, we could deadlock if we try to fetch the list
	 * later.  In any case, the relcache caches the data so this is usually
	 * pretty cheap.
	 *
	 * Note that we get a copy here, so we need not worry about relcache flush
	 * happening midway through.
	 */
	inplace_upd_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_HOT);

	block = ItemPointerGetBlockNumber(otid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	interesting_attrs = NULL;

	/*
	 * Before locking the buffer, pin the visibility map page if it appears to
	 * be necessary.  Since we haven't got the lock yet, someone else might be
	 * in the middle of changing this, so we'll need to recheck after we have
	 * the lock.
	 */
	if (PageIsAllVisible(page))
		visibilitymap_pin(relation, block, &vmbuffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(otid));
	Assert(ItemIdIsNormal(lp));

	/*
	 * Fill in enough data in oldtup for ZHeapDetermineModifiedColumns to work
	 * properly.
	 */
	oldtup.t_tableOid = RelationGetRelid(relation);
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	oldtup.t_len = ItemIdGetLength(lp);
	oldtup.t_self = *otid;

	/* the new tuple is ready, except for this: */
	newtup->t_tableOid = RelationGetRelid(relation);

	/* Fill in OID for newtup */
	if (relation->rd_rel->relhasoids)
	{
#ifdef NOT_USED
		/* this is redundant with an Assert in HeapTupleSetOid */
		Assert(newtup->t_data->t_infomask & HEAP_HASOID);
#endif
		ZHeapTupleSetOid(newtup, ZHeapTupleGetOid(&oldtup));
	}
	else
	{
		/* check there is not space for an OID */
		Assert(!(newtup->t_data->t_infomask & ZHEAP_HASOID));
	}

	/*
	 * inplace updates can be done only if the length of new tuple is lesser
	 * than or equal to old tuple and there are no index column updates.
	 */
	if (newtup->t_len <= oldtup.t_len)
	{
		interesting_attrs = bms_add_members(interesting_attrs, inplace_upd_attrs);
		inplace_upd_attrs_checked = true;
	}

	/* Determine columns modified by the update. */
	modified_attrs = ZHeapDetermineModifiedColumns(relation, interesting_attrs,
												  &oldtup, newtup);

	if (inplace_upd_attrs_checked &&
		!bms_overlap(modified_attrs, inplace_upd_attrs))
		use_inplace_update = true;
	else
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("non inplace updates are not supported")));

	/*
	 * Fixme - Weaker locks can be used for non-key column updates, however
	 * the same is not supportted for zheap as of now.
	 */
	*lockmode = LockTupleExclusive;

	/*
	 * ctid needs to be fetched from undo chain.  You might think that it will
	 * be always same as the passed in ctid as the old tuple is already visible
	 * out snapshot.  However, it is quite possible that after checking the
	 * visibility of old tuple, some concurrent session would have performed
	 * non in-place update and in such a case we need can only get it via
	 * undo.
	 */
	ctid = *otid;

check_tup_satisfies_update:
	result = ZHeapTupleSatisfiesUpdate(&oldtup, cid, buffer, &ctid, false,
									   &in_place_updated);

	if (result == HeapTupleInvisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to delete invisible tuple")));
	}
	else if (result == HeapTupleBeingUpdated && wait)
	{
		TransactionId xwait;

		/* must copy state data before unlocking buffer */
		xwait = ZHeapTupleHeaderGetRawXid(oldtup.t_data, opaque);

		if (!TransactionIdIsCurrentTransactionId(xwait))
		{
			/*
			 * Wait for regular transaction to end; but first, acquire tuple
			 * lock.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			heap_acquire_tuplock(relation, &(oldtup.t_self), *lockmode,
								 LockWaitBlock, &have_tuple_lock);
			XactLockTableWait(xwait, relation, &oldtup.t_self,
							  XLTW_Update);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * xwait is done, but if xwait had just locked the tuple then some
			 * other xact could update this tuple before we get to this point.
			 * Check for xid change, and start over if so.
			 */
			if (!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(oldtup.t_data, opaque),
									 xwait))
				goto check_tup_satisfies_update;
		}

		/*
		 * We may overwrite if previous xid aborted, or if it committed but
		 * only locked the tuple without updating it.
		 */
		if (TransactionIdDidCommit(xwait))
			result = HeapTupleUpdated;
		else
			result = HeapTupleMayBeUpdated;
	}

	if (crosscheck != InvalidSnapshot && result == HeapTupleMayBeUpdated)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleSatisfiesVisibility(&oldtup, crosscheck, buffer))
			result = HeapTupleUpdated;
	}

	if (result != HeapTupleMayBeUpdated)
	{
		Assert(result == HeapTupleSelfUpdated ||
			   result == HeapTupleUpdated ||
			   result == HeapTupleBeingUpdated);

		hufd->ctid = ctid;
		hufd->xmax = ZHeapTupleHeaderGetRawXid(oldtup.t_data, opaque);
		if (result == HeapTupleSelfUpdated)
			hufd->cmax = ZHeapTupleHeaderGetRawCommandId(oldtup.t_data, opaque);
		else
			hufd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		hufd->in_place_updated = in_place_updated;
		if (have_tuple_lock)
			UnlockTupleTuplock(relation, &(oldtup.t_self), *lockmode);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		bms_free(inplace_upd_attrs);
		return result;
	}

	/*
	 * Try to acquire the pin on visibility map if it is not already pinned.
	 * See heap_update for the detailed reason.
	 */
	if (vmbuffer == InvalidBuffer && PageIsAllVisible(page))
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		visibilitymap_pin(relation, block, &vmbuffer);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		goto check_tup_satisfies_update;
	}

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(page, xid);

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	/*
	 * Fixme: Api's for serializable isolation level that take zheaptuple as
	 * input needs to be written.
	 */
	/* CheckForSerializableConflictIn(relation, &oldtup, buffer); */

	prev_urecptr = PageGetUNDO(page, trans_slot_id);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_INPLACE_UPDATE;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;	/* Fixme - need to figure out how to set this value and then decide whether to WAL log it */
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_tsid = relation->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = ItemPointerGetBlockNumber(&(oldtup.t_self));
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&(oldtup.t_self));
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	/*
	 * Copy the entire old tuple including it's header in the undo record.
	 * We need this to reconstruct the old tuple if current tuple is not
	 * visible to some other transaction.
	 */
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_len,
						   sizeof(uint32));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_self,
						   sizeof(ItemPointerData));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &oldtup.t_tableOid,
						   sizeof(Oid));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) oldtup.t_data,
						   oldtup.t_len);

	urecptr = PrepareUndoInsert(&undorecord, UNDO_PERSISTENT);

	START_CRIT_SECTION();

	if (PageIsAllVisible(page))
	{
		PageClearAllVisible(page);
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	InsertPreparedUndo();
	PageSetUNDO(page, trans_slot_id, xid, cid, urecptr);

	ZHeapTupleHeaderSetXactSlot(oldtup.t_data, trans_slot_id);
	oldtup.t_data->t_infomask |= ZHEAP_INPLACE_UPDATED;

	/* keep the new tuple copy updated for the caller */
	ZHeapTupleHeaderSetXactSlot(newtup->t_data, trans_slot_id);
	newtup->t_data->t_infomask |= ZHEAP_INPLACE_UPDATED;

	/*
	 * For inplace updates, we copy the entire data portion including null
	 * bitmap of new tuple.
	 */
	ItemIdChangeLen(lp, newtup->t_len);
	memcpy((char *) oldtup.t_data + SizeofZHeapTupleHeader,
		   (char *) newtup->t_data + SizeofZHeapTupleHeader,
		   newtup->t_len - SizeofZHeapTupleHeader);

	MarkBufferDirty(buffer);

	/*
	 * Fixme - Do xlog stuff
	 */
	END_CRIT_SECTION();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	/*
	 * Fixme - need to support cache invalidation API's for zheaptuples.
	 */
	/* CacheInvalidateHeapTuple(relation, &oldtup, heaptup); */

	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);
	ReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();

	/*
	 * Release the lmgr tuple lock, if we had it.
	 */
	if (have_tuple_lock)
		UnlockTupleTuplock(relation, &(oldtup.t_self), *lockmode);

	pgstat_count_heap_update(relation, use_inplace_update);

	return HeapTupleMayBeUpdated;
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
 */
Datum
znocachegetattr(ZHeapTuple tuple,
				int attnum,
				TupleDesc tupleDesc)
{
	ZHeapTupleHeader tup = tuple->t_data;
	char	   *tp;				/* ptr to data part of tuple */
	bits8	   *bp = tup->t_bits;	/* ptr to null bitmap in tuple */
	bool		slow = false;	/* do we have to walk attrs? */
	int			off;			/* current offset within data */

	/* ----------------
	 *	 Three cases:
	 *
	 *	 1: No nulls and no variable-width attributes.
	 *	 2: Has a null or a var-width AFTER att.
	 *	 3: Has nulls or var-widths BEFORE att.
	 * ----------------
	 */

	attnum--;

	if (!ZHeapTupleNoNulls(tuple))
	{
		/*
		 * there's a null somewhere in the tuple
		 *
		 * check to see if any preceding bits are null...
		 */
		int			byte = attnum >> 3;
		int			finalbit = attnum & 0x07;

		/* check for nulls "before" final bit of last byte */
		if ((~bp[byte]) & ((1 << finalbit) - 1))
			slow = true;
		else
		{
			/* check for nulls in any "earlier" bytes */
			int			i;

			for (i = 0; i < byte; i++)
			{
				if (bp[i] != 0xFF)
				{
					slow = true;
					break;
				}
			}
		}
	}

	tp = (char *) tup + tup->t_hoff;

	if (!slow)
	{
		Form_pg_attribute att;

		/*
		 * If we get here, there are no nulls up to and including the target
		 * attribute.  If we have a cached offset, we can use it.
		 */
		att = TupleDescAttr(tupleDesc, attnum);
		if (att->attcacheoff >= 0)
			return fetchatt(att, tp + att->attcacheoff);

		/*
		 * Otherwise, check for non-fixed-length attrs up to and including
		 * target.  If there aren't any, it's safe to cheaply initialize the
		 * cached offsets for these attrs.
		 */
		if (ZHeapTupleHasVarWidth(tuple))
		{
			int			j;

			for (j = 0; j <= attnum; j++)
			{
				if (TupleDescAttr(tupleDesc, j)->attlen <= 0)
				{
					slow = true;
					break;
				}
			}
		}
	}

	if (!slow)
	{
		int			natts = tupleDesc->natts;
		int			j = 1;

		/*
		 * If we get here, we have a tuple with no nulls or var-widths up to
		 * and including the target attribute, so we can use the cached offset
		 * ... only we don't have it yet, or we'd not have got here.  Since
		 * it's cheap to compute offsets for fixed-width columns, we take the
		 * opportunity to initialize the cached offsets for *all* the leading
		 * fixed-width columns, in hope of avoiding future visits to this
		 * routine.
		 */
		TupleDescAttr(tupleDesc, 0)->attcacheoff = 0;

		/* we might have set some offsets in the slow path previously */
		while (j < natts && TupleDescAttr(tupleDesc, j)->attcacheoff > 0)
			j++;

		off = TupleDescAttr(tupleDesc, j - 1)->attcacheoff +
			TupleDescAttr(tupleDesc, j - 1)->attlen;

		for (; j < natts; j++)
		{
			Form_pg_attribute att = TupleDescAttr(tupleDesc, j);

			if (att->attlen <= 0)
				break;

			off = att_align_nominal(off, att->attalign);

			att->attcacheoff = off;

			off += att->attlen;
		}

		Assert(j > attnum);

		off = TupleDescAttr(tupleDesc, attnum)->attcacheoff;
	}
	else
	{
		bool		usecache = true;
		int			i;

		/*
		 * Now we know that we have to walk the tuple CAREFULLY.  But we still
		 * might be able to cache some offsets for next time.
		 *
		 * Note - This loop is a little tricky.  For each non-null attribute,
		 * we have to first account for alignment padding before the attr,
		 * then advance over the attr based on its length.  Nulls have no
		 * storage and no alignment padding either.  We can use/set
		 * attcacheoff until we reach either a null or a var-width attribute.
		 */
		off = 0;
		for (i = 0;; i++)		/* loop exit is at "break" */
		{
			Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

			if (ZHeapTupleHasNulls(tuple) && att_isnull(i, bp))
			{
				usecache = false;
				continue;		/* this cannot be the target att */
			}

			/* If we know the next offset, we can skip the rest */
			if (usecache && att->attcacheoff >= 0)
				off = att->attcacheoff;
			else if (att->attlen == -1)
			{
				/*
				 * We can only cache the offset for a varlena attribute if the
				 * offset is already suitably aligned, so that there would be
				 * no pad bytes in any case: then the offset will be valid for
				 * either an aligned or unaligned value.
				 */
				if (usecache &&
					off == att_align_nominal(off, att->attalign))
					att->attcacheoff = off;
				else
				{
					off = att_align_pointer(off, att->attalign, -1,
											tp + off);
					usecache = false;
				}
			}
			else
			{
				/* not varlena, so safe to use att_align_nominal */
				off = att_align_nominal(off, att->attalign);

				if (usecache)
					att->attcacheoff = off;
			}

			if (i == attnum)
				break;

			off = att_addlength_pointer(off, att->attlen, tp + off);

			if (usecache && att->attlen <= 0)
				usecache = false;
		}
	}

	return fetchatt(TupleDescAttr(tupleDesc, attnum), tp + off);
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
	ZHeapPageOpaque	opaque = NULL;

	if (BufferIsValid(buf))
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	Assert(zhtup);

	/* Currently, no sys attribute ever reads as NULL. */
	*isnull = false;

	/*
	 * Fixme - Attributes related to transaction information won't give
	 * correct information for all cases.  As of now, they will always
	 * return the latest xid, cid information on tuple, we need to fetch
	 * exact information using undo.
	 */
	switch (attnum)
	{
		case SelfItemPointerAttributeNumber:
			/* pass-by-reference datatype */
			result = PointerGetDatum(&(zhtup->t_self));
			break;
		case ObjectIdAttributeNumber:
			result = ObjectIdGetDatum(ZHeapTupleGetOid(zhtup));
			break;
		case MinTransactionIdAttributeNumber:
			Assert (BufferIsValid(buf));
			result = TransactionIdGetDatum(ZHeapTupleHeaderGetRawXid(zhtup->t_data, opaque));
			Assert (false);
			break;
		case MaxTransactionIdAttributeNumber:
			Assert (BufferIsValid(buf));
			result = TransactionIdGetDatum(ZHeapTupleHeaderGetRawXid(zhtup->t_data, opaque));
			Assert (false);
			break;
		case MinCommandIdAttributeNumber:
		case MaxCommandIdAttributeNumber:
			Assert (BufferIsValid(buf));
			result = CommandIdGetDatum(ZHeapTupleHeaderGetRawCommandId(zhtup->t_data, opaque));
			Assert (false);
			break;
		case TableOidAttributeNumber:
			result = ObjectIdGetDatum(zhtup->t_tableOid);
			break;
		default:
			elog(ERROR, "invalid attnum: %d", attnum);
			result = 0;			/* keep compiler quiet */
			break;
	}
	return result;
}

/*
 * Check if the specified attribute's value is same in both given tuples.
 * Subroutine for ZHeapDetermineModifiedColumns.
 */
static bool
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
		if (attrnum != ObjectIdAttributeNumber &&
			attrnum != TableOidAttributeNumber)
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
 * ZHeapDetermineModifiedColumns - Check which columns are being updated.
 *	This is same as HeapDetermineModifiedColumns except that it takes
 *	ZHeapTuple as input.
 */
static Bitmapset *
ZHeapDetermineModifiedColumns(Relation relation, Bitmapset *interesting_cols,
							  ZHeapTuple oldtup, ZHeapTuple newtup)
{
	int			attnum;
	Bitmapset  *modified = NULL;

	while ((attnum = bms_first_member(interesting_cols)) >= 0)
	{
		attnum += FirstLowInvalidHeapAttributeNumber;

		if (!zheap_tuple_attr_equals(RelationGetDescr(relation),
									 attnum, oldtup, newtup))
			modified = bms_add_member(modified,
								attnum - FirstLowInvalidHeapAttributeNumber);
	}

	return modified;
}

/*
 * -----------
 * Zheap transaction information related API's.
 * -----------
 */

/*
 * PageGetUNDO - Get the undo record pointer for a given transaction slot.
 */
static inline UndoRecPtr
PageGetUNDO(Page page, int trans_slot_id)
{
	ZHeapPageOpaque	opaque;

	Assert(trans_slot_id != InvalidXactSlotId);

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	return opaque->transinfo[trans_slot_id].urec_ptr;
}

/*
 * PageSetUNDO - Set the transaction information pointer for a given
 *		transaction slot.
 */
static inline void
PageSetUNDO(Page page, int trans_slot_id, TransactionId xid,
			CommandId cid, UndoRecPtr urecptr)
{
	ZHeapPageOpaque	opaque;

	Assert(trans_slot_id != InvalidXactSlotId);

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	opaque->transinfo[trans_slot_id].xid = xid;
	opaque->transinfo[trans_slot_id].cid = cid;
	opaque->transinfo[trans_slot_id].urec_ptr = urecptr;
}

/*
 * PageReserveTransactionSlot - Reserve the transaction slot in page.
 *
 *	This function returns true if either the page already has some slot that
 *	contains the transaction info or there is an empty slot; otherwise retruns
 *	false.
 */
static int
PageReserveTransactionSlot(Page page, TransactionId xid)
{
	ZHeapPageOpaque	opaque;
	int		latestFreeTransSlot = InvalidXactSlotId;
	int		i;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	for (i = 0; i < MAX_PAGE_TRANS_INFO_SLOTS; i++)
	{
		if (opaque->transinfo[i].xid == xid)
			return i;
		else if (opaque->transinfo[i].xid == InvalidTransactionId &&
				 latestFreeTransSlot == InvalidXactSlotId)
			latestFreeTransSlot = i;
	}

	if (latestFreeTransSlot >= 0)
		return latestFreeTransSlot;

	/* no transaction slot available */
	return InvalidXactSlotId;
}

/*
 * This function is similar to HeapTupleHeaderGetCmin except that it needs
 * to retrieve the cmin from zheap tuple.
 */
CommandId
ZHeapTupleHeaderGetCid(ZHeapTupleHeader tup, Buffer buf)
{
	ZHeapPageOpaque	opaque;
	CommandId	cid;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));
	
	cid = ZHeapTupleHeaderGetRawCommandId(tup, opaque);

	/*
	 * Fixme : We need to define and use ZHeapTupleHeaderGetXmin, once we
	 * we decide whether we need to freeze the tuples like we do for regular
	 * heap.
	 */
	Assert(TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tup, opaque)));

	/*
	 * Fixme : We need to enable combocid functionality once we define
	 * delete/update for zheap.
	 */
	/* if (tup->t_infomask & HEAP_COMBOCID)
		return GetRealCmin(cid);
	else
		return cid; */

	return cid;
}

/*
 * Initialize zheap page.
 */
void
ZheapInitPage(Page page, Size pageSize)
{
	ZHeapPageOpaque	opaque;
	int				i;

	PageInit(page, pageSize, sizeof(ZHeapPageOpaqueData));

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	for (i = 0; i < MAX_PAGE_TRANS_INFO_SLOTS; i++)
	{
		opaque->transinfo[i].xid = InvalidTransactionId;
		opaque->transinfo[i].cid = InvalidCommandId;
		/* Fixme: set the InvalidUrecPtr once it is defined. */
		opaque->transinfo[i].urec_ptr = -1;
	}
}

/*
 * -----------
 * Zheap scan related API's.
 * -----------
 */

/*
 * zinitscan - same as initscan except for tuple initialization
 */
static void
zinitscan(HeapScanDesc scan, ScanKey key, bool keep_startblock)
{
	bool		allow_strat;
	bool		allow_sync;

	/*
	 * Determine the number of blocks we have to scan.
	 *
	 * It is sufficient to do this once at scan start, since any tuples added
	 * while the scan is in progress will be invisible to my snapshot anyway.
	 * (That is not true when using a non-MVCC snapshot.  However, we couldn't
	 * guarantee to return tuples added after scan start anyway, since they
	 * might go into pages we already scanned.  To guarantee consistent
	 * results for a non-MVCC snapshot, the caller must hold some higher-level
	 * lock that ensures the interesting tuple(s) won't change.)
	 */
	if (scan->rs_parallel != NULL)
		scan->rs_nblocks = scan->rs_parallel->phs_nblocks;
	else
		scan->rs_nblocks = RelationGetNumberOfBlocks(scan->rs_rd);

	/*
	 * If the table is large relative to NBuffers, use a bulk-read access
	 * strategy and enable synchronized scanning (see syncscan.c).  Although
	 * the thresholds for these features could be different, we make them the
	 * same so that there are only two behaviors to tune rather than four.
	 * (However, some callers need to be able to disable one or both of these
	 * behaviors, independently of the size of the table; also there is a GUC
	 * variable that can disable synchronized scanning.)
	 *
	 * Note that heap_parallelscan_initialize has a very similar test; if you
	 * change this, consider changing that one, too.
	 */
	if (!RelationUsesLocalBuffers(scan->rs_rd) &&
		scan->rs_nblocks > NBuffers / 4)
	{
		allow_strat = scan->rs_allow_strat;
		allow_sync = scan->rs_allow_sync;
	}
	else
		allow_strat = allow_sync = false;

	if (allow_strat)
	{
		/* During a rescan, keep the previous strategy object. */
		if (scan->rs_strategy == NULL)
			scan->rs_strategy = GetAccessStrategy(BAS_BULKREAD);
	}
	else
	{
		if (scan->rs_strategy != NULL)
			FreeAccessStrategy(scan->rs_strategy);
		scan->rs_strategy = NULL;
	}

	if (scan->rs_parallel != NULL)
	{
		/* For parallel scan, believe whatever ParallelHeapScanDesc says. */
		scan->rs_syncscan = scan->rs_parallel->phs_syncscan;
	}
	else if (keep_startblock)
	{
		/*
		 * When rescanning, we want to keep the previous startblock setting,
		 * so that rewinding a cursor doesn't generate surprising results.
		 * Reset the active syncscan setting, though.
		 */
		scan->rs_syncscan = (allow_sync && synchronize_seqscans);
	}
	else if (allow_sync && synchronize_seqscans)
	{
		scan->rs_syncscan = true;
		scan->rs_startblock = ss_get_location(scan->rs_rd, scan->rs_nblocks);
	}
	else
	{
		scan->rs_syncscan = false;
		scan->rs_startblock = 0;
	}

	scan->rs_numblocks = InvalidBlockNumber;
	scan->rs_inited = false;
	scan->rs_cbuf = InvalidBuffer;
	scan->rs_cblock = InvalidBlockNumber;

	/* page-at-a-time fields are always invalid when not rs_inited */

	/*
	 * copy the scan key, if appropriate
	 */
	if (key != NULL)
		memcpy(scan->rs_key, key, scan->rs_nkeys * sizeof(ScanKeyData));

	/*
	 * Currently, we don't have a stats counter for bitmap heap scans (but the
	 * underlying bitmap index scans will be counted) or sample scans (we only
	 * update stats for tuple fetches there)
	 */
	if (!scan->rs_bitmapscan && !scan->rs_samplescan)
		pgstat_count_heap_scan(scan->rs_rd);
}

/*
 * zheap_beginscan - same as heap_beginscan
 */
HeapScanDesc
zheap_beginscan(Relation relation, Snapshot snapshot,
				int nkeys, ScanKey key)
{
	return zheap_beginscan_internal(relation, snapshot, nkeys, key, NULL,
								   true, true, true, false, false, false);
}

/*
 * zheap_beginscan_internal - same as heap_beginscan_internal except for tuple
 *	initialization
 */
static HeapScanDesc
zheap_beginscan_internal(Relation relation, Snapshot snapshot,
						 int nkeys, ScanKey key,
						 ParallelHeapScanDesc parallel_scan,
						 bool allow_strat,
						 bool allow_sync,
						 bool allow_pagemode,
						 bool is_bitmapscan,
						 bool is_samplescan,
						 bool temp_snap)
{
	HeapScanDesc scan;

	/*
	 * increment relation ref count while scanning relation
	 *
	 * This is just to make really sure the relcache entry won't go away while
	 * the scan has a pointer to it.  Caller should be holding the rel open
	 * anyway, so this is redundant in all normal scenarios...
	 */
	RelationIncrementReferenceCount(relation);

	/*
	 * allocate and initialize scan descriptor
	 */
	scan = (HeapScanDesc) palloc(sizeof(HeapScanDescData));

	scan->rs_rd = relation;
	scan->rs_snapshot = snapshot;
	scan->rs_nkeys = nkeys;
	scan->rs_bitmapscan = is_bitmapscan;
	scan->rs_samplescan = is_samplescan;
	scan->rs_strategy = NULL;	/* set in initscan */
	scan->rs_allow_strat = allow_strat;
	scan->rs_allow_sync = allow_sync;
	scan->rs_temp_snap = temp_snap;
	scan->rs_parallel = parallel_scan;

	/*
	 * we can use page-at-a-time mode if it's an MVCC-safe snapshot
	 */
	scan->rs_pageatatime = allow_pagemode && IsMVCCSnapshot(snapshot);

	/*
	 * For a seqscan in a serializable transaction, acquire a predicate lock
	 * on the entire relation. This is required not only to lock all the
	 * matching tuples, but also to conflict with new insertions into the
	 * table. In an indexscan, we take page locks on the index pages covering
	 * the range specified in the scan qual, but in a heap scan there is
	 * nothing more fine-grained to lock. A bitmap scan is a different story,
	 * there we have already scanned the index and locked the index pages
	 * covering the predicate. But in that case we still have to lock any
	 * matching heap tuples.
	 */
	if (!is_bitmapscan)
		PredicateLockRelation(relation, snapshot);

	scan->rs_cztup = NULL;

	/*
	 * we do this here instead of in initscan() because heap_rescan also calls
	 * initscan() and we don't want to allocate memory again
	 */
	if (nkeys > 0)
		scan->rs_key = (ScanKey) palloc(sizeof(ScanKeyData) * nkeys);
	else
		scan->rs_key = NULL;

	zinitscan(scan, key, false);

	return scan;
}

/*
 * zheapgetpage - Same as heapgetpage, but operate on zheap page and
 * in page-at-a-time mode, visible tuples are stored in rs_visztuples.
 */
static void
zheapgetpage(HeapScanDesc scan, BlockNumber page)
{
	Buffer		buffer;
	Snapshot	snapshot;
	Page		dp;
	int			lines;
	int			ntup;
	OffsetNumber lineoff;
	ItemId		lpp;
	bool		all_visible;

	Assert(page < scan->rs_nblocks);

	/* release previous scan buffer, if any */
	if (BufferIsValid(scan->rs_cbuf))
	{
		ReleaseBuffer(scan->rs_cbuf);
		scan->rs_cbuf = InvalidBuffer;
	}

	/*
	 * Be sure to check for interrupts at least once per page.  Checks at
	 * higher code levels won't be able to stop a seqscan that encounters many
	 * pages' worth of consecutive dead tuples.
	 */
	CHECK_FOR_INTERRUPTS();

	/* read page using selected strategy */
	buffer = ReadBufferExtended(scan->rs_rd, MAIN_FORKNUM, page,
									   RBM_NORMAL, scan->rs_strategy);
	scan->rs_cblock = page;

	if (!scan->rs_pageatatime)
	{
		scan->rs_cbuf = buffer;
		return;
	}

	snapshot = scan->rs_snapshot;

	/*
	 * Prune and repair fragmentation for the whole page, if possible.
	 * Fixme - Pruning is required in zheap for deletes, so we need to
	 * make it work.
	 */
	/* heap_page_prune_opt(scan->rs_rd, buffer); */

	/*
	 * We must hold share lock on the buffer content while examining tuple
	 * visibility.  Afterwards, however, the tuples we have found to be
	 * visible are guaranteed good as long as we hold the buffer pin.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = BufferGetPage(buffer);
	TestForOldSnapshot(snapshot, scan->rs_rd, dp);
	lines = PageGetMaxOffsetNumber(dp);
	ntup = 0;

	/*
	 * If the all-visible flag indicates that all tuples on the page are
	 * visible to everyone, we can skip the per-tuple visibility tests.
	 *
	 * Note: In hot standby, a tuple that's already visible to all
	 * transactions in the master might still be invisible to a read-only
	 * transaction in the standby. We partly handle this problem by tracking
	 * the minimum xmin of visible tuples as the cut-off XID while marking a
	 * page all-visible on master and WAL log that along with the visibility
	 * map SET operation. In hot standby, we wait for (or abort) all
	 * transactions that can potentially may not see one or more tuples on the
	 * page. That's how index-only scans work fine in hot standby. A crucial
	 * difference between index-only scans and heap scans is that the
	 * index-only scan completely relies on the visibility map where as heap
	 * scan looks at the page-level PD_ALL_VISIBLE flag. We are not sure if
	 * the page-level flag can be trusted in the same way, because it might
	 * get propagated somehow without being explicitly WAL-logged, e.g. via a
	 * full page write. Until we can prove that beyond doubt, let's check each
	 * tuple for visibility the hard way.
	 */
	all_visible = PageIsAllVisible(dp) && !snapshot->takenDuringRecovery;

	for (lineoff = FirstOffsetNumber, lpp = PageGetItemId(dp, lineoff);
		 lineoff <= lines;
		 lineoff++, lpp++)
	{
		if (ItemIdIsNormal(lpp))
		{
			ZHeapTuple loctup;
			ZHeapTuple	resulttup;
			Size		loctup_len;
			bool		valid = false;

			loctup_len = ItemIdGetLength(lpp);

			loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
			loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

			loctup->t_tableOid = RelationGetRelid(scan->rs_rd);
			loctup->t_len = loctup_len;
			ItemPointerSet(&(loctup->t_self), page, lineoff);

			/*
			 * We always need to make a copy of zheap tuple as once we release
			 * the buffer an in-place update can change the tuple.
			 */
			memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)), loctup->t_len);

			if (all_visible)
			{
				valid = true;
				resulttup = loctup;
			}
			else
			{
				resulttup = ZHeapTupleSatisfiesVisibility(loctup, snapshot, buffer);
				valid = resulttup ? true : false;
			}

			/* Fixme - Serialization failures needs to be detected for zheap. */
			/* CheckForSerializableConflictOut(valid, scan->rs_rd, &loctup,
											buffer, snapshot); */

			if (valid)
				scan->rs_visztuples[ntup++] = resulttup;
		}
	}

	UnlockReleaseBuffer(buffer);

	Assert(ntup <= MaxZHeapTuplesPerPage);
	scan->rs_ntuples = ntup;
}

/* ----------------
 *		zheapgettup_pagemode - fetch next zheap tuple in page-at-a-time mode
 *
 * ----------------
 */
static ZHeapTuple
zheapgettup_pagemode(HeapScanDesc scan,
					 ScanDirection dir,
					 int nkeys,
					 ScanKey key)
{
	ZHeapTuple	tuple = scan->rs_cztup;
	bool		backward = ScanDirectionIsBackward(dir);
	BlockNumber page;
	bool		finished;
	int			lines;
	int			lineindex;
	int			linesleft;

	/*
	 * calculate next starting lineindex, given scan direction
	 */
	if (ScanDirectionIsForward(dir))
	{
		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == 0 || scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				tuple = NULL;
				return tuple;
			}
			if (scan->rs_parallel != NULL)
			{
				page = heap_parallelscan_nextpage(scan);

				/* Other processes might have already finished the scan. */
				if (page == InvalidBlockNumber)
				{
					Assert(!BufferIsValid(scan->rs_cbuf));
					tuple = NULL;
					return tuple;
				}
			}
			else
				page = scan->rs_startblock;		/* first page */
			zheapgetpage(scan, page);
			lineindex = 0;
			scan->rs_inited = true;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
			lineindex = scan->rs_cindex + 1;
		}

		/*dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(scan->rs_snapshot, scan->rs_rd, dp);*/
		lines = scan->rs_ntuples;
		/* page and lineindex now reference the next visible tid */

		linesleft = lines - lineindex;
	}
	else if (backward)
	{
		/* backward parallel scan not supported */
		Assert(scan->rs_parallel == NULL);

		if (!scan->rs_inited)
		{
			/*
			 * return null immediately if relation is empty
			 */
			if (scan->rs_nblocks == 0 || scan->rs_numblocks == 0)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				tuple = NULL;
				return tuple;
			}

			/*
			 * Disable reporting to syncscan logic in a backwards scan; it's
			 * not very likely anyone else is doing the same thing at the same
			 * time, and much more likely that we'll just bollix things for
			 * forward scanners.
			 */
			scan->rs_syncscan = false;
			/* start from last page of the scan */
			if (scan->rs_startblock > 0)
				page = scan->rs_startblock - 1;
			else
				page = scan->rs_nblocks - 1;
			zheapgetpage(scan, page);
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
		}

		lines = scan->rs_ntuples;

		if (!scan->rs_inited)
		{
			lineindex = lines - 1;
			scan->rs_inited = true;
		}
		else
		{
			lineindex = scan->rs_cindex - 1;
		}
		/* page and lineindex now reference the previous visible tid */

		linesleft = lineindex + 1;
	}
	else
	{
		/* Fixme - no movement scan direction is yet to be implemented */
		Assert(false);
		/*
		 * ``no movement'' scan direction: refetch prior tuple
		 */
		if (!scan->rs_inited)
		{
			Assert(!BufferIsValid(scan->rs_cbuf));
			tuple = NULL;
			return tuple;
		}

		page = ItemPointerGetBlockNumber(&(tuple->t_self));
		if (page != scan->rs_cblock)
			zheapgetpage(scan, page);

		/*
		 * Fixme - We can't rely on the current tuple as an in-place update
		 * would have updated it, so we need to check its visibility again
		 * and fetch the latest tuple if required.
		 *
		 * Also need to think if we need to take a lock on page.
		 */
		return NULL;
	}

	/*
	 * advance the scan until we find a qualifying tuple or run out of stuff
	 * to scan
	 */
	for (;;)
	{
		while (linesleft > 0)
		{
			tuple = scan->rs_visztuples[lineindex];

			/*
			 * if current tuple qualifies, return it.
			 * Fixme - Key test needs to be implemented for zheap.
			 */
			Assert(key == NULL);
			/* if (key != NULL)
			{
				bool		valid;

				HeapKeyTest(tuple, RelationGetDescr(scan->rs_rd),
							nkeys, key, valid);
				if (valid)
				{
					scan->rs_cindex = lineindex;
					return;
				}
			}
			else
			{
				scan->rs_cindex = lineindex;
				return;
			} */

			scan->rs_cindex = lineindex;
			return tuple;
			/*
			 * otherwise move to the next item on the page
			 */
			/*--linesleft;
			if (backward)
				--lineindex;
			else
				++lineindex;*/
		}

		/*
		 * if we get here, it means we've exhausted the items on this page and
		 * it's time to move to the next.
		 */
		if (backward)
		{
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);
			if (page == 0)
				page = scan->rs_nblocks;
			page--;
		}
		else if (scan->rs_parallel != NULL)
		{
			page = heap_parallelscan_nextpage(scan);
			finished = (page == InvalidBlockNumber);
		}
		else
		{
			page++;
			if (page >= scan->rs_nblocks)
				page = 0;
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);

			/*
			 * Report our new scan position for synchronization purposes. We
			 * don't do that when moving backwards, however. That would just
			 * mess up any other forward-moving scanners.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_syncscan)
				ss_report_location(scan->rs_rd, page);
		}

		/*
		 * return NULL if we've exhausted all the pages
		 */
		if (finished)
		{
			if (BufferIsValid(scan->rs_cbuf))
				ReleaseBuffer(scan->rs_cbuf);
			scan->rs_cbuf = InvalidBuffer;
			scan->rs_cblock = InvalidBlockNumber;
			tuple = NULL;
			scan->rs_inited = false;
			return tuple;
		}

		zheapgetpage(scan, page);

		/*dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(scan->rs_snapshot, scan->rs_rd, dp);*/
		lines = scan->rs_ntuples;
		linesleft = lines;
		if (backward)
			lineindex = lines - 1;
		else
			lineindex = 0;
	}
}

#ifdef ZHEAPDEBUGALL
#define ZHEAPDEBUG_1 \
	elog(DEBUG2, "zheap_getnext([%s,nkeys=%d],dir=%d) called", \
		 RelationGetRelationName(scan->rs_rd), scan->rs_nkeys, (int) direction)
#define ZHEAPDEBUG_2 \
	elog(DEBUG2, "zheap_getnext returning EOS")
#define ZHEAPDEBUG_3 \
	elog(DEBUG2, "zheap_getnext returning tuple")
#else
#define ZHEAPDEBUG_1
#define ZHEAPDEBUG_2
#define ZHEAPDEBUG_3
#endif   /* !defined(ZHEAPDEBUGALL) */


ZHeapTuple
zheap_getnext(HeapScanDesc scan, ScanDirection direction)
{
	ZHeapTuple	zhtup = NULL;

	/* Note: no locking manipulations needed */

	ZHEAPDEBUG_1;				/* zheap_getnext( info ) */

	if (scan->rs_pageatatime)
		zhtup = zheapgettup_pagemode(scan, direction,
							scan->rs_nkeys, scan->rs_key);
	else
		Assert(false);	/* tuple mode is not supported for zheap */

	if (zhtup == NULL)
	{
		ZHEAPDEBUG_2;			/* zheap_getnext returning EOS */
		return NULL;
	}

	scan->rs_cztup = zhtup;

	/*
	 * if we get here it means we have a new current scan tuple, so point to
	 * the proper return buffer and return the tuple.
	 */
	ZHEAPDEBUG_3;				/* zheap_getnext returning tuple */

	pgstat_count_heap_getnext(scan->rs_rd);

	return zhtup;
}

/*
 * ----------
 * Page related API's.  Eventually we might need to split these API's
 * into a separate file like bufzpage.c or buf_zheap_page.c or some
 * thing like that.
 * ----------
 */

/*
 * ZPageAddItemExtended - Add an item to a zheap page.
 *
 *	This is similar to PageAddItemExtended except for max tuples that can
 *	be accomodated on a page and alignment for each item.
 */
OffsetNumber
ZPageAddItemExtended(Page page,
					 Item item,
					 Size size,
					 OffsetNumber offsetNumber,
					 int flags)
{
	PageHeader	phdr = (PageHeader) page;
	Size		alignedSize;
	int			lower;
	int			upper;
	ItemId		itemId;
	OffsetNumber limit;
	bool		needshuffle = false;

	/*
	 * Be wary about corrupted page pointers
	 */
	if (phdr->pd_lower < SizeOfPageHeaderData ||
		phdr->pd_lower > phdr->pd_upper ||
		phdr->pd_upper > phdr->pd_special ||
		phdr->pd_special > BLCKSZ)
		ereport(PANIC,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("corrupted page pointers: lower = %u, upper = %u, special = %u",
						phdr->pd_lower, phdr->pd_upper, phdr->pd_special)));

	/*
	 * Select offsetNumber to place the new item at
	 */
	limit = OffsetNumberNext(PageGetMaxOffsetNumber(page));

	/* was offsetNumber passed in? */
	if (OffsetNumberIsValid(offsetNumber))
	{
		/* yes, check it */
		if ((flags & PAI_OVERWRITE) != 0)
		{
			if (offsetNumber < limit)
			{
				itemId = PageGetItemId(phdr, offsetNumber);
				if (ItemIdIsUsed(itemId) || ItemIdHasStorage(itemId))
				{
					elog(WARNING, "will not overwrite a used ItemId");
					return InvalidOffsetNumber;
				}
			}
		}
		else
		{
			if (offsetNumber < limit)
				needshuffle = true;		/* need to move existing linp's */
		}
	}
	else
	{
		/* offsetNumber was not passed in, so find a free slot */
		/* if no free slot, we'll put it at limit (1st open slot) */
		if (PageHasFreeLinePointers(phdr))
		{
			/*
			 * Look for "recyclable" (unused) ItemId.  We check for no storage
			 * as well, just to be paranoid --- unused items should never have
			 * storage.
			 */
			for (offsetNumber = 1; offsetNumber < limit; offsetNumber++)
			{
				itemId = PageGetItemId(phdr, offsetNumber);
				if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
					break;
			}
			if (offsetNumber >= limit)
			{
				/* the hint is wrong, so reset it */
				PageClearHasFreeLinePointers(phdr);
			}
		}
		else
		{
			/* don't bother searching if hint says there's no free slot */
			offsetNumber = limit;
		}
	}

	/* Reject placing items beyond the first unused line pointer */
	if (offsetNumber > limit)
	{
		elog(WARNING, "specified item offset is too large");
		return InvalidOffsetNumber;
	}

	/* Reject placing items beyond heap boundary, if heap */
	if ((flags & PAI_IS_HEAP) != 0 && offsetNumber > MaxZHeapTuplesPerPage)
	{
		elog(WARNING, "can't put more than MaxHeapTuplesPerPage items in a heap page");
		return InvalidOffsetNumber;
	}

	/*
	 * Compute new lower and upper pointers for page, see if it'll fit.
	 *
	 * Note: do arithmetic as signed ints, to avoid mistakes if, say,
	 * alignedSize > pd_upper.
	 */
	if (offsetNumber == limit || needshuffle)
		lower = phdr->pd_lower + sizeof(ItemIdData);
	else
		lower = phdr->pd_lower;

	if (data_alignment_zheap == 0)
		alignedSize = size;	/* no alignment */
	else if (data_alignment_zheap == 4)
		alignedSize = INTALIGN(size);	/* four byte alignment */
	else
		alignedSize = MAXALIGN(size);

	upper = (int) phdr->pd_upper - (int) alignedSize;

	if (lower > upper)
		return InvalidOffsetNumber;

	/*
	 * OK to insert the item.  First, shuffle the existing pointers if needed.
	 */
	itemId = PageGetItemId(phdr, offsetNumber);

	if (needshuffle)
		memmove(itemId + 1, itemId,
				(limit - offsetNumber) * sizeof(ItemIdData));

	/* set the item pointer */
	ItemIdSetNormal(itemId, upper, size);

	/*
	 * Items normally contain no uninitialized bytes.  Core bufpage consumers
	 * conform, but this is not a necessary coding rule; a new index AM could
	 * opt to depart from it.  However, data type input functions and other
	 * C-language functions that synthesize datums should initialize all
	 * bytes; datumIsEqual() relies on this.  Testing here, along with the
	 * similar check in printtup(), helps to catch such mistakes.
	 *
	 * Values of the "name" type retrieved via index-only scans may contain
	 * uninitialized bytes; see comment in btrescan().  Valgrind will report
	 * this as an error, but it is safe to ignore.
	 */
	VALGRIND_CHECK_MEM_IS_DEFINED(item, size);

	/* copy the item's data onto the page */
	memcpy((char *) page + upper, item, size);

	/* adjust page header */
	phdr->pd_lower = (LocationIndex) lower;
	phdr->pd_upper = (LocationIndex) upper;

	return offsetNumber;
}

/*
 * PageGetZHeapFreeSpace
 *		Returns the size of the free (allocatable) space on a zheap page,
 *		reduced by the space needed for a new line pointer.
 *
 * This is same as PageGetZHeapFreeSpace except for max tuples that can
 * be accomodated on a page.
 */
Size
PageGetZHeapFreeSpace(Page page)
{
	Size		space;

	space = PageGetFreeSpace(page);
	if (space > 0)
	{
		OffsetNumber offnum,
					nline;

		nline = PageGetMaxOffsetNumber(page);
		if (nline >= MaxZHeapTuplesPerPage)
		{
			if (PageHasFreeLinePointers((PageHeader) page))
			{
				/*
				 * Since this is just a hint, we must confirm that there is
				 * indeed a free line pointer
				 */
				for (offnum = FirstOffsetNumber; offnum <= nline; offnum = OffsetNumberNext(offnum))
				{
					ItemId		lp = PageGetItemId(page, offnum);

					if (!ItemIdIsUsed(lp))
						break;
				}

				if (offnum > nline)
				{
					/*
					 * The hint is wrong, but we can't clear it here since we
					 * don't have the ability to mark the page dirty.
					 */
					space = 0;
				}
			}
			else
			{
				/*
				 * Although the hint might be wrong, PageAddItem will believe
				 * it anyway, so we must believe it too.
				 */
				space = 0;
			}
		}
	}
	return space;
}
