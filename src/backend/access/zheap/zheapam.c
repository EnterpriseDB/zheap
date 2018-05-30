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
 *	  In zheap, we never generate subtransaction id and rather always use top
 *	  transaction id.  The sub-transaction id is mainly required to detect the
 *	  visibility of tuple when the sub-transaction state is different from
 *	  main transaction state, say due to Rollback To SavePoint.  In zheap, we
 *	  always perform undo actions to make sure that the tuple state reaches to
 *	  the state where it is at the start of subtransaction in such a case.
 *	  This will also help in avoiding the transaction slots to grow inside a
 *	  page and will have lesser clog entries.  Another advantage is that it
 *	  will help us retaining the undo records for one transaction together
 *	  in undo log instead of those being interleaved which will avoid having
 *	  more undo records that have UREC_INFO_TRANSACTION.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/bufmask.h"
#include "access/htup_details.h"
#include "access/hio.h"
#include "access/parallel.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "access/relscan.h"
#include "access/tuptoaster.h"
#include "access/undoinsert.h"
#include "access/undolog.h"
#include "access/undolog_xlog.h"
#include "access/undorecord.h"
#include "access/visibilitymap.h"
#include "access/zheap.h"
#include "access/zhtup.h"
#include "access/zheapam_xlog.h"
#include "access/zmultilocker.h"
#include "catalog/catalog.h"
#include "executor/tuptable.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/undoloop.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "storage/predicate.h"
#include "storage/procarray.h"
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

static ZHeapTuple zheap_prepare_insert(Relation relation, ZHeapTuple tup,
									   int options);
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

static bool PageFreezeTransSlots(Relation relation, Buffer buf, bool *lock_reacquired);
static void RelationPutZHeapTuple(Relation relation, Buffer buffer,
								  ZHeapTuple tuple);
static XLogRecPtr log_zheap_update(Relation reln, UnpackedUndoRecord undorecord,
					UnpackedUndoRecord newundorecord, UndoRecPtr urecptr,
					UndoRecPtr newurecptr, Buffer oldbuf, Buffer newbuf,
					ZHeapTuple oldtup, ZHeapTuple newtup, bool inplace_update,
					bool all_visible_cleared, bool new_all_visible_cleared,
					xl_undolog_meta *undometa);
static HTSU_Result
zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 TransactionId xid, LockTupleMode mode, CommandId cid);
static void zheap_lock_tuple_guts(Relation rel, Buffer buf, ZHeapTuple zhtup,
					  TransactionId tup_xid, TransactionId xid,
					  LockTupleMode mode, uint32 epoch, int tup_trans_slot_id,
					  int trans_slot_id, UndoRecPtr prev_urecptr,
					  CommandId cid, bool any_multi_locker_member_alive);
static void compute_new_xid_infomask(ZHeapTuple zhtup, Buffer buf,
						 TransactionId tup_xid, int tup_trans_slot,
						 uint16 old_infomask, TransactionId add_to_xid,
						 int trans_slot, LockTupleMode mode, bool is_update,
						 uint16 *result_infomask, int *result_trans_slot);
static ZHeapFreeOffsetRanges *
ZHeapGetUsableOffsetRanges(Buffer buffer, ZHeapTuple *tuples, int ntuples,
						   Size saveFreeSpace);

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
 * zheap_deform_tuple - similar to heap_deform_tuple, but for zheap tuples.
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
	bits8	   *bp = tup->t_bits;		/* ptr to null bitmap in tuple */
	bool		slow = false;	/* can we use/set attcacheoff? */

	natts = ZHeapTupleHeaderGetNatts(tup);

	/*
	 * In inheritance situations, it is possible that the given tuple actually
	 * has more fields than the caller is expecting.  Don't run off the end of
	 * the caller's arrays.
	 */
	natts = Min(natts, tdesc_natts);

	tp = (char *) tup + tup->t_hoff;

	off = 0;

	for (attnum = 0; attnum < natts; attnum++)
	{
		Form_pg_attribute thisatt = TupleDescAttr(tupleDesc, attnum);

		if (hasnulls && att_isnull(attnum, bp))
		{
			values[attnum] = (Datum) 0;
			isnull[attnum] = true;
			slow = true;		/* can't use attcacheoff anymore */
			continue;
		}

		isnull[attnum] = false;

		if (!slow && thisatt->attcacheoff >= 0)
			off = thisatt->attcacheoff;
		else if (thisatt->attlen == -1)
		{
			/*
			 * We can only cache the offset for a varlena attribute if the
			 * offset is already suitably aligned, so that there would be no
			 * pad bytes in any case: then the offset will be valid for either
			 * an aligned or unaligned value.
			 */
			if (!slow &&
				off == att_align_nominal(off, thisatt->attalign))
				thisatt->attcacheoff = off;
			else
			{
				off = att_align_pointer(off, thisatt->attalign, -1,
										tp + off);
				slow = true;
			}
		}
		else
		{
			/* not varlena, so safe to use att_align_nominal */
			off = att_align_nominal(off, thisatt->attalign);

			if (!slow)
				thisatt->attcacheoff = off;
		}

		values[attnum] = fetchatt(thisatt, tp + off);

		off = att_addlength_pointer(off, thisatt->attlen, tp + off);

		if (thisatt->attlen <= 0)
			slow = true;		/* can't use attcacheoff anymore */
	}

	/*
	 * If tuple doesn't have all the atts indicated by tupleDesc, read the
	 * rest as null
	 */
	for (; attnum < tdesc_natts; attnum++)
	{
		values[attnum] = (Datum) 0;
		isnull[attnum] = true;
	}
}

/*
 * Subroutine for zheap_insert(). Prepares a tuple for insertion.
 *
 * This is similar to heap_prepare_insert except that we don't set
 * information in tuple header as that needs to be either set in
 * TPD entry or undorecord for this tuple.
 */
static ZHeapTuple
zheap_prepare_insert(Relation relation, ZHeapTuple tup, int options)
{
	/*
	 * Parallel operations are required to be strictly read-only in a parallel
	 * worker.  Parallel inserts are not safe even in the leader in the
	 * general case, because group locking means that heavyweight locks for
	 * relation extension or GIN page locks will not conflict between members
	 * of a lock group, but we don't prohibit that case here because there are
	 * useful special cases that we can safely allow, such as CREATE TABLE AS.
	 */
	if (IsParallelWorker())
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TRANSACTION_STATE),
				 errmsg("cannot insert tuples in a parallel worker")));

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

	tup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	tup->t_data->t_infomask2 &= ~ZHEAP_XACT_SLOT;

	if (options & ZHTUP_SLOT_FROZEN)
		ZHeapTupleHeaderSetXactSlot(tup->t_data, ZHTUP_SLOT_FROZEN);
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
		elog(ERROR, "toast tuple is not supported for zheap");
		return NULL;
		/* return toast_insert_or_update(relation, tup, NULL, options); */
	}
	else
		return tup;
}

/*
 * xid_infomask_changed - It checks whether the relevant status for a tuple
 *	xid has changed.
 *
 * Note the Xid field itself must be compared separately.
 */
static inline bool
xid_infomask_changed(uint16 new_infomask, uint16 old_infomask)
{
	const uint16 interesting = ZHEAP_XID_LOCK_ONLY;

	if ((new_infomask & interesting) != (old_infomask & interesting))
		return true;

	return false;
}

/*
 * zheap_exec_pending_rollback - Execute pending rollback actions for the
 *	given buffer (page).
 *
 * This function expects that the input buffer is locked.  We will release and
 * reacquire the buffer lock in this function, the same can be done in all the
 * callers of this function, but that is just a code duplication, so we instead
 * do it here.
 */
void
zheap_exec_pending_rollback(Relation rel, Buffer buffer, int slot_no)
{
	UndoRecPtr urec_ptr;
	Page	page;
	ZHeapPageOpaque opaque;
	TransactionId xid;

	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	urec_ptr = opaque->transinfo[slot_no].urec_ptr;
	xid = opaque->transinfo[slot_no].xid;

	/*
	 * Release buffer lock before applying undo actions.
	 */
	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	process_and_execute_undo_actions_page(urec_ptr, rel, buffer, xid, slot_no);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
}

/*
 * zheap_insert - insert tuple into a zheap
 *
 * The functionality related to heap is quite similar to heap_insert,
 * additionaly this function inserts an undo record and updates the undo
 * pointer in page header or in TPD entry for this page.
 *
 * XXX - Visibility map and page is all visible checks are required to support
 * index-only scans on zheap.
 */
Oid
zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate)
{
	TransactionId xid = GetTopTransactionId();
	uint32	epoch = GetEpochForXid(xid);
	ZHeapTuple	zheaptup;
	UnpackedUndoRecord	undorecord;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	bool		all_visible_cleared = false;
	int			trans_slot_id;
	Page		page;
	UndoRecPtr	urecptr, prev_urecptr;
	xl_undolog_meta	undometa;
	bool		lock_reacquired;

	data_alignment_zheap = data_alignment;

	/*
	 * Assign an OID, and toast the tuple if necessary.
	 *
	 * Note: below this point, heaptup is the data we actually intend to store
	 * into the relation; tup is the caller's original untoasted data.
	 */
	zheaptup = zheap_prepare_insert(relation, tup, options);

reacquire_buffer:
	/*
	 * Find buffer to insert this tuple into.  If the page is all visible,
	 * this will also pin the requisite visibility map page.
	 */
	buffer = RelationGetBufferForTuple(relation, zheaptup->t_len,
									   InvalidBuffer, options, bistate,
									   &vmbuffer, NULL);
	page = BufferGetPage(buffer);

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer, epoch, xid,
											   &prev_urecptr, &lock_reacquired);
	if (lock_reacquired)
		goto reacquire_buffer;

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

	if (options & HEAP_INSERT_SPECULATIVE)
	{
		/* Mark the tuple as speculatively inserted tuple. */
		zheaptup->t_data->t_infomask |= ZHEAP_SPECULATIVE_INSERT;
	}

	/*
	 * See heap_insert to know why checking conflicts is important
	 * before actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	/* prepare an undo record */
	undorecord.uur_type = UNDO_INSERT;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_prevxid = xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
	undorecord.uur_tsid = relation->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = BufferGetBlockNumber(buffer);
	undorecord.uur_tuple.len = 0;

	/*
	 * Store the speculative insertion token in undo, so that we can retrieve
	 * it during visibility check of the speculatively inserted tuples.
	 *
	 * Note that we don't need to WAL log this value as this is a temporary
	 * information required only on master node to detect conflicts for
	 * Insert .. On Conflict.
	 */
	if (options & HEAP_INSERT_SPECULATIVE)
	{
		uint32 specToken;

		undorecord.uur_payload.len = sizeof(uint32);
		specToken = GetSpeculativeInsertionToken();
		initStringInfo(&undorecord.uur_payload);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &specToken,
							   sizeof(uint32));
	}
	else
		undorecord.uur_payload.len = 0;

	urecptr = PrepareUndoInsert(&undorecord,
								UndoPersistenceForRelation(relation),
								InvalidTransactionId,
								&undometa);

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, trans_slot_id);

	RelationPutZHeapTuple(relation, buffer, zheaptup);

	if (PageIsAllVisible(BufferGetPage(buffer)))
	{
		all_visible_cleared = true;
		PageClearAllVisible(BufferGetPage(buffer));
		visibilitymap_clear(relation,
							ItemPointerGetBlockNumber(&(zheaptup->t_self)),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	MarkBufferDirty(buffer);

	Assert(undorecord.uur_block == ItemPointerGetBlockNumber(&(zheaptup->t_self)));
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&(zheaptup->t_self));
	InsertPreparedUndo();
	PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);

	/* XLOG stuff */
	if (!(options & HEAP_INSERT_SKIP_WAL) && RelationNeedsWAL(relation))
	{
		xl_undo_header	xlundohdr;
		xl_zheap_insert xlrec;
		xl_zheap_header xlhdr;
		XLogRecPtr	recptr;
		Page		page = BufferGetPage(buffer);
		uint8		info = XLOG_ZHEAP_INSERT;
		int			bufflags = 0;
		XLogRecPtr	RedoRecPtr;
		bool		doPageWrites;

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

		/*
		 * Store the information required to generate undo record during
		 * replay.
		 */
		xlundohdr.relfilenode = undorecord.uur_relfilenode;
		xlundohdr.tsid = undorecord.uur_tsid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		/* Heap related part. */
		xlrec.offnum = ItemPointerGetOffsetNumber(&zheaptup->t_self);
		xlrec.flags = 0;

		/*
		 * Fixme - Below code is to support visibility maps and speculative
		 * insertion in future. We need to test this code once those features
		 * are supported and remove this comment.
		 */
		if (all_visible_cleared)
			xlrec.flags |= XLZ_INSERT_ALL_VISIBLE_CLEARED;
		if (options & HEAP_INSERT_SPECULATIVE)
			xlrec.flags |= XLZ_INSERT_IS_SPECULATIVE;
		Assert(ItemPointerGetBlockNumber(&zheaptup->t_self) == BufferGetBlockNumber(buffer));

		/*
		 * For logical decoding, we need the tuple even if we're doing a full
		 * page write, so make sure it's included even if we take a full-page
		 * image. (XXX We could alternatively store a pointer into the FPW).
		 *
		 * Fixme - Current zheap doesn't support logical decoding, once it is
		 * supported, we need to test and remove this Fixme.
		 */
		if (RelationIsLogicallyLogged(relation))
		{
			xlrec.flags |= XLZ_INSERT_CONTAINS_NEW_TUPLE;
			bufflags |= REGBUF_KEEP_DATA;
		}

prepare_xlog:
		/* LOG undolog meta if this is the first WAL after the checkpoint. */
		LogUndoMetaData(&undometa);

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
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

		recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr,
									doPageWrites);
		if (recptr == InvalidXLogRecPtr)
			goto prepare_xlog;

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	/* be tidy */
	if (undorecord.uur_payload.len > 0)
	{
		Assert(options & HEAP_INSERT_SPECULATIVE);
		pfree(undorecord.uur_payload.data);
	}

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
 *
 * XXX - Visibility map and page is all visible checks are required to support
 * index-only scans on zheap.
 */
HTSU_Result
zheap_delete(Relation relation, ItemPointer tid,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
			 HeapUpdateFailureData *hufd)
{
	HTSU_Result result;
	TransactionId xid = GetTopTransactionId();
	TransactionId	tup_xid, oldestXidHavingUndo;
	CommandId		tup_cid;
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
	uint32		epoch;
	int			tup_trans_slot_id,
				trans_slot_id,
				new_trans_slot_id;
	uint16		new_infomask;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		all_visible_cleared = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	xl_undolog_meta undometa;

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

	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If TID is already delete marked due to pruning, then get new ctid, so
	 * that we can delete the new tuple.  We will get new ctid if the tuple
	 * was non-inplace-updated otherwise we will get same TID.
	 */
	if (ItemIdIsDeleted(lp))
	{
		ctid = *tid;
		ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
		result = HeapTupleUpdated;
		goto zheap_tuple_updated;
	}

	zheaptup.t_tableOid = RelationGetRelid(relation);
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);
	zheaptup.t_self = *tid;

	ctid = *tid;

check_tup_satisfies_update:
	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(&zheaptup, cid, buffer,
									   &ctid, &tup_trans_slot_id,
									   &tup_xid, &tup_cid, false, false,
									   snapshot, &in_place_updated_or_locked);

	if (result == HeapTupleInvisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to delete invisible tuple")));
	}
	else if ((result == HeapTupleBeingUpdated ||
			 ((result == HeapTupleMayBeUpdated) &&
			  ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask))) &&
			  wait)
	{
		List	*mlmembers = NIL;
		TransactionId xwait;
		uint16	infomask;
		bool    isCommitted;
		bool	can_continue = false;

		lock_reacquired = false;
		xwait = tup_xid;
		infomask = zheaptup.t_data->t_infomask;

		/*
		 * Sleep until concurrent transaction ends -- except when there's a
		 * single locker and it's our own transaction.  Note we don't care
		 * which lock mode the locker has, because we need the strongest one.
		 *
		 * Before sleeping, we need to acquire tuple lock to establish our
		 * priority for the tuple (see zheap_lock_tuple).  LockTuple will
		 * release us when we are next-in-line for the tuple.
		 *
		 * If we are forced to "start over" below, we keep the tuple lock;
		 * this arranges that we stay at the head of the line while rechecking
		 * tuple state.
		 */
		if (ZHeapTupleHasMultiLockers(infomask))
		{
			LockTupleMode	old_lock_mode;
			TransactionId	update_xact;
			bool			upd_xact_aborted;

			old_lock_mode = get_old_lock_mode(infomask);

			/*
			 * For aborted updates, we must allow to reverify the tuple in
			 * case it's values got changed.  See the similar handling in
			 * zheap_update.
			 */
			if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup.t_data->t_infomask))
				ZHeapTupleGetTransInfo(&zheaptup, buffer, NULL, NULL, &update_xact,
									   NULL, NULL, false);
			else
				update_xact = InvalidTransactionId;

			if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
								HWLOCKMODE_from_locktupmode(LockTupleExclusive)))
			{
				/*
				 * There is a potential conflict.  It is quite possible
				 * that by this time the locker has already been committed.
				 * So we need to check for conflict with all the possible
				 * lockers and wait for each of them after releasing a
				 * buffer lock and acquiring a lock on a tuple.
				 */
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
				heap_acquire_tuplock(relation, &(zheaptup.t_self), LockTupleExclusive,
									 LockWaitBlock, &have_tuple_lock);
				mlmembers = ZGetMultiLockMembers(&zheaptup, buffer, true);
				ZMultiLockMembersWait(relation, mlmembers, &zheaptup, buffer,
									  update_xact, LockTupleExclusive, false,
									  XLTW_Delete, NULL, &upd_xact_aborted);
				LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

				/*
				 * If the aborted xact is for update, then we need to reverify
				 * the tuple.
				 */
				if (upd_xact_aborted)
					goto check_tup_satisfies_update;
				lock_reacquired = true;

				/*
				 * There was no UPDATE in the Multilockers. No
				 * TransactionIdIsInProgress() call needed here, since we called
				 * ZMultiLockMembersWait() above.
				 */
				if (!TransactionIdIsValid(update_xact))
					can_continue = true;
			}
		}
		else if (!TransactionIdIsCurrentTransactionId(xwait))
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
			lock_reacquired = true;
		}

		if (lock_reacquired)
		{
			/*
			 * By the time, we require the lock on buffer, some other xact
			 * could have updated this tuple.  We need take care of the cases
			 * when page is pruned after we release the buffer lock. For this,
			 * we check if ItemId is not deleted and refresh the tuple offset
			 * position in page.  If TID is already delete marked due to
			 * pruning, then get new ctid, so that we can update the new
			 * tuple.
			 *
			 * We also need to ensure that no new lockers have been added in
			 * the meantime, if there is any new locker, then start again.
			 */
			if (ItemIdIsDeleted(lp))
			{
				ctid = *tid;
				ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
				result = HeapTupleUpdated;
				goto zheap_tuple_updated;
			}

			zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			zheaptup.t_len = ItemIdGetLength(lp);

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				List	*new_mlmembers;
				new_mlmembers = ZGetMultiLockMembers(&zheaptup, buffer, false);

				/*
				 * Ensure, no new lockers have been added, if so, then start
				 * again.
				 */
				if (!ZMultiLockMembersSame(mlmembers, new_mlmembers))
				{
					list_free_deep(mlmembers);
					list_free_deep(new_mlmembers);
					goto check_tup_satisfies_update;
				}

				any_multi_locker_member_alive =
					ZIsAnyMultiLockMemberRunning(new_mlmembers, &zheaptup,
												 buffer);
				list_free_deep(mlmembers);
				list_free_deep(new_mlmembers);
			}

			/*
			 * xwait is done, but if xwait had just locked the tuple then some
			 * other xact could update this tuple before we get to this point.
			 * Check for xid change, and start over if so.
			 */
			if (xid_infomask_changed(zheaptup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zheaptup.t_data, opaque),
									  xwait))
				goto check_tup_satisfies_update;

			/* Aborts of multi-lockers are already dealt above. */
			if(!ZHeapTupleHasMultiLockers(infomask))
			{
				bool	has_update = false;

				if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup.t_data->t_infomask))
					has_update = true;

				isCommitted = TransactionIdDidCommit(xwait);

				/*
				 * For aborted transaction, if the undo actions are not applied
				 * yet, then apply them before modifying the page.
				 */
				if (!isCommitted &&
					opaque->transinfo[tup_trans_slot_id].xid == xwait)
					zheap_exec_pending_rollback(relation, buffer,
												tup_trans_slot_id);

				/*
				 * For aborted updates, we must allow to reverify the tuple in
				 * case it's values got changed.
				 */
				if (!isCommitted && has_update)
					goto check_tup_satisfies_update;

				if (!has_update)
					can_continue = true;
			}
		}
		else
		{
			/*
			 * We can proceed with the delete, when there's a single locker
			 * and it's our own transaction.
			 */
			if (ZHEAP_XID_IS_LOCKED_ONLY(zheaptup.t_data->t_infomask))
				can_continue = true;
		}

		/*
		 * We may overwrite if previous xid is aborted or committed, but only
		 * locked the tuple without updating it.
		 */
		if (result != HeapTupleMayBeUpdated)
			result = can_continue ? HeapTupleMayBeUpdated : HeapTupleUpdated;
	}

	if (crosscheck != InvalidSnapshot && result == HeapTupleMayBeUpdated)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleSatisfiesVisibility(&zheaptup, crosscheck, buffer, NULL))
			result = HeapTupleUpdated;
	}

zheap_tuple_updated:
	if (result != HeapTupleMayBeUpdated)
	{
		Assert(result == HeapTupleSelfUpdated ||
			   result == HeapTupleUpdated ||
			   result == HeapTupleBeingUpdated);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(zheaptup.t_data->t_infomask));

		hufd->ctid = ctid;
		hufd->xmax = tup_xid;
		if (result == HeapTupleSelfUpdated)
			hufd->cmax = tup_cid;
		else
			hufd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		hufd->in_place_updated_or_locked = in_place_updated_or_locked;
		if (have_tuple_lock)
			UnlockTupleTuplock(relation, &(zheaptup.t_self), LockTupleExclusive);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		return result;
	}

	epoch = GetEpochForXid(xid);

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer, epoch, xid,
											   &prev_urecptr, &lock_reacquired);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * Also take care of cases when page is pruned after we release the
		 * buffer lock. For this we check if ItemId is not deleted and refresh
		 * the tuple offset position in page.  If TID is already delete marked
		 * due to pruning, then get new ctid, so that we can delete the new
		 * tuple.
		 */
		if (ItemIdIsDeleted(lp))
		{
			ctid = *tid;
			ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
			result = HeapTupleUpdated;
			goto zheap_tuple_updated;
		}

		zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zheaptup.t_len = ItemIdGetLength(lp);
		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&zheaptup, buffer, tup_xid, tup_trans_slot_id,
							 zheaptup.t_data->t_infomask, xid, trans_slot_id,
							 LockTupleExclusive, true, &new_infomask,
							 &new_trans_slot_id);
	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(new_trans_slot_id == trans_slot_id);

	/*
	 * If all the members were lockers and are all gone, we can do away
	 * with the MULTI_LOCKERS bit.
	 */
	if (ZHeapTupleHasMultiLockers(new_infomask) &&
		!any_multi_locker_member_alive)
		new_infomask &= ~ZHEAP_MULTI_LOCKERS;

	/*
	 * If the last transaction that has updated the tuple is already too
	 * old, then consider it as frozen which means it is all-visible.  This
	 * ensures that we don't need to store epoch in the undo record to check
	 * if the undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file ztqual.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(tup_xid, oldestXidHavingUndo))
		tup_xid = FrozenTransactionId;

	/*
	 * Fixme: Api's for serializable isolation level that take zheaptuple as
	 * input needs to be written.
	 */
	/* CheckForSerializableConflictIn(relation, &tp, buffer); */

	/*
	 * Prepare an undo record.  We need to separately store the latest
	 * transaction id that has changed the tuple to ensure that we don't
	 * try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */
	undorecord.uur_type = UNDO_DELETE;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
	undorecord.uur_tsid = relation->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = offnum;
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	/*
	 * Copy the entire old tuple including it's header in the undo record.
	 * We need this to reconstruct the tuple if current tuple is not
	 * visible to some other transaction.  We choose to write the complete
	 * tuple in undo record for delete operation so that we can reuse the
	 * space after the transaction performing the operation commits.
	 */
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_len,
						   sizeof(uint32));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_self,
						   sizeof(ItemPointerData));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) &zheaptup.t_tableOid,
						   sizeof(Oid));
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) zheaptup.t_data,
						   zheaptup.t_len);

	urecptr = PrepareUndoInsert(&undorecord,
								UndoPersistenceForRelation(relation),
								InvalidTransactionId,
								&undometa);

	START_CRIT_SECTION();

	if (PageIsAllVisible(page))
	{
		all_visible_cleared = true;
		PageClearAllVisible(page);
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	InsertPreparedUndo();
	PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);

	/*
	 * If this transaction commits, the tuple will become DEAD sooner or
	 * later.  If the transaction finally aborts, the subsequent page pruning
	 * will be a no-op and the hint will be cleared.
	 */
	ZPageSetPrunable(page, xid);

	ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, new_trans_slot_id);
	zheaptup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	zheaptup.t_data->t_infomask |= ZHEAP_DELETED | new_infomask;

	MarkBufferDirty(buffer);

	/*
	 * Do xlog stuff
	 */
	if (RelationNeedsWAL(relation))
	{
		ZHeapTupleHeader	zhtuphdr = NULL;
		xl_undo_header	xlundohdr;
		xl_zheap_delete xlrec;
		xl_zheap_header	xlhdr;
		XLogRecPtr	recptr;
		XLogRecPtr	RedoRecPtr;
		uint32		totalundotuplen = 0;
		Size		dataoff;
		bool		doPageWrites;

		/*
		 * Store the information required to generate undo record during
		 * replay.
		 */
		xlundohdr.relfilenode = undorecord.uur_relfilenode;
		xlundohdr.tsid = undorecord.uur_tsid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xlrec.prevxid = tup_xid;
		xlrec.offnum = ItemPointerGetOffsetNumber(&zheaptup.t_self);
		xlrec.infomask = zheaptup.t_data->t_infomask;
		xlrec.trans_slot_id = ZHeapTupleHeaderGetXactSlot(zheaptup.t_data);
		xlrec.flags = all_visible_cleared ? XLZ_DELETE_ALL_VISIBLE_CLEARED : 0;

		/*
		 * If full_page_writes is enabled, and the buffer image is not
		 * included in the WAL then we can rely on the tuple in the page to
		 * regenerate the undo tuple during recovery as the tuple state must
		 * be same as now, otherwise we need to store it explicitly.
		 *
		 * Since we don't yet have the insert lock, including the page
		 * image decision could change later and in that case we need prepare
		 * the WAL record again.
		 */
prepare_xlog:
		/* LOG undolog meta if this is the first WAL after the checkpoint. */
		LogUndoMetaData(&undometa);

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
		if (!doPageWrites || XLogCheckBufferNeedsBackup(buffer))
		{
			xlrec.flags |= XLZ_HAS_DELETE_UNDOTUPLE;

			totalundotuplen = *((uint32 *) &undorecord.uur_tuple.data[0]);
			dataoff = sizeof(uint32) + sizeof(ItemPointerData) + sizeof(Oid);
			zhtuphdr = (ZHeapTupleHeader) &undorecord.uur_tuple.data[dataoff];

			xlhdr.t_infomask2 = zhtuphdr->t_infomask2;
			xlhdr.t_infomask = zhtuphdr->t_infomask;
			xlhdr.t_hoff = zhtuphdr->t_hoff;
		}

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xlrec, SizeOfZHeapDelete);
		if (xlrec.flags & XLZ_HAS_DELETE_UNDOTUPLE)
		{
			XLogRegisterData((char *) &xlhdr, SizeOfZHeapHeader);
			/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
			XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
							totalundotuplen - SizeofZHeapTupleHeader);
		}

		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		/* filtering by origin on a row level is much more efficient */
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

		recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_DELETE,
									RedoRecPtr, doPageWrites);
		if (recptr == InvalidXLogRecPtr)
			goto prepare_xlog;
		PageSetLSN(page, recptr);
	}

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

	/*
	 * Release the lmgr tuple lock, if we had it.
	 */
	if (have_tuple_lock)
		UnlockTupleTuplock(relation, &(zheaptup.t_self), LockTupleExclusive);

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
 * XXX - Visibility map and page is all visible needs to be maintained for
 * index-only scans on zheap.
 *
 * For input and output values, see heap_update.
 */
HTSU_Result
zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
			 HeapUpdateFailureData *hufd, LockTupleMode *lockmode)
{
	HTSU_Result result;
	TransactionId xid = GetTopTransactionId();
	TransactionId tup_xid, save_tup_xid, oldestXidHavingUndo;
	CommandId	tup_cid;
	Bitmapset  *inplace_upd_attrs = NULL;
	Bitmapset  *key_attrs = NULL;
	Bitmapset  *interesting_attrs = NULL;
	Bitmapset  *modified_attrs = NULL;
	ItemId		lp;
	ZHeapTupleData oldtup;
	ZHeapPageOpaque	opaque;
	UndoRecPtr	urecptr, prev_urecptr, new_prev_urecptr;
	UndoRecPtr	new_urecptr = InvalidUndoRecPtr;
	UnpackedUndoRecord	undorecord, new_undorecord;
	Page		page;
	BlockNumber block;
	ItemPointerData	ctid;
	Buffer		buffer,
				newbuf,
				vmbuffer = InvalidBuffer,
				vmbuffer_new = InvalidBuffer;
	Size		newtupsize,
				pagefree;
	uint32		epoch;
	int			tup_trans_slot_id,
				trans_slot_id,
				new_trans_slot_id,
				result_trans_slot_id;
	uint16		old_infomask;
	uint16		new_infomask;
	uint16		infomask_old_tuple = 0;
	uint16		infomask_new_tuple = 0;
	bool		all_visible_cleared = false;
	bool		new_all_visible_cleared = false;
	bool		have_tuple_lock = false;
	bool		is_index_updated = false;
	bool		use_inplace_update = false;
	bool		in_place_updated_or_locked = false;
	bool		key_intact = false;
	bool		checked_lockers = false;
	bool		locker_remains = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	xl_undolog_meta	undometa;

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

	data_alignment_zheap = data_alignment;

	/*
	 * Fetch the list of attributes to be checked for various operations.
	 *
	 * For in-place update considerations, this is wasted effort if we fail to
	 * update or have to put the new tuple on a different page.  But we must
	 * compute the list before obtaining buffer lock --- in the worst case, if
	 * we are doing an update on one of the relevant system catalogs, we could
	 * deadlock if we try to fetch the list later.  Note, that as of now
	 * system catalogs are always stored in heap, so we might not hit the
	 * deadlock case, but it can be supported in future.  In any case, the
	 * relcache caches the data so this is usually pretty cheap.
	 *
	 * Note that we get a copy here, so we need not worry about relcache flush
	 * happening midway through.
	 */
	inplace_upd_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_HOT);
	key_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_KEY);

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
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If TID is already delete marked due to pruning, then get new ctid, so
	 * that we can update the new tuple.  We will get new ctid if the tuple
	 * was non-inplace-updated otherwise we will get same TID.
	 */
	if (ItemIdIsDeleted(lp))
	{
		ctid = *otid;
		ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
		result = HeapTupleUpdated;
		goto zheap_tuple_updated;
	}

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
		ZHeapTupleSetOid(newtup, ZHeapTupleGetOid(&oldtup));
	}
	else
	{
		/* check there is not space for an OID */
		Assert(!(newtup->t_data->t_infomask & ZHEAP_HASOID));
	}

	interesting_attrs = bms_add_members(interesting_attrs, inplace_upd_attrs);
	interesting_attrs = bms_add_members(interesting_attrs, key_attrs);

	/* Determine columns modified by the update. */
	modified_attrs = ZHeapDetermineModifiedColumns(relation, interesting_attrs,
												   &oldtup, newtup);

	is_index_updated = bms_overlap(modified_attrs, inplace_upd_attrs);

	/*
	 * inplace updates can be done only if the length of new tuple is lesser
	 * than or equal to old tuple and there are no index column updates.
	 */
	if ((newtup->t_len <= oldtup.t_len) && !is_index_updated)
		use_inplace_update = true;
	else
		use_inplace_update = false;

	/*
	 * Similar to heap, if we're not updating any "key" column, we can grab a
	 * weaker lock type.  See heap_update.
	 */
	if (!bms_overlap(modified_attrs, key_attrs))
	{
		*lockmode = LockTupleNoKeyExclusive;
		key_intact = true;
	}
	else
	{
		*lockmode = LockTupleExclusive;
		key_intact = false;
	}

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
	checked_lockers = false;
	locker_remains = false;
	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(&oldtup, cid, buffer, &ctid,
									   &tup_trans_slot_id, &tup_xid,
									   &tup_cid, false, false, snapshot,
									   &in_place_updated_or_locked);

	if (result == HeapTupleInvisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to update invisible tuple")));
	}
	else if ((result == HeapTupleBeingUpdated ||
			 ((result == HeapTupleMayBeUpdated) &&
			  ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask))) &&
			  wait)
	{
		List	*mlmembers;
		TransactionId xwait;
		uint16		infomask;
		bool		can_continue = false;

		/* must copy state data before unlocking buffer */
		xwait = tup_xid;
		infomask = oldtup.t_data->t_infomask;

		if (ZHeapTupleHasMultiLockers(infomask))
		{
			TransactionId update_xact;
			LockTupleMode	old_lock_mode;
			int			remain;
			bool		isAborted;
			bool		upd_xact_aborted;

			old_lock_mode = get_old_lock_mode(infomask);

			/*
			 * For the conflicting lockers, we need to be careful about
			 * applying pending undo actions for aborted transactions; if we
			 * leave any transaction whether locker or updater, it can lead to
			 * inconsistency.  Basically, in such a case after waiting for all
			 * the conflicting transactions we might clear the multilocker
			 * flag and proceed with update and it is quite possible that after
			 * the update, undo worker rollbacks some of the previous locker
			 * which can overwrite the tuple (Note, till multilocker bit is set,
			 * the rollback actions won't overwrite the tuple).
			 *
			 * OTOH for non-conflicting lockers, as we don't clear the
			 * multi-locker flag, there is no urgency to perform undo actions
			 * for aborts of lockers.  The work involved in finding and
			 * aborting lockers is non-trivial (w.r.t performance), so it is
			 * better to avoid it.
			 *
			 * After abort, if it is only a locker, then it will be completely
			 * gone; but if it is an update, then after applying pending
			 * actions, the tuple might get changed and we must allow to
			 * reverify the tuple in case it's values got changed.
			 */
			if (!ZHEAP_XID_IS_LOCKED_ONLY(oldtup.t_data->t_infomask))
				ZHeapTupleGetTransInfo(&oldtup, buffer, NULL, NULL, &update_xact,
									   NULL, NULL, false);
			else
				update_xact = InvalidTransactionId;

			if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
									HWLOCKMODE_from_locktupmode(*lockmode)))
			{
				/*
				 * There is a potential conflict.  It is quite possible
				 * that by this time the locker has already been committed.
				 * So we need to check for conflict with all the possible
				 * lockers and wait for each of them after releasing a
				 * buffer lock and acquiring a lock on a tuple.
				 */
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
				heap_acquire_tuplock(relation, &(oldtup.t_self), *lockmode,
									 LockWaitBlock, &have_tuple_lock);
				mlmembers = ZGetMultiLockMembers(&oldtup, buffer, true);
				ZMultiLockMembersWait(relation, mlmembers, &oldtup, buffer,
									  update_xact, *lockmode, false,
									  XLTW_Update, &remain,
									  &upd_xact_aborted);
				checked_lockers = true;
				locker_remains = remain != 0;
				LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

				/*
				 * If the aborted xact is for update, then we need to reverify
				 * the tuple.
				 */
				if (upd_xact_aborted)
					goto check_tup_satisfies_update;

				/*
				 * Also take care of cases when page is pruned after we
				 * release the buffer lock. For this we check if ItemId is not
				 * deleted and refresh the tuple offset position in page.  If
				 * TID is already delete marked due to pruning, then get new
				 * ctid, so that we can update the new tuple.
				 *
				 * We also need to ensure that no new lockers have been added
				 * in the meantime, if there is any new locker, then start
				 * again.
				 */
				if (ItemIdIsDeleted(lp))
				{
					ctid = *otid;
					ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
					result = HeapTupleUpdated;
					goto zheap_tuple_updated;
				}

				oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
				oldtup.t_len = ItemIdGetLength(lp);

				if (ZHeapTupleHasMultiLockers(infomask))
				{
					List	*new_mlmembers;
					new_mlmembers = ZGetMultiLockMembers(&oldtup, buffer, false);

					/*
					 * Ensure, no new lockers have been added, if so, then start
					 * again.
					 */
					if (!ZMultiLockMembersSame(mlmembers, new_mlmembers))
					{
						list_free_deep(mlmembers);
						list_free_deep(new_mlmembers);
						goto check_tup_satisfies_update;
					}

					any_multi_locker_member_alive =
						ZIsAnyMultiLockMemberRunning(new_mlmembers, &oldtup,
													 buffer);
					list_free_deep(mlmembers);
					list_free_deep(new_mlmembers);
				}

				/*
				 * xwait is done, but if xwait had just locked the tuple then some
				 * other xact could update this tuple before we get to this point.
				 * Check for xid change, and start over if so.
				 */
				if (xid_infomask_changed(oldtup.t_data->t_infomask, infomask) ||
					!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(oldtup.t_data, opaque),
										 xwait))
					goto check_tup_satisfies_update;
			}
			else if (TransactionIdIsValid(update_xact))
			{
				isAborted = TransactionIdDidAbort(update_xact);

				/*
				 * For aborted transaction, if the undo actions are not applied
				 * yet, then apply them before modifying the page.
				 */
				if (isAborted && opaque->transinfo[tup_trans_slot_id].xid == xwait)
				{
					zheap_exec_pending_rollback(relation, buffer,
												tup_trans_slot_id);
					goto check_tup_satisfies_update;
				}
			}

			/*
			 * There was no UPDATE in the Multilockers. No
			 * TransactionIdIsInProgress() call needed here, since we called
			 * ZMultiLockMembersWait() above.
			 */
			if (!TransactionIdIsValid(update_xact))
				can_continue = true;
		}
		else if (TransactionIdIsCurrentTransactionId(xwait))
		{
			/*
			 * The only locker is ourselves; we can avoid grabbing the tuple
			 * lock here, but must preserve our locking information.
			 */
			checked_lockers = true;
			locker_remains = true;
			can_continue = true;
		}
		else if (ZHEAP_XID_IS_KEYSHR_LOCKED(infomask) && key_intact)
		{
			/*
			 * If it's just a key-share locker, and we're not changing the key
			 * columns, we don't need to wait for it to end; but we need to
			 * preserve it as locker.
			 */
			checked_lockers = true;
			locker_remains = true;
			can_continue = true;
		}
		else
		{
			bool	isCommitted;
			bool	has_update = false;

			/*
			 * Wait for regular transaction to end; but first, acquire tuple
			 * lock.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			heap_acquire_tuplock(relation, &(oldtup.t_self), *lockmode,
								 LockWaitBlock, &have_tuple_lock);
			XactLockTableWait(xwait, relation, &oldtup.t_self,
							  XLTW_Update);
			checked_lockers = true;
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * Also take care of cases when page is pruned after we release the
			 * buffer lock. For this we check if ItemId is not deleted and refresh
			 * the tuple offset position in page.  If TID is already delete marked
			 * due to pruning, then get new ctid, so that we can update the new
			 * tuple.
			 */
			if (ItemIdIsDeleted(lp))
			{
				ctid = *otid;
				ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
				result = HeapTupleUpdated;
				goto zheap_tuple_updated;
			}

			oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			oldtup.t_len = ItemIdGetLength(lp);

			/*
			 * xwait is done, but if xwait had just locked the tuple then some
			 * other xact could update this tuple before we get to this point.
			 * Check for xid change, and start over if so.
			 */
			if (xid_infomask_changed(oldtup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(oldtup.t_data, opaque),
									 xwait))
				goto check_tup_satisfies_update;

			if (!ZHEAP_XID_IS_LOCKED_ONLY(oldtup.t_data->t_infomask))
				has_update = true;

			/*
			 * We may overwrite if previous xid is aborted, or if it is committed
			 * but only locked the tuple without updating it.
			 */
			isCommitted = TransactionIdDidCommit(xwait);

			/*
			 * For aborted transaction, if the undo actions are not applied
			 * yet, then apply them before modifying the page.
			 */
			if (!isCommitted &&
				opaque->transinfo[tup_trans_slot_id].xid == xwait)
				zheap_exec_pending_rollback(relation, buffer,
											tup_trans_slot_id);

			/*
			 * For aborted updates, we must allow to reverify the tuple in
			 * case it's values got changed.
			 */
			if (!isCommitted && has_update)
				goto check_tup_satisfies_update;

			if (!has_update)
				can_continue = true;
		}

		/*
		 * We may overwrite if previous xid is aborted or committed, but only
		 * locked the tuple without updating it.
		 */
		if (result != HeapTupleMayBeUpdated)
			result = can_continue ? HeapTupleMayBeUpdated : HeapTupleUpdated;
	}
	else if (result == HeapTupleMayBeUpdated)
	{
		/*
		 * There is no active locker on the tuple, so we avoid grabbing
		 * the lock on new tuple.
		 */
		checked_lockers = true;
		locker_remains = false;
	}

	if (crosscheck != InvalidSnapshot && result == HeapTupleMayBeUpdated)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleSatisfiesVisibility(&oldtup, crosscheck, buffer, NULL))
			result = HeapTupleUpdated;
	}

zheap_tuple_updated:
	if (result != HeapTupleMayBeUpdated)
	{
		Assert(result == HeapTupleSelfUpdated ||
			   result == HeapTupleUpdated ||
			   result == HeapTupleBeingUpdated);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(oldtup.t_data->t_infomask));

		hufd->ctid = ctid;
		hufd->xmax = tup_xid;
		if (result == HeapTupleSelfUpdated)
			hufd->cmax = tup_cid;
		else
			hufd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		hufd->in_place_updated_or_locked = in_place_updated_or_locked;
		if (have_tuple_lock)
			UnlockTupleTuplock(relation, &(oldtup.t_self), *lockmode);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		bms_free(inplace_upd_attrs);
		bms_free(key_attrs);
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

		/*
		 * Also take care of cases when page is pruned after we release the
		 * buffer lock. For this we check if ItemId is not deleted and refresh
		 * the tuple offset position in page.  If TID is already delete marked
		 * due to pruning, then get new ctid, so that we can update the new
		 * tuple.
		 */
		if (ItemIdIsDeleted(lp))
		{
			ctid = *otid;
			ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
			result = HeapTupleUpdated;
			goto zheap_tuple_updated;
		}

		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		oldtup.t_len = ItemIdGetLength(lp);
		goto check_tup_satisfies_update;
	}

	epoch = GetEpochForXid(xid);

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer, epoch, xid,
											   &prev_urecptr, &lock_reacquired);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * Also take care of cases when page is pruned after we release the
		 * buffer lock. For this we check if ItemId is not deleted and refresh
		 * the tuple offset position in page.  If TID is already delete marked
		 * due to pruning, then get new ctid, so that we can update the new
		 * tuple.
		 */
		if (ItemIdIsDeleted(lp))
		{
			ctid = *otid;
			ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
			result = HeapTupleUpdated;
			goto zheap_tuple_updated;
		}

		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		oldtup.t_len = ItemIdGetLength(lp);

		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	/*
	 * Save the xid that has updated the tuple to compute infomask for
	 * tuple.
	 */
	save_tup_xid = tup_xid;

	/*
	 * If the last transaction that has updated the tuple is already too
	 * old, then consider it as frozen which means it is all-visible.  This
	 * ensures that we don't need to store epoch in the undo record to check
	 * if the undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file ztqual.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(tup_xid, oldestXidHavingUndo))
	{
		tup_xid = FrozenTransactionId;
	}

	pagefree = PageGetZHeapFreeSpace(page);

	if (data_alignment_zheap == 0)
		newtupsize = newtup->t_len;	/* no alignment */
	else if (data_alignment_zheap == 4)
		newtupsize = INTALIGN(newtup->t_len);	/* four byte alignment */
	else
		newtupsize = MAXALIGN(newtup->t_len);

	/*
	 * If it is a non inplace update then check we have sufficient free space
	 * to insert in same page. If not try defragmentation and recheck the
	 * freespace again.
	 */
	if (!use_inplace_update && newtupsize > pagefree)
	{
		zheap_page_prune_opt(relation, buffer);
		pagefree = PageGetZHeapFreeSpace(page);
		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	}

	/*
	 * In one special case if we are updating the last tuple of page,
	 * we can combine free space immediately next to that tuple with
	 * the original tuple space and try to do inplace update there!
	 */
	if (!use_inplace_update &&
		ItemIdGetOffset(lp) == ((PageHeader) page)->pd_upper &&
		(pagefree + oldtup.t_len) >= newtupsize &&
		!is_index_updated)
		use_inplace_update = true;

	/* updated tuple doesn't fit on current page */
	if (!use_inplace_update && newtupsize > pagefree)
	{
		uint16	lock_old_infomask;

		/*
		 * To prevent concurrent sessions from updating the tuple, we have to
		 * temporarily mark it locked, while we release the lock.
		 */
		undorecord.uur_info = 0;
		undorecord.uur_prevlen = 0;
		undorecord.uur_relfilenode = relation->rd_node.relNode;
		undorecord.uur_prevxid = tup_xid;
		undorecord.uur_xid = xid;
		undorecord.uur_cid = cid;
		undorecord.uur_tsid = relation->rd_node.spcNode;
		undorecord.uur_fork = MAIN_FORKNUM;
		undorecord.uur_blkprev = prev_urecptr;
		undorecord.uur_block = ItemPointerGetBlockNumber(&(oldtup.t_self));
		undorecord.uur_offset = ItemPointerGetOffsetNumber(&(oldtup.t_self));
		undorecord.uur_payload.len = 0;

		initStringInfo(&undorecord.uur_tuple);

		/*
		 * Here, we are storing old tuple header which is required to
		 * reconstruct the old copy of tuple.
		 */
		appendBinaryStringInfo(&undorecord.uur_tuple,
							   (char *) oldtup.t_data,
							   SizeofZHeapTupleHeader);

		urecptr = PrepareUndoInsert(&undorecord,
									UndoPersistenceForRelation(relation),
									InvalidTransactionId,
									&undometa);

		/* Compute the new xid and infomask to store into the tuple. */
		compute_new_xid_infomask(&oldtup, buffer, save_tup_xid,
								 tup_trans_slot_id, oldtup.t_data->t_infomask,
								 xid, trans_slot_id, *lockmode, false,
								 &lock_old_infomask, &result_trans_slot_id);
		/*
		 * There must not be any stronger locker than the current operation,
		 * otherwise it would have waited for it to finish.
		 */
		Assert(result_trans_slot_id == trans_slot_id);

		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */
		if (ZHeapTupleHasMultiLockers(lock_old_infomask) &&
			!any_multi_locker_member_alive)
			lock_old_infomask &= ~ZHEAP_MULTI_LOCKERS;

		if (ZHeapTupleHasMultiLockers(lock_old_infomask))
			undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
		else
			undorecord.uur_type = UNDO_XID_LOCK_ONLY;

		START_CRIT_SECTION();

		InsertPreparedUndo();
		PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);

		ZHeapTupleHeaderSetXactSlot(oldtup.t_data, result_trans_slot_id);

		oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		oldtup.t_data->t_infomask |= lock_old_infomask;
		
		/* Set prev_urecptr to the latest undo record in the slot. */
		prev_urecptr = urecptr;

		MarkBufferDirty(buffer);

		/*
		 * Do xlog stuff
		 */
		if (RelationNeedsWAL(relation))
		{
			xl_zheap_lock	xlrec;
			xl_undo_header  xlundohdr;
			XLogRecPtr      recptr;
			XLogRecPtr		RedoRecPtr;
			bool			doPageWrites;

			/*
			 * Store the information required to generate undo record during
			 * replay.
			 */
			xlundohdr.relfilenode = undorecord.uur_relfilenode;
			xlundohdr.tsid = undorecord.uur_tsid;
			xlundohdr.urec_ptr = urecptr;
			xlundohdr.blkprev = undorecord.uur_blkprev;

			xlrec.prev_xid = tup_xid;
			xlrec.offnum = ItemPointerGetOffsetNumber(&(oldtup.t_self));
			xlrec.infomask = oldtup.t_data->t_infomask;
			xlrec.trans_slot_id = trans_slot_id;

prepare_xlog:
			/* LOG undolog meta if this is the first WAL after the checkpoint. */
			LogUndoMetaData(&undometa);

			GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

			XLogBeginInsert();
			XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);
			XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
			XLogRegisterData((char *) &xlrec, SizeOfZHeapLock);

			/*
			 * We always include old tuple header for undo in WAL record
			 * irrespective of full page image is taken or not. This is done
			 * since savings for not including a zheap tuple header are less
			 * compared to code complexity. However in future, if required we
			 * can do it similar to what we have done in zheap_update or
			 * zheap_delete.
			 */
			XLogRegisterData((char *) undorecord.uur_tuple.data,
							 SizeofZHeapTupleHeader);

			recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_LOCK, RedoRecPtr,
										doPageWrites);
			if (recptr == InvalidXLogRecPtr)
				goto prepare_xlog;

			PageSetLSN(page, recptr);
		}
		END_CRIT_SECTION();

		pfree(undorecord.uur_tuple.data);

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		UnlockReleaseUndoBuffers();

		/* update the value of xid that has last updated the tuple */
		tup_xid = xid;

reacquire_buffer:
		/*
		 * Get a new page for inserting tuple.  We will need to acquire buffer
		 * locks on both old and new pages.  See heap_update.
		 */
		newbuf = RelationGetBufferForTuple(relation, newtup->t_len,
										   buffer, 0, NULL,
										   &vmbuffer_new, &vmbuffer);

		/* reserve the transaction slot on a new page */
		new_trans_slot_id = PageReserveTransactionSlot(relation,
													   newbuf,
													   epoch,
													   xid,
													   &new_prev_urecptr,
													   &lock_reacquired);
		if (lock_reacquired)
			goto reacquire_buffer;

		if (new_trans_slot_id == InvalidXactSlotId)
		{
			/* release the new bufeer and lock on old buffer */
			UnlockReleaseBuffer(newbuf);
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

			pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
			pg_usleep(10000L);	/* 10 ms */
			pgstat_report_wait_end();

			goto reacquire_buffer;
		}
	}
	else
	{
		newbuf = buffer;
		new_trans_slot_id = trans_slot_id;
	}

	/*
	 * Fixme: Api's for serializable isolation level that take zheaptuple as
	 * input needs to be written.
	 */
	/* CheckForSerializableConflictIn(relation, &oldtup, buffer); */

	/*
	 * Prepare an undo record for old tuple.  We need to separately store the
	 * latest transaction id that has changed the tuple to ensure that we
	 * don't try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = relation->rd_node.relNode;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
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
	 * visible to some other transaction.  We choose to write the complete
	 * tuple in undo record for update operation so that we can reuse the
	 * space of old tuples for non-inplace-updates after the transaction
	 * performing the operation commits.
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

	if (use_inplace_update)
	{
		undorecord.uur_type = UNDO_INPLACE_UPDATE;
		urecptr = PrepareUndoInsert(&undorecord,
									UndoPersistenceForRelation(relation),
									InvalidTransactionId,
									&undometa);
	}
	else
	{
		undorecord.uur_type = UNDO_UPDATE;

		/*
		 * we need to initialize the length of payload before actually knowing
		 * the value to ensure that the required space is reserved in undo.
		 */
		undorecord.uur_payload.len = sizeof(ItemPointerData);
		urecptr = PrepareUndoInsert(&undorecord,
									UndoPersistenceForRelation(relation),
									InvalidTransactionId,
									&undometa);

		initStringInfo(&undorecord.uur_payload);
		/* Make more room for tuple location if needed */
		enlargeStringInfo(&undorecord.uur_payload, sizeof(ItemPointerData));

		if (buffer == newbuf)
			prev_urecptr = urecptr;
		else
			prev_urecptr = new_prev_urecptr;

		/* prepare an undo record for new tuple */
		new_undorecord.uur_type = UNDO_INSERT;
		new_undorecord.uur_info = 0;
		new_undorecord.uur_prevlen = 0;
		new_undorecord.uur_relfilenode = relation->rd_node.relNode;
		new_undorecord.uur_prevxid = xid;
		new_undorecord.uur_xid = xid;
		new_undorecord.uur_cid = cid;
		new_undorecord.uur_tsid = relation->rd_node.spcNode;
		new_undorecord.uur_fork = MAIN_FORKNUM;
		new_undorecord.uur_blkprev = prev_urecptr;
		new_undorecord.uur_block = BufferGetBlockNumber(newbuf);
		new_undorecord.uur_payload.len = 0;
		new_undorecord.uur_tuple.len = 0;

		new_urecptr = PrepareUndoInsert(&new_undorecord,
										UndoPersistenceForRelation(relation),
										InvalidTransactionId,
										NULL);
	}

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&oldtup, buffer, save_tup_xid, tup_trans_slot_id,
							 oldtup.t_data->t_infomask, xid, trans_slot_id,
							 *lockmode, true, &old_infomask,
							 &result_trans_slot_id);

	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(result_trans_slot_id == trans_slot_id);

	/*
	 * We can't rely on any_multi_locker_member_alive to clear the multi locker
	 * bit, if the the lock on the buffer is released inbetween.
	 */
	if (buffer == newbuf)
	{
		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */
		if (ZHeapTupleHasMultiLockers(old_infomask) &&
			!any_multi_locker_member_alive)
			old_infomask &= ~ZHEAP_MULTI_LOCKERS;
	}

	/*
	 * Propagate the lockers information to the new tuple.  Since we're doing
	 * an update, the only possibility is that the lockers had FOR KEY SHARE
	 * lock.  For in-place updates, we are not creating any new version, so
	 * we don't need to propagate anything.
	 */
	if ((checked_lockers && !locker_remains) || use_inplace_update)
		new_infomask = 0;
	else
		new_infomask = ZHEAP_XID_KEYSHR_LOCK | ZHEAP_XID_LOCK_ONLY;

	if (use_inplace_update)
	{
		infomask_old_tuple = infomask_new_tuple =
					old_infomask | new_infomask | ZHEAP_INPLACE_UPDATED;
	}
	else
	{
		infomask_old_tuple = old_infomask | ZHEAP_UPDATED;
		infomask_new_tuple = new_infomask;
	}

	START_CRIT_SECTION();

	if (PageIsAllVisible(page))
	{
		all_visible_cleared = true;
		PageClearAllVisible(page);
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}
	if (newbuf != buffer && PageIsAllVisible(BufferGetPage(newbuf)))
	{
		new_all_visible_cleared = true;
		PageClearAllVisible(BufferGetPage(newbuf));
		visibilitymap_clear(relation, BufferGetBlockNumber(newbuf),
							vmbuffer_new, VISIBILITYMAP_VALID_BITS);
	}

	/*
	 * A page can be pruned for non-inplace updates or inplace updates that
	 * results in shorter tuples.  If this transaction commits, the tuple will
	 * become DEAD sooner or later.  If the transaction finally aborts, the
	 * subsequent page pruning will be a no-op and the hint will be cleared.
	 */
	if (!use_inplace_update || (newtup->t_len < oldtup.t_len))
		ZPageSetPrunable(page, xid);

	ZHeapTupleHeaderSetXactSlot(oldtup.t_data, result_trans_slot_id);
	oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	oldtup.t_data->t_infomask |= infomask_old_tuple;

	/* keep the new tuple copy updated for the caller */
	ZHeapTupleHeaderSetXactSlot(newtup->t_data, new_trans_slot_id);
	newtup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	newtup->t_data->t_infomask |= infomask_new_tuple;

	if (use_inplace_update)
	{
		/*
		 * For inplace updates, we copy the entire data portion including null
		 * bitmap of new tuple.
		 *
		 * For the special case where we are doing inplace updates even when
		 * the new tuple is bigger, we need to adjust the old tuple's location
		 * so that new tuple can be copied at that location as it is.
		 */
		ItemIdChangeLen(lp, newtup->t_len);
		if (newtup->t_len > oldtup.t_len)
		{
			ZHeapTupleHeader new_pos;

			((PageHeader) page)->pd_upper =
								(((PageHeader) page)->pd_upper + oldtup.t_len) -
								newtupsize;
			ItemIdChangeOff(lp, ((PageHeader) page)->pd_upper);
			new_pos= (ZHeapTupleHeader) PageGetItem(page, lp);

			/*
			 * Since the source and destination may overlap, use memmove() as
			 * against memcpy().
			 */
			memmove((char *) new_pos, (char *) oldtup.t_data,
					SizeofZHeapTupleHeader);

			oldtup.t_data = new_pos;
		}

		memcpy((char *) oldtup.t_data + SizeofZHeapTupleHeader,
			   (char *) newtup->t_data + SizeofZHeapTupleHeader,
			   newtup->t_len - SizeofZHeapTupleHeader);

		/*
		 * Copy everything from new tuple in infomask apart from visibility
		 * flags.
		 */
		oldtup.t_data->t_infomask = oldtup.t_data->t_infomask &
											ZHEAP_VIS_STATUS_MASK;
		oldtup.t_data->t_infomask |= (newtup->t_data->t_infomask &
										~ZHEAP_VIS_STATUS_MASK);
		/* Copy number of attributes in infomask2 of new tuple. */
		oldtup.t_data->t_infomask2 &= ~ZHEAP_NATTS_MASK;
		oldtup.t_data->t_infomask2 |=
					newtup->t_data->t_infomask2 & ZHEAP_NATTS_MASK;
		/* also update the tuple length and self pointer */
		oldtup.t_len = newtup->t_len;
		ItemPointerCopy(&oldtup.t_self, &newtup->t_self);
	}
	else
	{
		/* insert tuple at new location */
		RelationPutZHeapTuple(relation, newbuf, newtup);

		/* update new tuple location in undo record */
		appendBinaryStringInfoNoExtend(&undorecord.uur_payload,
									   (char *) &newtup->t_self,
									   sizeof(ItemPointerData));

		new_undorecord.uur_offset = ItemPointerGetOffsetNumber(&(newtup->t_self));
	}

	InsertPreparedUndo();
	if (use_inplace_update)
		PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);
	else
	{
		if (newbuf == buffer)
			PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, new_urecptr);
		else
		{
			/* set transaction slot information for old page */
			PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);
			/* set transaction slot information for new page */
			PageSetUNDO(new_undorecord,
						BufferGetPage(newbuf),
						new_trans_slot_id,
						epoch,
						xid,
						new_urecptr);

			MarkBufferDirty(newbuf);
		}
	}

	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		XLogRecPtr	recptr;

		/*
		 * For logical decoding we need combocids to properly decode the
		 * catalog.
		 */
		if (RelationIsAccessibleInLogicalDecoding(relation))
		{
			/*
			 * Fixme: This won't work as it needs to access cmin/cmax which
			 * we probably needs to retrieve from UNDO.
			 */
			/*log_heap_new_cid(relation, &oldtup);
			log_heap_new_cid(relation, heaptup);*/
		}

		recptr = log_zheap_update(relation, undorecord, new_undorecord,
								  urecptr, new_urecptr, buffer, newbuf,
								  &oldtup, newtup,
								  use_inplace_update,
								  all_visible_cleared,
								  new_all_visible_cleared,
								  &undometa);
		if (newbuf != buffer)
		{
			PageSetLSN(BufferGetPage(newbuf), recptr);
		}
		PageSetLSN(BufferGetPage(buffer), recptr);
	}

	END_CRIT_SECTION();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);

	if (!use_inplace_update)
		pfree(undorecord.uur_payload.data);

	if (newbuf != buffer)
		LockBuffer(newbuf, BUFFER_LOCK_UNLOCK);
	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	/*
	 * Fixme - need to support cache invalidation API's for zheaptuples.
	 */
	/* CacheInvalidateHeapTuple(relation, &oldtup, heaptup); */

	if (BufferIsValid(vmbuffer_new))
		ReleaseBuffer(vmbuffer_new);
	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);
	if (newbuf != buffer)
		ReleaseBuffer(newbuf);
	ReleaseBuffer(buffer);
	UnlockReleaseUndoBuffers();

	/*
	 * Release the lmgr tuple lock, if we had it.
	 */
	if (have_tuple_lock)
		UnlockTupleTuplock(relation, &(oldtup.t_self), *lockmode);

	/*
	 * As of now, we only count non-inplace updates as that are required to
	 * decide whether to trigger autovacuum.
	 */
	if (!use_inplace_update)
		pgstat_count_heap_update(relation, false);

	data_alignment_zheap = 1;

	bms_free(inplace_upd_attrs);
	bms_free(interesting_attrs);
	bms_free(modified_attrs);

	bms_free(key_attrs);
	return HeapTupleMayBeUpdated;
}

/*
 * log_zheap_update - Perform XLogInsert for a zheap-update operation.
 *
 * We need to store enough information in the WAL record so that undo records
 * can be regenerated at the WAL replay time.
 *
 * Caller must already have modified the buffer(s) and marked them dirty.
 */
static XLogRecPtr
log_zheap_update(Relation reln, UnpackedUndoRecord undorecord,
				 UnpackedUndoRecord newundorecord, UndoRecPtr urecptr,
				 UndoRecPtr newurecptr, Buffer oldbuf, Buffer newbuf,
				 ZHeapTuple oldtup, ZHeapTuple newtup, bool inplace_update,
				 bool all_visible_cleared, bool new_all_visible_cleared,
				 xl_undolog_meta *undometa)
{
	xl_undo_header	xlundohdr,
					xlnewundohdr;
	xl_zheap_header	xlundotuphdr,
					xlhdr;
	xl_zheap_update xlrec;
	ZHeapTuple	difftup;
	ZHeapTupleHeader	zhtuphdr;
	uint16		prefix_suffix[2];
	uint16		prefixlen = 0,
				suffixlen = 0;
	XLogRecPtr	recptr;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;
	char	*oldp = NULL;
	char	*newp = NULL;
	int		oldlen, newlen;
	uint32	totalundotuplen;
	Size	dataoff;
	int		bufflags = REGBUF_STANDARD;
	uint8	info = XLOG_ZHEAP_UPDATE;

	totalundotuplen = *((uint32 *) &undorecord.uur_tuple.data[0]);
	dataoff = sizeof(uint32) + sizeof(ItemPointerData) + sizeof(Oid);
	zhtuphdr = (ZHeapTupleHeader) &undorecord.uur_tuple.data[dataoff];

	if (inplace_update)
	{
		/*
		 * For inplace updates the old tuple is in undo record and the
		 * new tuple is replaced in page where old tuple was present.
		 */
		oldp = (char *) zhtuphdr + zhtuphdr->t_hoff;
		oldlen = totalundotuplen - zhtuphdr->t_hoff;
		newp = (char *) oldtup->t_data + oldtup->t_data->t_hoff;
		newlen = oldtup->t_len - oldtup->t_data->t_hoff;

		difftup = oldtup;
	}
	else if (oldbuf == newbuf)
	{
		oldp = (char *) oldtup->t_data + oldtup->t_data->t_hoff;
		oldlen = oldtup->t_len - oldtup->t_data->t_hoff;
		newp = (char *) newtup->t_data + newtup->t_data->t_hoff;
		newlen = newtup->t_len - newtup->t_data->t_hoff;

		difftup = newtup;
	}
	else
	{
		difftup = newtup;
	}

	/*
	 * See log_heap_update to know under what some circumstances we can use
	 * prefix-suffix compression.
	 */
	if (oldbuf == newbuf && !XLogCheckBufferNeedsBackup(newbuf))
	{
		Assert(oldp != NULL && newp != NULL);

		/* Check for common prefix between undo and old tuple */
		for (prefixlen = 0; prefixlen < Min(oldlen, newlen); prefixlen++)
		{
			if (oldp[prefixlen] != newp[prefixlen])
				break;
		}

		/*
		 * Storing the length of the prefix takes 2 bytes, so we need to save
		 * at least 3 bytes or there's no point.
		 */
		if (prefixlen < 3)
			prefixlen = 0;

		/* Same for suffix */
		for (suffixlen = 0; suffixlen < Min(oldlen, newlen) - prefixlen; suffixlen++)
		{
			if (oldp[oldlen - suffixlen - 1] != newp[newlen - suffixlen - 1])
				break;
		}
		if (suffixlen < 3)
			suffixlen = 0;
	}

	/*
	 * Store the information required to generate undo record during
	 * replay.
	 */
	xlundohdr.relfilenode = undorecord.uur_relfilenode;
	xlundohdr.tsid = undorecord.uur_tsid;
	xlundohdr.urec_ptr = urecptr;
	xlundohdr.blkprev = undorecord.uur_blkprev;

	xlrec.prevxid = undorecord.uur_prevxid;
	xlrec.old_offnum = ItemPointerGetOffsetNumber(&oldtup->t_self);
	xlrec.old_infomask = oldtup->t_data->t_infomask;
	xlrec.old_trans_slot_id = ZHeapTupleHeaderGetXactSlot(oldtup->t_data);
	xlrec.new_offnum = ItemPointerGetOffsetNumber(&difftup->t_self);
	xlrec.flags = 0;
	if (all_visible_cleared)
		xlrec.flags |= XLZ_UPDATE_OLD_ALL_VISIBLE_CLEARED;
	if (new_all_visible_cleared)
		xlrec.flags |= XLZ_UPDATE_NEW_ALL_VISIBLE_CLEARED;
	if (prefixlen > 0)
		xlrec.flags |= XLZ_UPDATE_PREFIX_FROM_OLD;
	if (suffixlen > 0)
		xlrec.flags |= XLZ_UPDATE_SUFFIX_FROM_OLD;

	if (!inplace_update)
	{
		Page		page = BufferGetPage(newbuf);

		xlrec.flags |= XLZ_NON_INPLACE_UPDATE;

		xlnewundohdr.relfilenode = newundorecord.uur_relfilenode;
		xlnewundohdr.tsid = newundorecord.uur_tsid;
		xlnewundohdr.urec_ptr = newurecptr;
		xlnewundohdr.blkprev = newundorecord.uur_blkprev;

		Assert(newtup);
		/* If new tuple is the single and first tuple on page... */
		if (ItemPointerGetOffsetNumber(&(newtup->t_self)) == FirstOffsetNumber &&
			PageGetMaxOffsetNumber(page) == FirstOffsetNumber)
		{
			info |= XLOG_ZHEAP_INIT_PAGE;
			bufflags |= REGBUF_WILL_INIT;
		}
	}

	/*
	 * If full_page_writes is enabled, and the buffer image is not
	 * included in the WAL then we can rely on the tuple in the page to
	 * regenerate the undo tuple during recovery.  For detail comments related
	 * to handling of full_page_writes get changed at run time, refer comments
	 * in zheap_delete.
	 */
prepare_xlog:
	/* LOG undolog meta if this is the first WAL after the checkpoint. */
	LogUndoMetaData(undometa);

	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
	if (!doPageWrites || XLogCheckBufferNeedsBackup(oldbuf))
	{
		xlrec.flags |= XLZ_HAS_UPDATE_UNDOTUPLE;

		xlundotuphdr.t_infomask2 = zhtuphdr->t_infomask2;
		xlundotuphdr.t_infomask = zhtuphdr->t_infomask;
		xlundotuphdr.t_hoff = zhtuphdr->t_hoff;
	}

	XLogBeginInsert();
	XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
	XLogRegisterData((char *) &xlrec, SizeOfZHeapUpdate);
	if (!inplace_update)
		XLogRegisterData((char *) &xlnewundohdr, SizeOfUndoHeader);
	if (xlrec.flags & XLZ_HAS_UPDATE_UNDOTUPLE)
	{
		XLogRegisterData((char *) &xlundotuphdr, SizeOfZHeapHeader);
		/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
		XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
						 totalundotuplen - SizeofZHeapTupleHeader);
	}

	XLogRegisterBuffer(0, newbuf, bufflags);
	if (oldbuf != newbuf)
		XLogRegisterBuffer(1, oldbuf, REGBUF_STANDARD);

	/*
	 * Prepare WAL data for the new tuple.
	 */
	if (prefixlen > 0 || suffixlen > 0)
	{
		if (prefixlen > 0 && suffixlen > 0)
		{
			prefix_suffix[0] = prefixlen;
			prefix_suffix[1] = suffixlen;
			XLogRegisterBufData(0, (char *) &prefix_suffix, sizeof(uint16) * 2);
		}
		else if (prefixlen > 0)
		{
			XLogRegisterBufData(0, (char *) &prefixlen, sizeof(uint16));
		}
		else
		{
			XLogRegisterBufData(0, (char *) &suffixlen, sizeof(uint16));
		}
	}

	xlhdr.t_infomask2 = difftup->t_data->t_infomask2;
	xlhdr.t_infomask = difftup->t_data->t_infomask;
	xlhdr.t_hoff = difftup->t_data->t_hoff;
	Assert(SizeofZHeapTupleHeader + prefixlen + suffixlen <= difftup->t_len);

	/*
	 * PG73FORMAT: write bitmap [+ padding] [+ oid] + data
	 *
	 * The 'data' doesn't include the common prefix or suffix.
	 */
	XLogRegisterBufData(0, (char *) &xlhdr, SizeOfZHeapHeader);
	if (prefixlen == 0)
	{
		XLogRegisterBufData(0,
							((char *) difftup->t_data) + SizeofZHeapTupleHeader,
							difftup->t_len - SizeofZHeapTupleHeader - suffixlen);
	}
	else
	{
		/*
		 * Have to write the null bitmap and data after the common prefix as
		 * two separate rdata entries.
		 */
		/* bitmap [+ padding] [+ oid] */
		if (difftup->t_data->t_hoff - SizeofZHeapTupleHeader > 0)
		{
			XLogRegisterBufData(0,
								((char *) difftup->t_data) + SizeofZHeapTupleHeader,
								difftup->t_data->t_hoff - SizeofZHeapTupleHeader);
		}

		/* data after common prefix */
		XLogRegisterBufData(0,
			  ((char *) difftup->t_data) + difftup->t_data->t_hoff + prefixlen,
			  difftup->t_len - difftup->t_data->t_hoff - prefixlen - suffixlen);
	}

	/* filtering by origin on a row level is much more efficient */
	XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

	recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr, doPageWrites);
	if (recptr == InvalidXLogRecPtr)
		goto prepare_xlog;

	return recptr;
}

/*
 * zheap_lock_tuple - lock a tuple.
 *
 *	The functionality is same as heap_lock_tuple except that here we always
 *	make a copy of the tuple before returning to the caller.  We maintain
 *	the pin on buffer to keep the specs same as heap_lock_tuple.
 *
 *	eval - indicates whether the tuple will be evaluated to see if it still
 *	matches the qualification.
 *
 * XXX - Here, we are purposefully not doing anything for visibility map
 * as it is not clear whether we ever need all_frozen kind of concept for
 * zheap.
 */
HTSU_Result
zheap_lock_tuple(Relation relation, ZHeapTuple tuple,
				 CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
				 bool follow_updates, bool eval, Snapshot snapshot,
				 Buffer *buffer, HeapUpdateFailureData *hufd)
{
	HTSU_Result result;
	ZHeapTupleData	zhtup;
	ZHeapPageOpaque	opaque;
	UndoRecPtr	prev_urecptr;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	Page		page;
	ItemPointerData	ctid;
	TransactionId xid, tup_xid;
	CommandId	tup_cid;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	uint32		epoch;
	int			tup_trans_slot_id,
				trans_slot_id;
	bool		require_sleep;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		any_multi_locker_member_alive = false;
	bool		isAborted = false;
	bool		lock_reacquired;

	xid = GetTopTransactionId();
	epoch = GetEpochForXid(xid);

	*buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

	LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

	page = BufferGetPage(*buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If TID is already delete marked due to pruning, then get new ctid, so
	 * that we can lock the new tuple.  We will get new ctid if the tuple
	 * was non-inplace-updated otherwise we will get same TID.
	 */
	if (ItemIdIsDeleted(lp))
	{
		ctid = *tid;
		ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
		result = HeapTupleUpdated;
		goto failed;
	}

	zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zhtup.t_len = ItemIdGetLength(lp);
	zhtup.t_tableOid = RelationGetRelid(relation);
	zhtup.t_self = *tid;

 	/*
	 * Get the transaction slot and undo record pointer if we are already in a
	 * transaction.
	 */
	trans_slot_id = PageGetTransactionSlot(*buffer, epoch, xid);
	if (trans_slot_id != InvalidXactSlotId)
		urec_ptr = ZHeapPageGetRawUndoPtr(trans_slot_id, opaque);

	/*
	 * ctid needs to be fetched from undo chain.  See zheap_update.
	 */
	ctid = *tid;

check_tup_satisfies_update:
	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(&zhtup, cid, *buffer, &ctid,
									   &tup_trans_slot_id, &tup_xid,
									   &tup_cid, false, eval, snapshot,
									   &in_place_updated_or_locked);
	if (result == HeapTupleInvisible)
	{
		/* Give caller an opportunity to throw a more specific error. */
		result = HeapTupleInvisible;
		goto out_locked;
	}
	else if (result == HeapTupleBeingUpdated ||
			 result == HeapTupleUpdated ||
			 (result == HeapTupleMayBeUpdated &&
			  ZHeapTupleHasMultiLockers(zhtup.t_data->t_infomask)))
	{
		TransactionId	xwait;
		uint16			infomask;

		xwait = tup_xid;
		infomask = zhtup.t_data->t_infomask;

		/*
		 * make a copy of the tuple before releasing the lock as some other
		 * backend can perform in-place update this tuple once we relase the
		 * lock.
		 */
		tuple->t_tableOid = RelationGetRelid(relation);
		tuple->t_len = zhtup.t_len;
		tuple->t_self = zhtup.t_self;
		memcpy(tuple->t_data, zhtup.t_data, zhtup.t_len);

		LockBuffer(*buffer, BUFFER_LOCK_UNLOCK);

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 */
		if (ZHeapTupleHasMultiLockers(infomask))
		{
			List	*mlmembers;
			ListCell   *lc;

			if (trans_slot_id != InvalidXactSlotId)
			{
				mlmembers = ZGetMultiLockMembersForCurrentXact(&zhtup, *buffer,
													trans_slot_id, urec_ptr);

				foreach(lc, mlmembers)
				{
					ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

					/*
					 * Only members of our own transaction must be present in
					 * the list.
					 */
					Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

					if (mlmember->mode >= mode)
					{
						list_free_deep(mlmembers);
						result = HeapTupleMayBeUpdated;
						goto out_unlocked;
					}
				}

				list_free_deep(mlmembers);
			}
		}
		else if (TransactionIdIsCurrentTransactionId(xwait))
		{
			switch (mode)
			{
				case LockTupleKeyShare:
					Assert(ZHEAP_XID_IS_KEYSHR_LOCKED(infomask) ||
						   ZHEAP_XID_IS_SHR_LOCKED(infomask) ||
						   ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						   ZHEAP_XID_IS_EXCL_LOCKED(infomask));
					{
						result = HeapTupleMayBeUpdated;
						goto out_unlocked;
					}
					break;
				case LockTupleShare:
					if (ZHEAP_XID_IS_SHR_LOCKED(infomask) ||
						ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = HeapTupleMayBeUpdated;
						goto out_unlocked;
					}
					break;
				case LockTupleNoKeyExclusive:
					if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = HeapTupleMayBeUpdated;
						goto out_unlocked;
					}
					break;
				case LockTupleExclusive:
					if (ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = HeapTupleMayBeUpdated;
						goto out_unlocked;
					}
					break;
			}
		}

		/*
		 * Initially assume that we will have to wait for the locking
		 * transaction(s) to finish.  We check various cases below in which
		 * this can be turned off.
		 */
		require_sleep = true;
		if (mode == LockTupleKeyShare)
		{
			if (!(ZHEAP_XID_IS_EXCL_LOCKED(infomask)))
			{
				bool		updated;

				updated = !ZHEAP_XID_IS_LOCKED_ONLY(infomask);

				/*
				 * If there are updates, follow the update chain; bail out if
				 * that cannot be done.
				 */
				if (follow_updates && updated)
				{
					if (!ItemPointerEquals(&zhtup.t_self, &ctid))
					{
						HTSU_Result res;

						res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
													   xid, mode, cid);
						if (res != HeapTupleMayBeUpdated)
						{
							result = res;
							/* recovery code expects to have buffer lock held */
							LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
							goto failed;
						}
					}
				}

				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

				/*
				 * Also take care of cases when page is pruned after we release
				 * the buffer lock. For this we check if ItemId is not deleted
				 * and refresh the tuple offset position in page.  If TID is
				 * already delete marked due to pruning, then get new ctid, so
				 * that we can lock the new tuple.
				 */
				if (ItemIdIsDeleted(lp))
				{
					ctid = *tid;
					ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
					result = HeapTupleUpdated;
					goto failed;
				}

				zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
				zhtup.t_len = ItemIdGetLength(lp);

				/*
				 * Make sure it's still an appropriate lock, else start over.
				 * Also, if it wasn't updated before we released the lock, but
				 * is updated now, we start over too; the reason is that we
				 * now need to follow the update chain to lock the new
				 * versions.
				 */
				if (!(ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask)) &&
					((ZHEAP_XID_IS_EXCL_LOCKED(zhtup.t_data->t_infomask)) ||
					 !updated))
					goto check_tup_satisfies_update;

				/* Skip sleeping */
				require_sleep = false;

				/*
				 * Note we allow Xid to change here; other updaters/lockers
				 * could have modified it before we grabbed the buffer lock.
				 * However, this is not a problem, because with the recheck we
				 * just did we ensure that they still don't conflict with the
				 * lock we want.
				 */
			}
		}
		else if (mode == LockTupleShare)
		{
			/*
			 * If we're requesting Share, we can similarly avoid sleeping if
			 * there's no update and no exclusive lock present.
			 */
			if (ZHEAP_XID_IS_LOCKED_ONLY(infomask) &&
				!ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) &&
				!ZHEAP_XID_IS_EXCL_LOCKED(infomask))
			{
				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

				/*
				 * Also take care of cases when page is pruned after we release
				 * the buffer lock. For this we check if ItemId is not deleted
				 * and refresh the tuple offset position in page.  If TID is
				 * already delete marked due to pruning, then get new ctid, so
				 * that we can lock the new tuple.
				 */
				if (ItemIdIsDeleted(lp))
				{
					ctid = *tid;
					ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
					result = HeapTupleUpdated;
					goto failed;
				}

				zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
				zhtup.t_len = ItemIdGetLength(lp);

				/*
				 * Make sure it's still an appropriate lock, else start over.
				 * See above about allowing xid to change.
				 */
				if (!ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask) ||
					ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(zhtup.t_data->t_infomask) ||
					ZHEAP_XID_IS_EXCL_LOCKED(zhtup.t_data->t_infomask))
					goto check_tup_satisfies_update;

				/* Skip sleeping */
				require_sleep = false;
			}
		}
		else if (mode == LockTupleNoKeyExclusive)
		{
			LockTupleMode	old_lock_mode;

			old_lock_mode = get_old_lock_mode(infomask);

			/*
			 * If we're requesting NoKeyExclusive, we might also be able to
			 * avoid sleeping; just ensure that there no conflicting lock
			 * already acquired.
			 */
			if (ZHeapTupleHasMultiLockers(infomask))
			{
				if (!DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
									HWLOCKMODE_from_locktupmode(mode)))
				{
					LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
					if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
						!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zhtup.t_data, opaque),
											 xwait))
						goto check_tup_satisfies_update;
					require_sleep = false;
				}
			}
			else if (old_lock_mode == LockTupleKeyShare)
			{
				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
				if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
					 !TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zhtup.t_data, opaque),
										  xwait))
					goto check_tup_satisfies_update;
				require_sleep = false;
			}

			/*
			 * Also take care of cases when page is pruned after we release
			 * the buffer lock. For this we check if ItemId is not deleted
			 * and refresh the tuple offset position in page.  If TID is
			 * already delete marked due to pruning, then get new ctid, so
			 * that we can lock the new tuple.
			 */
			if (ItemIdIsDeleted(lp))
			{
				ctid = *tid;
				ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
				result = HeapTupleUpdated;
				goto failed;
			}

		}

		/*
		 * As a check independent from those above, we can also avoid sleeping
		 * if the current transaction is the sole locker of the tuple.  Note
		 * that the strength of the lock already held is irrelevant; this is
		 * not about recording the lock (which will be done regardless of this
		 * optimization, below).  Also, note that the cases where we hold a
		 * lock stronger than we are requesting are already handled above
		 * by not doing anything.
		 */
		if (require_sleep &&
			!ZHeapTupleHasMultiLockers(infomask)
			&& TransactionIdIsCurrentTransactionId(xwait))
		{
			/*
			 * ... but if the xid changed in the meantime, start over
			 *
			 * Also take care of cases when page is pruned after we release
			 * the buffer lock. For this we check if ItemId is not deleted and
			 * refresh the tuple offset position in page.  If TID is already
			 * delete marked due to pruning, then get new ctid, so that we can
			 * lock the new tuple.
			 */
			LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
			if (ItemIdIsDeleted(lp))
			{
				ctid = *tid;
				ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
				result = HeapTupleUpdated;
				goto failed;
			}

			zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			zhtup.t_len = ItemIdGetLength(lp);

			if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
				 !TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zhtup.t_data, opaque),
									  xwait))
				goto check_tup_satisfies_update;
			require_sleep = false;
		}

		if (require_sleep && result == HeapTupleUpdated)
		{
			LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
			goto failed;
		}
		else if (require_sleep)
		{
			List	*mlmembers = NIL;
			bool	upd_xact_aborted = false;

			/*
			 * Acquire tuple lock to establish our priority for the tuple, or
			 * die trying.  LockTuple will release us when we are next-in-line
			 * for the tuple.  We must do this even if we are share-locking.
			 *
			 * If we are forced to "start over" below, we keep the tuple lock;
			 * this arranges that we stay at the head of the line while
			 * rechecking tuple state.
			 */
			if (!heap_acquire_tuplock(relation, tid, mode, wait_policy,
									  &have_tuple_lock))
			{
				/*
				 * This can only happen if wait_policy is Skip and the lock
				 * couldn't be obtained.
				 */
				result = HeapTupleWouldBlock;
				/* recovery code expects to have buffer lock held */
				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
				goto failed;
			}

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				LockTupleMode	old_lock_mode;
				TransactionId	update_xact;

				old_lock_mode = get_old_lock_mode(infomask);

				/*
				 * For aborted updates, we must allow to reverify the tuple in
				 * case it's values got changed.
				 */
				if (!ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask))
					ZHeapTupleGetTransInfo(&zhtup, *buffer, NULL, NULL, &update_xact,
										   NULL, NULL, true);
				else
					update_xact = InvalidTransactionId;

				if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
									HWLOCKMODE_from_locktupmode(mode)))
				{
					/*
					 * There is a potential conflict.  It is quite possible
					 * that by this time the locker has already been committed.
					 * So we need to check for conflict with all the possible
					 * lockers and wait for each of them.
					 */
					mlmembers = ZGetMultiLockMembers(&zhtup, *buffer, true);

					/* wait for multixact to end, or die trying  */
					switch (wait_policy)
					{
						case LockWaitBlock:
							ZMultiLockMembersWait(relation, mlmembers, &zhtup,
												  *buffer, update_xact, mode,
												  false, XLTW_Lock, NULL,
												  &upd_xact_aborted);
							break;
						case LockWaitSkip:
							if (!ConditionalZMultiLockMembersWait(relation,
																  mlmembers,
																  *buffer,
																  update_xact,
																  mode,
																  NULL,
																  &upd_xact_aborted))
							{
								result = HeapTupleWouldBlock;
								/* recovery code expects to have buffer lock held */
								LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
								goto failed;
							}
							break;
						case LockWaitError:
							if (!ConditionalZMultiLockMembersWait(relation,
																  mlmembers,
																  *buffer,
																  update_xact,
																  mode,
																  NULL,
																  &upd_xact_aborted))
								ereport(ERROR,
										(errcode(ERRCODE_LOCK_NOT_AVAILABLE),
										 errmsg("could not obtain lock on row in relation \"%s\"",
												RelationGetRelationName(relation))));

							break;
					}
				}
			}
			else
			{
				/* wait for regular transaction to end, or die trying */
				switch (wait_policy)
				{
					case LockWaitBlock:
						XactLockTableWait(xwait, relation, &zhtup.t_self,
										  XLTW_Lock);
						break;
					case LockWaitSkip:
						if (!ConditionalXactLockTableWait(xwait))
						{
							result = HeapTupleWouldBlock;
							/* recovery code expects to have buffer lock held */
							LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
							goto failed;
						}
						break;
					case LockWaitError:
						if (!ConditionalXactLockTableWait(xwait))
							ereport(ERROR,
									(errcode(ERRCODE_LOCK_NOT_AVAILABLE),
										errmsg("could not obtain lock on row in relation \"%s\"",
										RelationGetRelationName(relation))));
						break;
				}
			}

			/* if there are updates, follow the update chain */
			if (follow_updates && !ZHEAP_XID_IS_LOCKED_ONLY(infomask))
			{
				HTSU_Result res;

				if (!ItemPointerEquals(&zhtup.t_self, &ctid))
				{
					res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
												   xid, mode, cid);
					if (res != HeapTupleMayBeUpdated)
					{
						result = res;
						/* recovery code expects to have buffer lock held */
						LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
						goto failed;
					}
				}
			}

			LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * Also take care of cases when page is pruned after we release
			 * the buffer lock. For this we check if ItemId is not deleted and
			 * refresh the tuple offset position in page.  If TID is already
			 * delete marked due to pruning, then get new ctid, so that we can
			 * lock the new tuple.
			 */
			if (ItemIdIsDeleted(lp))
			{
				ctid = *tid;
				ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
				result = HeapTupleUpdated;
				goto failed;
			}

			zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			zhtup.t_len = ItemIdGetLength(lp);

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				List	*new_mlmembers;

				/*
				 * If the aborted xact is for update, then we need to reverify
				 * the tuple.
				 */
				if (upd_xact_aborted)
					goto check_tup_satisfies_update;

				new_mlmembers = ZGetMultiLockMembers(&zhtup, *buffer, false);

				/*
				 * Ensure, no new lockers have been added, if so, then start
				 * again.
				 */
				if (!ZMultiLockMembersSame(mlmembers, new_mlmembers))
				{
					list_free_deep(mlmembers);
					list_free_deep(new_mlmembers);
					goto check_tup_satisfies_update;
				}

				any_multi_locker_member_alive =
					ZIsAnyMultiLockMemberRunning(new_mlmembers, &zhtup,
												 *buffer);
				list_free_deep(mlmembers);
				list_free_deep(new_mlmembers);
			}

			/*
			 * xwait is done, but if xwait had just locked the tuple then some
			 * other xact could update this tuple before we get to this point.
			 * Check for xid change, and start over if so.
			 */
			if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(ZHeapTupleHeaderGetRawXid(zhtup.t_data, opaque),
									 xwait))
				goto check_tup_satisfies_update;
		}

		/*
		 * We may overwrite if previous xid is aborted, or if it is committed
		 * but only locked the tuple without updating it.
		 */
		isAborted = TransactionIdDidAbort(xwait);

		/*
		 * For aborted transaction, if the undo actions are not applied
		 * yet, then apply them before modifying the page.
		 */
		if (isAborted &&
			!TransactionIdIsCurrentTransactionId(xwait) &&
			opaque->transinfo[tup_trans_slot_id].xid == xwait)
			zheap_exec_pending_rollback(relation, *buffer,
										tup_trans_slot_id);

		/*
		 * For aborted updates, we must allow to reverify the tuple in
		 * case it's values got changed.
		 */
		if (isAborted &&
			!ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask))
			goto check_tup_satisfies_update;

		/*
		 * We may lock if previous xid committed or aborted but only locked
		 * the tuple without updating it; or if we didn't have to wait at all
		 * for whatever reason.
		 */
		if (!require_sleep ||
			ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask) ||
			result == HeapTupleMayBeUpdated)
			result = HeapTupleMayBeUpdated;
		else
			result = HeapTupleUpdated;
	}
	else if (result == HeapTupleMayBeUpdated)
	{
		TransactionId	xwait;
		uint16			infomask;

		xwait = tup_xid;
		infomask = zhtup.t_data->t_infomask;

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 *
		 * Note that inplace-updates without key updates are considered
		 * equivalent to lock mode LockTupleNoKeyExclusive.
		 */
		if (ZHeapTupleHasMultiLockers(infomask))
		{
			List	*mlmembers;
			ListCell   *lc;

			if (trans_slot_id != InvalidXactSlotId)
			{
				mlmembers = ZGetMultiLockMembersForCurrentXact(&zhtup,
									*buffer, trans_slot_id, urec_ptr);

				foreach(lc, mlmembers)
				{
					ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

					/*
					 * Only members of our own transaction must be present in
					 * the list.
					 */
					Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

					if (mlmember->mode >= mode)
					{
						list_free_deep(mlmembers);
						result = HeapTupleMayBeUpdated;
						goto out_locked;
					}
				}

				list_free_deep(mlmembers);
			}
		}
		else if (TransactionIdIsCurrentTransactionId(xwait))
		{
			tuple->t_tableOid = RelationGetRelid(relation);
			tuple->t_len = zhtup.t_len;
			tuple->t_self = zhtup.t_self;
			memcpy(tuple->t_data, zhtup.t_data, zhtup.t_len);

			switch (mode)
			{
				case LockTupleKeyShare:
					if (ZHEAP_XID_IS_KEYSHR_LOCKED(infomask) ||
						ZHEAP_XID_IS_SHR_LOCKED(infomask) ||
						ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask) ||
						ZHeapTupleIsInPlaceUpdated(infomask))
					{
						goto out_locked;
					}
					break;
				case LockTupleShare:
					if (ZHEAP_XID_IS_SHR_LOCKED(infomask) ||
						ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask) ||
						ZHeapTupleIsInPlaceUpdated(infomask))
						{
							goto out_locked;
						}
						break;
				case LockTupleNoKeyExclusive:
						if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
							ZHeapTupleIsInPlaceUpdated(infomask))
						{
							goto out_locked;
						}
						break;
				case LockTupleExclusive:
					if (ZHeapTupleIsInPlaceUpdated(infomask) &&
						ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						goto out_locked;
					}
					break;
			}
		}
	}

failed:
	if (result != HeapTupleMayBeUpdated)
	{
		Assert(result == HeapTupleSelfUpdated || result == HeapTupleUpdated ||
			   result == HeapTupleWouldBlock);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(zhtup.t_data->t_infomask));

		hufd->ctid = ctid;
		hufd->xmax = tup_xid;
		if (result == HeapTupleSelfUpdated)
			hufd->cmax = tup_cid;
		else
			hufd->cmax = InvalidCommandId;
		hufd->in_place_updated_or_locked = in_place_updated_or_locked;
		goto out_locked;
	}

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, *buffer, epoch, xid,
											   &prev_urecptr, &lock_reacquired);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(*buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);	/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * Also take care of cases when page is pruned after we release
		 * the buffer lock. For this we check if ItemId is not deleted and
		 * refresh the tuple offset position in page.  If TID is already
		 * delete marked due to pruning, then get new ctid, so that we can
		 * lock the new tuple.
		 */
		if (ItemIdIsDeleted(lp))
		{
			ctid = *tid;
			ZHeapPageGetNewCtid(*buffer, &ctid, &tup_xid, &tup_cid);
			result = HeapTupleUpdated;
			goto failed;
		}

		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);

		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before locking a tuple */
	Assert(trans_slot_id != InvalidXactSlotId);

	/*
	 * If all the members were lockers and are all gone, we can do away
	 * with the MULTI_LOCKERS bit.
	 */
	zheap_lock_tuple_guts(relation, *buffer, &zhtup, tup_xid, xid, mode, epoch,
						  tup_trans_slot_id, trans_slot_id, prev_urecptr, cid,
						  !any_multi_locker_member_alive);

	tuple->t_tableOid = RelationGetRelid(relation);
	tuple->t_len = zhtup.t_len;
	tuple->t_self = zhtup.t_self;

	memcpy(tuple->t_data, zhtup.t_data, zhtup.t_len);

	result = HeapTupleMayBeUpdated;

out_locked:
	LockBuffer(*buffer, BUFFER_LOCK_UNLOCK);
out_unlocked:

	/*
	 * Don't update the visibility map here. Locking a tuple doesn't change
	 * visibility info.
	 */

	/*
	 * Now that we have successfully marked the tuple as locked, we can
	 * release the lmgr tuple lock, if we had it.
	 */
	if (have_tuple_lock)
		UnlockTupleTuplock(relation, tid, mode);

	return result;
}

/*
 * test_lockmode_for_conflict - Helper function for zheap_lock_updated_tuple.
 *
 * Given a lockmode held by the transaction identified with the given xid,
 * does the current transaction need to wait, fail, or can it continue if
 * it wanted to acquire a lock of the given mode (required_mode)?  "needwait"
 * is set to true if waiting is necessary; if it can continue, then
 * HeapTupleMayBeUpdated is returned.
 */
static HTSU_Result
test_lockmode_for_conflict(Relation rel, Buffer buf, LockTupleMode old_mode,
						   TransactionId xid, int trans_slot_id,
						   LockTupleMode required_mode, bool has_update,
						   bool *needwait)
{
	*needwait = false;

	/*
	 * Note: we *must* check TransactionIdIsInProgress before
	 * TransactionIdDidAbort/Commit; see comment at top of tqual.c for an
	 * explanation.
	 */
	if (TransactionIdIsCurrentTransactionId(xid))
	{
		/*
		 * The tuple has already been locked by our own transaction.  This is
		 * very rare but can happen if multiple transactions are trying to
		 * lock an ancient version of the same tuple.
		 */
		return HeapTupleSelfUpdated;
	}
	else if (TransactionIdIsInProgress(xid))
	{
		/*
		 * If the locking transaction is running, what we do depends on
		 * whether the lock modes conflict: if they do, then we must wait for
		 * it to finish; otherwise we can fall through to lock this tuple
		 * version without waiting.
		 */
		if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_mode),
								HWLOCKMODE_from_locktupmode(required_mode)))
		{
			*needwait = true;
		}

		/*
		 * If we set needwait above, then this value doesn't matter;
		 * otherwise, this value signals to caller that it's okay to proceed.
		 */
		return HeapTupleMayBeUpdated;
	}
	else if (TransactionIdDidAbort(xid))
	{
		/*
		 * For aborted transaction, if the undo actions are not applied
		 * yet, then apply them before modifying the page.
		 */
		zheap_exec_pending_rollback(rel, buf, trans_slot_id);

		/*
		 * If it was only a locker, then the lock is completely gone now and
		 * we can return success; but if it was an update, then after applying
		 * pending actions, the tuple might have changed and we must report
		 * error to the caller.  It will allow caller to reverify the tuple in
		 * case it's values got changed.
		 */
		if (has_update)
			return HeapTupleUpdated;
		else
			return HeapTupleMayBeUpdated;
	}
	else if (TransactionIdDidCommit(xid))
	{
		/*
		 * The other transaction committed.  If it was only a locker, then the
		 * lock is completely gone now and we can return success; but if it
		 * was an update, then what we do depends on whether the two lock
		 * modes conflict.  If they conflict, then we must report error to
		 * caller. But if they don't, we can fall through to allow the current
		 * transaction to lock the tuple.
		 *
		 * Note: the reason we worry about has_update here is because as soon
		 * as a transaction ends, all its locks are gone and meaningless, and
		 * thus we can ignore them; whereas its updates persist.  In the
		 * TransactionIdIsInProgress case, above, we don't need to check
		 * because we know the lock is still "alive" and thus a conflict needs
		 * always be checked.
		 */
		if (!has_update)
			return HeapTupleMayBeUpdated;

		if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_mode),
								HWLOCKMODE_from_locktupmode(required_mode)))
			/* bummer */
			return HeapTupleUpdated;

		return HeapTupleMayBeUpdated;
	}

	/* Not in progress, not aborted, not committed -- must have crashed */
	return HeapTupleMayBeUpdated;
}

/*
 * zheap_lock_updated_tuple - Lock all the versions of updated tuple.
 *
 * Fetch the tuple pointed to by tid in rel, reserve transaction slot on a
 * page for a given and mark it as locked by the given xid with the given
 * mode; if this tuple is updated, recurse to lock the new version as well.
 * During chain traversal, we might find some intermediate version which
 * is pruned (due to non-inplace-update got committed and the version only
 * has line pointer), so we need to continue fetching the newer versions
 * to lock them.
 *
 * Note that it is important to lock all the versions that are from
 * non-committed transaction, but if the transaction that has created the
 * new version is committed, we only care to lock its latest version.
 */
static HTSU_Result
zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 TransactionId xid, LockTupleMode mode, CommandId cid)
{
	HTSU_Result result;
	ZHeapTuple	mytup;
	UndoRecPtr	prev_urecptr;
	Buffer		buf;
	Page		page;
	ItemPointerData tupid;
	TransactionId	tup_xid;
	int			tup_trans_slot;
	TransactionId	priorXmax = InvalidTransactionId;
	uint32		epoch;
	int			trans_slot_id;
	bool		lock_reacquired;

	ItemPointerCopy(ctid, &tupid);

	for (;;)
	{
		ZHeapTupleData	zhtup;
		ItemId	lp;
		uint16	old_infomask;

		if (!zheap_fetch(rel, SnapshotAny, ctid, &mytup, &buf, false, NULL))
		{
			/*
			 * if we fail to find the updated version of the tuple, it's
			 * because it was vacuumed/pruned/rolledback away after its creator
			 * transaction aborted.  So behave as if we got to the end of the
			 * chain, and there's no further tuple to lock: return success to
			 * caller.
			 */
			if (mytup == NULL)
				return HeapTupleMayBeUpdated;

			/*
			 * If we reached the end of the chain, we're done, so return
			 * success.  See EvalPlanQualZFetch for detailed reason.
			 */
			if (TransactionIdIsValid(priorXmax) &&
				!ValidateTuplesXact(mytup, SnapshotAny, buf, priorXmax, true))
				return HeapTupleMayBeUpdated;

			/* deleted, so forget about it */
			if (ItemPointerEquals(&(mytup->t_self), ctid))
				return HeapTupleMayBeUpdated;

			/* updated row should have xid matching this xmax */
			ZHeapTupleGetTransInfo(mytup, buf, NULL, NULL, &priorXmax, NULL,
								   NULL, true);

			/* continue to lock the next version of tuple */
			continue;
		}

lock_tuple:
		CHECK_FOR_INTERRUPTS();

		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * If we reached the end of the chain, we're done, so return
		 * success.  See EvalPlanQualZFetch for detailed reason.
		 */
		if (TransactionIdIsValid(priorXmax) &&
			!ValidateTuplesXact(mytup, SnapshotAny, buf, priorXmax, false))
		{
			UnlockReleaseBuffer(buf);
			return HeapTupleMayBeUpdated;
		}

		ZHeapTupleGetTransInfo(mytup, buf, &tup_trans_slot, NULL, &tup_xid, NULL, NULL,
							   false);
		old_infomask = mytup->t_data->t_infomask;

		/*
		 * If this tuple was created by an aborted (sub)transaction, then we
		 * already locked the last live one in the chain, thus we're done, so
		 * return success.
		 */
		if (!IsZHeapTupleModified(old_infomask) &&
			TransactionIdDidAbort(tup_xid))
		{
			result = HeapTupleMayBeUpdated;
			goto out_locked;
		}

		/*
		 * If this tuple version has been updated or locked by some concurrent
		 * transaction(s), what we do depends on whether our lock mode
		 * conflicts with what those other transactions hold, and also on the
		 * status of them.
		 */
		if (IsZHeapTupleModified(old_infomask))
		{
			LockTupleMode	old_lock_mode;
			bool		needwait;
			bool		has_update = false;

			if (ZHeapTupleHasMultiLockers(old_infomask))
			{
				List	*mlmembers;
				ListCell   *lc;
				TransactionId	update_xact = InvalidTransactionId;

				/*
				 * As we always maintain strongest lock mode on the tuple, it
				 * must be pointing to the transaction id of the updater.
				 */
				if (!ZHEAP_XID_IS_LOCKED_ONLY(old_infomask))
					update_xact = tup_xid;

				mlmembers = ZGetMultiLockMembers(mytup, buf, false);
				foreach(lc, mlmembers)
				{
					ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

					if (TransactionIdIsValid(update_xact))
					{
						has_update = (update_xact == mlmember->xid) ?
											true : false;
					}

					result = test_lockmode_for_conflict(rel,
														buf,
														mlmember->mode,
														mlmember->xid,
														mlmember->trans_slot_id,
														mode, has_update,
														&needwait);
					if (result == HeapTupleSelfUpdated)
					{
						list_free_deep(mlmembers);
						goto next;
					}

					if (needwait)
					{
						LockBuffer(buf, BUFFER_LOCK_UNLOCK);
						XactLockTableWait(mlmember->xid, rel,
										  &mytup->t_self,
										  XLTW_LockUpdated);
						list_free_deep(mlmembers);
						goto lock_tuple;
					}
					if (result != HeapTupleMayBeUpdated)
					{
						list_free_deep(mlmembers);
						goto out_locked;
					}
				}
			}
			else
			{
				/*
				 * For a non-multi locker, we first need to compute the
				 * corresponding lock mode by using the infomask bits.
				 */
				if (ZHEAP_XID_IS_LOCKED_ONLY(old_infomask))
				{
					if (ZHEAP_XID_IS_KEYSHR_LOCKED(old_infomask))
						old_lock_mode = LockTupleKeyShare;
					else if (ZHEAP_XID_IS_SHR_LOCKED(old_infomask))
						old_lock_mode = LockTupleShare;
					else if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(old_infomask))
						old_lock_mode = LockTupleNoKeyExclusive;
					else if (ZHEAP_XID_IS_EXCL_LOCKED(old_infomask))
						old_lock_mode = LockTupleExclusive;
					else
					{
						/* LOCK_ONLY can't be present alone */
						pg_unreachable();
					}
				}
				else
				{
					has_update = true;
					/* it's an update, but which kind? */
					if (old_infomask & ZHEAP_XID_EXCL_LOCK)
						old_lock_mode = LockTupleExclusive;
					else
						old_lock_mode = LockTupleNoKeyExclusive;
				}

				result = test_lockmode_for_conflict(rel, buf, old_lock_mode,
													tup_xid, tup_trans_slot,
													mode, has_update,
													&needwait);

				/*
				 * If the tuple was already locked by ourselves in a previous
				 * iteration of this (say zheap_lock_tuple was forced to
				 * restart the locking loop because of a change in xid), then
				 * we hold the lock already on this tuple version and we don't
				 * need to do anything; and this is not an error condition
				 * either.  We just need to skip this tuple and continue
				 * locking the next version in the update chain.
				 */
				if (result == HeapTupleSelfUpdated)
					goto next;

				if (needwait)
				{
					LockBuffer(buf, BUFFER_LOCK_UNLOCK);
					XactLockTableWait(tup_xid, rel, &mytup->t_self,
									  XLTW_LockUpdated);
					goto lock_tuple;
				}
				if (result != HeapTupleMayBeUpdated)
				{
					goto out_locked;
				}
			}
		}

		epoch = GetEpochForXid(xid);

		/*
		 * The transaction information of tuple needs to be set in transaction
		 * slot, so needs to reserve the slot before proceeding with the actual
		 * operation.  It will be costly to wait for getting the slot, but we do
		 * that by releasing the buffer lock.
		 */
		trans_slot_id = PageReserveTransactionSlot(rel, buf, epoch, xid,
											&prev_urecptr, &lock_reacquired);
		if (lock_reacquired)
			goto lock_tuple;

		if (trans_slot_id == InvalidXactSlotId)
		{
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);

			pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
			pg_usleep(10000L);	/* 10 ms */
			pgstat_report_wait_end();

			goto lock_tuple;
		}

		/* transaction slot must be reserved before locking a tuple */
		Assert(trans_slot_id != InvalidXactSlotId);

		page = BufferGetPage(buf);
		lp = PageGetItemId(page, ItemPointerGetOffsetNumber(&mytup->t_self));

		Assert(ItemIdIsNormal(lp));

		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);
		zhtup.t_tableOid = mytup->t_tableOid;
		zhtup.t_self = mytup->t_self;

		zheap_lock_tuple_guts(rel, buf, &zhtup, tup_xid, xid, mode, epoch,
							  tup_trans_slot, trans_slot_id, prev_urecptr,
							  cid, false);

next:
		/*
		 * if we find the end of update chain, or if the transaction that has
		 * updated the tuple is aborter, we're done.
		 */
		if (TransactionIdDidAbort(tup_xid) ||
			ItemPointerEquals(&mytup->t_self, ctid) ||
			ZHEAP_XID_IS_LOCKED_ONLY(mytup->t_data->t_infomask))
		{
			result = HeapTupleMayBeUpdated;
			goto out_locked;
		}

		/*
		 * Updated row should have xid matching this xmax.
		 *
		 * XXX Using tup_xid will work as this must be the xid of updater if
		 * any on the tuple; that is because we always maintain the strongest
		 * locker information on the tuple.
		 */
		priorXmax = tup_xid;

		/*
		 * As we still hold a snapshot to which priorXmax is not visible, neither
		 * the transaction slot on tuple can be marked as frozen nor the
		 * corresponding undo be discarded.
		 */
		Assert(TransactionIdIsValid(priorXmax));

		/* be tidy */
		zheap_freetuple(mytup);
		UnlockReleaseBuffer(buf);
	}

	result = HeapTupleMayBeUpdated;

out_locked:
	UnlockReleaseBuffer(buf);

	return result;
}

/*
 * zheap_lock_tuple_guts - Helper function for locking the tuple.
 *
 * It locks the tuple in given mode, writes an undo and WAL for the
 * operation.
 *
 * It is the responsibility of caller to lock and unlock the buffer ('buf').
 */
static void
zheap_lock_tuple_guts(Relation rel, Buffer buf, ZHeapTuple zhtup,
					  TransactionId tup_xid, TransactionId xid,
					  LockTupleMode mode, uint32 epoch, int tup_trans_slot_id,
					  int trans_slot_id, UndoRecPtr prev_urecptr,
					  CommandId cid, bool clear_multi_locker)
{
	TransactionId oldestXidHavingUndo;
	UndoRecPtr	urecptr;
	UnpackedUndoRecord	undorecord;
	int			new_trans_slot_id;
	uint16		  old_infomask;
	uint16		  new_infomask = 0;
	Page		  page;
	xl_undolog_meta undometa;

	page = BufferGetPage(buf);

	/* Compute the new xid and infomask to store into the tuple. */
	old_infomask = zhtup->t_data->t_infomask;
	compute_new_xid_infomask(zhtup, buf, tup_xid, tup_trans_slot_id,
							 old_infomask, xid, trans_slot_id, mode, false,
							 &new_infomask, &new_trans_slot_id);

	if (ZHeapTupleHasMultiLockers(new_infomask) && clear_multi_locker)
		new_infomask &= ~ZHEAP_MULTI_LOCKERS;

	/*
	 * If the last transaction that has updated the tuple is already too
	 * old, then consider it as frozen which means it is all-visible.  This
	 * ensures that we don't need to store epoch in the undo record to check
	 * if the undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file ztqual.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
						pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(tup_xid, oldestXidHavingUndo))
		tup_xid = FrozenTransactionId;

	/*
	 * Prepare an undo record.  We need to separately store the latest
	 * transaction id that has changed the tuple to ensure that we don't
	 * try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */

	if (ZHeapTupleHasMultiLockers(new_infomask))
		undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
	else
		undorecord.uur_type = UNDO_XID_LOCK_ONLY;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_relfilenode = rel->rd_node.relNode;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
	undorecord.uur_tsid = rel->rd_node.spcNode;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = ItemPointerGetBlockNumber(&(zhtup->t_self));
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&(zhtup->t_self));

	initStringInfo(&undorecord.uur_tuple);
	initStringInfo(&undorecord.uur_payload);

	/*
	 * Here, we are storing zheap tuple header which is required to
	 * reconstruct the old copy of tuple.
	 */
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) zhtup->t_data,
						   SizeofZHeapTupleHeader);

	/*
	 * We keep the lock mode in undo record as for multi lockers we can't have
	 * that information in tuple header.  We need lock mode later to detect
	 * conflicts.
	 */
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) &mode,
						   sizeof(LockTupleMode));

	urecptr = PrepareUndoInsert(&undorecord,
								UndoPersistenceForRelation(rel),
								InvalidTransactionId,
								&undometa);


	START_CRIT_SECTION();

	InsertPreparedUndo();
	PageSetUNDO(undorecord, page, trans_slot_id, epoch, xid, urecptr);

	ZHeapTupleHeaderSetXactSlot(zhtup->t_data, new_trans_slot_id);
	zhtup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	zhtup->t_data->t_infomask |= new_infomask;

	MarkBufferDirty(buf);

	/*
	 * Do xlog stuff
	 */
	if (RelationNeedsWAL(rel))
	{
		xl_zheap_lock	xlrec;
		xl_undo_header  xlundohdr;
		XLogRecPtr      recptr;
		XLogRecPtr		RedoRecPtr;
		bool			doPageWrites;

		/*
		 * Store the information required to generate undo record during
		 * replay.
		 */
		xlundohdr.relfilenode = undorecord.uur_relfilenode;
		xlundohdr.tsid = undorecord.uur_tsid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xlrec.prev_xid = tup_xid;
		xlrec.offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
		xlrec.infomask = zhtup->t_data->t_infomask;
		xlrec.trans_slot_id = new_trans_slot_id;
		xlrec.flags = 0;
		if (new_trans_slot_id != trans_slot_id)
			xlrec.flags |= XLZ_LOCK_TRANS_SLOT_FOR_UREC;

prepare_xlog:
		/* LOG undolog meta if this is the first WAL after the checkpoint. */
		LogUndoMetaData(&undometa);

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
		XLogBeginInsert();
		XLogRegisterBuffer(0, buf, REGBUF_STANDARD);
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xlrec, SizeOfZHeapLock);

		/*
		 * We always include old tuple header for undo in WAL record
		 * irrespective of full page image is taken or not. This is done
		 * since savings for not including a zheap tuple header are less
		 * compared to code complexity. However in future, if required we
		 * can do it similar to what we have done in zheap_update or
		 * zheap_delete.
		 */
		XLogRegisterData((char *) undorecord.uur_tuple.data,
						 SizeofZHeapTupleHeader);
		XLogRegisterData((char *) &mode, sizeof(LockTupleMode));
		if (xlrec.flags & XLZ_LOCK_TRANS_SLOT_FOR_UREC)
			XLogRegisterData((char *) &trans_slot_id, sizeof(trans_slot_id));

		recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_LOCK, RedoRecPtr,
									doPageWrites);
		if (recptr == InvalidXLogRecPtr)
			goto prepare_xlog;

		PageSetLSN(page, recptr);
	}
	END_CRIT_SECTION();

	pfree(undorecord.uur_tuple.data);
	pfree(undorecord.uur_payload.data);
	UnlockReleaseUndoBuffers();
}

/*
 * compute_new_xid_infomask - Given the old values of tuple header's infomask,
 * compute the new values for tuple header which includes lock mode, new
 * infomask and transaction slot.
 *
 * We don't clear the multi lockers bit in this function as for that we need
 * to ensure that all the lockers are gone.  Unfortunately, it is not easy to
 * do that as we need to traverse all the undo chains for the current page to
 * ensure the same and doing it here which is quite common code path doesn't
 * seem advisable.  We clear this bit lazily when we detect the conflict and
 * we anyway need to traverse the undo chains for the page.
 */
static void
compute_new_xid_infomask(ZHeapTuple zhtup, Buffer buf, TransactionId tup_xid,
						 int tup_trans_slot, uint16 old_infomask,
						 TransactionId add_to_xid, int trans_slot,
						 LockTupleMode mode, bool is_update,
						 uint16 *result_infomask, int *result_trans_slot)
{
	int			new_trans_slot;
	uint16		new_infomask;
	bool		old_tuple_has_update = false;

	Assert(TransactionIdIsValid(add_to_xid));

	new_infomask = 0;
	new_trans_slot = trans_slot;

	if ((IsZHeapTupleModified(old_infomask) &&
		 TransactionIdIsInProgress(tup_xid)) ||
		ZHeapTupleHasMultiLockers(old_infomask))
	{
		ZGetMultiLockInfo(old_infomask, tup_xid, tup_trans_slot,
						  add_to_xid, &new_infomask, &new_trans_slot,
						  &mode, &old_tuple_has_update);
	}
	else if (!is_update &&
			 TransactionIdIsInProgress(tup_xid))
	{
		/*
		 * Normally if the tuple is not modified and the current transaction
		 * is in progress, the other transaction can't lock the tuple.
		 * However, this can happen while locking the updated tuple chain.  We
		 * keep the transaction slot of original tuple as that will allow us to
		 * check the visibility of tuple by just referring the current
		 * transaction slot.
		 */
		if (tup_xid != add_to_xid)
		{
			new_infomask |= ZHEAP_MULTI_LOCKERS;
			new_trans_slot = tup_trans_slot;
		}
	}
	else if (!is_update &&
			 !ZHEAP_XID_IS_LOCKED_ONLY(old_infomask) &&
			 IsZHeapTupleModified(old_infomask) &&
			 TransactionIdDidCommit(tup_xid) &&
			 ZHeapTupleHasMultiLockers(old_infomask))
	{
		/*
		 * It's a committed update, so we gotta preserve him as updater of the
		 * tuple.  Also, indicate that tuple has multiple lockers.  We need to
		 * do this only when tuple already has multiple lockers.
		 */
		new_infomask |= ZHEAP_MULTI_LOCKERS;
		if (ZHEAP_XID_IS_EXCL_LOCKED(old_infomask))
			new_infomask |= ZHEAP_XID_EXCL_LOCK;
		else
			new_infomask |= ZHEAP_XID_NOKEY_EXCL_LOCK;

		if (ZHeapTupleIsInPlaceUpdated(old_infomask))
		{
			new_infomask |= ZHEAP_INPLACE_UPDATED;
		}
		else
		{
			Assert(ZHeapTupleIsUpdated(old_infomask));
			new_infomask |= ZHEAP_UPDATED;
		}

		new_trans_slot = tup_trans_slot;
		goto infomask_is_computed;
	}

	if (is_update && !ZHeapTupleHasMultiLockers(new_infomask))
	{
		if (mode == LockTupleExclusive)
			new_infomask |= ZHEAP_XID_EXCL_LOCK;
	}
	else
	{
		if (!is_update && !old_tuple_has_update)
			new_infomask |= ZHEAP_XID_LOCK_ONLY;
		switch (mode)
		{
			case LockTupleKeyShare:
				new_infomask |= ZHEAP_XID_KEYSHR_LOCK;
				break;
			case LockTupleShare:
				new_infomask |= ZHEAP_XID_SHR_LOCK;
				break;
			case LockTupleNoKeyExclusive:
				new_infomask |= ZHEAP_XID_NOKEY_EXCL_LOCK;
				break;
			case LockTupleExclusive:
				new_infomask |= ZHEAP_XID_EXCL_LOCK;
				break;
			default:
				elog(ERROR, "invalid lock mode");
		}
	}

infomask_is_computed:

	*result_infomask = new_infomask;

	if (result_trans_slot)
		*result_trans_slot = new_trans_slot;
 }

/*
 *	zheap_finish_speculative - mark speculative insertion as successful
 *
 * To successfully finish a speculative insertion we have to clear speculative
 * flag from tuple.  See heap_finish_speculative why it is important to clear
 * the information of speculative insertion on tuple.
 */
void
zheap_finish_speculative(Relation relation, ZHeapTuple tuple)
{
	Buffer		buffer;
	Page		page;
	OffsetNumber offnum;
	ItemId		lp = NULL;
	ZHeapTupleHeader zhtup;

	buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(&(tuple->t_self)));
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	page = (Page) BufferGetPage(buffer);

	offnum = ItemPointerGetOffsetNumber(&(tuple->t_self));
	if (PageGetMaxOffsetNumber(page) >= offnum)
		lp = PageGetItemId(page, offnum);

	if (PageGetMaxOffsetNumber(page) < offnum || !ItemIdIsNormal(lp))
		elog(ERROR, "invalid lp");

	zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	Assert(ZHeapTupleHeaderIsSpeculative(tuple->t_data));

	MarkBufferDirty(buffer);

	/* Clear the speculative insertion marking from the tuple. */
	zhtup->t_infomask &= ~ZHEAP_SPECULATIVE_INSERT;

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		xl_zheap_confirm xlrec;
		XLogRecPtr	recptr;

		xlrec.offnum = ItemPointerGetOffsetNumber(&tuple->t_self);
		xlrec.flags = XLZ_SPEC_INSERT_SUCCESS;

		XLogBeginInsert();

		/* We want the same filtering on this as on a plain insert */
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

		XLogRegisterData((char *) &xlrec, SizeOfZHeapConfirm);
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		recptr = XLogInsert(RM_ZHEAP2_ID, XLOG_ZHEAP_CONFIRM);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buffer);
}

/*
 *	zheap_abort_speculative - kill a speculatively inserted tuple
 *
 * Marks a tuple that was speculatively inserted in the same command as dead.
 * That makes it immediately appear as dead to all transactions, including our
 * own.  In particular, it makes another backend inserting a duplicate key
 * value won't unnecessarily wait for our whole transaction to finish (it'll
 * just wait for our speculative insertion to finish).
 *
 * The functionality is same as heap_abort_speculative, but we achieve it
 * differently.
 */
void
zheap_abort_speculative(Relation relation, ZHeapTuple tuple)
{
	TransactionId xid = GetTopTransactionId();
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	ZHeapTupleHeader zhtuphdr;
	Page		page;
	BlockNumber block;
	Buffer		buffer;
	ZHeapPageOpaque opaque;

	Assert(ItemPointerIsValid(tid));

	block = ItemPointerGetBlockNumber(tid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	/*
	 * Page can't be all visible, we just inserted into it, and are still
	 * running.
	 */
	Assert(!PageIsAllVisible(page));

	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));
	Assert(ItemIdIsNormal(lp));

	zhtuphdr = (ZHeapTupleHeader) PageGetItem(page, lp);

	/*
	 * Sanity check that the tuple really is a speculatively inserted tuple,
	 * inserted by us.
	 */
	if (ZHeapTupleHeaderGetRawXid(zhtuphdr, opaque) != xid)
		elog(ERROR, "attempted to kill a tuple inserted by another transaction");
	if (!(IsToastRelation(relation) || ZHeapTupleHeaderIsSpeculative(zhtuphdr)))
		elog(ERROR, "attempted to kill a non-speculative tuple");
	Assert(!IsZHeapTupleModified(zhtuphdr->t_infomask));

	START_CRIT_SECTION();

	/*
	 * The tuple will become DEAD immediately.  Flag that this page is a
	 * candidate for pruning.  The action here is exactly same as what we do
	 * for rolling back insert.
	 */
	ItemIdSetDead(lp);
	ZPageSetPrunable(page, xid);

	MarkBufferDirty(buffer);

	/*
	 * XLOG stuff
	 *
	 * The WAL records generated here match heap_delete().  The same recovery
	 * routines are used.
	 */
	if (RelationNeedsWAL(relation))
	{
		xl_zheap_confirm xlrec;
		XLogRecPtr	recptr;

		xlrec.offnum = ItemPointerGetOffsetNumber(&tuple->t_self);
		xlrec.flags = XLZ_SPEC_INSERT_FAILED;

		XLogBeginInsert();

		XLogRegisterData((char *) &xlrec, SizeOfZHeapConfirm);
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		/* No replica identity & replication origin logged */

		recptr = XLogInsert(RM_ZHEAP2_ID, XLOG_ZHEAP_CONFIRM);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	/*
	 * Fixme - need to delete from toast table once we have support for toast
	 * tables in zheap.
	 */

	/*
	 * Never need to mark tuple for invalidation, since catalogs don't support
	 * speculative insertion
	 */

	/* Now we can release the buffer */
	ReleaseBuffer(buffer);

	/* count deletion, as we counted the insertion too */
	pgstat_count_heap_delete(relation);
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

static TransactionId
zheap_fetchinsertxid(ZHeapTuple zhtup, ZHeapPageOpaque opaque)
{
	UndoRecPtr urec_ptr;
	TransactionId xid = InvalidTransactionId;
	int	trans_slot_id = InvalidXactSlotId;
	int	prev_trans_slot_id;
	TransactionId result;
	BlockNumber blk;
	OffsetNumber offnum;
	UnpackedUndoRecord	*urec;
	ZHeapTuple	undo_tup;

	urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(zhtup->t_data, opaque);
	prev_trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
	blk = ItemPointerGetBlockNumber(&zhtup->t_self);
	offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
	undo_tup = zhtup;

	while(true)
	{
		urec = UndoFetchRecord(urec_ptr, blk, offnum, xid, NULL, ZHeapSatisfyUndoRecord);
		if (urec != NULL)
		{
			/*
			 * If we have valid undo record, then check if we have
			 * reached the insert log and return the corresponding
			 * transaction id.
			 */
			if (urec->uur_type == UNDO_INSERT)
			{
				result = urec->uur_xid;
				UndoRecordRelease(urec);
				break;
			}

			undo_tup = CopyTupleFromUndoRecord(urec, undo_tup,
						 (undo_tup) == (zhtup) ? false : true);
			trans_slot_id =
					ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);

			xid = urec->uur_prevxid;
			urec_ptr = urec->uur_blkprev;
			UndoRecordRelease(urec);
			if (!UndoRecPtrIsValid(urec_ptr))
			{
				zheap_freetuple(undo_tup);
				result = FrozenTransactionId;
				break;
			}


			/*
			 * Change the undo chain if the undo tuple is stamped
			 * with the different transaction slot.
			 */
			if (trans_slot_id != prev_trans_slot_id)
			{
				urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(undo_tup->t_data, opaque);
				prev_trans_slot_id = trans_slot_id;
			}
			zhtup = undo_tup;
		}
		else
		{
			/*
			 * Undo record could be null only when it's undo log
			 * is/about to be discarded. We cannot use any assert
			 * for checking is the log is actually discarded, since
			 * UndoFetchRecord can return NULL for the records which
			 * are not yet discarded but are about to be discarded.
			 */
			result = FrozenTransactionId;
			break;
		}
	}

	return result;
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
	CommandId cid;
	TransactionId xid = InvalidTransactionId;
	bool	release_buf = false;

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
		Relation rel = relation_open(zhtup->t_tableOid, NoLock);
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
		case ObjectIdAttributeNumber:
			result = ObjectIdGetDatum(ZHeapTupleGetOid(zhtup));
			break;
		case MinTransactionIdAttributeNumber:
		{
			ZHeapPageOpaque opaque;

			opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

			/*
			 * Fixme - Need to check whether we need any handling of epoch here.
			 */
			if(ZHeapTupleHeaderGetXactSlot(zhtup->t_data) == ZHTUP_SLOT_FROZEN)
				result = TransactionIdGetDatum(FrozenTransactionId);
			else if (IsZHeapTupleModified(zhtup->t_data->t_infomask) ||
					 zhtup->t_data->t_infomask & ZHEAP_INVALID_XACT_SLOT)
				result = TransactionIdGetDatum(zheap_fetchinsertxid(zhtup, opaque));
			else
			{
				uint64  epoch_xid;
				ZHeapTupleGetTransInfo(zhtup, buf, NULL, &epoch_xid, &xid,
									   NULL, NULL, false);

				if (!TransactionIdIsValid(xid) || epoch_xid <
					pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
					xid = FrozenTransactionId;
				result = TransactionIdGetDatum(xid);
			}
		}
			break;
		case MaxTransactionIdAttributeNumber:
			if (IsZHeapTupleModified(zhtup->t_data->t_infomask))
			{
				uint64  epoch_xid;

				ZHeapTupleGetTransInfo(zhtup, buf, NULL, &epoch_xid, &xid,
									   NULL, NULL, false);

				if (!TransactionIdIsValid(xid) || epoch_xid <
					pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
					xid = FrozenTransactionId;
				result = TransactionIdGetDatum(xid);
			}
			else
				result = TransactionIdGetDatum(InvalidTransactionId);

			break;
		case MinCommandIdAttributeNumber:
		case MaxCommandIdAttributeNumber:
			Assert (BufferIsValid(buf));
			cid = ZHeapTupleGetCid(zhtup, buf, InvalidUndoRecPtr);
			/*
			 * To maintain the compatibility of cid with that of heap,
			 * return the FirstCommandId if it comes to be InvalidCommandId
			 * otherwise the command id as returned by ZHeapTupleGetCid.
			 */
			if (cid == InvalidCommandId)
				result = CommandIdGetDatum(FirstCommandId);
			else
				result = CommandIdGetDatum(cid);
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
		case ObjectIdAttributeNumber:
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
 * PageSetUNDO - Set the transaction information pointer for a given
 *		transaction slot.
 */
void
PageSetUNDO(UnpackedUndoRecord undorecord, Page page, int trans_slot_id,
			uint32 epoch, TransactionId xid, UndoRecPtr urecptr)
{
	ZHeapPageOpaque	opaque;

	Assert(trans_slot_id != InvalidXactSlotId);

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	opaque->transinfo[trans_slot_id].xid_epoch = epoch;
	opaque->transinfo[trans_slot_id].xid = xid;
	opaque->transinfo[trans_slot_id].urec_ptr = urecptr;

	elog(DEBUG1, "undo record: TransSlot: %d, Epoch: %d, TransactionId: %d, urec: " UndoRecPtrFormat ", prev_urec: " UINT64_FORMAT ", block: %d, offset: %d, undo_op: %d, xid_tup: %d, reloid: %d",
				 trans_slot_id, epoch, xid, urecptr, undorecord.uur_blkprev, undorecord.uur_block, undorecord.uur_offset, undorecord.uur_type,
				 undorecord.uur_prevxid, undorecord.uur_relfilenode);
}

/*
 * PageGetTransactionSlot - Get the transaction slot for the given epoch and
 *			xid.
 */
int
PageGetTransactionSlot(Buffer buf, uint32 epoch, TransactionId xid)
{
	ZHeapPageOpaque	opaque;
	int		slot_no;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	for (slot_no = 0; slot_no < ZHEAP_PAGE_TRANS_SLOTS; slot_no++)
	{
		if (opaque->transinfo[slot_no].xid_epoch == epoch &&
			opaque->transinfo[slot_no].xid == xid)
			return slot_no;
	}

	return InvalidXactSlotId;
}

/*
 * PageReserveTransactionSlot - Reserve the transaction slot in page.
 *
 *	This function returns transaction slot number if either the page already
 *	has some slot that contains the transaction info or there is an empty
 *	slot or it manages to reuse some existing slot; otherwise retruns false.
 */
int
PageReserveTransactionSlot(Relation relation, Buffer buf, uint32 epoch,
						   TransactionId xid, UndoRecPtr *urec_ptr,
						   bool *lock_reacquired)
{
	ZHeapPageOpaque	opaque;
	int		latestFreeTransSlot = InvalidXactSlotId;
	int		slot_no;

	*lock_reacquired = false;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	for (slot_no = 0; slot_no < ZHEAP_PAGE_TRANS_SLOTS; slot_no++)
	{
		if (opaque->transinfo[slot_no].xid_epoch == epoch &&
			opaque->transinfo[slot_no].xid == xid)
		{
			*urec_ptr = opaque->transinfo[slot_no].urec_ptr;
			return slot_no;
		}
		else if (opaque->transinfo[slot_no].xid == InvalidTransactionId &&
				 latestFreeTransSlot == InvalidXactSlotId)
			latestFreeTransSlot = slot_no;
	}

	if (latestFreeTransSlot >= 0)
	{
		*urec_ptr = opaque->transinfo[latestFreeTransSlot].urec_ptr;
		return latestFreeTransSlot;
	}

	/* no transaction slot available, try to reuse some existing slot */
	if (PageFreezeTransSlots(relation, buf, lock_reacquired))
	{
		/*
		 * If the lock is reacquired inside, then we allow callers to reverify
		 * the condition whether then can still perform the required
		 * operation.
		 */
		if (*lock_reacquired)
			return InvalidXactSlotId;

		for (slot_no = 0; slot_no < ZHEAP_PAGE_TRANS_SLOTS; slot_no++)
		{
			if (opaque->transinfo[slot_no].xid == InvalidTransactionId)
			{
				*urec_ptr = opaque->transinfo[slot_no].urec_ptr;
				return slot_no;
			}
		}

		/*
		 * After freezing transaction slots, we should get atleast one free
		 * slot.
		 */
		Assert(false);
	}

	/* no transaction slot available */
	return InvalidXactSlotId;
}

/*
 * zheap_freeze_or_invalidate_tuples - Clear the slot information or set
 *									   invalid_xact flags.
 *
 * 	Process all the tuples on the page and match their trasaction slot with
 *	the input slot array, if tuple is pointing to the slot then set the tuple
 *  slot as ZHTUP_SLOT_FROZEN if is frozen is true otherwise set
 *  ZHEAP_INVALID_XACT_SLOT flag on the tuple
 */
void
zheap_freeze_or_invalidate_tuples(Page page, int nSlots, int *slots,
								  bool isFrozen)
{
	OffsetNumber offnum, maxoff;
	int	i;

	/* clear the slot info from tuples */
	maxoff = PageGetMaxOffsetNumber(page);

	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
	{
		ZHeapTupleHeader	tup_hdr;
		ItemId		itemid;
		int		trans_slot;

		itemid = PageGetItemId(page, offnum);

		if (ItemIdIsDead(itemid))
			continue;

		if (!ItemIdIsUsed(itemid))
		{
			if (!ItemIdHasPendingXact(itemid))
				continue;
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else if (ItemIdIsDeleted(itemid))
		{
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else
		{
			tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
			trans_slot = ZHeapTupleHeaderGetXactSlot(tup_hdr);
		}

		for (i = 0; i < nSlots; i++)
		{
			if (trans_slot == slots[i])
			{
				/*
				 * Set transaction slots of tuple as frozen to indicate tuple
				 * is all visible and mark the deleted itemids as dead.
				 */
				if (isFrozen)
				{
					if (!ItemIdIsUsed(itemid))
					{
						/* This must be unused entry which has xact information. */
						Assert(ItemIdHasPendingXact(itemid));

						/*
						 * The pending xact must be commited if the corresponding
						 * slot is being marked as frozen.  So, clear the pending
						 * xact and transaction slot information from itemid.
						 */
						ItemIdSetUnused(itemid);
					}
					else if (ItemIdIsDeleted(itemid))
					{
						/*
						 * The deleted item must not be visible to anyone if the
						 * corresponding slot is being marked as frozen.  So,
						 * marking it as dead.
						 */
						ItemIdSetDead(itemid);
					}
					else
						ZHeapTupleHeaderSetXactSlot(tup_hdr, ZHTUP_SLOT_FROZEN);
				}
				else
				{
					/*
					 * We just append the invalid xact flag in the tuple/itemid to
					 * indicate that for this tuple/itemid we need to fetch the
					 * transaction information from undo record.  Also, we
					 * ensure to clear the transaction information from unused
					 * itemid.
					 */
					if (!ItemIdIsUsed(itemid))
					{
						/* This must be unused entry which has xact information. */
						Assert(ItemIdHasPendingXact(itemid));

						/*
						 * The pending xact is commited.  So, clear the pending xact
						 * and transaction slot information from itemid.
						 */
						ItemIdSetUnused(itemid);
					}
					else if (ItemIdIsDeleted(itemid))
						ItemIdSetInvalidXact(itemid);
					else
						tup_hdr->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
					break;
				}
				break;
			}
		}
	}
}

/*
 * GetCompletedSlotOffsets
 *
 * Find all the tuples pointing to the transaction slots for committed
 * transactions.
 */
void
GetCompletedSlotOffsets(Page page, int nCompletedXactSlots,
						int *completed_slots,
						OffsetNumber *offset_completed_slots,
						int	*numOffsets)
{
	int				noffsets = 0;
	OffsetNumber 	offnum, maxoff;

	maxoff = PageGetMaxOffsetNumber(page);

	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
	{
		ZHeapTupleHeader	tup_hdr;
		ItemId		itemid;
		int			i, trans_slot;

		itemid = PageGetItemId(page, offnum);

		if (ItemIdIsDead(itemid))
			continue;

		if (!ItemIdIsUsed(itemid))
		{
			if (!ItemIdHasPendingXact(itemid))
				continue;
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else if (ItemIdIsDeleted(itemid))
		{
			if ((ItemIdGetVisibilityInfo(itemid) & ITEMID_XACT_INVALID))
				continue;
			trans_slot = ItemIdGetTransactionSlot(itemid);
		}
		else
		{
			tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
			if (tup_hdr->t_infomask & ZHEAP_INVALID_XACT_SLOT)
				continue;
			trans_slot = ZHeapTupleHeaderGetXactSlot(tup_hdr);
		}

		for (i = 0; i < nCompletedXactSlots; i++)
		{
			/*
			 * we don't need to include the tuples that have not changed
			 * since the last time as the special undo record for them can
			 * be found in the undo chain of their present slot.
			 */
			if (trans_slot == completed_slots[i])
			{
				offset_completed_slots[noffsets++] = offnum;
				break;
			}
		}
	}

	*numOffsets = noffsets;
}

/*
 * PageFreezeTransSlots - Make the transaction slots available for reuse.
 *
 *	This function tries to free up some existing transaction slots so that
 *	they can be reused.  To reuse the slot, it needs to ensure one of the below
 *	conditions:
 *	(a) the xid is committed, all-visible and doesn't have pending rollback
 *	to perform.
 *	(b) if the xid is committed, then ensure to mark a special flag on the
 *	tuples that are modified by that xid on the current page.
 *	(c) if the xid is rolledback, then ensure that rollback is performed or
 *	at least undo actions for this page have been replayed.
 *
 *	For committed/aborted transactions, we simply clear the xid from the
 *	transaction slot and undo record pointer is kept as it is to ensure that
 *	we don't break the undo chain for that slot. We also mark the tuples that
 *	are modified by committed xid with a special flag indicating that slot for
 *	this tuple is reused.  The special flag is just an indication that the
 *	transaction information of the transaction that has modified the tuple can
 *	be retrieved from the undo.
 *
 *	If we don't do so, then after that slot got reused for some other
 *	unrelated transaction, it might become tricky to traverse the undo chain.
 *	In such a case, it is quite possible that the particular tuple has not
 *	been modified, but it is still pointing to transaction slot which has been
 *	reused by new transaction and that transaction is still not committed.
 *	During the visibility check for such a tuple, it can appear that the tuple
 *	is modified by current transaction which is clearly wrong and can lead to
 *	wrong results.  One such case would be when we try to fetch the commandid
 *	for that tuple to check the visibility, it will fetch the commandid for a
 *	different transaction that is already committed.
 *
 *	The basic principle used here is to ensure that we can always fetch the
 *	transaction information of tuple until it is frozen (committed and
 *	all-visible).
 *
 *	This also ensures that we are consistent with how other operations work in
 *	zheap i.e the tuple always reflect the current state.
 *
 *	We don't need any special handling for the tuples that are locked by
 *	multiple transactions (aka tuples that have MULTI_LOCKERS bit set).
 *	Basically, we always maintain either strongest lockers or latest lockers
 *	(when all the lockers are of same mode) transaction slot on the tuple.
 *	In either case, we should be able to detect the visibility of tuple based
 *	on the latest locker information.
 *
 *	This function assumes that the caller already has Exclusive lock on the
 *	buffer.
 *
 *	This function returns true if it manages to free some transaction slot,
 *	false otherwise.
 */
static bool
PageFreezeTransSlots(Relation relation, Buffer buf, bool *lock_reacquired)
{
	Page	page;
	ZHeapPageOpaque	opaque;
	uint64		oldestXidWithEpochHavingUndo;
	int		slot_no;
	int		frozen_slots[ZHEAP_PAGE_TRANS_SLOTS];
	int		nFrozenSlots = 0;
	int		completed_xact_slots[ZHEAP_PAGE_TRANS_SLOTS];
	int		nCompletedXactSlots = 0;
	int		aborted_xact_slots[ZHEAP_PAGE_TRANS_SLOTS];
	int		nAbortedXactSlots = 0;

	oldestXidWithEpochHavingUndo = pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo);

	page = BufferGetPage(buf);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Clear the slot information from tuples.  The basic idea is to collect
	 * all the transaction slots that can be cleared.  Then traverse the page
	 * to see if any tuple has marking for any of the slots, if so, just clear
	 * the slot information from the tuple.
	 */
	for (slot_no = 0; slot_no < ZHEAP_PAGE_TRANS_SLOTS; slot_no++)
	{
		uint64	slot_xid_epoch = opaque->transinfo[slot_no].xid_epoch;
		TransactionId	slot_xid = opaque->transinfo[slot_no].xid;

		/*
		 * Transaction slot can be considered frozen if it belongs to previous
		 * epoch or transaction id is old enough that it is all visible.
		 */
		slot_xid_epoch = MakeEpochXid(slot_xid_epoch, slot_xid);

		if (slot_xid_epoch < oldestXidWithEpochHavingUndo)
			frozen_slots[nFrozenSlots++] = slot_no;
	}

	if (nFrozenSlots)
	{
		TransactionId	latestxid = InvalidTransactionId;
		int		i;


		START_CRIT_SECTION();

		/* clear the transaction slot info on tuples */
		zheap_freeze_or_invalidate_tuples(page, nFrozenSlots, frozen_slots,
										  true);

		/* Initialize the frozen slots. */
		for (i = 0; i < nFrozenSlots; i++)
		{
			slot_no = frozen_slots[i];

			/* Remember the latest xid. */
			if (TransactionIdFollows(opaque->transinfo[slot_no].xid, latestxid))
				latestxid = opaque->transinfo[slot_no].xid;

			opaque->transinfo[slot_no].xid_epoch = 0;
			opaque->transinfo[slot_no].xid = InvalidTransactionId;
			opaque->transinfo[slot_no].urec_ptr = InvalidUndoRecPtr;
		}

		MarkBufferDirty(buf);

		/*
		 * Xlog Stuff
		 *
		 * Log all the frozen_slots number for which we need to clear the
		 * transaction slot information.  Also, note down the latest xid
		 * corresponding to the frozen slots. This is required to ensure that
		 * no standby query conflicts with the frozen xids.
		 */
		if (RelationNeedsWAL(relation))
		{
			xl_zheap_freeze_xact_slot xlrec;
			XLogRecPtr	recptr;

			XLogBeginInsert();

			xlrec.nFrozen = nFrozenSlots;
			xlrec.lastestFrozenXid = latestxid;

			XLogRegisterData((char *) &xlrec, SizeOfZHeapFreezeXactSlot);

			XLogRegisterBuffer(0, buf, REGBUF_STANDARD);
			XLogRegisterBufData(0, (char *) &frozen_slots, nFrozenSlots * sizeof(int));

			recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_FREEZE_XACT_SLOT);
			PageSetLSN(page, recptr);
		}

		END_CRIT_SECTION();

		return true;
	}

	/*
	 * Try to reuse transaction slots of committed/aborted transactions. This
	 * is just like above but it will maintain a link to the previous
	 * transaction undo record in this slot.  This is to ensure that if there
	 * is still any alive snapshot to which this transaction is not visible,
	 * it can fetch the record from undo and check the visibility.
	 */
	for (slot_no = 0; slot_no < ZHEAP_PAGE_TRANS_SLOTS; slot_no++)
	{
		if (!TransactionIdIsInProgress(opaque->transinfo[slot_no].xid))
		{
			if (TransactionIdDidCommit(opaque->transinfo[slot_no].xid))
				completed_xact_slots[nCompletedXactSlots++] = slot_no;
			else
				aborted_xact_slots[nAbortedXactSlots++] = slot_no;
		}
	}

	if (nCompletedXactSlots)
	{
		int i;

		/* NO EREPORT(ERROR) from here till changes are logged */
		START_CRIT_SECTION();

		/* Mark INVALID_XACT_SLOT flag on the tuple. */
		zheap_freeze_or_invalidate_tuples(page, nCompletedXactSlots,
										  completed_xact_slots, false);

		/*
		 * Clear the xid information from the slot but keep the undo record
		 * pointer as it is so that undo records of the transaction are
		 * accessible by traversing slot's undo chain even though the slots
		 * are reused.
		 */
		for (i = 0; i < nCompletedXactSlots; i++)
		{
			slot_no = completed_xact_slots[i];
			opaque->transinfo[slot_no].xid_epoch = 0;
			opaque->transinfo[slot_no].xid = InvalidTransactionId;
		}

		MarkBufferDirty(buf);

		/*
		 * Xlog Stuff
		 */
		if (RelationNeedsWAL(relation))
		{
			xl_zheap_invalid_xact_slot xlrec;
			XLogRecPtr	recptr;

			XLogBeginInsert();

			xlrec.nCompletedSlots = nCompletedXactSlots;

			XLogRegisterData((char *) &xlrec, SizeOfZHeapInvalidXactSlot);

			XLogRegisterBuffer(0, buf, REGBUF_STANDARD);
			XLogRegisterBufData(0, (char *) &completed_xact_slots, nCompletedXactSlots * sizeof(int));

			recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_INVALID_XACT_SLOT);
			PageSetLSN(page, recptr);
		}

		END_CRIT_SECTION();

		return true;
	}
	else if (nAbortedXactSlots)
	{
		int		i;
		UndoRecPtr *urecptr = palloc(nAbortedXactSlots * sizeof(UndoRecPtr));
		TransactionId *xid = palloc(nAbortedXactSlots * sizeof(TransactionId));

		/* Collect slot information before releasing the lock. */
		for (i = 0; i < nAbortedXactSlots; i++)
		{
			urecptr[i] = opaque->transinfo[aborted_xact_slots[i]].urec_ptr;
			xid[i] = opaque->transinfo[aborted_xact_slots[i]].xid;
		}

		/*
		 * We need to release and the lock before applying undo actions for a
		 * page as we might need to traverse the long undo chain for a page.
		 */
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		for (i = 0; i < nAbortedXactSlots; i++)
			process_and_execute_undo_actions_page(urecptr[i],
												  relation,
												  buf,
												  xid[i],
												  aborted_xact_slots[i]);

		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
		*lock_reacquired = true;
		pfree(urecptr);
		pfree(xid);
		return true;
	}

	return false;
}

/*
 * ZHeapTupleGetCid - Retrieve command id from tuple's undo record.
 *
 * It is expected that the caller of this function has atleast read lock
 * on the buffer.
 */
CommandId
ZHeapTupleGetCid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr)
{
	ZHeapPageOpaque	opaque;
	UnpackedUndoRecord	*urec;
	CommandId	current_cid;
	TransactionId	xid;
	uint64		epoch_xid;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	epoch_xid = ZHeapTupleHeaderGetRawEpoch(zhtup->t_data, opaque);
	xid = ZHeapTupleHeaderGetRawXid(zhtup->t_data, opaque);

	epoch_xid = MakeEpochXid(epoch_xid, xid);

	if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return InvalidCommandId;

	/*
	 * If urec_ptr is not provided, fetch the latest undo pointer from the page.
	 */
	if (!UndoRecPtrIsValid(urec_ptr))
		urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(zhtup->t_data, opaque);

	Assert(UndoRecPtrIsValid(urec_ptr));
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);
	if (urec == NULL)
		return InvalidCommandId;

	current_cid = urec->uur_cid;

	UndoRecordRelease(urec);

	return current_cid;
}

/*
 * ZHeapTupleGetCtid - Retrieve tuple id from tuple's undo record.
 *
 * It is expected that caller of this function has atleast read lock
 * on the buffer and we call it only for non-inplace-updated tuples.
 */
void
ZHeapTupleGetCtid(ZHeapTuple zhtup, Buffer buf, ItemPointer	ctid)
{
	*ctid = zhtup->t_self;
	ZHeapPageGetCtid(ZHeapTupleHeaderGetXactSlot(zhtup->t_data), buf, ctid);
}

/*
 * ZHeapTupleGetSpecToken - Retrieve speculative token from tuple's undo
 *			record.
 *
 * It is expected that caller of this function has atleast read lock
 * on the buffer.
 */
void
ZHeapTupleGetSpecToken(ZHeapTuple zhtup, Buffer buf, uint32 *specToken)
{
	ZHeapPageOpaque	opaque;
	UnpackedUndoRecord	*urec;
	UndoRecPtr	urec_ptr;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));
	urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(zhtup->t_data, opaque);

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/*
	 * We always expect urec to be valid as it try to fetch speculative token
	 * of tuples for which inserting transaction hasn't been committed.  So,
	 * corresponding undo record can't be discarded.
	 */
	Assert(urec);

	*specToken = *(uint32 *) urec->uur_payload.data;

	UndoRecordRelease(urec);
}

/*
 * ZHeapTupleGetTransInfo - Retrieve transaction information of transaction
 *			that has modified the tuple.
 *
 * nobuflock indicates whether caller has lock on the buffer 'buf'. If nobuflock
 * is false, we rely on the supplied tuple zhtup to fetch the slot and undo
 * information. Otherwise, we take buffer lock and fetch the actual tuple.
 */
void
ZHeapTupleGetTransInfo(ZHeapTuple zhtup, Buffer buf, int *trans_slot,
					   uint64 *epoch_xid_out, TransactionId *xid_out,
					   CommandId *cid_out, UndoRecPtr *urec_ptr_out,
					   bool nobuflock)
{
	ZHeapTupleHeader	tuple = zhtup->t_data;
	ZHeapPageOpaque		opaque;
	UndoRecPtr	urec_ptr;
	uint64		epoch;
	TransactionId	xid = InvalidTransactionId;
	CommandId	cid;
	ItemId	lp;
	Page	page;
	ItemPointer tid = &(zhtup->t_self);
	int		trans_slot_id;
	bool	is_invalid_slot = false;

	/*
	 * We are going to access special space in the page to retrieve the
	 * transaction information and that requires share lock on buffer.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));
	if (!ItemIdIsDeleted(lp))
	{
		if (nobuflock)
		{
			/*
			 * If the tuple is updated such that its transaction slot has
			 * been changed, then we will never be able to get the correct
			 * tuple from undo. To avoid, that we get the latest tuple from
			 * page rather than relying on it's in-memory copy.
			 */
			zhtup->t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
			zhtup->t_len = ItemIdGetLength(lp);
			tuple = zhtup->t_data;
		}
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(tuple);
		urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque);
		if (tuple->t_infomask & ZHEAP_INVALID_XACT_SLOT)
			is_invalid_slot = true;
	}
	else
	{
		/*
		 * If it's deleted and pruned, we fetch the slot and undo information
		 * from the item pointer itself.
		 */
		trans_slot_id = ItemIdGetTransactionSlot(lp);
		urec_ptr = ZHeapPageGetUndoPtr(trans_slot_id, opaque);
		if (ItemIdGetVisibilityInfo(lp) & ITEMID_XACT_INVALID)
			is_invalid_slot = true;
	}

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (trans_slot_id != ZHTUP_SLOT_FROZEN)
	{
		if (is_invalid_slot)
		{
			FetchTransInfoFromUndo(zhtup, &epoch, &xid, &cid, &urec_ptr);
		}
		else
		{
			lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));
			if (!ItemIdIsDeleted(lp))
			{
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(tuple);
				epoch = (uint64) ZHeapTupleHeaderGetRawEpoch(tuple, opaque);
				xid = ZHeapTupleHeaderGetRawXid(tuple, opaque);
				cid = ZHeapTupleGetCid(zhtup, buf, InvalidUndoRecPtr);
				urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque);
			}
			else
			{
				epoch = (uint64) ZHeapPageGetRawEpoch(trans_slot_id, opaque);
				xid = ZHeapPageGetRawXid(trans_slot_id, opaque);
				cid = ZHeapPageGetCid(trans_slot_id, buf,
									  ItemPointerGetOffsetNumber(tid));
				urec_ptr = ZHeapPageGetUndoPtr(trans_slot_id, opaque);
			}
		}
	}
	else
	{
		trans_slot_id = InvalidXactSlotId;
		epoch = 0;
		xid = InvalidTransactionId;
		cid = InvalidCommandId;
		urec_ptr = InvalidUndoRecPtr;
	}

	/* Set the value of required parameters. */
	if (trans_slot)
		*trans_slot = trans_slot_id;
	if (epoch_xid_out)
		*epoch_xid_out = MakeEpochXid(epoch, xid);
	if (xid_out)
		*xid_out = xid;
	if (cid_out)
		*cid_out = cid;
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
	if (urec_ptr_out)
		*urec_ptr_out = urec_ptr;

	return;
}

/*
 * ZHeapPageGetCid - Retrieve command id from tuple's undo record.
 *
 * This is similar to ZHeapTupleGetCid with a difference that here we use
 * transaction slot to fetch the appropriate undo record.  It is expected that
 * the caller of this function has atleast read lock on the buffer.
 */
CommandId
ZHeapPageGetCid(int trans_slot, Buffer buf, OffsetNumber off)
{
	ZHeapPageOpaque	opaque;
	UnpackedUndoRecord	*urec;
	CommandId	current_cid;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	if (TransactionIdPrecedes(ZHeapPageGetRawXid(trans_slot, opaque),
							  RecentGlobalXmin))
		return InvalidCommandId;

	urec = UndoFetchRecord(ZHeapPageGetUndoPtr(trans_slot, opaque),
						   BufferGetBlockNumber(buf),
						   off,
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);
	if (urec == NULL)
		return InvalidCommandId;

	current_cid = urec->uur_cid;

	UndoRecordRelease(urec);

	return current_cid;
}


/*
 * ZHeapPageGetCtid - Retrieve tuple id from tuple's undo record.
 *
 * It is expected that caller of this function has atleast read lock.
 */
void
ZHeapPageGetCtid(int trans_slot, Buffer buf, ItemPointer ctid)
{
	ZHeapPageOpaque	opaque;
	UnpackedUndoRecord	*urec;
	UndoRecPtr	urec_ptr;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buf));

	urec_ptr = ZHeapPageGetUndoPtr(trans_slot, opaque);

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(ctid),
						   ItemPointerGetOffsetNumber(ctid),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/*
	 * We always expect urec here to be valid as it try to fetch ctid of
	 * tuples that are visible to the snapshot, so corresponding undo record
	 * can't be discarded.
	 */
	Assert(urec);

	/*
	 * The tuple should be deleted/updated previously. Else, the caller should
	 * not be calling this function.
	 */
	Assert(urec->uur_type == UNDO_DELETE || urec->uur_type == UNDO_UPDATE);

	/*
	 * For a deleted tuple, ctid refers to self.
	 */
	if (urec->uur_type != UNDO_DELETE)
	{
		Assert(urec->uur_payload.len > 0);
		*ctid = *(ItemPointer) urec->uur_payload.data;
	}

	UndoRecordRelease(urec);
}


/*
 * ValidateTuplesXact - Check if the tuple is modified by priorXmax.
 *
 *	We need to traverse the undo chain of tuple to see if any of its
 *	prior version is modified by priorXmax.
 *
 *  nobuflock indicates whether caller has lock on the buffer 'buf'.
 */
bool
ValidateTuplesXact(ZHeapTuple tuple, Snapshot snapshot, Buffer buf,
				   TransactionId priorXmax, bool nobuflock)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleData	zhtup;
	UnpackedUndoRecord	*urec = NULL;
	UndoRecPtr		urec_ptr;
	ZHeapTuple	undo_tup = NULL;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	Page		page;
	TransactionId	xid;
	TransactionId	prev_undo_xid = InvalidTransactionId;
	int	trans_slot_id = InvalidXactSlotId;
	int	prev_trans_slot_id;
	bool		valid = false;

	/*
	 * As we are going to access special space in the page to retrieve the
	 * transaction information share lock on buffer is required.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(tid));

	zhtup.t_tableOid = tuple->t_tableOid;
	zhtup.t_self = *tid;

	if(ItemIdIsDead(lp) || !ItemIdHasStorage(lp))
	{
		/*
		 * If the tuple is already removed by Rollbacks/pruning, then we
		 * don't need to proceed further.
		 */
		if (nobuflock)
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		return false;
	}
	else if (!ItemIdIsDeleted(lp))
	{
		/*
		 * If the tuple is updated such that its transaction slot has been
		 * changed, then we will never be able to get the correct tuple from undo.
		 * To avoid, that we get the latest tuple from page rather than relying on
		 * it's in-memory copy.
		 */
		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);
		xid = ZHeapTupleHeaderGetRawXid(zhtup.t_data, opaque);
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup.t_data);
		urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(zhtup.t_data, opaque);
	}
	else
	{
		ZHeapTuple vis_tuple;
		trans_slot_id = ItemIdGetTransactionSlot(lp);
		xid = ZHeapPageGetRawXid(trans_slot_id, opaque);
		urec_ptr = ZHeapPageGetUndoPtr(trans_slot_id, opaque);

		/*
		 * XXX for now we shall get a visible undo tuple for the given
		 * dirty snapshot. The tuple data is needed below in
		 * CopyTupleFromUndoRecord and some undo records will not have
		 * tuple data and mask info with them.
		 * */
		vis_tuple = ZHeapGetVisibleTuple(ItemPointerGetOffsetNumber(tid),
										 snapshot, buf, NULL);
		Assert(vis_tuple != NULL);
		zhtup.t_data = vis_tuple->t_data;
		zhtup.t_len = vis_tuple->t_len;
	}

	if (TransactionIdEquals(xid, priorXmax))
	{
		valid = true;
		goto tuple_is_valid;
	}

	undo_tup = &zhtup;

	/*
	 * Current xid on tuple must not precede RecentGlobalXmin as it will be
	 * greater than priorXmax which was not visible to our snapshot.
	 */
	Assert(TransactionIdEquals(xid, InvalidTransactionId) ||
		   !TransactionIdPrecedes(xid, RecentGlobalXmin));

	do
	{
		prev_trans_slot_id = trans_slot_id;
		Assert(prev_trans_slot_id != ZHTUP_SLOT_FROZEN);

		urec = UndoFetchRecord(urec_ptr,
							   ItemPointerGetBlockNumber(&undo_tup->t_self),
							   ItemPointerGetOffsetNumber(&undo_tup->t_self),
							   prev_undo_xid,
							   NULL,
							   ZHeapSatisfyUndoRecord);

		/*
		 * As we still hold a snapshot to which priorXmax is not visible, neither
		 * the transaction slot on tuple can be marked as frozen nor the
		 * corresponding undo be discarded.
		 */
		Assert(urec != NULL);

		if (TransactionIdEquals(urec->uur_xid, priorXmax))
		{
			valid = true;
			goto tuple_is_valid;
		}

		/* don't free the tuple passed by caller */
		undo_tup = CopyTupleFromUndoRecord(urec, undo_tup,
										   (undo_tup) == (&zhtup) ? false : true);

		Assert(!TransactionIdPrecedes(urec->uur_prevxid, RecentGlobalXmin));

		trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
		prev_undo_xid = urec->uur_prevxid;

		/*
		 * Change the undo chain if the undo tuple is stamped with the different
		 * transaction slot.
		 */
		if (prev_trans_slot_id != trans_slot_id)
			urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(undo_tup->t_data, opaque);
		else
			urec_ptr = urec->uur_blkprev;

		UndoRecordRelease(urec);
		urec = NULL;
	} while (UndoRecPtrIsValid(urec_ptr));

tuple_is_valid:
	if (urec)
		UndoRecordRelease(urec);
	if (undo_tup && undo_tup != &zhtup)
		pfree(undo_tup);

	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

	return valid;
}

/*
 * Initialize zheap page.
 */
void
ZheapInitPage(Page page, Size pageSize)
{
	ZHeapPageOpaque	opaque;
	int				i;

	/*
	 * The size of the opaque space depends on the number of transaction
	 * slots in a page. We set it to default here.
	 */
	PageInit(page, pageSize, ZHEAP_PAGE_TRANS_SLOTS * sizeof(TransInfo));

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	for (i = 0; i < ZHEAP_PAGE_TRANS_SLOTS; i++)
	{
		opaque->transinfo[i].xid_epoch = 0;
		opaque->transinfo[i].xid = InvalidTransactionId;
		opaque->transinfo[i].urec_ptr = InvalidUndoRecPtr;
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

/* ----------------
 *		zheap_rescan		- similar to heap_rescan
 * ----------------
 */
void
zheap_rescan(HeapScanDesc scan,
			ScanKey key)
{
	/*
	 * unpin scan buffers
	 */
	if (BufferIsValid(scan->rs_cbuf))
		ReleaseBuffer(scan->rs_cbuf);

	/*
	 * reinitialize scan descriptor
	 */
	zinitscan(scan, key, true);
}

/* ----------------
 *		zheap_rescan_set_params	- similar to heap_rescan_set_params
 * ----------------
 */
void
zheap_rescan_set_params(HeapScanDesc scan, ScanKey key,
					   bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	/* adjust parameters */
	scan->rs_allow_strat = allow_strat;
	scan->rs_allow_sync = allow_sync;
	scan->rs_pageatatime = allow_pagemode && IsMVCCSnapshot(scan->rs_snapshot);
	/* ... and rescan */
	zheap_rescan(scan, key);
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
 * zheap_beginscan_strat - same as heap_beginscan_strat
 */
HeapScanDesc
zheap_beginscan_strat(Relation relation, Snapshot snapshot,
					int nkeys, ScanKey key,
					bool allow_strat, bool allow_sync)
{
	return zheap_beginscan_internal(relation, snapshot, nkeys, key, NULL,
									allow_strat, allow_sync, true,
									false, false, false);
}

/*
 * zheap_beginscan_sampling - same as zheap_beginscan_sampling
 */
HeapScanDesc
zheap_beginscan_sampling(Relation relation, Snapshot snapshot,
						int nkeys, ScanKey key,
						bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	return zheap_beginscan_internal(relation, snapshot, nkeys, key, NULL,
								   allow_strat, allow_sync, allow_pagemode,
								   false, true, false);
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
	scan->rs_ntuples = 0;

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
 *	zheap_beginscan_parallel - Same as heap_beginscan_parallel, except begins
 *	scan on zheap tables for parallel query.
 */
HeapScanDesc
zheap_beginscan_parallel(Relation relation, ParallelHeapScanDesc parallel_scan)
{
	Snapshot	snapshot;

	Assert(RelationGetRelid(relation) == parallel_scan->phs_relid);
	snapshot = RestoreSnapshot(parallel_scan->phs_snapshot_data);
	RegisterSnapshot(snapshot);

	return zheap_beginscan_internal(relation, snapshot, 0, NULL, parallel_scan,
								   true, true, true, false, false, true);
}

/*
 * zheapgetpage - Same as heapgetpage, but operate on zheap page and
 * in page-at-a-time mode, visible tuples are stored in rs_visztuples.
 */
void
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
		if (ItemIdIsNormal(lpp) || ItemIdIsDeleted(lpp))
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
			if (ItemIdIsDeleted(lpp))
			{
				if (all_visible)
				{
					valid = true;
					resulttup = NULL;
				}
				else
				{
					resulttup = ZHeapGetVisibleTuple(lineoff, snapshot, buffer,
													 NULL);
					valid = resulttup ? true : false;
				}
			}
			else
			{
				/*
				 * We always need to make a copy of zheap tuple as once we
				 * release the buffer, an in-place update can change the tuple.
				 */
				memcpy(loctup->t_data,
					   ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)),
					   loctup->t_len);

				if (all_visible)
				{
					valid = true;
					resulttup = loctup;
				}
				else
				{
					resulttup = ZHeapTupleSatisfiesVisibility(loctup, snapshot,
															  buffer, NULL);
					valid = resulttup ? true : false;
				}
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
					 ScanDirection dir)
{
	ZHeapTuple	tuple = scan->rs_cztup;
	bool		backward = ScanDirectionIsBackward(dir);
	BlockNumber page;
	bool		finished;
	int			lines;
	int			lineindex;
	int			linesleft;
	int			i = 0;

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
		/*
		 * In executor it seems NoMovementScanDirection is nothing but
		 * do-nothing flag so we should not be here. The else part is still
		 * here to keep the code as in heapgettup_pagemode.
		 */
		Assert(false);
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
		 * For now we shall free all of the zheap tuples stored in rs_visztuples.
		 * Later a better memory management is required.
		 */
		for (i = 0; i < scan->rs_ntuples; i++)
			zheap_freetuple(scan->rs_visztuples[i]);
		scan->rs_ntuples = 0;

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

/*
 * Similar to heapgettup, but for fetching zheap tuple.
 */
static ZHeapTuple
zheapgettup(HeapScanDesc scan,
		   ScanDirection dir)
{
	ZHeapTuple	tuple = scan->rs_cztup;
	Snapshot	snapshot = scan->rs_snapshot;
	bool		backward = ScanDirectionIsBackward(dir);
	BlockNumber page;
	bool		finished;
	Page		dp;
	int			lines;
	OffsetNumber lineoff;
	int			linesleft;
	ItemId		lpp;

	/*
	 * calculate next starting lineoff, given scan direction
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
				return NULL;
			}
			if (scan->rs_parallel != NULL)
			{
				page = heap_parallelscan_nextpage(scan);

				/* Other processes might have already finished the scan. */
				if (page == InvalidBlockNumber)
				{
					Assert(!BufferIsValid(scan->rs_cbuf));
					return NULL;
				}
			}
			else
				page = scan->rs_startblock;		/* first page */
			zheapgetpage(scan, page);
			lineoff = FirstOffsetNumber;		/* first offnum */
			scan->rs_inited = true;
		}
		else
		{
			/* continue from previously returned page/tuple */
			page = scan->rs_cblock;		/* current page */
			lineoff =			/* next offnum */
				OffsetNumberNext(ItemPointerGetOffsetNumber(&(tuple->t_self)));
		}

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_rd, dp);
		lines = PageGetMaxOffsetNumber(dp);
		/* page and lineoff now reference the physically next tid */

		linesleft = lines - lineoff + 1;
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
				return NULL;
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

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_rd, dp);
		lines = PageGetMaxOffsetNumber(dp);

		if (!scan->rs_inited)
		{
			lineoff = lines;	/* final offnum */
			scan->rs_inited = true;
		}
		else
		{
			lineoff =			/* previous offnum */
				OffsetNumberPrev(ItemPointerGetOffsetNumber(&(tuple->t_self)));
		}
		/* page and lineoff now reference the physically previous tid */

		linesleft = lineoff;
	}
	else
	{
		/*
		 * In executor it seems NoMovementScanDirection is nothing but
		 * do-nothing flag so we should not be here. The else part is still
		 * here to keep the code as in heapgettup_pagemode.
		 */
		Assert(false);

		return NULL;
	}

	/*
	 * advance the scan until we find a qualifying tuple or run out of stuff
	 * to scan
	 */
	lpp = PageGetItemId(dp, lineoff);
	for (;;)
	{
		while (linesleft > 0)
		{
			if (ItemIdIsNormal(lpp))
			{
				ZHeapTuple	tuple;
				ZHeapTuple loctup;
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

				tuple = ZHeapTupleSatisfiesVisibility(loctup, snapshot, scan->rs_cbuf, NULL);
				valid = tuple ? true : false;

				/* FIXME - Serialization failures needs to be detected for zheap. */
				/* CheckForSerializableConflictOut(valid, scan->rs_rd, &loctup,
												buffer, snapshot); */

				if (valid)
				{
					LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
					return tuple;
				}
			}

			/*
			 * otherwise move to the next item on the page
			 */
			--linesleft;
			if (backward)
			{
				--lpp;			/* move back in this page's ItemId array */
				--lineoff;
			}
			else
			{
				++lpp;			/* move forward in this page's ItemId array */
				++lineoff;
			}
		}

		/*
		 * if we get here, it means we've exhausted the items on this page and
		 * it's time to move to the next.
		 */
		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

		/*
		 * advance to next/prior page and detect end of scan
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
			scan->rs_inited = false;
			return NULL;
		}

		zheapgetpage(scan, page);

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		dp = BufferGetPage(scan->rs_cbuf);
		TestForOldSnapshot(snapshot, scan->rs_rd, dp);
		lines = PageGetMaxOffsetNumber((Page) dp);
		linesleft = lines;
		if (backward)
		{
			lineoff = lines;
			lpp = PageGetItemId(dp, lines);
		}
		else
		{
			lineoff = FirstOffsetNumber;
			lpp = PageGetItemId(dp, FirstOffsetNumber);
		}
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

	/*
	 * The key will be passed only for catalog table scans and catalog tables
	 * are always a heap table!. So incase of zheap it should be set to NULL.
	 */
	Assert (scan->rs_key == NULL);

	if (scan->rs_pageatatime)
		zhtup = zheapgettup_pagemode(scan, direction);
	else
		zhtup = zheapgettup(scan, direction);

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
 *	zheap_search_buffer - search tuple satisfying snapshot
 *
 * On entry, *tid is the TID of a tuple, and buffer is the buffer holding
 * this tuple.  We search for the first visible member satisfying the given
 * snapshot. If one is found, we return the tuple, in addition to updating
 * *tid. Return NULL otherwise.
 *
 * The caller must already have pin and (at least) share lock on the buffer;
 * it is still pinned/locked at exit.  Also, We do not report any pgstats
 * count; caller may do so if wanted.
 */
ZHeapTuple
zheap_search_buffer(ItemPointer tid, Relation relation, Buffer buffer,
					Snapshot snapshot, bool *all_dead)
{
	Page		dp = (Page) BufferGetPage(buffer);
	ItemId		lp;
	OffsetNumber offnum;
	ZHeapTuple	loctup;
	ZHeapTupleData	loctup_tmp;
	ZHeapTuple	resulttup = NULL;
	Size		loctup_len;

	if (all_dead)
		*all_dead = false;

	Assert(ItemPointerGetBlockNumber(tid) == BufferGetBlockNumber(buffer));
	offnum = ItemPointerGetOffsetNumber(tid);
	/* check for bogus TID */
	if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(dp))
		return NULL;

	lp = PageGetItemId(dp, offnum);

	/* check for unused or dead items */
	if (!(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp)))
	{
		if (all_dead)
			*all_dead = true;
		return NULL;
	}

	/*
	 * If the record is deleted, its place in the page might have been taken
	 * by another of its kind. Try to get it from the UNDO if it is still
	 * visible.
	 */
	if (ItemIdIsDeleted(lp))
	{
		resulttup = ZHeapGetVisibleTuple(offnum, snapshot, buffer, all_dead);
	}
	else
	{
		loctup_len = ItemIdGetLength(lp);

		loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
		loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

		loctup->t_tableOid = RelationGetRelid(relation);
		loctup->t_len = loctup_len;
		loctup->t_self = *tid;

		/*
		 * We always need to make a copy of zheap tuple as once we release the
		 * buffer an in-place update can change the tuple.
		 */
		memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lp)), loctup->t_len);

		/* If it's visible per the snapshot, we must return it */
		resulttup = ZHeapTupleSatisfiesVisibility(loctup, snapshot, buffer, NULL);
	}

	/* Fixme - Serialization failures needs to be detected for zheap. */
	/* CheckForSerializableConflictOut(valid, relation, zheapTuple,
									buffer, snapshot); */

	if (resulttup)
	{
		/* set the tid */
		*tid = resulttup->t_self;
	}
	else if (!ItemIdIsDeleted(lp))
	{
		/*
		 * Temporarily get the copy of tuple from page to check if tuple is
		 * surely dead.  We can't rely on the copy of local tuple (loctup)
		 * that is prepared for the visibility test as that would have been
		 * freed.
		 */
		loctup_tmp.t_tableOid = RelationGetRelid(relation);
		loctup_tmp.t_data = (ZHeapTupleHeader) PageGetItem((Page) dp, lp);
		loctup_tmp.t_len = ItemIdGetLength(lp);
		loctup_tmp.t_self = *tid;

		/*
		 * If we can't see it, maybe no one else can either.  At caller
		 * request, check whether tuple is dead to all transactions.
		 */
		if (!resulttup && all_dead &&
			ZHeapTupleIsSurelyDead(&loctup_tmp,
								   pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo),
								   buffer))
			*all_dead = true;
	}
	else
	{
		/* For deleted item pointers, we've already set the value for all_dead. */
		return NULL;
	}

	return resulttup;
}

/*
 * zheap_search - search for a zheap tuple satisfying snapshot.
 *
 * This is the same API as zheap_search_buffer, except that the caller
 * does not provide the buffer containing the page, rather we access it
 * locally.
 */
bool
zheap_search(ItemPointer tid, Relation relation, Snapshot snapshot,
			 bool *all_dead)
{
	Buffer	buffer;
	ZHeapTuple	zheapTuple = NULL;

	buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);
	zheapTuple = zheap_search_buffer(tid, relation, buffer, snapshot, all_dead);
	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return (zheapTuple != NULL);
}

/*
 * zheap_fetch - Fetch a tuple based on TID.
 *
 *	This function is quite similar to heap_fetch with few differences like
 *	it will always allocate the memory for tuple and do a memcpy of the tuple
 *	instead of pointing it to disk tuple.  It is the responsibility of the
 *	caller to free the tuple.
 */
bool
zheap_fetch(Relation relation,
			Snapshot snapshot,
			ItemPointer tid,
			ZHeapTuple *tuple,
			Buffer *userbuf,
			bool keep_buf,
			Relation stats_relation)
{
	ZHeapTuple	resulttup;
	ItemId		lp;
	Buffer		buffer;
	Page		page;
	Size		tup_len;
	OffsetNumber offnum;
	bool		valid;
	ItemPointerData	ctid;

	/*
	 * Fetch and pin the appropriate page of the relation.
	 */
	buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

	/*
	 * Need share lock on buffer to examine tuple commit status.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);
	page = BufferGetPage(buffer);

	/*
	 * We'd better check for out-of-range offnum in case of VACUUM since the
	 * TID was obtained.
	 */
	offnum = ItemPointerGetOffsetNumber(tid);
	if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(page))
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		if (keep_buf)
			*userbuf = buffer;
		else
		{
			ReleaseBuffer(buffer);
			*userbuf = InvalidBuffer;
		}
		*tuple = NULL;
		return false;
	}

	/*
	 * get the item line pointer corresponding to the requested tid
	 */
	lp = PageGetItemId(page, offnum);

	/*
	 * Must check for dead and unused items.
	 */
	if (!ItemIdIsNormal(lp) && !ItemIdIsDeleted(lp))
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		if (keep_buf)
			*userbuf = buffer;
		else
		{
			ReleaseBuffer(buffer);
			*userbuf = InvalidBuffer;
		}
		*tuple = NULL;
		return false;
	}

	if (ItemIdIsDeleted(lp))
	{
		CommandId		tup_cid;
		TransactionId	tup_xid;

		*tuple = ZHeapGetVisibleTuple(offnum, snapshot, buffer, NULL);
		ctid = *tid;
		ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
		resulttup = *tuple;
		valid = resulttup ? true : false;
	}
	else
	{
		/*
		 * fill in *tuple fields
		 */
		tup_len = ItemIdGetLength(lp);

		*tuple = palloc(ZHEAPTUPLESIZE + tup_len);
		(*tuple)->t_data = (ZHeapTupleHeader) ((char *) (*tuple) + ZHEAPTUPLESIZE);

		(*tuple)->t_tableOid = RelationGetRelid(relation);
		(*tuple)->t_len = tup_len;
		(*tuple)->t_self = *tid;

		/*
		 * We always need to make a copy of zheap tuple as once we release
		 * the lock on buffer an in-place update can change the tuple.
		 */
		memcpy((*tuple)->t_data, ((ZHeapTupleHeader) PageGetItem(page, lp)), tup_len);
		ItemPointerSetInvalid(&ctid);

		/*
		 * check time qualification of tuple, then release lock
		 */
		resulttup = ZHeapTupleSatisfiesVisibility(*tuple, snapshot, buffer, &ctid);
		valid = resulttup ? true : false;
	}

	/*
	 * Pass back the ctid if the tuple is invisible because it was updated.
	 * Apart from SnapshotAny, ctid must be changed only when current
	 * tuple in not visible.
	 */
	if (ItemPointerIsValid(&ctid))
	{
		if (snapshot == SnapshotAny || !valid)
		{
			*tid = ctid;
		}
	}

	/*
	 * Fixme - Serializable isolation level is not supportted for zheap tuples
	 */
	/* if (valid)
		PredicateLockTuple(relation, tuple, snapshot);

	CheckForSerializableConflictOut(valid, relation, tuple, buffer, snapshot);*/

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	if (valid)
	{
		/*
		 * All checks passed, so return the tuple as valid. Caller is now
		 * responsible for releasing the buffer.
		 */
		*userbuf = buffer;
		*tuple = resulttup;

		/* Count the successful fetch against appropriate rel, if any */
		if (stats_relation != NULL)
			pgstat_count_heap_fetch(stats_relation);

		return true;
	}

	/* Tuple failed time qual, but maybe caller wants to see it anyway. */
	if (keep_buf)
		*userbuf = buffer;
	else
	{
		ReleaseBuffer(buffer);
		*userbuf = InvalidBuffer;
	}

	return false;
}

/*
 * zheap_fetch_undo_guts
 *
 * Main function for fetching the previous version of the tuple from the undo
 * storage.
 */
ZHeapTuple
zheap_fetch_undo_guts(ZHeapTuple ztuple, Buffer buffer, ItemPointer tid)
{
	UnpackedUndoRecord	*urec;
	ZHeapPageOpaque	opaque;
	UndoRecPtr	urec_ptr;
	ZHeapTuple	undo_tup;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));
	urec_ptr = ZHeapTupleHeaderGetRawUndoPtr(ztuple->t_data, opaque);

	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(tid),
						   ItemPointerGetOffsetNumber(tid),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/*
	 * This function is used for trigger to retrieve previous version of the
	 * tuple from undolog. Since, the transaction that is updating the tuple
	 * is still in progress, neither undo record can be discarded nor it's
	 * transaction slot can be reused.
	 */
	Assert(urec != NULL);
	Assert(urec->uur_type == UNDO_INPLACE_UPDATE);

	undo_tup = CopyTupleFromUndoRecord(urec, NULL, false);
	UndoRecordRelease(urec);

	return undo_tup;
}

/*
 * zheap_fetch_undo
 *
 * Fetch the previous version of the tuple from the undo. In case of IN_PLACE
 * update old tuple and new tuple has the same TID. And, trigger just
 * stores the tid for fetching the old and new tuple so for fetching the older
 * tuple this function should be called.
 */
bool
zheap_fetch_undo(Relation relation,
				 Snapshot snapshot,
				 ItemPointer tid,
				 ZHeapTuple *tuple,
				 Buffer *userbuf,
				 Relation stats_relation)
{
	ZHeapTuple	undo_tup;
	Buffer		buffer;

	if (!zheap_fetch(relation, snapshot, tid, tuple, &buffer, true, NULL))
		return false;

	undo_tup = zheap_fetch_undo_guts(*tuple, buffer, tid);
	zheap_freetuple(*tuple);
	*tuple = undo_tup;

	ReleaseBuffer(buffer);

	return true;
}

/*
 * ZHeapTupleHeaderAdvanceLatestRemovedXid - Advance the latestremovexid, if
 * tuple is deleted by a transaction greater than latestremovexid.  This is
 * required to generate conflicts on Hot Standby.
 *
 * If we change this function then we need a similar change in
 * *_xlog_vacuum_get_latestRemovedXid functions as well.
 *
 * This is quite similar to HeapTupleHeaderAdvanceLatestRemovedXid.
 */
void
ZHeapTupleHeaderAdvanceLatestRemovedXid(ZHeapTupleHeader tuple,
										TransactionId xid,
										TransactionId *latestRemovedXid)
{
	Assert (tuple->t_infomask & ZHEAP_DELETED ||
		tuple->t_infomask & ZHEAP_UPDATED);

	/*
	 * Ignore tuples inserted by an aborted transaction.
	 *
	 * XXX we can ignore the tuple if it was non-in-place updated/deleted
	 * by the inserting transaction, but for that we need to traverse the
	 * complete undo chain to find the root tuple, is it really worth?
	 */
	if (TransactionIdDidCommit(xid))
	{
		if (TransactionIdFollows(xid, *latestRemovedXid))
			*latestRemovedXid = xid;
	}

	/* *latestRemovedXid may still be invalid at end */
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
 *	be accomodated on a page and alignment for each item.  It also
 *	additionally handles the itemids that are marked as unused, but still
 *	can't be reused.
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
			bool	hasPendingXact = false;

			/*
			 * Look for "recyclable" (unused) ItemId.  We check for no storage
			 * as well, just to be paranoid --- unused items should never have
			 * storage.
			 */
			for (offsetNumber = 1; offsetNumber < limit; offsetNumber++)
			{
				itemId = PageGetItemId(phdr, offsetNumber);
				if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
				{
					/*
					 * We allow Unused entries to be reused only if there is no
					 * transaction information for the entry or the transaction
					 * is committed.
					 */
					if (ItemIdHasPendingXact(itemId))
					{
						TransactionId	xid;
						ZHeapPageOpaque	opaque;

						opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

						/*
						 * Here, we are relying on the transaction information in
						 * slot as if the corresponding slot has been reused, then
						 * transaction information from the entry would have been
						 * cleared.  See PageFreezeTransSlots.
						 */
						xid = ZHeapPageGetRawXid(ItemIdGetTransactionSlot(itemId), opaque);
						if (TransactionIdIsValid(xid) &&
							!TransactionIdDidCommit(xid))
						{
							hasPendingXact = true;
							continue;
						}
					}
					break;
				}
			}
			if (offsetNumber >= limit && !hasPendingXact)
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
 * This is same as PageGetHeapFreeSpace except for max tuples that can
 * be accomodated on a page or the way unused items are dealt.
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

					/*
					 * The unused items that have pending xact information
					 * can't be reused.
					 */
					if (!ItemIdIsUsed(lp) && !ItemIdHasPendingXact(lp))
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

/*
 * RelationPutZHeapTuple - Same as RelationPutHeapTuple, but for ZHeapTuple.
 */
static void
RelationPutZHeapTuple(Relation relation,
					  Buffer buffer,
					  ZHeapTuple tuple)
{
	OffsetNumber offnum;

	/* Add the tuple to the page */
	offnum = ZPageAddItem(BufferGetPage(buffer), (Item) tuple->t_data,
						  tuple->t_len, InvalidOffsetNumber, false, true);

	if (offnum == InvalidOffsetNumber)
		elog(PANIC, "failed to add tuple to page");

	/* Update tuple->t_self to the actual position where it was stored */
	ItemPointerSet(&(tuple->t_self), BufferGetBlockNumber(buffer), offnum);
}

/*
 * CopyTupleFromUndoRecord
 *	Extract the tuple from undo record.  Deallocate the previous version
 *	of tuple and form the new version.
 *
 *	free_zhtup - if true, free the previous version of tuple.
 */
ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						bool free_zhtup)
{
	ZHeapTuple	undo_tup;

	switch (urec->uur_type)
	{
		case UNDO_INSERT:
			{
				Assert(zhtup != NULL);

				/*
				 * We need to deal with undo of root tuple only for a special
				 * case where during non-inplace update operation, we
				 * propagate the lockers information to the freshly inserted
				 * tuple. But, we've to make sure the inserted tuple is locked only.
				 */
				Assert(ZHEAP_XID_IS_LOCKED_ONLY(zhtup->t_data->t_infomask));

				undo_tup = palloc(ZHEAPTUPLESIZE + zhtup->t_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				undo_tup->t_tableOid = zhtup->t_tableOid;
				undo_tup->t_len = zhtup->t_len;
				undo_tup->t_self = zhtup->t_self;
				memcpy(undo_tup->t_data, zhtup->t_data, zhtup->t_len);

				/*
				 * Ensure to clear the visibility related information from
				 * the tuple.  This is required for the cases where the passed
				 * in tuple has lock only flags set on it.
				 */
				undo_tup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;

				/*
				 * Free the previous version of tuple, see comments in
				 * UNDO_INPLACE_UPDATE case.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);
			}
			break;
		case UNDO_XID_LOCK_ONLY:
		case UNDO_XID_MULTI_LOCK_ONLY:
			{
				ZHeapTupleHeader	undo_tup_hdr;

				Assert(zhtup != NULL);

				undo_tup_hdr = (ZHeapTupleHeader) urec->uur_tuple.data;

				/*
				 * For locked tuples, undo tuple data is always same as prior
				 * tuple's data as we don't modify it.
				 */
				undo_tup = palloc(ZHEAPTUPLESIZE + zhtup->t_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				undo_tup->t_tableOid = zhtup->t_tableOid;
				undo_tup->t_len = zhtup->t_len;
				undo_tup->t_self = zhtup->t_self;
				memcpy(undo_tup->t_data, zhtup->t_data, zhtup->t_len);

				/*
				 * Free the previous version of tuple, see comments in
				 * UNDO_INPLACE_UPDATE case.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);

				/*
				 * override the tuple header values with values fetched from
				 * undo record
				 */
				undo_tup->t_data->t_infomask2 = undo_tup_hdr->t_infomask2;
				undo_tup->t_data->t_infomask = undo_tup_hdr->t_infomask;
				undo_tup->t_data->t_hoff = undo_tup_hdr->t_hoff;
			}
			break;
		case UNDO_DELETE:
		case UNDO_UPDATE:
		case UNDO_INPLACE_UPDATE:
			{
				Size		offset = 0;
				uint32		undo_tup_len;

				/*
				 * After this point, the previous version of tuple won't be used.
				 * If we don't free the previous version, then we might accumulate
				 * lot of memory when many prior versions needs to be traversed.
				 *
				 * XXX One way to save deallocation and allocation of memory is to
				 * only make a copy of prior version of tuple when it is determined
				 * that the version is visible to current snapshot.  In practise,
				 * we don't need to traverse many prior versions, so let's be tidy.
				 */
				undo_tup_len = *((uint32 *) &urec->uur_tuple.data[offset]);

				undo_tup = palloc(ZHEAPTUPLESIZE + undo_tup_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				memcpy(&undo_tup->t_len, &urec->uur_tuple.data[offset], sizeof(uint32));
				offset += sizeof(uint32);

				memcpy(&undo_tup->t_self, &urec->uur_tuple.data[offset], sizeof(ItemPointerData));
				offset += sizeof(ItemPointerData);

				memcpy(&undo_tup->t_tableOid, &urec->uur_tuple.data[offset], sizeof(Oid));
				offset += sizeof(Oid);

				memcpy(undo_tup->t_data, (ZHeapTupleHeader) &urec->uur_tuple.data[offset], undo_tup_len);

				if (free_zhtup)
					zheap_freetuple(zhtup);
			}
			break;
		default:
			elog(ERROR, "unsupported undo record type");
			/*
			 * During tests, we take down the server to notice the error easily.
			 * This can be removed later.
			 */
			Assert(0);
	}

	return undo_tup;
}

/*
 * ZHeapGetUsableOffsetRanges
 *
 * Given a page and a set of tuples, it calculates how many tuples can fit in
 * the page and the contiguous ranges of free offsets that can be used/reused
 * in the same page to store those tuples.
 */
ZHeapFreeOffsetRanges *
ZHeapGetUsableOffsetRanges(Buffer buffer,
						   ZHeapTuple *tuples,
						   int ntuples,
						   Size saveFreeSpace)
{
	Page			page;
	PageHeader		phdr;
	int				nthispage;
	Size			used_space;
	Size			avail_space;
	OffsetNumber 	limit, offsetNumber;
	ZHeapFreeOffsetRanges	*zfree_offset_ranges;

	page = BufferGetPage(buffer);
	phdr = (PageHeader) page;

	zfree_offset_ranges = (ZHeapFreeOffsetRanges *)
							palloc0(sizeof(ZHeapFreeOffsetRanges));

	zfree_offset_ranges->nranges = 0;
	limit = OffsetNumberNext(PageGetMaxOffsetNumber(page));
	avail_space = PageGetExactFreeSpace(page);
	nthispage = 0;
	used_space = 0;

	if (PageHasFreeLinePointers(phdr))
	{
		bool in_range = false;
		/*
		 * Look for "recyclable" (unused) ItemId.  We check for no storage
		 * as well, just to be paranoid --- unused items should never have
		 * storage.
		 */
		for (offsetNumber = 1; offsetNumber < limit; offsetNumber++)
		{
			ItemId itemId = PageGetItemId(phdr, offsetNumber);

			if (nthispage >= ntuples)
			{
				/* No more tuples to insert */
				break;
			}
			if (!ItemIdIsUsed(itemId) && !ItemIdHasStorage(itemId))
			{
				ZHeapTuple zheaptup = tuples[nthispage];
				Size needed_space = used_space + MAXALIGN(zheaptup->t_len) + saveFreeSpace;

				/* Check if we can fit this tuple in the page */
				if (avail_space < needed_space)
				{
					/* No more space to insert tuples in this page */
					break;
				}

				used_space += MAXALIGN(zheaptup->t_len);
				nthispage++;

				if (!in_range)
				{
					/* Start of a new range */
					zfree_offset_ranges->nranges++;
					zfree_offset_ranges->startOffset[zfree_offset_ranges->nranges - 1] = offsetNumber;
					in_range = true;
				}
				zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1] = offsetNumber;
			}
			else
			{
				in_range = false;
			}
		}
	}

	/*
	 * Now, there are no free line pointers. Check whether we can insert another
	 * tuple in the page, then we'll insert another range starting from limit to
	 * max offset number. We can decide the actual end offset for this range while
	 * inserting tuples in the buffer.
	 */
	if ((limit <= MaxZHeapTuplesPerPage) && (nthispage < ntuples))
	{
		ZHeapTuple zheaptup = tuples[nthispage];
		Size needed_space = used_space + sizeof(ItemIdData) +
			MAXALIGN(zheaptup->t_len) + saveFreeSpace;

		/* Check if we can fit this tuple + a new offset in the page */
		if (avail_space >= needed_space)
		{
			zfree_offset_ranges->nranges++;
			zfree_offset_ranges->startOffset[zfree_offset_ranges->nranges - 1] = limit;
			zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1] = MaxOffsetNumber;
		}
	}

	return zfree_offset_ranges;
}

/*
 *	zheap_multi_insert	- insert multiple tuple into a zheap
 *
 * Similar to heap_multi_insert(), but inserts zheap tuples.
 */
void
zheap_multi_insert(Relation relation, ZHeapTuple *tuples, int ntuples,
				  CommandId cid, int options, BulkInsertState bistate)
{
	ZHeapTuple	*zheaptuples;
	int			i;
	int			ndone;
	char	   *scratch = NULL;
	Page		page;
	bool		needwal;
	bool		need_tuple_data = RelationIsLogicallyLogged(relation);
	bool		need_cids = RelationIsAccessibleInLogicalDecoding(relation);
	Size		saveFreeSpace;
	TransactionId	xid = GetTopTransactionId();
	uint32		epoch = GetEpochForXid(xid);
	xl_undolog_meta	undometa;
	bool		lock_reacquired;

	needwal = !(options & HEAP_INSERT_SKIP_WAL) && RelationNeedsWAL(relation);
	saveFreeSpace = RelationGetTargetPageFreeSpace(relation,
												   HEAP_DEFAULT_FILLFACTOR);

	/* Toast and set header data in all the tuples */
	zheaptuples = palloc(ntuples * sizeof(ZHeapTuple));
	for (i = 0; i < ntuples; i++)
		zheaptuples[i] = zheap_prepare_insert(relation, tuples[i], options);

	/*
	 * Allocate some memory to use for constructing the WAL record. Using
	 * palloc() within a critical section is not safe, so we allocate this
	 * beforehand. This has consideration that offset ranges and tuples to be
	 * stored in page will have size lesser than BLCKSZ. This is true since a
	 * zheap page contains page header and transaction slots in special area
	 * which are not stored in scratch area. In future, if we reduce the number
	 * of transaction slots to one, we may need to allocate twice the BLCKSZ of
	 * scratch area.
	 */
	if (needwal)
		scratch = palloc(BLCKSZ);

	/*
	 * See heap_multi_insert to know why checking conflicts is important
	 * before actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	ndone = 0;
	while (ndone < ntuples)
	{
		Buffer	buffer;
		Buffer	vmbuffer = InvalidBuffer;
		bool	all_visible_cleared = false;
		int		nthispage = 0;
		int		trans_slot_id;
		UndoRecPtr		urecptr,
						prev_urecptr;
		UnpackedUndoRecord		*undorecord;
		ZHeapFreeOffsetRanges	*zfree_offset_ranges;
		bool	undometa_fetched = false;

		CHECK_FOR_INTERRUPTS();

reacquire_buffer:
		/*
		 * Find buffer where at least the next tuple will fit.  If the page is
		 * all-visible, this will also pin the requisite visibility map page.
		 */
		buffer = RelationGetBufferForTuple(relation, zheaptuples[ndone]->t_len,
										   InvalidBuffer, options, bistate,
										   &vmbuffer, NULL);
		page = BufferGetPage(buffer);

		/*
		 * The transaction information of tuple needs to be set in transaction
		 * slot, so needs to reserve the slot before proceeding with the actual
		 * operation.  It will be costly to wait for getting the slot, but we do
		 * that by releasing the buffer lock.
		 */
		trans_slot_id = PageReserveTransactionSlot(relation, buffer, epoch, xid,
											&prev_urecptr, &lock_reacquired);
		if (lock_reacquired)
			goto reacquire_buffer;

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

		/*
		 * RelationGetBufferForTuple has ensured that the first tuple fits.
		 * Keep calm and put that on the page, and then as many other tuples
		 * as fit.
		 */
		if ((options & ZHTUP_SLOT_FROZEN) != ZHTUP_SLOT_FROZEN)
			ZHeapTupleHeaderSetXactSlot(zheaptuples[ndone]->t_data, trans_slot_id);

		/*
		 * Get the unused offset ranges in the page. This is required for
		 * deciding the number of undo records to be prepared later.
		 */
		zfree_offset_ranges = ZHeapGetUsableOffsetRanges(buffer,
													  &zheaptuples[ndone],
													  ntuples - ndone,
													  saveFreeSpace);

		/*
		 * We've ensured at least one tuple fits in the page. So, there'll be
		 * at least one offset range.
		 */
		Assert(zfree_offset_ranges->nranges > 0);

		/*
		 * For every contiguous free or new offsets, we insert an undo record.
		 * In the payload data of each undo record, we store the start and end
		 * available offset for a contiguous range.
		 */
		undorecord = (UnpackedUndoRecord *) palloc(zfree_offset_ranges->nranges
												   * sizeof(UnpackedUndoRecord));
		/* Start UNDO prepare Stuff */
		urecptr = prev_urecptr;

		UndoSetPrepareSize(zfree_offset_ranges->nranges);

		for (i = 0; i < zfree_offset_ranges->nranges; i++)
		{
			/* prepare an undo record */
			undorecord[i].uur_type = UNDO_MULTI_INSERT;
			undorecord[i].uur_info = 0;
			undorecord[i].uur_prevlen = 0;	/* Fixme - need to figure out how to set this value and then decide whether to WAL log it */
			undorecord[i].uur_relfilenode = relation->rd_node.relNode;
			undorecord[i].uur_xid = xid;
			undorecord[i].uur_cid = cid;
			undorecord[i].uur_tsid = relation->rd_node.spcNode;
			undorecord[i].uur_fork = MAIN_FORKNUM;
			undorecord[i].uur_blkprev = urecptr;
			undorecord[i].uur_block = BufferGetBlockNumber(buffer);
			undorecord[i].uur_tuple.len = 0;
			undorecord[i].uur_offset = 0;
			undorecord[i].uur_payload.len = 2 * sizeof(OffsetNumber);

			urecptr = PrepareUndoInsert(&undorecord[i],
										UndoPersistenceForRelation(relation),
										InvalidTransactionId,
										undometa_fetched ? NULL : &undometa);
			initStringInfo(&undorecord[i].uur_payload);
			undometa_fetched = true;
		}
		Assert(UndoRecPtrIsValid(urecptr));
		elog(DEBUG1, "Undo record prepared: %d for Block Number: %d",
			 zfree_offset_ranges->nranges, BufferGetBlockNumber(buffer));
		/* End UNDO prepare Stuff */

		/* NO EREPORT(ERROR) from here till changes are logged */
		START_CRIT_SECTION();

		nthispage = 0;
		for (i = 0; i < zfree_offset_ranges->nranges; i++)
		{
			OffsetNumber offnum, endoffnum;
			for (offnum = zfree_offset_ranges->startOffset[i];
				 offnum <= zfree_offset_ranges->endOffset[i]; offnum++)
			{
				ZHeapTuple	zheaptup;

				if (ndone + nthispage == ntuples)
					break;

				zheaptup = zheaptuples[ndone + nthispage];

				/* Make sure that the tuple fits in the page. */
				if (PageGetZHeapFreeSpace(page) < MAXALIGN(zheaptup->t_len) + saveFreeSpace)
					break;

				if ((options & ZHTUP_SLOT_FROZEN) != ZHTUP_SLOT_FROZEN)
					ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, trans_slot_id);

				RelationPutZHeapTuple(relation, buffer, zheaptup);

				/*
				 * Let's make sure that we've decided the offset ranges
				 * correctly.
				 */
				Assert(offnum == ItemPointerGetOffsetNumber(&(zheaptup->t_self)));

				/*
				 * We don't use heap_multi_insert for catalog tuples yet, but
				 * better be prepared...
				 * Fixme: This won't work as it needs to access cmin/cmax which
				 * we probably needs to retrieve from TPD or UNDO.
				 */
				 if (needwal && need_cids)
				 {
					/* log_heap_new_cid(relation, heaptup); */
				 }
				 nthispage++;
			}

			/*
			 * Store the offset ranges in undo payload. We've not calculated the
			 * end offset for the last range previously. Hence, we set it to
			 * offnum - 1. There is no harm in doing the same for previous undo
			 * records as well.
			 */
			endoffnum = offnum - 1;
			appendBinaryStringInfo(&undorecord[i].uur_payload,
										   (char *) &zfree_offset_ranges->startOffset[i],
										   sizeof(OffsetNumber));
			appendBinaryStringInfo(&undorecord[i].uur_payload,
										  (char *) &endoffnum,
										   sizeof(OffsetNumber));
			elog(DEBUG1, "start offset: %d, end offset: %d",
				 zfree_offset_ranges->startOffset[i], endoffnum);
		}

		if (PageIsAllVisible(page))
		{
			all_visible_cleared = true;
			PageClearAllVisible(page);
			visibilitymap_clear(relation,
								BufferGetBlockNumber(buffer),
								vmbuffer, VISIBILITYMAP_VALID_BITS);
		}

		/*
		 * XXX Should we set PageSetPrunable on this page ? See heap_insert()
		 */

		MarkBufferDirty(buffer);

		/* Insert the undo */
		InsertPreparedUndo();

		/*
		 * We're sending the undo record for debugging purpose. So, just send
		 * the last one.
		 */
		PageSetUNDO(undorecord[zfree_offset_ranges->nranges - 1],
					page,
					trans_slot_id,
					epoch,
					xid,
					urecptr);

		/*
		 * XLOG stuff
		 *
		 */
		if (needwal)
		{
			xl_undo_header	xlundohdr;
			XLogRecPtr	recptr;
			xl_zheap_multi_insert *xlrec;
			uint8		info = XLOG_ZHEAP_MULTI_INSERT;
			char	   *tupledata;
			int			totaldatalen;
			char	   *scratchptr = scratch;
			bool		init;
			int			bufflags = 0;
			XLogRecPtr	RedoRecPtr;
			bool		doPageWrites;

			/*
			 * Store the information required to generate undo record during
			 * replay. All undo records have same information apart from the
			 * payload data. Hence, we can copy the same from the last record.
			 */
			xlundohdr.relfilenode = undorecord[zfree_offset_ranges->nranges - 1].uur_relfilenode;
			xlundohdr.tsid = undorecord[zfree_offset_ranges->nranges - 1].uur_tsid;
			xlundohdr.urec_ptr = urecptr;
			xlundohdr.blkprev = prev_urecptr;

			/* allocate xl_zheap_multi_insert struct from the scratch area */
			xlrec = (xl_zheap_multi_insert *) scratchptr;
			xlrec->flags = all_visible_cleared ? XLZ_INSERT_ALL_VISIBLE_CLEARED : 0;
			xlrec->ntuples = nthispage;
			scratchptr += SizeOfZHeapMultiInsert;

			/* copy the offset ranges as well */
			memcpy((char *)scratchptr, (char *)&zfree_offset_ranges->nranges, sizeof(int));
			scratchptr += sizeof(int);
			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				memcpy((char *)scratchptr, (char *)undorecord[i].uur_payload.data, undorecord[i].uur_payload.len);
				scratchptr += undorecord[i].uur_payload.len;
			}

			/* the rest of the scratch space is used for tuple data */
			tupledata = scratchptr;

			/*
			 * Write out an xl_multi_insert_tuple and the tuple data itself
			 * for each tuple.
			 */
			for (i = 0; i < nthispage; i++)
			{
				ZHeapTuple	zheaptup = zheaptuples[ndone + i];
				xl_multi_insert_ztuple *tuphdr;
				int			datalen;

				/* xl_multi_insert_tuple needs two-byte alignment. */
				tuphdr = (xl_multi_insert_ztuple *) SHORTALIGN(scratchptr);
				scratchptr = ((char *) tuphdr) + SizeOfMultiInsertZTuple;

				tuphdr->t_infomask2 = zheaptup->t_data->t_infomask2;
				tuphdr->t_infomask = zheaptup->t_data->t_infomask;
				tuphdr->t_hoff = zheaptup->t_data->t_hoff;

				/* write bitmap [+ padding] [+ oid] + data */
				datalen = zheaptup->t_len - SizeofZHeapTupleHeader;
				memcpy(scratchptr,
					   (char *) zheaptup->t_data + SizeofZHeapTupleHeader,
					   datalen);
				tuphdr->datalen = datalen;
				scratchptr += datalen;
			}
			totaldatalen = scratchptr - tupledata;
			Assert((scratchptr - scratch) < BLCKSZ);

			if (need_tuple_data)
				xlrec->flags |= XLZ_INSERT_CONTAINS_NEW_TUPLE;

			/*
			 * Signal that this is the last xl_zheap_multi_insert record
			 * emitted by this call to zheap_multi_insert(). Needed for logical
			 * decoding so it knows when to cleanup temporary data.
			 */
			if (ndone + nthispage == ntuples)
				xlrec->flags |= XLZ_INSERT_LAST_IN_MULTI;

			/*
			 * If the page was previously empty, we can reinit the page
			 * instead of restoring the whole thing.
			 */
			init = (ItemPointerGetOffsetNumber(&(zheaptuples[ndone]->t_self)) == FirstOffsetNumber &&
					PageGetMaxOffsetNumber(page) == FirstOffsetNumber + nthispage - 1);

			if (init)
			{
				info |= XLOG_ZHEAP_INIT_PAGE;
				bufflags |= REGBUF_WILL_INIT;
			}

			/*
			 * If we're doing logical decoding, include the new tuple data
			 * even if we take a full-page image of the page.
			 */
			if (need_tuple_data)
				bufflags |= REGBUF_KEEP_DATA;

prepare_xlog:
			/* LOG undolog meta if this is the first WAL after the checkpoint. */
			LogUndoMetaData(&undometa);
			GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

			XLogBeginInsert();
			/* copy undo related info in maindata */
			XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
			/* copy xl_multi_insert_tuple in maindata */
			XLogRegisterData((char *) xlrec, tupledata - scratch);
			XLogRegisterBuffer(0, buffer, REGBUF_STANDARD | bufflags);

			/* copy tuples in block data */
			XLogRegisterBufData(0, tupledata, totaldatalen);

			/* filtering by origin on a row level is much more efficient */
			XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

			recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr,
										doPageWrites);
			if (recptr == InvalidXLogRecPtr)
				goto prepare_xlog;

			PageSetLSN(page, recptr);
		}

		END_CRIT_SECTION();

		/* be tidy */
		for (i = 0; i < zfree_offset_ranges->nranges; i++)
			pfree(undorecord[i].uur_payload.data);
		pfree(zfree_offset_ranges);
		pfree(undorecord);

		UnlockReleaseBuffer(buffer);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		UnlockReleaseUndoBuffers();

		ndone += nthispage;
	}

	/*
	 * We're done with the actual inserts.  Check for conflicts again, to
	 * ensure that all rw-conflicts in to these inserts are detected.  Without
	 * this final check, a sequential scan of the heap may have locked the
	 * table after the "before" check, missing one opportunity to detect the
	 * conflict, and then scanned the table before the new tuples were there,
	 * missing the other chance to detect the conflict.
	 *
	 * For heap inserts, we only need to check for table-level SSI locks. Our
	 * new tuples can't possibly conflict with existing tuple locks, and heap
	 * page locks are only consolidated versions of tuple locks; they do not
	 * lock "gaps" as index page locks do.  So we don't need to specify a
	 * buffer when making the call.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	/*
	 * If tuples are cachable, mark them for invalidation from the caches in
	 * case we abort.  Note it is OK to do this after releasing the buffer,
	 * because the heaptuples data structure is all in local memory, not in
	 * the shared buffer.
	 */
	if (IsCatalogRelation(relation))
	{
		/*
		for (i = 0; i < ntuples; i++)
			CacheInvalidateHeapTuple(relation, zheaptuples[i], NULL); */
	}

	/*
	 * Copy t_self fields back to the caller's original tuples. This does
	 * nothing for untoasted tuples (tuples[i] == heaptuples[i)], but it's
	 * probably faster to always copy than check.
	 */
	for (i = 0; i < ntuples; i++)
		tuples[i]->t_self = zheaptuples[i]->t_self;

	pgstat_count_heap_insert(relation, ntuples);
}

/*
 * Mask a zheap page before performing consistency checks on it.
 */
void
zheap_mask(char *pagedata, BlockNumber blkno)
{
	Page		page = (Page) pagedata;
	OffsetNumber off;

	mask_page_lsn_and_checksum(page);

	mask_page_hint_bits(page);
	mask_unused_space(page);

	for (off = 1; off <= PageGetMaxOffsetNumber(page); off++)
	{
		ItemId		iid = PageGetItemId(page, off);
		char	   *page_item;

		page_item = (char *) (page + ItemIdGetOffset(iid));

		/*
		 * Ignore any padding bytes after the tuple, when the length of the
		 * item is not MAXALIGNed.
		 */
		if (ItemIdHasStorage(iid))
		{
			int			len = ItemIdGetLength(iid);
			int			padlen = MAXALIGN(len) - len;

			if (padlen > 0)
				memset(page_item + len, MASK_MARKER, padlen);
		}
	}
}

/*
 * Per-undorecord callback from UndoFetchRecord to check whether
 * an undorecord satisfies the given conditions.
 */
bool
ZHeapSatisfyUndoRecord(UnpackedUndoRecord* urec, BlockNumber blkno,
								OffsetNumber offset, TransactionId xid)
{
	Assert(urec != NULL);
	Assert(blkno != InvalidBlockNumber);

	if ((urec->uur_block != blkno ||
		(TransactionIdIsValid(xid) && !TransactionIdEquals(xid, urec->uur_xid))))
		return false;

	switch (urec->uur_type)
	{
		case UNDO_MULTI_INSERT:
			{
				OffsetNumber	start_offset;
				OffsetNumber	end_offset;

				start_offset = ((OffsetNumber *) urec->uur_payload.data)[0];
				end_offset = ((OffsetNumber *) urec->uur_payload.data)[1];

				if (offset >= start_offset && offset <= end_offset)
					return true;
			}
			break;
		case UNDO_ITEMID_UNUSED:
			{
				/*
				 * We don't expect to check the visibility of any unused item,
				 * but the undo record of same can be present in chain which
				 * we need to ignore.
				 */
			}
			break;
		default:
			{
				Assert(offset != InvalidOffsetNumber);
				if (urec->uur_offset == offset)
					return true;
			}
			break;
	}

	return false;
}

/*
 *	zheap_get_latest_tid -  get the latest tid of a specified tuple
 *
 * Functionally, it serves the same purpose as heap_get_latest_tid(), but it
 * follows a different way of traversing the ctid chain of updated tuples.
 */
void
zheap_get_latest_tid(Relation relation,
					 Snapshot snapshot,
					 ItemPointer tid)
{
	BlockNumber blk;
	ItemPointerData ctid;
	TransactionId priorXmax;
	int			tup_len;

	/* this is to avoid Assert failures on bad input */
	if (!ItemPointerIsValid(tid))
		return;

	/*
	 * Since this can be called with user-supplied TID, don't trust the input
	 * too much.  (RelationGetNumberOfBlocks is an expensive check, so we
	 * don't check t_ctid links again this way.  Note that it would not do to
	 * call it just once and save the result, either.)
	 */
	blk = ItemPointerGetBlockNumber(tid);
	if (blk >= RelationGetNumberOfBlocks(relation))
		elog(ERROR, "block number %u is out of range for relation \"%s\"",
			 blk, RelationGetRelationName(relation));

	/*
	 * Loop to chase down ctid links.  At top of loop, ctid is the tuple we
	 * need to examine, and *tid is the TID we will return if ctid turns out
	 * to be bogus.
	 *
	 * Note that we will loop until we reach the end of the t_ctid chain.
	 * Depending on the snapshot passed, there might be at most one visible
	 * version of the row, but we don't try to optimize for that.
	 */
	ctid = *tid;
	priorXmax = InvalidTransactionId;
	for (;;)
	{
		Buffer		buffer;
		Page		page;
		OffsetNumber offnum;
		ItemId		lp;
		ZHeapTuple	tp;
		ZHeapTuple	resulttup;
		ItemPointerData new_ctid;
		uint16		infomask;

		/*
		 * Read, pin, and lock the page.
		 */
		buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(&ctid));
		LockBuffer(buffer, BUFFER_LOCK_SHARE);
		page = BufferGetPage(buffer);

		/*
		 * Check for bogus item number.  This is not treated as an error
		 * condition because it can happen while following a ctid link. We
		 * just assume that the prior tid is OK and return it unchanged.
		 */
		offnum = ItemPointerGetOffsetNumber(&ctid);
		if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(page))
		{
			UnlockReleaseBuffer(buffer);
			break;
		}
		lp = PageGetItemId(page, offnum);
		if (!ItemIdIsNormal(lp))
		{
			UnlockReleaseBuffer(buffer);
			break;
		}

		/*
		 * We always need to make a copy of zheap tuple; if an older version is
		 * returned from the undo record, the passed in tuple gets freed.
		 */
		tup_len = ItemIdGetLength(lp);
		tp = palloc(ZHEAPTUPLESIZE + tup_len);
		tp->t_data = (ZHeapTupleHeader) (((char *) tp) + ZHEAPTUPLESIZE);
		tp->t_tableOid = RelationGetRelid(relation);
		tp->t_len = tup_len;
		tp->t_self = ctid;

		memcpy(tp->t_data, ((ZHeapTupleHeader) PageGetItem(page, lp)),
			   tup_len);

		/* Save the infomask. The tuple might get freed, as mentioned above */
		infomask = tp->t_data->t_infomask;

		/*
		 * Ensure that the tuple is same as what we are expecting.  If the
		 * the current or any prior version of tuple doesn't contain the
		 * effect of priorXmax, then the slot must have been recycled and
		 * reused for an unrelated tuple.  This implies that the latest
		 * version of the row was deleted, so we need do nothing.
		 */
		if (TransactionIdIsValid(priorXmax) &&
			!ValidateTuplesXact(tp, snapshot, buffer, priorXmax, false))
		{
			UnlockReleaseBuffer(buffer);
			break;
		}

		/*
		 * Check time qualification of tuple; if visible, set it as the new
		 * result candidate.
		 */
		ItemPointerSetInvalid(&new_ctid);
		resulttup = ZHeapTupleSatisfiesVisibility(tp, snapshot, buffer,
												  &new_ctid);

#if 0
		/*
		 * Fixme - Serializable isolation level is not supportted for zheap
		 * tuples.
		 */
		CheckForSerializableConflictOut(resulttup != NULL, relation, tp,
										buffer, snapshot);
#endif

		/* Pass back the tuple ctid if it's visible */
		if (resulttup != NULL)
			*tid = ctid;

		/* If there's a valid ctid link, follow it, else we're done. */
		if (!ItemPointerIsValid(&new_ctid) ||
			ZHEAP_XID_IS_LOCKED_ONLY(infomask) ||
			ItemPointerEquals(&ctid, &new_ctid))
		{
			if (resulttup != NULL)
				zheap_freetuple(resulttup);
			UnlockReleaseBuffer(buffer);
			break;
		}

		/* Get the transaction who modified this tuple */
		ZHeapTupleGetTransInfo(resulttup != NULL ? resulttup : tp,
							   buffer, NULL, NULL, &priorXmax, NULL, NULL,
							   false);

		ctid = new_ctid;

		if (resulttup != NULL)
			zheap_freetuple(resulttup);
		UnlockReleaseBuffer(buffer);
	}							/* end of loop */
}
