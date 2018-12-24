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
#include "access/parallel.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "access/relscan.h"
#include "access/tpd.h"
#include "access/tuptoaster.h"
#include "access/undoinsert.h"
#include "access/undolog.h"
#include "access/undolog_xlog.h"
#include "access/undorecord.h"
#include "access/visibilitymap.h"
#include "access/zheap.h"
#include "access/zhio.h"
#include "access/zhtup.h"
#include "access/zheapam_xlog.h"
#include "access/zmultilocker.h"
#include "catalog/catalog.h"
#include "catalog/index.h"
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/undoloop.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "storage/predicate.h"
#include "storage/procarray.h"
#include "storage/itemid.h"
#include "utils/datum.h"
#include "utils/expandeddatum.h"
#include "utils/inval.h"
#include "utils/memdebug.h"
#include "utils/rel.h"
#include "utils/tqual.h"

 /*
  * Possible lock modes for a tuple.
  */
typedef enum LockOper
{
	/* SELECT FOR 'KEY SHARE/SHARE/NO KEY UPDATE/UPDATE' */
	LockOnly,
	/* Via EvalPlanQual where after locking we will update it */
	LockForUpdate,
	/* Update/Delete */
	ForUpdate
} LockOper;

extern bool synchronize_seqscans;
static int GetTPDBlockNumberFromHeapBuffer(Buffer heapbuf);
static ZHeapTuple zheap_prepare_insert(Relation relation, ZHeapTuple tup,
									   int options);
static bool ZHeapProjIndexIsUnchanged(Relation relation, ZHeapTuple oldtup,
											 ZHeapTuple newtup);
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

static void RelationPutZHeapTuple(Relation relation, Buffer buffer,
								  ZHeapTuple tuple);
static void log_zheap_update(Relation reln, UnpackedUndoRecord undorecord,
					UnpackedUndoRecord newundorecord, UndoRecPtr urecptr,
					UndoRecPtr newurecptr, Buffer oldbuf, Buffer newbuf,
					ZHeapTuple oldtup, ZHeapTuple newtup,
					int old_tup_trans_slot_id, int trans_slot_id,
					int new_trans_slot_id, bool inplace_update,
					bool all_visible_cleared, bool new_all_visible_cleared,
					xl_undolog_meta *undometa);
static HTSU_Result
zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 TransactionId xid, LockTupleMode mode, LockOper lockopr,
						 CommandId cid, bool *rollback_and_relocked);
static void zheap_lock_tuple_guts(Relation rel, Buffer buf, ZHeapTuple zhtup,
					  TransactionId tup_xid, TransactionId xid,
					  LockTupleMode mode, LockOper lockopr, uint32 epoch,
					  int tup_trans_slot_id, int trans_slot_id,
					  TransactionId single_locker_xid, int single_locker_trans_slot,
					  UndoRecPtr prev_urecptr, CommandId cid,
					  bool any_multi_locker_member_alive);
static void compute_new_xid_infomask(ZHeapTuple zhtup, Buffer buf,
						 TransactionId tup_xid, int tup_trans_slot,
						 uint16 old_infomask, TransactionId add_to_xid,
						 int trans_slot, TransactionId single_locker_xid,
						 LockTupleMode mode, LockOper lockoper,
						 uint16 *result_infomask, int *result_trans_slot);
static ZHeapFreeOffsetRanges *
ZHeapGetUsableOffsetRanges(Buffer buffer, ZHeapTuple *tuples, int ntuples,
						   Size saveFreeSpace);
static inline void CheckAndLockTPDPage(Relation relation, int new_trans_slot_id,
									   int old_trans_slot_id, Buffer newbuf,
									   Buffer oldbuf);

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
			//data = (char *) att_align_nominal(data, att->attalign);
			//store_att_byval(data, values[i], att->attlen);
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

	if (tupleDescriptor->tdhasoid)		/* else leave infomask = 0 */
		td->t_infomask = ZHEAP_HASOID;

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
	bits8	   *bp = tup->t_bits;		/* ptr to null bitmap in tuple */

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
			memcpy(&values[attnum], tp + off, thisatt->attlen);
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
	 * In zheap, we don't support the optimization for HEAP_INSERT_SKIP_WAL.
	 * If we skip writing/using WAL, we must force the relation down to disk
	 * (using heap_sync) before it's safe to commit the transaction. This
	 * requires writing out any dirty buffers of that relation and then doing
	 * a forced fsync. For zheap, we've to fsync the corresponding undo buffers
	 * as well. It is difficult to keep track of dirty undo buffers and fsync
	 * them at end of the operation in some function similar to heap_sync.
	 * But, if we're freezing the tuple during insertion, we can use the
	 * HEAP_INSERT_SKIP_WAL optimization since we don't write undo for the same.
	 */
	Assert(!(options & HEAP_INSERT_SKIP_WAL) || (options & HEAP_INSERT_FROZEN));

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

	if (options & HEAP_INSERT_FROZEN)
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
		Assert(!ZHeapTupleHasExternal(tup));
		return tup;
	}
	else if (ZHeapTupleHasExternal(tup) || tup->t_len > TOAST_TUPLE_THRESHOLD)
		 return ztoast_insert_or_update(relation, tup, NULL, options);
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
bool
zheap_exec_pending_rollback(Relation rel, Buffer buffer, int slot_no,
							TransactionId xwait)
{
	UndoRecPtr urec_ptr;
	TransactionId xid;
	uint32	epoch;
	int		out_slot_no PG_USED_FOR_ASSERTS_ONLY;

	out_slot_no =  GetTransactionSlotInfo(buffer,
										  InvalidOffsetNumber,
										  slot_no,
										  &epoch,
										  &xid,
										  &urec_ptr,
										  true,
										  true);

	/* As the rollback is pending, the slot can't be frozen. */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

	if (xwait != xid)
		return false;

	/*
	 * Release buffer lock before applying undo actions.
	 */
	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	process_and_execute_undo_actions_page(urec_ptr, rel, buffer, epoch, xid, slot_no);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	return true;
}

/*
 * zbuffer_exec_pending_rollback - apply any pending rollback on the input buffer
 *
 * This method traverses all the transaction slots of the current page including
 * tpd slots and applies any pending aborts on the page.
 *
 * It expects the caller has an exclusive lock on the relation. It also returns
 * the corresponding TPD block number in case it has rolled back any transactions
 * from the corresponding TPD page, if any.
 */
void
zbuffer_exec_pending_rollback(Relation rel, Buffer buf, BlockNumber *tpd_blkno)
{
	int				slot_no;
	int				total_trans_slots = 0;
	uint64			epoch;
	TransactionId	xid;
	UndoRecPtr		urec_ptr;
	TransInfo 		*trans_slots = NULL;
	bool			any_tpd_slot_rolled_back = false;

	Assert(tpd_blkno != NULL);

	/*
	 * Fetch all the transaction information from the page and its corresponding
	 * TPD page.
	 */
	trans_slots = GetTransactionsSlotsForPage(rel, buf, &total_trans_slots, tpd_blkno);

	for (slot_no = 0; slot_no < total_trans_slots; slot_no++)
	{
		epoch = trans_slots[slot_no].xid_epoch;
		xid = trans_slots[slot_no].xid;
		urec_ptr = trans_slots[slot_no].urec_ptr;

		/*
		 * There shouldn't be any other in-progress transaction as we hold an
		 * exclusive lock on the relation.
		 */
		Assert(TransactionIdIsCurrentTransactionId(xid) ||
			   !TransactionIdIsInProgress(xid));

		/* If the transaction is aborted, apply undo actions */
		if (TransactionIdIsValid(xid) && TransactionIdDidAbort(xid))
		{
			/* Remember if we've rolled back a transactio from a TPD-slot. */
			if ((slot_no >= ZHEAP_PAGE_TRANS_SLOTS - 1) &&
				BlockNumberIsValid(*tpd_blkno))
				any_tpd_slot_rolled_back = true;
			process_and_execute_undo_actions_page(urec_ptr, rel, buf, epoch,
												  xid, slot_no);
		}
	}

	/*
	 * If we've not rolled back anything from TPD slot, there is no
	 * need set the TPD buffer.
	 */
	if (!any_tpd_slot_rolled_back)
		*tpd_blkno = InvalidBlockNumber;

	/* be tidy */
	pfree(trans_slots);
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
	TransactionId xid = InvalidTransactionId;
	uint32	epoch = 0;
	ZHeapTuple	zheaptup;
	UnpackedUndoRecord	undorecord;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	bool		all_visible_cleared = false;
	int			trans_slot_id = InvalidXactSlotId;
	Page		page;
	UndoRecPtr	urecptr = InvalidUndoRecPtr,
				prev_urecptr = InvalidUndoRecPtr;
	xl_undolog_meta	undometa;
	uint8		vm_status = 0;
	bool		lock_reacquired;
	bool		skip_undo;

	/*
	 * We can skip inserting undo records if the tuples are to be marked
	 * as frozen.
	 */
	skip_undo = (options & HEAP_INSERT_FROZEN);

	if (!skip_undo)
	{
		/* We don't need a transaction id if we are skipping undo */
		xid = GetTopTransactionId();
		epoch = GetEpochForXid(xid);
	}

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
	if (BufferIsValid(vmbuffer))
	{
		ReleaseBuffer(vmbuffer);
		vmbuffer = InvalidBuffer;
	}

	buffer = RelationGetBufferForZTuple(relation, zheaptup->t_len,
										InvalidBuffer, options, bistate,
										&vmbuffer, NULL);
	page = BufferGetPage(buffer);

	if (!skip_undo)
	{
		/*
		 * The transaction information of tuple needs to be set in transaction
		 * slot, so needs to reserve the slot before proceeding with the actual
		 * operation.  It will be costly to wait for getting the slot, but we do
		 * that by releasing the buffer lock.
		 *
		 * We don't yet know the offset number of the inserting tuple so just pass
		 * the max offset number + 1 so that if it need to get slot from the TPD
		 * it can ensure that the TPD has sufficient map entries.
		 */
		trans_slot_id = PageReserveTransactionSlot(relation,
												   buffer,
												   PageGetMaxOffsetNumber(page) + 1,
												   epoch,
												   xid,
												   &prev_urecptr,
												   &lock_reacquired,
												   false);
		if (lock_reacquired)
		{
			UnlockReleaseBuffer(buffer);
			goto reacquire_buffer;
		}

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
	}

	if (options & HEAP_INSERT_SPECULATIVE)
	{
		/*
		 * We can't skip writing undo speculative insertions as we have to
		 * write the token in undo.
		 */
		Assert(!skip_undo);

		/* Mark the tuple as speculatively inserted tuple. */
		zheaptup->t_data->t_infomask |= ZHEAP_SPECULATIVE_INSERT;
	}

	/*
	 * See heap_insert to know why checking conflicts is important
	 * before actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	if (!skip_undo)
	{
		/*
		 * Prepare an undo record.  Unlike other operations, insert operation
		 * doesn't have a prior version to store in undo, so ideally, we don't
		 * need to store any additional information like
		 * UREC_INFO_PAYLOAD_CONTAINS_SLOT for TPD entries.  However, for the sake
		 * of consistency with inserts via non-inplace updates, we keep the
		 * additional information in this operation.  Also, we need such an
		 * information in future where we need to know more information for undo
		 * tuples and it would be good for forensic purpose as well.
		 */
		undorecord.uur_type = UNDO_INSERT;
		undorecord.uur_info = 0;
		undorecord.uur_prevlen = 0;
		undorecord.uur_reloid = relation->rd_id;
		undorecord.uur_prevxid = FrozenTransactionId;
		undorecord.uur_xid = xid;
		undorecord.uur_cid = cid;
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
								   (char *)&specToken,
								   sizeof(uint32));
		}
		else
			undorecord.uur_payload.len = 0;

		urecptr = PrepareUndoInsert(&undorecord,
									InvalidTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									&undometa);
	}

	/*
	 * If there is a valid vmbuffer get its status.  The vmbuffer will not
	 * be valid if operated page is newly extended, see
	 * RelationGetBufferForZTuple. Also, anyway by default vm status
	 * bits are clear for those pages hence no need to clear it again!
	 */
	if (BufferIsValid(vmbuffer))
		vm_status = visibilitymap_get_status(relation,
								BufferGetBlockNumber(buffer),
								&vmbuffer);

	/*
	 * Lock the TPD page before starting critical section.  We might need
	 * to access it in ZPageAddItemExtended.  Note that if the transaction
	 * slot belongs to TPD entry, then the TPD page must be locked during
	 * slot reservation.
	 *
	 * XXX We can optimize this by avoid taking TPD page lock unless the page
	 * has some unused item which requires us to fetch the transaction
	 * information from TPD.
	 */
	if (trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
		ZHeapPageHasTPDSlot((PageHeader) page) &&
		PageHasFreeLinePointers((PageHeader) page))
		TPDPageLock(relation, buffer);

	/* NO EREPORT(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	if (!(options & HEAP_INSERT_FROZEN))
		ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, trans_slot_id);

	RelationPutZHeapTuple(relation, buffer, zheaptup);

	if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) ||
		(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
	{
		all_visible_cleared = true;
		visibilitymap_clear(relation,
						ItemPointerGetBlockNumber(&(zheaptup->t_self)),
						vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	if (!skip_undo)
	{
		Assert(undorecord.uur_block == ItemPointerGetBlockNumber(&(zheaptup->t_self)));
		undorecord.uur_offset = ItemPointerGetOffsetNumber(&(zheaptup->t_self));
		InsertPreparedUndo();
		PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch, xid,
					urecptr, NULL, 0);
	}

	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
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
		xlundohdr.reloid = relation->rd_id;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		/* Heap related part. */
		xlrec.offnum = ItemPointerGetOffsetNumber(&zheaptup->t_self);
		xlrec.flags = 0;

		if (all_visible_cleared)
			xlrec.flags |= XLZ_INSERT_ALL_VISIBLE_CLEARED;
		if (options & HEAP_INSERT_SPECULATIVE)
			xlrec.flags |= XLZ_INSERT_IS_SPECULATIVE;
		if (skip_undo)
			xlrec.flags |= XLZ_INSERT_IS_FROZEN;
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
		if (!skip_undo)
		{
			/*
			 * LOG undolog meta if this is the first WAL after the checkpoint.
			 */
			LogUndoMetaData(&undometa);
		}

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xlrec, SizeOfZHeapInsert);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			/*
			 * We can't have a valid transaction slot when we are skipping
			 * undo.
			 */
			Assert(!skip_undo);
			xlrec.flags |= XLZ_INSERT_CONTAINS_TPD_SLOT;
			XLogRegisterData((char *) &trans_slot_id, sizeof(trans_slot_id));
		}

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
		if (xlrec.flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
			(void) RegisterTPDBuffer(page, 1);
		RegisterUndoLogBuffers(2);

		/* filtering by origin on a row level is much more efficient */
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

		recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr,
									doPageWrites);
		if (recptr == InvalidXLogRecPtr)
		{
			ResetRegisteredTPDBuffers();
			goto prepare_xlog;
		}

		PageSetLSN(page, recptr);
		if (xlrec.flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
			TPDPageSetLSN(page, recptr);
		UndoLogBuffersSetLSN(recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buffer);
	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);
	if (!skip_undo)
	{
		/* be tidy */
		if (undorecord.uur_payload.len > 0)
			pfree(undorecord.uur_payload.data);
		UnlockReleaseUndoBuffers();
	}
	UnlockReleaseTPDBuffers();

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

		/*
		 * Since, in ZHeap we have speculative flag in the tuple header only,
		 * copy the speculative flag to the new tuple if required.
		 */
		if (ZHeapTupleHeaderIsSpeculative(zheaptup->t_data))
			tup->t_data->t_infomask |= ZHEAP_SPECULATIVE_INSERT;

		zheap_freetuple(zheaptup);
	}

	return ZHeapTupleGetOid(tup);
}

/*
 *	simple_zheap_delete - delete a zheap tuple
 *
 * This routine may be used to delete a tuple when concurrent updates of
 * the target tuple are not expected (for example, because we have a lock
 * on the relation associated with the tuple).  Any failure is reported
 * via ereport().
 */
void
simple_zheap_delete(Relation relation, ItemPointer tid, Snapshot snapshot)
{
	HTSU_Result result;
	HeapUpdateFailureData hufd;

	result = zheap_delete(relation, tid,
						 GetCurrentCommandId(true), InvalidSnapshot, snapshot,
						 true, /* wait for commit */
						 &hufd, false /* changingPart */);
	switch (result)
	{
		case HeapTupleSelfUpdated:
			/* Tuple was already updated in current command? */
			elog(ERROR, "tuple already updated by self");
			break;

		case HeapTupleMayBeUpdated:
			/* done successfully */
			break;

		case HeapTupleUpdated:
			elog(ERROR, "tuple concurrently updated");
			break;

		default:
			elog(ERROR, "unrecognized zheap_delete status: %u", result);
			break;
	}
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
			 HeapUpdateFailureData *hufd, bool changingPart)
{
	HTSU_Result result;
	TransactionId xid = GetTopTransactionId();
	TransactionId	tup_xid,
					oldestXidHavingUndo,
					single_locker_xid;
	SubTransactionId	tup_subxid = InvalidSubTransactionId;
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
	uint32		epoch = GetEpochForXid(xid);
	int			tup_trans_slot_id,
				trans_slot_id,
				new_trans_slot_id,
				single_locker_trans_slot;
	uint16		new_infomask, temp_infomask;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		all_visible_cleared = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	bool		hasSubXactLock = false;
	bool		hasPayload = false;
	xl_undolog_meta undometa;
	uint8		vm_status;

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

	/*
	 * Before locking the buffer, pin the visibility map page mainly to avoid
	 * doing I/O after locking the buffer.
	 */
	visibilitymap_pin(relation, blkno, &vmbuffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

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
	result = ZHeapTupleSatisfiesUpdate(relation, &zheaptup, cid, buffer, &ctid,
									   &tup_trans_slot_id, &tup_xid, &tup_subxid,
									   &tup_cid, &single_locker_xid,
									   &single_locker_trans_slot, false, false,
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
		SubTransactionId	xwait_subxid;
		int		xwait_trans_slot;
		uint16	infomask;
		bool    isCommitted;
		bool	can_continue = false;

		lock_reacquired = false;
		xwait_subxid = tup_subxid;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = tup_xid;
			xwait_trans_slot = tup_trans_slot_id;
		}

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
			bool			upd_xact_aborted = false;

			/*
			 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
			 * transaction has already locked the tuple for update because of
			 * multilocker flag. In that case, we've to check whether the current
			 * transaction has already locked the tuple for update.
			 */

			/*
			 * Get the transaction slot and undo record pointer if we are already in a
			 * transaction.
			 */
			trans_slot_id = PageGetTransactionSlotId(relation, buffer, epoch, xid,
													 &prev_urecptr, false, false,
													 NULL);

			if (trans_slot_id != InvalidXactSlotId)
			{
				List	*mlmembers;
				ListCell   *lc;

				/*
				 * If any subtransaction of the current top transaction already holds
				 * a lock as strong as or stronger than what we're requesting, we
				 * effectively hold the desired lock already.  We *must* succeed
				 * without trying to take the tuple lock, else we will deadlock
				 * against anyone wanting to acquire a stronger lock.
				 */
				mlmembers = ZGetMultiLockMembersForCurrentXact(&zheaptup,
													trans_slot_id, prev_urecptr);

				foreach(lc, mlmembers)
				{
					ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

					/*
					 * Only members of our own transaction must be present in
					 * the list.
					 */
					Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

					if (mlmember->mode >= LockTupleExclusive)
					{
						result = HeapTupleMayBeUpdated;
						/*
						 * There is no other active locker on the tuple except
						 * current transaction id, so we can delete the tuple.
						 */
						goto zheap_tuple_updated;
					}
				}

				list_free_deep(mlmembers);
			}

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
				mlmembers = ZGetMultiLockMembers(relation, &zheaptup, buffer,
												 true);

				/*
				 * If there is no multi-lock members apart from the current transaction
				 * then no need for tuplock, just go ahead.
				 */
				if (mlmembers != NIL)
				{
					heap_acquire_tuplock(relation, &(zheaptup.t_self), LockTupleExclusive,
										 LockWaitBlock, &have_tuple_lock);
					ZMultiLockMembersWait(relation, mlmembers, &zheaptup, buffer,
										  update_xact, LockTupleExclusive, false,
										  XLTW_Delete, NULL, &upd_xact_aborted);
				}
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
			if (xwait_subxid != InvalidSubTransactionId)
				SubXactLockTableWait(xwait, xwait_subxid, relation,
									 &zheaptup.t_self, XLTW_Delete);
			else
				XactLockTableWait(xwait, relation, &zheaptup.t_self,
								  XLTW_Delete);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
			lock_reacquired = true;
		}

		if (lock_reacquired)
		{
			TransactionId	current_tup_xid;

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
				new_mlmembers = ZGetMultiLockMembers(relation, &zheaptup,
													 buffer, false);

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
			 * other xact could update/lock this tuple before we get to this
			 * point.  Check for xid change, and start over if so.  We need to
			 * do some special handling for lockers because their xid is never
			 * stored on the tuples.  If there was a single locker on the
			 * tuple and that locker is gone and some new locker has locked
			 * the tuple, we won't be able to identify that by infomask/xid on
			 * the tuple, rather we need to fetch the locker xid.
			 */
			ZHeapTupleGetTransInfo(&zheaptup, buffer, NULL, NULL,
								   &current_tup_xid, NULL, NULL, false);
			if (xid_infomask_changed(zheaptup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(current_tup_xid, xwait))
			{
				if (ZHEAP_XID_IS_LOCKED_ONLY(zheaptup.t_data->t_infomask) &&
					!ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask) &&
					TransactionIdIsValid(single_locker_xid))
				{
					TransactionId current_single_locker_xid = InvalidTransactionId;

					(void) GetLockerTransInfo(relation, &zheaptup, buffer, NULL,
											  NULL, &current_single_locker_xid,
											  NULL, NULL);
					if (!TransactionIdEquals(single_locker_xid,
											 current_single_locker_xid))
						goto check_tup_satisfies_update;

				}
				else
					goto check_tup_satisfies_update;
			}

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
				if (!isCommitted)
					zheap_exec_pending_rollback(relation,
												buffer,
												xwait_trans_slot,
												xwait);

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
	else if (result == HeapTupleUpdated
			 && ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask))
	{
		/*
		 * Get the transaction slot and undo record pointer if we are already in a
		 * transaction.
		 */
		trans_slot_id = PageGetTransactionSlotId(relation, buffer, epoch, xid,
												 &prev_urecptr, false, false,
												 NULL);

		if (trans_slot_id != InvalidXactSlotId)
		{
			List	*mlmembers;
			ListCell   *lc;

			/*
			 * If any subtransaction of the current top transaction already holds
			 * a lock as strong as or stronger than what we're requesting, we
			 * effectively hold the desired lock already.  We *must* succeed
			 * without trying to take the tuple lock, else we will deadlock
			 * against anyone wanting to acquire a stronger lock.
			 */
			mlmembers = ZGetMultiLockMembersForCurrentXact(&zheaptup,
												trans_slot_id, prev_urecptr);

			foreach(lc, mlmembers)
			{
				ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

				/*
				 * Only members of our own transaction must be present in
				 * the list.
				 */
				Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

				if (mlmember->mode >= LockTupleExclusive)
				{
					result = HeapTupleMayBeUpdated;
					/*
					 * There is no other active locker on the tuple except
					 * current transaction id, so we can delete the tuple.
					 */
					break;
				}
			}

			list_free_deep(mlmembers);
		}

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

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(zheaptup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&hufd->ctid);
		else
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

	/*
	 * Acquire subtransaction lock, if current transaction is a
	 * subtransaction.
	 */
	if (IsSubTransaction())
	{
		SubXactLockTableInsert(GetCurrentSubTransactionId());
		hasSubXactLock = true;
	}

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer,
											   PageGetMaxOffsetNumber(page),
											   epoch, xid, &prev_urecptr,
											   &lock_reacquired, false);
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

	/*
	 * It's possible that tuple slot is now marked as frozen. Hence, we refetch
	 * the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must be
	 * frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zheaptup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		tup_trans_slot_id = ZHTUP_SLOT_FROZEN;
		tup_xid = InvalidTransactionId;
	}

	temp_infomask = zheaptup.t_data->t_infomask;

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&zheaptup, buffer, tup_xid, tup_trans_slot_id,
							 temp_infomask, xid, trans_slot_id,
							 single_locker_xid, LockTupleExclusive, ForUpdate,
							 &new_infomask, &new_trans_slot_id);
	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(new_trans_slot_id == trans_slot_id);

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

	CheckForSerializableConflictIn(relation, &(zheaptup.t_self), buffer);

	/*
	 * Prepare an undo record.  We need to separately store the latest
	 * transaction id that has changed the tuple to ensure that we don't
	 * try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */
	undorecord.uur_type = UNDO_DELETE;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_reloid = relation->rd_id;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = offnum;

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
	/*
	 * Store the transaction slot number for undo tuple in undo record, if
	 * the slot belongs to TPD entry.  We can always get the current tuple's
	 * transaction slot number by referring offset->slot map in TPD entry,
	 * however that won't be true for tuple in undo.
	 */
	if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
		initStringInfo(&undorecord.uur_payload);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &tup_trans_slot_id,
							   sizeof(tup_trans_slot_id));
		hasPayload = true;
	}

	/*
	 * Store subtransaction id in undo record.  See SubXactLockTableWait
	 * to know why we need to store subtransaction id in undo.
	 */
	if (hasSubXactLock)
	{
		SubTransactionId subxid = GetCurrentSubTransactionId();

		if (!hasPayload)
		{
			initStringInfo(&undorecord.uur_payload);
			hasPayload = true;
		}

		undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &subxid,
							   sizeof(subxid));
	}

	if (!hasPayload)
		undorecord.uur_payload.len = 0;

	urecptr = PrepareUndoInsert(&undorecord,
								InvalidTransactionId,
								UndoPersistenceForRelation(relation),
								NULL,
								&undometa);
	/* We must have a valid vmbuffer. */
	Assert(BufferIsValid(vmbuffer));
	vm_status = visibilitymap_get_status(relation,
								BufferGetBlockNumber(buffer), &vmbuffer);

	START_CRIT_SECTION();

	/*
	 * If all the members were lockers and are all gone, we can do away
	 * with the MULTI_LOCKERS bit.
	 */

	if (ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask) &&
		!any_multi_locker_member_alive)
		zheaptup.t_data->t_infomask &= ~ZHEAP_MULTI_LOCKERS;

	if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) ||
		(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
	{
		all_visible_cleared = true;
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	InsertPreparedUndo();
	PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch, xid,
				urecptr, NULL, 0);

	/*
	 * If this transaction commits, the tuple will become DEAD sooner or
	 * later.  If the transaction finally aborts, the subsequent page pruning
	 * will be a no-op and the hint will be cleared.
	 */
	ZPageSetPrunable(page, xid);

	ZHeapTupleHeaderSetXactSlot(zheaptup.t_data, new_trans_slot_id);
	zheaptup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	zheaptup.t_data->t_infomask |= ZHEAP_DELETED | new_infomask;

	/* Signal that this is actually a move into another partition */
	if (changingPart)
		ZHeapTupleHeaderSetMovedPartitions(zheaptup.t_data);

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
		xlundohdr.reloid = undorecord.uur_reloid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xlrec.prevxid = tup_xid;
		xlrec.offnum = ItemPointerGetOffsetNumber(&zheaptup.t_self);
		xlrec.infomask = zheaptup.t_data->t_infomask;
		xlrec.trans_slot_id = trans_slot_id;
		xlrec.flags = all_visible_cleared ? XLZ_DELETE_ALL_VISIBLE_CLEARED : 0;

		if (changingPart)
			xlrec.flags |= XLZ_DELETE_IS_PARTITION_MOVE;
		if (hasSubXactLock)
			xlrec.flags |= XLZ_DELETE_CONTAINS_SUBXACT;

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
		if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			xlrec.flags |= XLZ_DELETE_CONTAINS_TPD_SLOT;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xlrec, SizeOfZHeapDelete);
		if (xlrec.flags & XLZ_DELETE_CONTAINS_TPD_SLOT)
			XLogRegisterData((char *) &tup_trans_slot_id,
							 sizeof(tup_trans_slot_id));
		if (xlrec.flags & XLZ_HAS_DELETE_UNDOTUPLE)
		{
			XLogRegisterData((char *) &xlhdr, SizeOfZHeapHeader);
			/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
			XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
							totalundotuplen - SizeofZHeapTupleHeader);
		}

		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			(void) RegisterTPDBuffer(page, 1);
		RegisterUndoLogBuffers(2);

		/* filtering by origin on a row level is much more efficient */
		XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

		recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_DELETE,
									RedoRecPtr, doPageWrites);
		if (recptr == InvalidXLogRecPtr)
		{
			ResetRegisteredTPDBuffers();
			goto prepare_xlog;
		}
		PageSetLSN(page, recptr);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			TPDPageSetLSN(page, recptr);
		UndoLogBuffersSetLSN(recptr);
	}

	END_CRIT_SECTION();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);
	if (undorecord.uur_payload.len > 0)
		pfree(undorecord.uur_payload.data);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	if (vmbuffer != InvalidBuffer)
		ReleaseBuffer(vmbuffer);

	UnlockReleaseUndoBuffers();
	/*
	 * If the tuple has toasted out-of-line attributes, we need to delete
	 * those items too.  We have to do this before releasing the buffer
	 * because we need to look at the contents of the tuple, but it's OK to
	 * release the content lock on the buffer first.
	 */
	if (relation->rd_rel->relkind != RELKIND_RELATION &&
		relation->rd_rel->relkind != RELKIND_MATVIEW)
	{
		/* toast table entries should never be recursively toasted */
		Assert(!ZHeapTupleHasExternal(&zheaptup));
	}
	else if (ZHeapTupleHasExternal(&zheaptup))
		ztoast_delete(relation, &zheaptup, false);

	/* Now we can release the buffer */
	ReleaseBuffer(buffer);
	UnlockReleaseTPDBuffers();

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
	TransactionId tup_xid,
				  save_tup_xid,
				  oldestXidHavingUndo,
				  single_locker_xid;
	SubTransactionId	tup_subxid = InvalidSubTransactionId;
	CommandId	tup_cid;
	Bitmapset  *inplace_upd_attrs = NULL;
	Bitmapset  *inplace_upd_proj_attrs = NULL;
	Bitmapset  *key_attrs = NULL;
	Bitmapset  *interesting_attrs = NULL;
	Bitmapset  *modified_attrs = NULL;
	ItemId		lp;
	ZHeapTupleData oldtup;
	ZHeapTuple	zheaptup;
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
				oldtupsize,
				pagefree;
	uint32		epoch = GetEpochForXid(xid);
	int			tup_trans_slot_id,
				trans_slot_id,
				new_trans_slot_id,
				result_trans_slot_id,
				single_locker_trans_slot;
	uint16		old_infomask;
	uint16		new_infomask, temp_infomask;
	uint16		infomask_old_tuple = 0;
	uint16		infomask_new_tuple = 0;
	OffsetNumber	old_offnum, max_offset;
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
	bool		need_toast;
	bool		hasSubXactLock = false;
	xl_undolog_meta	undometa;
	uint8		vm_status;
	uint8		vm_status_new = 0;

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
	inplace_upd_proj_attrs = RelationGetIndexAttrBitmap(relation,
														INDEX_ATTR_BITMAP_PROJ);
	key_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_KEY);

	block = ItemPointerGetBlockNumber(otid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);

	interesting_attrs = NULL;

	/*
	 * Before locking the buffer, pin the visibility map page mainly to avoid
	 * doing I/O after locking the buffer.
	 */
	visibilitymap_pin(relation, block, &vmbuffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	old_offnum = ItemPointerGetOffsetNumber(otid);
	lp = PageGetItemId(page, old_offnum);
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

		/*
		 * Since tuple data is gone let's be conservative about lock mode.
		 *
		 * XXX We could optimize here by checking whether the key column is
		 * not updated and if so, then use lower lock level, but this case
		 * should be rare enough that it won't matter.
		 */
		*lockmode = LockTupleExclusive;
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
	interesting_attrs = bms_add_members(interesting_attrs,
										inplace_upd_proj_attrs);
	interesting_attrs = bms_add_members(interesting_attrs, key_attrs);

	/* Determine columns modified by the update. */
	modified_attrs = ZHeapDetermineModifiedColumns(relation, interesting_attrs,
												   &oldtup, newtup);

	/*
	 * Check if any of the index columns have been changed; or if we have
	 * projection functional indexes, check whether the old and the new values
	 * are the same.
	 */
	is_index_updated =
		bms_overlap(modified_attrs, inplace_upd_attrs)
		|| (bms_overlap(modified_attrs, inplace_upd_proj_attrs)
			&& !ZHeapProjIndexIsUnchanged(relation, &oldtup, newtup));

	if (relation->rd_rel->relkind != RELKIND_RELATION &&
		relation->rd_rel->relkind != RELKIND_MATVIEW)
	{
		/* toast table entries should never be recursively toasted */
		Assert(!ZHeapTupleHasExternal(&oldtup));
		Assert(!ZHeapTupleHasExternal(newtup));
		need_toast = false;
	}
	else
		need_toast = (newtup->t_len >= TOAST_TUPLE_THRESHOLD ||
					 ZHeapTupleHasExternal(&oldtup) ||
					 ZHeapTupleHasExternal(newtup));

	oldtupsize = SHORTALIGN(oldtup.t_len);
	newtupsize = SHORTALIGN(newtup->t_len);

	/*
	 * inplace updates can be done only if the length of new tuple is lesser
	 * than or equal to old tuple and there are no index column updates and
	 * the tuple does not require TOAST-ing.
	 */
	if ((newtupsize <= oldtupsize) && !is_index_updated && !need_toast)
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
	result = ZHeapTupleSatisfiesUpdate(relation, &oldtup, cid, buffer, &ctid,
									   &tup_trans_slot_id, &tup_xid, &tup_subxid,
									   &tup_cid, &single_locker_xid,
									   &single_locker_trans_slot, false, false,
									   snapshot, &in_place_updated_or_locked);

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
		SubTransactionId xwait_subxid;
		int			xwait_trans_slot;
		uint16		infomask;
		bool		can_continue = false;

		xwait_subxid = tup_subxid;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = tup_xid;
			xwait_trans_slot = tup_trans_slot_id;
		}

		/* must copy state data before unlocking buffer */
		infomask = oldtup.t_data->t_infomask;

		if (ZHeapTupleHasMultiLockers(infomask))
		{
			TransactionId update_xact;
			LockTupleMode	old_lock_mode;
			int		remain = 0;
			bool		isAborted;
			bool		upd_xact_aborted = false;

			/*
			 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
			 * transaction has already locked the tuple for update because of
			 * multilocker flag. In that case, we've to check whether the current
			 * transaction has already locked the tuple for update.
			 */

			/*
			 * Get the transaction slot and undo record pointer if we are already in a
			 * transaction.
			 */
			trans_slot_id = PageGetTransactionSlotId(relation, buffer, epoch, xid,
													 &prev_urecptr, false, false,
													 NULL);

			if (trans_slot_id != InvalidXactSlotId)
			{
				List	*mlmembers;
				ListCell   *lc;

				/*
				 * If any subtransaction of the current top transaction already holds
				 * a lock as strong as or stronger than what we're requesting, we
				 * effectively hold the desired lock already.  We *must* succeed
				 * without trying to take the tuple lock, else we will deadlock
				 * against anyone wanting to acquire a stronger lock.
				 */
				mlmembers = ZGetMultiLockMembersForCurrentXact(&oldtup,
													trans_slot_id, prev_urecptr);

				foreach(lc, mlmembers)
				{
					ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

					/*
					 * Only members of our own transaction must be present in
					 * the list.
					 */
					Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

					if (mlmember->mode >= *lockmode)
					{
						result = HeapTupleMayBeUpdated;

						/*
						 * There is no other active locker on the tuple except
						 * current transaction id, so we can update the tuple.
						 * However, we need to propagate lockers information.
						 */
						checked_lockers = true;
						locker_remains = true;
						goto zheap_tuple_updated;
					}
				}

				list_free_deep(mlmembers);
			}

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
				TransactionId	current_tup_xid;

				/*
				 * There is a potential conflict.  It is quite possible
				 * that by this time the locker has already been committed.
				 * So we need to check for conflict with all the possible
				 * lockers and wait for each of them after releasing a
				 * buffer lock and acquiring a lock on a tuple.
				 */
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
				mlmembers = ZGetMultiLockMembers(relation, &oldtup, buffer,
												 true);

				/*
				 * If there is no multi-lock members apart from the current transaction
				 * then no need for tuplock, just go ahead.
				 */
				if (mlmembers != NIL)
				{
					heap_acquire_tuplock(relation, &(oldtup.t_self), *lockmode,
										 LockWaitBlock, &have_tuple_lock);
					ZMultiLockMembersWait(relation, mlmembers, &oldtup, buffer,
										  update_xact, *lockmode, false,
										  XLTW_Update, &remain,
										  &upd_xact_aborted);
				}
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
					new_mlmembers = ZGetMultiLockMembers(relation, &oldtup,
														 buffer, false);

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
				ZHeapTupleGetTransInfo(&oldtup, buffer, NULL, NULL, &current_tup_xid,
									   NULL, NULL, false);
				if (xid_infomask_changed(oldtup.t_data->t_infomask, infomask) ||
					!TransactionIdEquals(current_tup_xid, xwait))
					goto check_tup_satisfies_update;
			}
			else if (TransactionIdIsValid(update_xact))
			{
				isAborted = TransactionIdDidAbort(update_xact);

				/*
				 * For aborted transaction, if the undo actions are not applied
				 * yet, then apply them before modifying the page.
				 */
				if (isAborted &&
					zheap_exec_pending_rollback(relation, buffer,
												xwait_trans_slot, xwait))
					goto check_tup_satisfies_update;
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
			TransactionId	current_tup_xid;

			/*
			 * Wait for regular transaction to end; but first, acquire tuple
			 * lock.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			heap_acquire_tuplock(relation, &(oldtup.t_self), *lockmode,
								 LockWaitBlock, &have_tuple_lock);
			if (xwait_subxid != InvalidSubTransactionId)
				SubXactLockTableWait(xwait, xwait_subxid, relation,
									 &oldtup.t_self, XLTW_Update);
			else
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
			 * other xact could update/lock this tuple before we get to this
			 * point.  Check for xid change, and start over if so.  We need to
			 * do some special handling for lockers because their xid is never
			 * stored on the tuples.  If there was a single locker on the
			 * tuple and that locker is gone and some new locker has locked
			 * the tuple, we won't be able to identify that by infomask/xid on
			 * the tuple, rather we need to fetch the locker xid.
			 */
			ZHeapTupleGetTransInfo(&oldtup, buffer, NULL, NULL,
								   &current_tup_xid, NULL, NULL, false);
			if (xid_infomask_changed(oldtup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(current_tup_xid, xwait))
			{
				if (ZHEAP_XID_IS_LOCKED_ONLY(oldtup.t_data->t_infomask) &&
					!ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask) &&
					TransactionIdIsValid(single_locker_xid))
				{
					TransactionId current_single_locker_xid = InvalidTransactionId;

					(void) GetLockerTransInfo(relation, &oldtup, buffer, NULL,
											  NULL, &current_single_locker_xid,
											  NULL, NULL);
					if (!TransactionIdEquals(single_locker_xid,
											 current_single_locker_xid))
						goto check_tup_satisfies_update;

				}
				else
					goto check_tup_satisfies_update;
			}

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
			if (!isCommitted)
				zheap_exec_pending_rollback(relation, buffer,
											xwait_trans_slot, xwait);

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
	else if (result == HeapTupleUpdated &&
			 ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask))
	{
		/*
		 * If a tuple is updated and is visible to our snapshot, we allow to update
		 * it;  Else, we return HeapTupleUpdated and visit EvalPlanQual path to
		 * check whether the quals still match.  In that path, we also lock the
		 * tuple so that nobody can update it before us.
		 *
		 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
		 * transaction has already locked the tuple for update because of
		 * multilocker flag. In that case, we've to check whether the current
		 * transaction has already locked the tuple for update.
		 */

		/*
		 * Get the transaction slot and undo record pointer if we are already in a
		 * transaction.
		 */
		trans_slot_id = PageGetTransactionSlotId(relation, buffer, epoch, xid,
												 &prev_urecptr, false, false,
												 NULL);

		if (trans_slot_id != InvalidXactSlotId)
		{
			List	*mlmembers;
			ListCell   *lc;

			/*
			 * If any subtransaction of the current top transaction already holds
			 * a lock as strong as or stronger than what we're requesting, we
			 * effectively hold the desired lock already.  We *must* succeed
			 * without trying to take the tuple lock, else we will deadlock
			 * against anyone wanting to acquire a stronger lock.
			 */
			mlmembers = ZGetMultiLockMembersForCurrentXact(&oldtup,
												trans_slot_id, prev_urecptr);

			foreach(lc, mlmembers)
			{
				ZMultiLockMember *mlmember = (ZMultiLockMember *) lfirst(lc);

				/*
				 * Only members of our own transaction must be present in
				 * the list.
				 */
				Assert(TransactionIdIsCurrentTransactionId(mlmember->xid));

				if (mlmember->mode >= *lockmode)
				{
					result = HeapTupleMayBeUpdated;

					/*
					 * There is no other active locker on the tuple except
					 * current transaction id, so we can update the tuple.
					 */
					checked_lockers = true;
					locker_remains = false;
					break;
				}
			}

			list_free_deep(mlmembers);
		}

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

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(oldtup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&hufd->ctid);
		else
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
		bms_free(inplace_upd_proj_attrs);
		bms_free(key_attrs);
		return result;
	}

	/* Acquire subtransaction lock, if current transaction is a subtransaction. */
	if (IsSubTransaction())
	{
		SubXactLockTableInsert(GetCurrentSubTransactionId());
		hasSubXactLock = true;
	}

	/*
	 * If it is a non inplace update then check we have sufficient free space
	 * to insert in same page. If not try defragmentation and recheck the
	 * freespace again.
	 */
	if (!use_inplace_update && !is_index_updated && !need_toast)
	{
		bool	pruned;

		/* Here, we pass delta space required to accomodate the new tuple. */
		pruned = zheap_page_prune_opt(relation, buffer, old_offnum,
									  (newtupsize - oldtupsize));

		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);

		/*
		 * Check if the non-inplace update is due to non-index update and we
		 * are able to perform pruning, then we must be able to perform
		 * inplace update.
		 */
		if (pruned)
			use_inplace_update = true;
	}
	
	max_offset = PageGetMaxOffsetNumber(BufferGetPage(buffer));
	pagefree = PageGetZHeapFreeSpace(page);

	/* 
	 * Incase of the non in-place update we also need to
	 * reserve a map for the new tuple.
	 */
	if (!use_inplace_update)
		max_offset += 1;

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer, max_offset,
											   epoch, xid, &prev_urecptr,
											   &lock_reacquired, false);
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
	 * It's possible that tuple slot is now marked as frozen. Hence, we refetch
	 * the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	oldtup.t_len = ItemIdGetLength(lp);

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must be
	 * frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (oldtup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		tup_trans_slot_id = ZHTUP_SLOT_FROZEN;
		tup_xid = InvalidTransactionId;
	}

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

	/*
	 * updated tuple doesn't fit on current page or the toaster needs
	 * to be activated
	 */
	if ((!use_inplace_update && newtupsize > pagefree) || need_toast)
	{
		uint16	lock_old_infomask;
		BlockNumber	oldblk, newblk;

		/*
		 * To prevent concurrent sessions from updating the tuple, we have to
		 * temporarily mark it locked, while we release the lock.
		 */
		undorecord.uur_info = 0;
		undorecord.uur_prevlen = 0;
		undorecord.uur_reloid = relation->rd_id;
		undorecord.uur_prevxid = tup_xid;
		undorecord.uur_xid = xid;
		undorecord.uur_cid = cid;
		undorecord.uur_fork = MAIN_FORKNUM;
		undorecord.uur_blkprev = prev_urecptr;
		undorecord.uur_block = ItemPointerGetBlockNumber(&(oldtup.t_self));
		undorecord.uur_offset = ItemPointerGetOffsetNumber(&(oldtup.t_self));

		initStringInfo(&undorecord.uur_tuple);
		initStringInfo(&undorecord.uur_payload);

		/*
		 * Here, we are storing old tuple header which is required to
		 * reconstruct the old copy of tuple.
		 */
		appendBinaryStringInfo(&undorecord.uur_tuple,
							   (char *) oldtup.t_data,
							   SizeofZHeapTupleHeader);
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) (lockmode),
							   sizeof(LockTupleMode));
		/*
		 * Store the transaction slot number for undo tuple in undo record, if
		 * the slot belongs to TPD entry.  We can always get the current tuple's
		 * transaction slot number by referring offset->slot map in TPD entry,
		 * however that won't be true for tuple in undo.
		 */
		if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &tup_trans_slot_id,
								   sizeof(tup_trans_slot_id));
		}

		/*
		 * Store subtransaction id in undo record.  See SubXactLockTableWait
		 * to know why we need to store subtransaction id in undo.
		 */
		if (hasSubXactLock)
		{
			SubTransactionId subxid = GetCurrentSubTransactionId();

			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &subxid,
								   sizeof(subxid));
		}

		urecptr = PrepareUndoInsert(&undorecord,
									InvalidTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									&undometa);

		temp_infomask = oldtup.t_data->t_infomask;

		/* Compute the new xid and infomask to store into the tuple. */
		compute_new_xid_infomask(&oldtup, buffer, save_tup_xid,
								 tup_trans_slot_id, temp_infomask,
								 xid, trans_slot_id, single_locker_xid,
								 *lockmode, LockForUpdate, &lock_old_infomask,
								 &result_trans_slot_id);

		if (ZHeapTupleHasMultiLockers(lock_old_infomask))
			undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
		else
			undorecord.uur_type = UNDO_XID_LOCK_FOR_UPDATE;

		START_CRIT_SECTION();

		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */

		if (ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask) &&
			!any_multi_locker_member_alive)
			oldtup.t_data->t_infomask &= ~ZHEAP_MULTI_LOCKERS;

		InsertPreparedUndo();

		/*
		 * We never set the locker slot on the tuple, so pass set_tpd_map_slot
		 * flag as false from the locker.  From all other places it should
		 * always be passed as true so that the proper slot get set in the TPD
		 * offset map if its a TPD slot.
		 */
		PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch,
					xid, urecptr, NULL, 0);

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
			xlundohdr.reloid = undorecord.uur_reloid;
			xlundohdr.urec_ptr = urecptr;
			xlundohdr.blkprev = undorecord.uur_blkprev;

			xlrec.prev_xid = tup_xid;
			xlrec.offnum = ItemPointerGetOffsetNumber(&(oldtup.t_self));
			xlrec.infomask = oldtup.t_data->t_infomask;
			xlrec.trans_slot_id = result_trans_slot_id;
			xlrec.flags = 0;

			if (result_trans_slot_id != trans_slot_id)
			{
				Assert(result_trans_slot_id == tup_trans_slot_id);
				xlrec.flags |= XLZ_LOCK_TRANS_SLOT_FOR_UREC;
			}
			else if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
				xlrec.flags |= XLZ_LOCK_CONTAINS_TPD_SLOT;

			if (hasSubXactLock)
				 xlrec.flags |= XLZ_LOCK_CONTAINS_SUBXACT;
			if (undorecord.uur_type == UNDO_XID_LOCK_FOR_UPDATE)
				xlrec.flags |= XLZ_LOCK_FOR_UPDATE;

prepare_xlog:
			/* LOG undolog meta if this is the first WAL after the checkpoint. */
			LogUndoMetaData(&undometa);

			GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

			XLogBeginInsert();
			XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);
			if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
				(void) RegisterTPDBuffer(page, 1);
			XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
			XLogRegisterData((char *) &xlrec, SizeOfZHeapLock);
			RegisterUndoLogBuffers(2);

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
			XLogRegisterData((char *) (lockmode), sizeof(LockTupleMode));
			if (xlrec.flags & XLZ_LOCK_TRANS_SLOT_FOR_UREC)
				XLogRegisterData((char *) &trans_slot_id, sizeof(trans_slot_id));
			else if (xlrec.flags & XLZ_LOCK_CONTAINS_TPD_SLOT)
				XLogRegisterData((char *) &tup_trans_slot_id, sizeof(tup_trans_slot_id));

			recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_LOCK, RedoRecPtr,
										doPageWrites);
			if (recptr == InvalidXLogRecPtr)
			{
				ResetRegisteredTPDBuffers();
				goto prepare_xlog;
			}

			PageSetLSN(page, recptr);
			if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
				TPDPageSetLSN(page, recptr);
			UndoLogBuffersSetLSN(recptr);
		}
		END_CRIT_SECTION();

		pfree(undorecord.uur_tuple.data);
		pfree(undorecord.uur_payload.data);

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		UnlockReleaseUndoBuffers();
		UnlockReleaseTPDBuffers();

		/*
		 * Let the toaster do its thing, if needed.
		 *
		 * Note: below this point, zheaptup is the data we actually intend to
		 * store into the relation; newtup is the caller's original untoasted
		 * data.
		 */
		if (need_toast)
		{
			zheaptup = ztoast_insert_or_update(relation, newtup, &oldtup, 0);
			newtupsize = SHORTALIGN(zheaptup->t_len);	/* short aligned */
		}
		else
			zheaptup = newtup;
reacquire_buffer:
		/*
		 * Get a new page for inserting tuple.  We will need to acquire buffer
		 * locks on both old and new pages.  See heap_update.
		 */
		if (BufferIsValid(vmbuffer_new))
		{
			ReleaseBuffer(vmbuffer_new);
			vmbuffer_new = InvalidBuffer;
		}

		if (newtupsize > pagefree)
		{
			newbuf = RelationGetBufferForZTuple(relation, zheaptup->t_len,
												buffer, 0, NULL,
												&vmbuffer_new, &vmbuffer);
		}
		else
		{
			/* Re-acquire the lock on the old tuple's page. */
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
			/* Re-check using the up-to-date free space */
			pagefree = PageGetZHeapFreeSpace(page);
			if (newtupsize > pagefree)
			{
				/*
				 * Rats, it doesn't fit anymore.  We must now unlock and
				 * relock to avoid deadlock.  Fortunately, this path should
				 * seldom be taken.
				 */
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
				newbuf = RelationGetBufferForZTuple(relation, zheaptup->t_len,
													buffer, 0, NULL,
													&vmbuffer_new, &vmbuffer);
			}
			else
			{
				/* OK, it fits here, so we're done. */
				newbuf = buffer;
			}
		}

		max_offset = PageGetMaxOffsetNumber(BufferGetPage(newbuf));
		oldblk = BufferGetBlockNumber(buffer);
		newblk = BufferGetBlockNumber(newbuf);

		/*
		 * If we have got the new block than reserve the slot in same order in
		 * which buffers are locked (ascending).
		 */
		if (oldblk == newblk)
		{
			new_trans_slot_id = PageReserveTransactionSlot(relation,
														   newbuf,
														   max_offset + 1,
														   epoch,
														   xid,
														   &new_prev_urecptr,
														   &lock_reacquired,
														   false);
			/*
			 * We should get the same slot what we reserved previously because
			 * our transaction information should already be there.  But, there
			 * is possibility that our slot might have moved to the TPD in such
			 * case we should get previous slot_no + 1.
			 */
			Assert((new_trans_slot_id == trans_slot_id) ||
					(ZHeapPageHasTPDSlot((PageHeader)page) &&
					 new_trans_slot_id == trans_slot_id + 1));

			trans_slot_id = new_trans_slot_id;
		}
		else
			MultiPageReserveTransSlot(relation,
									  buffer, newbuf,
									  old_offnum, max_offset,
									  epoch, xid,
									  &prev_urecptr, &new_prev_urecptr,
									  &trans_slot_id, &new_trans_slot_id,
									  &lock_reacquired);

		if (lock_reacquired || (new_trans_slot_id == InvalidXactSlotId))
		{
			/*
			 * If non in-place update is happening on two different buffers,
			 * then release the new buffer, and release the lock on old buffer.
			 * Else, only release the lock on old buffer.
			 */
			if (buffer != newbuf)
				UnlockReleaseBuffer(newbuf);

			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			UnlockReleaseTPDBuffers();

			if (new_trans_slot_id == InvalidXactSlotId)
			{
				pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
				pg_usleep(10000L);	/* 10 ms */
				pgstat_report_wait_end();
			}

			goto reacquire_buffer;
		}

		/*
		 * After we release the lock on page, it could be pruned.  As we have
		 * lock on the tuple, it couldn't be removed underneath us, but its
		 * position could be changes, so need to refresh the tuple position.
		 *
		 * XXX Though the length of the tuple wouldn't have changed, but there
		 * is no harm in refrehsing it for the sake of consistency of code.
		 */
		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		oldtup.t_len = ItemIdGetLength(lp);
		tup_trans_slot_id = trans_slot_id;
		tup_xid = xid;
	}
	else
	{
		/* No TOAST work needed, and it'll fit on same page */
		newbuf = buffer;
		new_trans_slot_id = trans_slot_id;
		zheaptup = newtup;
	}

	CheckForSerializableConflictIn(relation, &(oldtup.t_self), buffer);

	/*
	 * Prepare an undo record for old tuple.  We need to separately store the
	 * latest transaction id that has changed the tuple to ensure that we
	 * don't try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_reloid = relation->rd_id;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
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
		bool	hasPayload = false;

		undorecord.uur_type = UNDO_INPLACE_UPDATE;

		/*
		 * Store the transaction slot number for undo tuple in undo record, if
		 * the slot belongs to TPD entry.  We can always get the current tuple's
		 * transaction slot number by referring offset->slot map in TPD entry,
		 * however that won't be true for tuple in undo.
		 */
		if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			initStringInfo(&undorecord.uur_payload);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &tup_trans_slot_id,
								   sizeof(tup_trans_slot_id));
			hasPayload = true;
		}

		/*
		 * Store subtransaction id in undo record.  See SubXactLockTableWait
		 * to know why we need to store subtransaction id in undo.
		 */
		if (hasSubXactLock)
		{
			SubTransactionId subxid = GetCurrentSubTransactionId();

			if (!hasPayload)
			{
				initStringInfo(&undorecord.uur_payload);
				hasPayload = true;
			}

			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &subxid,
								   sizeof(subxid));
		}

		if (!hasPayload)
			undorecord.uur_payload.len = 0;

		urecptr = PrepareUndoInsert(&undorecord,
									InvalidTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									&undometa);
	}
	else
	{
		Size	payload_len;
		UnpackedUndoRecord	undorec[2];

		undorecord.uur_type = UNDO_UPDATE;

		/*
		 * we need to initialize the length of payload before actually knowing
		 * the value to ensure that the required space is reserved in undo.
		 */
		payload_len = sizeof(ItemPointerData);
		if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			payload_len += sizeof(tup_trans_slot_id);
		}

		/*
		 * Store subtransaction id in undo record.  See SubXactLockTableWait
		 * to know why we need to store subtransaction id in undo.
		 */
		if (hasSubXactLock)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
			payload_len += sizeof(SubTransactionId);
		}

		undorecord.uur_payload.len = payload_len;

		/* prepare an undo record for new tuple */
		new_undorecord.uur_type = UNDO_INSERT;
		new_undorecord.uur_info = 0;
		new_undorecord.uur_prevlen = 0;
		new_undorecord.uur_reloid = relation->rd_id;
		new_undorecord.uur_prevxid = xid;
		new_undorecord.uur_xid = xid;
		new_undorecord.uur_cid = cid;
		new_undorecord.uur_fork = MAIN_FORKNUM;
		new_undorecord.uur_block = BufferGetBlockNumber(newbuf);
		new_undorecord.uur_payload.len = 0;
		new_undorecord.uur_tuple.len = 0;

		if (new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			new_undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			initStringInfo(&new_undorecord.uur_payload);
			appendBinaryStringInfo(&new_undorecord.uur_payload,
								   (char *) &new_trans_slot_id,
								   sizeof(new_trans_slot_id));
		}
		else
			new_undorecord.uur_payload.len = 0;

		undorec[0] = undorecord;
		undorec[1] = new_undorecord;
		UndoSetPrepareSize(undorec, 2, InvalidTransactionId,
						   UndoPersistenceForRelation(relation), NULL, &undometa);

		/* copy updated record (uur_info might got updated )*/
		undorecord = undorec[0];
		new_undorecord = undorec[1];

		urecptr = PrepareUndoInsert(&undorecord,
									InvalidTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									NULL);

		initStringInfo(&undorecord.uur_payload);

		/* Make more room for tuple location if needed */
		enlargeStringInfo(&undorecord.uur_payload, payload_len);

		if (buffer == newbuf)
			new_undorecord.uur_blkprev = urecptr;
		else
			new_undorecord.uur_blkprev = new_prev_urecptr;

		new_urecptr = PrepareUndoInsert(&new_undorecord,
										InvalidTransactionId,
										UndoPersistenceForRelation(relation),
										NULL,
										NULL);

		/* Check and lock the TPD page before starting critical section. */
		CheckAndLockTPDPage(relation, new_trans_slot_id, trans_slot_id,
							newbuf, buffer);

	}

	/*
	 * We can't rely on any_multi_locker_member_alive to clear the multi locker
	 * bit, if the the lock on the buffer is released inbetween.
	 */
	temp_infomask = oldtup.t_data->t_infomask;

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&oldtup, buffer, save_tup_xid, tup_trans_slot_id,
							 temp_infomask, xid, trans_slot_id,
							 single_locker_xid, *lockmode, ForUpdate,
							 &old_infomask, &result_trans_slot_id);

	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(result_trans_slot_id == trans_slot_id);

	/*
	 * Propagate the lockers information to the new tuple.  Since we're doing
	 * an update, the only possibility is that the lockers had FOR KEY SHARE
	 * lock.  For in-place updates, we are not creating any new version, so
	 * we don't need to propagate anything.
	 */
	if ((checked_lockers && !locker_remains) || use_inplace_update)
		new_infomask = 0;
	else
	{
		/*
		 * We should also set the multilocker flag if it was there previously,
		 * else, we set the tuple as locked-only.
		 */
		new_infomask = ZHEAP_XID_KEYSHR_LOCK;
		if (ZHeapTupleHasMultiLockers(old_infomask))
			new_infomask |= ZHEAP_MULTI_LOCKERS | ZHEAP_XID_LOCK_ONLY;
		else
			new_infomask |= ZHEAP_XID_LOCK_ONLY;
	}

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

	/* We must have a valid buffer. */
	Assert(BufferIsValid(vmbuffer));
	vm_status = visibilitymap_get_status(relation,
								BufferGetBlockNumber(buffer), &vmbuffer);

	/*
	 * If the page is new, then there will no valid vmbuffer_new and the
	 * visisbilitymap is reset already, hence, need not to clear anything.
	 */
	if (newbuf != buffer && BufferIsValid(vmbuffer_new))
		vm_status_new = visibilitymap_get_status(relation,
								BufferGetBlockNumber(newbuf), &vmbuffer_new);

	/*
	 * Make sure we have space to register regular pages, a couple of TPD
	 * pages and undo log pages, before we enter the critical section.
	 * TODO: what is the maximum number of pages we could touch?
	 */
	XLogEnsureRecordSpace(8, 0);

	START_CRIT_SECTION();

	if (buffer == newbuf)
	{
		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */
		if (ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask) &&
			!any_multi_locker_member_alive)
			oldtup.t_data->t_infomask &= ~ZHEAP_MULTI_LOCKERS;
	}

	if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) ||
		(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
	{
		all_visible_cleared = true;
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	if (newbuf != buffer)
	{
		if ((vm_status_new & VISIBILITYMAP_ALL_VISIBLE) ||
			(vm_status_new & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
		{
			new_all_visible_cleared = true;
			visibilitymap_clear(relation, BufferGetBlockNumber(newbuf),
					vmbuffer_new, VISIBILITYMAP_VALID_BITS);
		}
	}

	/*
	 * A page can be pruned for non-inplace updates or inplace updates that
	 * results in shorter tuples.  If this transaction commits, the tuple will
	 * become DEAD sooner or later.  If the transaction finally aborts, the
	 * subsequent page pruning will be a no-op and the hint will be cleared.
	 */
	if (!use_inplace_update || (zheaptup->t_len < oldtup.t_len))
		ZPageSetPrunable(page, xid);

	/* oldtup should be pointing to right place in page */
	Assert(oldtup.t_data == (ZHeapTupleHeader) PageGetItem(page, lp));

	ZHeapTupleHeaderSetXactSlot(oldtup.t_data, result_trans_slot_id);
	oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	oldtup.t_data->t_infomask |= infomask_old_tuple;

	/* keep the new tuple copy updated for the caller */
	ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, new_trans_slot_id);
	zheaptup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	zheaptup->t_data->t_infomask |= infomask_new_tuple;

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
		ItemIdChangeLen(lp, zheaptup->t_len);
		memcpy((char *) oldtup.t_data + SizeofZHeapTupleHeader,
			   (char *) zheaptup->t_data + SizeofZHeapTupleHeader,
			   zheaptup->t_len - SizeofZHeapTupleHeader);

		/*
		 * Copy everything from new tuple in infomask apart from visibility
		 * flags.
		 */
		oldtup.t_data->t_infomask = oldtup.t_data->t_infomask &
											ZHEAP_VIS_STATUS_MASK;
		oldtup.t_data->t_infomask |= (zheaptup->t_data->t_infomask &
										~ZHEAP_VIS_STATUS_MASK);
		/* Copy number of attributes in infomask2 of new tuple. */
		oldtup.t_data->t_infomask2 &= ~ZHEAP_NATTS_MASK;
		oldtup.t_data->t_infomask2 |=
					newtup->t_data->t_infomask2 & ZHEAP_NATTS_MASK;
		/* also update the tuple length and self pointer */
		oldtup.t_len = zheaptup->t_len;
		oldtup.t_data->t_hoff = zheaptup->t_data->t_hoff;
		ItemPointerCopy(&oldtup.t_self, &zheaptup->t_self);
	}
	else
	{
		/* insert tuple at new location */
		RelationPutZHeapTuple(relation, newbuf, zheaptup);

		/* update new tuple location in undo record */
		appendBinaryStringInfoNoExtend(&undorecord.uur_payload,
									   (char *) &zheaptup->t_self,
									   sizeof(ItemPointerData));
		if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			appendBinaryStringInfoNoExtend(&undorecord.uur_payload,
										  (char *) &tup_trans_slot_id,
										  sizeof(tup_trans_slot_id));
		if (hasSubXactLock)
		{
			SubTransactionId subxid = GetCurrentSubTransactionId();

			appendBinaryStringInfoNoExtend(&undorecord.uur_payload,
										   (char *) &subxid,
										   sizeof(subxid));
		}

		new_undorecord.uur_offset = ItemPointerGetOffsetNumber(&(zheaptup->t_self));
	}

	InsertPreparedUndo();
	if (use_inplace_update)
		PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch,
					xid, urecptr, NULL, 0);
	else
	{
		if (newbuf == buffer)
		{
			OffsetNumber usedoff[2];
			
			usedoff[0] = undorecord.uur_offset;
			usedoff[1] = new_undorecord.uur_offset;

			PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch,
						xid, new_urecptr, usedoff, 2);
		}
		else
		{
			/* set transaction slot information for old page */
			PageSetUNDO(undorecord, buffer, trans_slot_id, true, epoch,
						xid, urecptr, NULL, 0);
			/* set transaction slot information for new page */
			PageSetUNDO(new_undorecord,
						newbuf,
						new_trans_slot_id,
						true,
						epoch,
						xid,
						new_urecptr,
						NULL,
						0);

			MarkBufferDirty(newbuf);
		}
	}

	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
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

		log_zheap_update(relation, undorecord, new_undorecord,
						 urecptr, new_urecptr, buffer, newbuf,
						 &oldtup, zheaptup, tup_trans_slot_id,
						 trans_slot_id, new_trans_slot_id,
						 use_inplace_update, all_visible_cleared,
						 new_all_visible_cleared, &undometa);
	}

	END_CRIT_SECTION();

	/* be tidy */
	pfree(undorecord.uur_tuple.data);
	if (undorecord.uur_payload.len > 0)
		pfree(undorecord.uur_payload.data);

	if (!use_inplace_update && new_undorecord.uur_payload.len > 0)
		pfree(new_undorecord.uur_payload.data);

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
	UnlockReleaseTPDBuffers();

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
	else
		pgstat_count_zheap_update(relation);

	/*
	 * If heaptup is a private copy, release it.  Don't forget to copy t_self
	 * back to the caller's image, too.
	 */
	if (zheaptup != newtup)
	{
		newtup->t_self = zheaptup->t_self;
		zheap_freetuple(zheaptup);
	}
	bms_free(inplace_upd_attrs);
	bms_free(inplace_upd_proj_attrs);
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
static void
log_zheap_update(Relation reln, UnpackedUndoRecord undorecord,
				 UnpackedUndoRecord newundorecord, UndoRecPtr urecptr,
				 UndoRecPtr newurecptr, Buffer oldbuf, Buffer newbuf,
				 ZHeapTuple oldtup, ZHeapTuple newtup,
				 int old_tup_trans_slot_id, int trans_slot_id,
				 int new_trans_slot_id, bool inplace_update,
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
	xlundohdr.reloid = undorecord.uur_reloid;
	xlundohdr.urec_ptr = urecptr;
	xlundohdr.blkprev = undorecord.uur_blkprev;

	xlrec.prevxid = undorecord.uur_prevxid;
	xlrec.old_offnum = ItemPointerGetOffsetNumber(&oldtup->t_self);
	xlrec.old_infomask = oldtup->t_data->t_infomask;
	xlrec.old_trans_slot_id = trans_slot_id;
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
	if (undorecord.uur_info & UREC_INFO_PAYLOAD_CONTAINS_SUBXACT)
		xlrec.flags |= XLZ_UPDATE_CONTAINS_SUBXACT;

	if (!inplace_update)
	{
		Page		page = BufferGetPage(newbuf);

		xlrec.flags |= XLZ_NON_INPLACE_UPDATE;

		xlnewundohdr.reloid = newundorecord.uur_reloid;
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
	if (old_tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		xlrec.flags |= XLZ_UPDATE_OLD_CONTAINS_TPD_SLOT;
		XLogRegisterData((char *) &old_tup_trans_slot_id,
						 sizeof(old_tup_trans_slot_id));
	}
	if (!inplace_update)
	{
		XLogRegisterData((char *) &xlnewundohdr, SizeOfUndoHeader);
		if (new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			xlrec.flags |= XLZ_UPDATE_NEW_CONTAINS_TPD_SLOT;
			XLogRegisterData((char *) &new_trans_slot_id,
							 sizeof(new_trans_slot_id));
		}
	}
	if (xlrec.flags & XLZ_HAS_UPDATE_UNDOTUPLE)
	{
		XLogRegisterData((char *) &xlundotuphdr, SizeOfZHeapHeader);
		/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
		XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
						 totalundotuplen - SizeofZHeapTupleHeader);
	}

	XLogRegisterBuffer(0, newbuf, bufflags);
	if (oldbuf != newbuf)
	{
		uint8	block_id;

		XLogRegisterBuffer(1, oldbuf, REGBUF_STANDARD);
		block_id = 2;
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			block_id = RegisterTPDBuffer(BufferGetPage(oldbuf), block_id);
		if (new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			RegisterTPDBuffer(BufferGetPage(newbuf), block_id);
	}
	else
	{
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			/*
			 * Block id '1' is reserved for oldbuf if that is different from
			 * newbuf.
			 */
			RegisterTPDBuffer(BufferGetPage(oldbuf), 2);
		}
	}
	RegisterUndoLogBuffers(5);

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
	{
		ResetRegisteredTPDBuffers();
		goto prepare_xlog;
	}

	if (newbuf != oldbuf)
	{
		PageSetLSN(BufferGetPage(newbuf), recptr);
		if (new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			TPDPageSetLSN(BufferGetPage(newbuf), recptr);
	}
	PageSetLSN(BufferGetPage(oldbuf), recptr);
	if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		TPDPageSetLSN(BufferGetPage(oldbuf), recptr);
	UndoLogBuffersSetLSN(recptr);
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
	UndoRecPtr	prev_urecptr;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	Page		page;
	ItemPointerData	ctid;
	TransactionId xid,
				  tup_xid,
				  single_locker_xid;
	SubTransactionId tup_subxid = InvalidSubTransactionId;
	CommandId	tup_cid;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	uint32		epoch;
	int			tup_trans_slot_id,
				trans_slot_id,
				single_locker_trans_slot;
	OffsetNumber	offnum;
	LockOper	lockopr;
	bool		require_sleep;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	bool		rollback_and_relocked;

	xid = GetTopTransactionId();
	epoch = GetEpochForXid(xid);
	lockopr = eval ? LockForUpdate : LockOnly;

	*buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

	LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

	page = BufferGetPage(*buffer);
	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
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
	trans_slot_id = PageGetTransactionSlotId(relation, *buffer, epoch, xid,
											 &urec_ptr, false, false, NULL);

	/*
	 * ctid needs to be fetched from undo chain.  See zheap_update.
	 */
	ctid = *tid;

check_tup_satisfies_update:
	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(relation, &zhtup, cid, *buffer, &ctid,
									   &tup_trans_slot_id, &tup_xid, &tup_subxid,
									   &tup_cid, &single_locker_xid,
									   &single_locker_trans_slot, false, eval,
									   snapshot, &in_place_updated_or_locked);
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
		SubTransactionId	xwait_subxid;
		int				xwait_trans_slot;
		uint16			infomask;

		xwait_subxid = tup_subxid;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = tup_xid;
			xwait_trans_slot = tup_trans_slot_id;
		}

		infomask = zhtup.t_data->t_infomask;

		/*
		 * make a copy of the tuple before releasing the lock as some other
		 * backend can perform in-place update this tuple once we release the
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
				mlmembers = ZGetMultiLockMembersForCurrentXact(&zhtup,
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
					if (!ZHeapTupleIsMoved(zhtup.t_data->t_infomask) &&
						!ItemPointerEquals(&zhtup.t_self, &ctid))
					{
						HTSU_Result res;

						res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
													   xid, mode, lockopr, cid,
													   &rollback_and_relocked);

						/*
						 * If the update was by some aborted transaction and its
						 * pending undo actions are applied now, then check the
						 * latest copy of the tuple.
						 */
						if (rollback_and_relocked)
						{
							LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
							goto check_tup_satisfies_update;
						}
						else if (res != HeapTupleMayBeUpdated)
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
			TransactionId	current_tup_xid;
			bool	buf_lock_reacquired = false;

			old_lock_mode = get_old_lock_mode(infomask);

			/*
			 * If we're requesting NoKeyExclusive, we might also be able to
			 * avoid sleeping; just ensure that there is no conflicting lock
			 * already acquired.
			 */
			if (ZHeapTupleHasMultiLockers(infomask))
			{
				if (!DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
									HWLOCKMODE_from_locktupmode(mode)))
				{
					LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
					buf_lock_reacquired = true;
				}
			}
			else if (old_lock_mode == LockTupleKeyShare)
			{
				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
				buf_lock_reacquired = true;
			}

			if (buf_lock_reacquired)
			{
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

				ZHeapTupleGetTransInfo(&zhtup, *buffer, NULL, NULL, &current_tup_xid,
										   NULL, NULL, false);

				if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
					!TransactionIdEquals(current_tup_xid, xwait))
					goto check_tup_satisfies_update;
				/* Skip sleeping */
				require_sleep = false;
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
			!ZHeapTupleHasMultiLockers(infomask) &&
			TransactionIdIsCurrentTransactionId(xwait))
		{
			TransactionId	current_tup_xid;

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

			ZHeapTupleGetTransInfo(&zhtup, *buffer, NULL, NULL, &current_tup_xid,
								   NULL, NULL, false);
			if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(current_tup_xid, xwait))
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
			TransactionId   current_tup_xid;

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
				if (!ZHEAP_XID_IS_LOCKED_ONLY(infomask))
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
					mlmembers = ZGetMultiLockMembers(relation, &zhtup,
													 *buffer, true);

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
						{
							if (xwait_subxid != InvalidSubTransactionId)
								SubXactLockTableWait(xwait, xwait_subxid, relation,
													 &zhtup.t_self, XLTW_Lock);
							else
								XactLockTableWait(xwait, relation, &zhtup.t_self,
												  XLTW_Lock);
						}
						break;
					case LockWaitSkip:
						if (xwait_subxid != InvalidSubTransactionId)
						{
							if (!ConditionalSubXactLockTableWait(xwait, xwait_subxid))
							{
								result = HeapTupleWouldBlock;
								/* recovery code expects to have buffer lock held */
								LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
								goto failed;
							}
						}
						else if (!ConditionalXactLockTableWait(xwait))
						{
								result = HeapTupleWouldBlock;
								/* recovery code expects to have buffer lock held */
								LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
								goto failed;
						}
						break;
					case LockWaitError:
						if (xwait_subxid != InvalidSubTransactionId)
						{
							if (!ConditionalSubXactLockTableWait(xwait, xwait_subxid))
									ereport(ERROR,
									(errcode(ERRCODE_LOCK_NOT_AVAILABLE),
										errmsg("could not obtain lock on row in relation \"%s\"",
										RelationGetRelationName(relation))));
						}
						else if (!ConditionalXactLockTableWait(xwait))
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

				if (!ZHeapTupleIsMoved(zhtup.t_data->t_infomask) &&
					!ItemPointerEquals(&zhtup.t_self, &ctid))
				{
					res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
												   xid, mode, lockopr, cid,
												   &rollback_and_relocked);

					/*
					 * If the update was by some aborted transaction and its
					 * pending undo actions are applied now, then check the
					 * latest copy of the tuple.
					 */
					if (rollback_and_relocked)
					{
						LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
						goto check_tup_satisfies_update;
					}
					else if (res != HeapTupleMayBeUpdated)
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

				new_mlmembers = ZGetMultiLockMembers(relation, &zhtup,
													 *buffer, false);

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
			 * other xact could update/lock this tuple before we get to this
			 * point.  Check for xid change, and start over if so.  We need to
			 * do some special handling for lockers because their xid is never
			 * stored on the tuples.  If there was a single locker on the
			 * tuple and that locker is gone and some new locker has locked
			 * the tuple, we won't be able to identify that by infomask/xid on
			 * the tuple, rather we need to fetch the locker xid.
			 */
			ZHeapTupleGetTransInfo(&zhtup, *buffer, NULL, NULL,
								   &current_tup_xid, NULL, NULL, false);
			if (xid_infomask_changed(zhtup.t_data->t_infomask, infomask) ||
				!TransactionIdEquals(current_tup_xid, xwait))
			{
				if (ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask) &&
					!ZHeapTupleHasMultiLockers(zhtup.t_data->t_infomask) &&
					TransactionIdIsValid(single_locker_xid))
				{
					TransactionId current_single_locker_xid = InvalidTransactionId;

					(void) GetLockerTransInfo(relation, &zhtup, *buffer, NULL,
											  NULL, &current_single_locker_xid,
											  NULL, NULL);
					if (!TransactionIdEquals(single_locker_xid,
											 current_single_locker_xid))
						goto check_tup_satisfies_update;

				}
				else
					goto check_tup_satisfies_update;
			}
		}

		if (TransactionIdIsValid(xwait) && TransactionIdDidAbort(xwait))
		{
			/*
			 * For aborted transaction, if the undo actions are not applied
			 * yet, then apply them before modifying the page.
			 */
			if (!TransactionIdIsCurrentTransactionId(xwait))
				zheap_exec_pending_rollback(relation, *buffer,
											xwait_trans_slot, xwait);

			/*
			 * For aborted updates, we must allow to reverify the tuple in
			 * case it's values got changed.
			 */
			if (!ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask))
				goto check_tup_satisfies_update;
		}

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

		if (TransactionIdIsValid(single_locker_xid))
			xwait = single_locker_xid;
		else
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

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(zhtup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&hufd->ctid);
		else
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
	trans_slot_id = PageReserveTransactionSlot(relation, *buffer,
											   PageGetMaxOffsetNumber(page),
											   epoch, xid, &prev_urecptr,
											   &lock_reacquired, false);
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
	 * It's possible that tuple slot is now marked as frozen. Hence, we refetch
	 * the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zhtup.t_len = ItemIdGetLength(lp);

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must be
	 * frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zhtup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		tup_trans_slot_id = ZHTUP_SLOT_FROZEN;
		tup_xid = InvalidTransactionId;
	}

	/*
	 * If all the members were lockers and are all gone, we can do away
	 * with the MULTI_LOCKERS bit.
	 */
	zheap_lock_tuple_guts(relation, *buffer, &zhtup, tup_xid, xid, mode,
						  lockopr, epoch, tup_trans_slot_id, trans_slot_id,
						  single_locker_xid, single_locker_trans_slot,
						  prev_urecptr, cid, !any_multi_locker_member_alive);

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
 * HeapTupleMayBeUpdated is returned.  To notify the caller if some pending
 * rollback is applied, rollback_and_relocked is set to true.
 */
static HTSU_Result
test_lockmode_for_conflict(Relation rel, Buffer buf, ZHeapTuple zhtup,
						   UndoRecPtr urec_ptr, LockTupleMode old_mode,
						   TransactionId xid, int trans_slot_id,
						   LockTupleMode required_mode, bool has_update,
						   SubTransactionId *subxid, bool *needwait,
						   bool *rollback_and_relocked)
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
			if (subxid)
				ZHeapTupleGetSubXid(zhtup, buf, urec_ptr, subxid);
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
		zheap_exec_pending_rollback(rel, buf, trans_slot_id, xid);

		/*
		 * If it was only a locker, then the lock is completely gone now and
		 * we can return success; but if it was an update, then after applying
		 * pending actions, the tuple might have changed and we must report
		 * error to the caller.  It will allow caller to reverify the tuple in
		 * case it's values got changed.
		 */

		*rollback_and_relocked = true;

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
 * to lock them.  The bool rolled_and_relocked is used to notify the caller
 * that the update has been performed by an aborted transaction and it's
 * pending undo actions are applied here.
 *
 * Note that it is important to lock all the versions that are from
 * non-committed transaction, but if the transaction that has created the
 * new version is committed, we only care to lock its latest version.
 *
 */
static HTSU_Result
zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 TransactionId xid, LockTupleMode mode,
						 LockOper lockopr, CommandId cid,
						 bool *rollback_and_relocked)
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
	uint64		epoch_xid;
	int			trans_slot_id;
	bool		lock_reacquired;
	OffsetNumber	offnum;

	ItemPointerCopy(ctid, &tupid);

	if (rollback_and_relocked)
		*rollback_and_relocked = false;

	for (;;)
	{
		ZHeapTupleData	zhtup;
		ItemId	lp;
		uint16	old_infomask;
		UndoRecPtr	urec_ptr;

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

			/* deleted or moved to another partition, so forget about it */
			if (ZHeapTupleIsMoved(mytup->t_data->t_infomask) ||
				ItemPointerEquals(&(mytup->t_self), ctid))
				return HeapTupleMayBeUpdated;

			/* updated row should have xid matching this xmax */
			ZHeapTupleGetTransInfo(mytup, buf, NULL, NULL, &priorXmax, NULL,
								   NULL, true);

			/* continue to lock the next version of tuple */
			continue;
		}

lock_tuple:
		urec_ptr = InvalidUndoRecPtr;

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

		ZHeapTupleGetTransInfo(mytup, buf, &tup_trans_slot, &epoch_xid,
							   &tup_xid, NULL, &urec_ptr, false);
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
			SubTransactionId	subxid = InvalidSubTransactionId;
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

				mlmembers = ZGetMultiLockMembers(rel, mytup, buf, false);
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
														NULL,
														InvalidUndoRecPtr,
														mlmember->mode,
														mlmember->xid,
														mlmember->trans_slot_id,
														mode, has_update,
														NULL,
														&needwait,
														rollback_and_relocked);

					/*
					 * If the update was by some aborted transaction with
					 * pending rollback, then it's undo actions are applied.
					 * Now, notify the caller to check for the latest
					 * copy of the tuple.
					 */
					if (*rollback_and_relocked)
					{
						list_free_deep(mlmembers);
						goto out_locked;
					}

					if (result == HeapTupleSelfUpdated)
					{
						list_free_deep(mlmembers);
						goto next;
					}

					if (needwait)
					{
						LockBuffer(buf, BUFFER_LOCK_UNLOCK);

						if (mlmember->subxid != InvalidSubTransactionId)
							SubXactLockTableWait(mlmember->xid, mlmember->subxid,
												 rel, &mytup->t_self,
												 XLTW_LockUpdated);
						else
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
					/*
					 * We don't expect to lock updated version of a tuple if
					 * there is only a single locker on the tuple and previous
					 * modifier is all-visible.
					 */
					Assert(!(tup_trans_slot == ZHTUP_SLOT_FROZEN ||
					epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo)));

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

				result = test_lockmode_for_conflict(rel, buf, mytup, urec_ptr,
													old_lock_mode, tup_xid,
													tup_trans_slot, mode,
													has_update, &subxid,
													&needwait,
													rollback_and_relocked);

				/*
				 * If the update was by some aborted transaction with
				 * pending rollback, then it's undo actions are applied.
				 * Now, notify the caller to check for the latest
				 * copy of the tuple.
				 */
				if (*rollback_and_relocked)
					goto out_locked;

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
					if (subxid != InvalidSubTransactionId)
						SubXactLockTableWait(tup_xid, subxid, rel,
											 &mytup->t_self,
											 XLTW_LockUpdated);
					else
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
		offnum = ItemPointerGetOffsetNumber(&mytup->t_self);

		/*
		 * The transaction information of tuple needs to be set in transaction
		 * slot, so needs to reserve the slot before proceeding with the actual
		 * operation.  It will be costly to wait for getting the slot, but we do
		 * that by releasing the buffer lock.
		 */
		trans_slot_id = PageReserveTransactionSlot(rel, buf, offnum, epoch, xid,
											&prev_urecptr, &lock_reacquired, false);
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
		lp = PageGetItemId(page, offnum);

		Assert(ItemIdIsNormal(lp));

		/*
		 * It's possible that tuple slot is now marked as frozen. Hence, we refetch
		 * the tuple here.
		 */
		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);
		zhtup.t_tableOid = mytup->t_tableOid;
		zhtup.t_self = mytup->t_self;

		/*
		 * If the slot is marked as frozen, the latest modifier of the tuple must be
		 * frozen.
		 */
		if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zhtup.t_data)) == ZHTUP_SLOT_FROZEN)
		{
			tup_trans_slot = ZHTUP_SLOT_FROZEN;
			tup_xid = InvalidTransactionId;
		}

		zheap_lock_tuple_guts(rel, buf, &zhtup, tup_xid, xid, mode, lockopr,
							  epoch, tup_trans_slot, trans_slot_id,
							  InvalidTransactionId, InvalidXactSlotId,
							  prev_urecptr, cid, false);

next:
		/*
		 * if we find the end of update chain, or if the transaction that has
		 * updated the tuple is aborter, we're done.
		 */
		if (TransactionIdDidAbort(tup_xid) ||
			ZHeapTupleIsMoved(mytup->t_data->t_infomask) ||
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
					  LockTupleMode mode, LockOper lockopr, uint32 epoch,
					  int tup_trans_slot_id, int trans_slot_id,
					  TransactionId single_locker_xid,
					  int single_locker_trans_slot, UndoRecPtr prev_urecptr,
					  CommandId cid, bool clear_multi_locker)
{
	TransactionId oldestXidHavingUndo;
	UndoRecPtr	urecptr;
	UnpackedUndoRecord	undorecord;
	int			new_trans_slot_id;
	uint16		  old_infomask, temp_infomask;
	uint16		  new_infomask = 0;
	Page		  page;
	xl_undolog_meta undometa;
	bool		hasSubXactLock = false;

	page = BufferGetPage(buf);

	/* Compute the new xid and infomask to store into the tuple. */
	old_infomask = zhtup->t_data->t_infomask;

	temp_infomask = old_infomask;
	if (ZHeapTupleHasMultiLockers(old_infomask) && clear_multi_locker)
		old_infomask &= ~ZHEAP_MULTI_LOCKERS;
	compute_new_xid_infomask(zhtup, buf, tup_xid, tup_trans_slot_id,
							 temp_infomask, xid, trans_slot_id,
							 single_locker_xid, mode, lockopr,
							 &new_infomask, &new_trans_slot_id);


	/* Acquire subtransaction lock, if current transaction is a subtransaction. */
	if (IsSubTransaction())
	{
		SubXactLockTableInsert(GetCurrentSubTransactionId());
		hasSubXactLock = true;
	}

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
	else if (lockopr == LockForUpdate)
		undorecord.uur_type = UNDO_XID_LOCK_FOR_UPDATE;
	else
		undorecord.uur_type = UNDO_XID_LOCK_ONLY;
	undorecord.uur_info = 0;
	undorecord.uur_prevlen = 0;
	undorecord.uur_reloid = rel->rd_id;
	undorecord.uur_prevxid = tup_xid;
	undorecord.uur_xid = xid;
	/*
	 * While locking the tuple, we set the command id as FirstCommandId since
	 * it doesn't modify the tuple, just updates the infomask.
	 */
	undorecord.uur_cid = FirstCommandId;
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

	if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &tup_trans_slot_id,
							   sizeof(tup_trans_slot_id));
	}

	/*
	 * Store subtransaction id in undo record.  See SubXactLockTableWait
	 * to know why we need to store subtransaction id in undo.
	 */
	if (hasSubXactLock)
	{
		SubTransactionId subxid = GetCurrentSubTransactionId();

		undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
		appendBinaryStringInfo(&undorecord.uur_payload,
							   (char *) &subxid,
							   sizeof(subxid));
	}

	urecptr = PrepareUndoInsert(&undorecord,
								InvalidTransactionId,
								UndoPersistenceForRelation(rel),
								NULL,
								&undometa);

	START_CRIT_SECTION();

	InsertPreparedUndo();

	/*
	 * We never set the locker slot on the tuple, so pass set_tpd_map_slot flag
	 * as false from the locker.  From all other places it should always be
	 * passed as true so that the proper slot get set in the TPD offset map if
	 * its a TPD slot.
	 */
	PageSetUNDO(undorecord, buf, trans_slot_id,
				(lockopr == LockForUpdate) ? true : false,
				epoch, xid, urecptr, NULL, 0);

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
		xlundohdr.reloid = undorecord.uur_reloid;
		xlundohdr.urec_ptr = urecptr;
		xlundohdr.blkprev = prev_urecptr;

		xlrec.prev_xid = tup_xid;
		xlrec.offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
		xlrec.infomask = zhtup->t_data->t_infomask;
		xlrec.trans_slot_id = new_trans_slot_id;
		xlrec.flags = 0;
		if (new_trans_slot_id != trans_slot_id)
		{
			Assert(new_trans_slot_id == tup_trans_slot_id);
			xlrec.flags |= XLZ_LOCK_TRANS_SLOT_FOR_UREC;
		}
		else if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			xlrec.flags |= XLZ_LOCK_CONTAINS_TPD_SLOT;

		if (hasSubXactLock)
			xlrec.flags |= XLZ_LOCK_CONTAINS_SUBXACT;
		if (lockopr == LockForUpdate)
			xlrec.flags |= XLZ_LOCK_FOR_UPDATE;

prepare_xlog:
		/* LOG undolog meta if this is the first WAL after the checkpoint. */
		LogUndoMetaData(&undometa);

		GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
		XLogBeginInsert();
		XLogRegisterBuffer(0, buf, REGBUF_STANDARD);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			(void) RegisterTPDBuffer(page, 1);
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
		XLogRegisterData((char *) &xlrec, SizeOfZHeapLock);
		RegisterUndoLogBuffers(2);

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
		else if (xlrec.flags & XLZ_LOCK_CONTAINS_TPD_SLOT)
			XLogRegisterData((char *) &tup_trans_slot_id, sizeof(tup_trans_slot_id));

		recptr = XLogInsertExtended(RM_ZHEAP_ID, XLOG_ZHEAP_LOCK, RedoRecPtr,
									doPageWrites);
		if (recptr == InvalidXLogRecPtr)
		{
			ResetRegisteredTPDBuffers();
			goto prepare_xlog;
		}

		PageSetLSN(page, recptr);
		if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			TPDPageSetLSN(page, recptr);
		UndoLogBuffersSetLSN(recptr);
	}
	END_CRIT_SECTION();

	pfree(undorecord.uur_tuple.data);
	pfree(undorecord.uur_payload.data);
	UnlockReleaseUndoBuffers();
	UnlockReleaseTPDBuffers();
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
 *
 * We ensure that the tuple always point to the transaction slot of latest
 * inserter/updater except for cases where we lock first and then update the
 * tuple (aka locks via EvalPlanQual mechanism).  For example, say after a
 * committed insert/update, a new request arrives to lock the tuple in key
 * share mode, we will keep the inserter's/updater's slot on the tuple and
 * set the multi-locker and key-share bit.  If the inserter/updater is already
 * known to be having a frozen slot (visible to every one), we will set the
 * key-share locker bit and the tuple will indicate a frozen slot.  Similarly,
 * for a new updater, if the tuple has a single locker, then the undo will
 * have a frozen tuple and for multi-lockers, the undo of updater will have
 * previous inserter/updater slot; in both cases the new tuple will point to
 * the updaters slot.  Now, the rollback of a single locker will set the
 * frozen slot on tuple and the rollback of multi-locker won't change slot
 * information on tuple.  We don't want to keep the slot of locker on the
 * tuple as after rollback, we will lose track of last updater/inserter.
 *
 * When we are locking for the purpose of updating the tuple, we don't need
 * to preserve previous updater's information and we also keep the latest
 * slot on tuple.  This is only true when there are no previous lockers on
 * the tuple.
 */
static void
compute_new_xid_infomask(ZHeapTuple zhtup, Buffer buf, TransactionId tup_xid,
						 int tup_trans_slot, uint16 old_infomask,
						 TransactionId add_to_xid, int trans_slot,
						 TransactionId single_locker_xid, LockTupleMode mode,
						 LockOper lockoper, uint16 *result_infomask,
						 int *result_trans_slot)
{
	int			new_trans_slot;
	uint16		new_infomask;
	bool		old_tuple_has_update = false;
	bool		is_update = false;

	Assert(TransactionIdIsValid(add_to_xid));

	new_infomask = 0;
	new_trans_slot = trans_slot;
	is_update = (lockoper == ForUpdate || lockoper == LockForUpdate);

	if ((IsZHeapTupleModified(old_infomask) &&
		 TransactionIdIsInProgress(tup_xid)) ||
		ZHeapTupleHasMultiLockers(old_infomask))
	{
		ZGetMultiLockInfo(old_infomask, tup_xid, tup_trans_slot,
						  add_to_xid, &new_infomask, &new_trans_slot,
						  &mode, &old_tuple_has_update, is_update);
	}
	else if (!is_update &&
			 TransactionIdIsInProgress(single_locker_xid))
	{
		LockTupleMode old_mode;

		/*
		 * When there is a single in-progress locker on the tuple and previous
		 * inserter/updater became all visible, we've to set multi-locker flag
		 * and highest lock mode. If current transaction tries to reacquire
		 * a lock, we don't set multi-locker flag.
		 */
		Assert(ZHEAP_XID_IS_LOCKED_ONLY(old_infomask));
		if (single_locker_xid != add_to_xid)
		{
			new_infomask |= ZHEAP_MULTI_LOCKERS;
			new_trans_slot = tup_trans_slot;
		}

		old_mode = get_old_lock_mode(old_infomask);

		/* Acquire the strongest of both. */
		if (mode < old_mode)
			mode = old_mode;

		/* Keep the old tuple slot as it is */
		new_trans_slot = tup_trans_slot;
	}
	else if (!is_update &&
			 TransactionIdIsInProgress(tup_xid))
	{
		/*
		 * Normally if the tuple is not modified and the current transaction
		 * is in progress, the other transaction can't lock the tuple except
		 * itself.
		 *
		 * However, this can happen while locking the updated tuple chain.  We
		 * keep the transaction slot of original tuple as that will allow us to
		 * check the visibility of tuple by just referring the current
		 * transaction slot.
		 */
		Assert((tup_xid == add_to_xid) || (mode == LockTupleKeyShare));

		if (tup_xid != add_to_xid)
		{
			new_infomask |= ZHEAP_MULTI_LOCKERS;
			new_trans_slot = tup_trans_slot;
		}
	}
	else if (!is_update &&
			 tup_trans_slot == ZHTUP_SLOT_FROZEN)
	{
		/*
		 * It's a frozen update or insert, so the locker must not change the
		 * slot on a tuple.  The lockmode to be used on tuple is computed
		 * below. There could be a single committed/aborted locker (multilocker
		 * case is handled in the first condition). In that case, we can ignore
		 * the locker. If the locker is still in progress, it'll be handled in
		 * above case.
		 */
		new_trans_slot = ZHTUP_SLOT_FROZEN;
	}
	else if (!is_update &&
			 !ZHEAP_XID_IS_LOCKED_ONLY(old_infomask) &&
			 tup_trans_slot != ZHTUP_SLOT_FROZEN &&
			 (TransactionIdDidCommit(tup_xid)
			  || !TransactionIdIsValid(tup_xid)))
	{
		/*
		 * It's a committed update or insert, so we gotta preserve him as
		 * updater of the tuple.  Also, indicate that tuple has multiple
		 * lockers.
		 *
		 * Tuple xid could be invalid if the corresponding transaction is
		 * discarded or the tuple is marked as frozen.  The later case is
		 * handled in the above condition (slot frozen).  In the former case,
		 * we can consider it as a committed update or insert.
		 */
		old_tuple_has_update = true;
		new_infomask |= ZHEAP_MULTI_LOCKERS;

		if (ZHEAP_XID_IS_EXCL_LOCKED(old_infomask))
			new_infomask |= ZHEAP_XID_EXCL_LOCK;
		else if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(old_infomask))
			new_infomask |= ZHEAP_XID_NOKEY_EXCL_LOCK;
		else
		{
			/*
			 * Tuple must not be locked in any other mode as we are here
			 * because either the tuple is updated or inserted and the
			 * corresponding transaction is committed.
			 */
			Assert(!(ZHEAP_XID_IS_KEYSHR_LOCKED(old_infomask) ||
					 ZHEAP_XID_IS_SHR_LOCKED(old_infomask)));
		}

		if (ZHeapTupleIsInPlaceUpdated(old_infomask))
			new_infomask |= ZHEAP_INPLACE_UPDATED;
		else if (ZHeapTupleIsUpdated(old_infomask))
			new_infomask |= ZHEAP_UPDATED;
		else
		{
			/*
			 * This is a freshly inserted tuple, allow to set the requested
			 * lock mode on tuple.
			 */
			old_tuple_has_update = false;
		}

		new_trans_slot = tup_trans_slot;

		if (old_tuple_has_update)
			goto infomask_is_computed;
	}
	else if (!is_update &&
			 ZHEAP_XID_IS_LOCKED_ONLY(old_infomask) &&
			 tup_trans_slot != ZHTUP_SLOT_FROZEN &&
			 (TransactionIdDidCommit(tup_xid)
			  || !TransactionIdIsValid(tup_xid)))
	{
		LockTupleMode old_mode;

		/*
		 * This case arises for non-inplace updates when the newly inserted
		 * tuple is marked as locked-only, but multi-locker bit is not set.
		 *
		 * See comments in above condition to know when tup_xid can be
		 * invalid.
		 */
		new_infomask |= ZHEAP_MULTI_LOCKERS;

		/* The tuple is locked-only. */
		Assert(!(old_infomask &
				 (ZHEAP_DELETED | ZHEAP_UPDATED | ZHEAP_INPLACE_UPDATED)));

		old_mode = get_old_lock_mode(old_infomask);

		/* Acquire the strongest of both. */
		if (mode < old_mode)
			mode = old_mode;

		/* Keep the old tuple slot as it is */
		new_trans_slot = tup_trans_slot;
	}

	if (is_update && !ZHeapTupleHasMultiLockers(new_infomask))
	{
		if (lockoper == LockForUpdate)
		{
			/*
			 * When we are locking for the purpose of updating the tuple, we
			 * don't need to preserve previous updater's information.
			 */
			new_infomask |= ZHEAP_XID_LOCK_ONLY;
			if (mode == LockTupleExclusive)
				new_infomask |= ZHEAP_XID_EXCL_LOCK;
			else
				new_infomask |= ZHEAP_XID_NOKEY_EXCL_LOCK;
		}
		else if (mode == LockTupleExclusive)
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

	/*
	 * We store the reserved transaction slot only when we update the
	 * tuple. For lock only, we keep the old transaction slot in the
	 * tuple.
	 */
	Assert(is_update || new_trans_slot == tup_trans_slot);
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
	TransactionId	current_tup_xid;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	ZHeapTupleHeader zhtuphdr;
	Page		page;
	BlockNumber block;
	Buffer		buffer;
	OffsetNumber	offnum;
	int			out_slot_no PG_USED_FOR_ASSERTS_ONLY;
	int			trans_slot_id;

	Assert(ItemPointerIsValid(tid));

	block = ItemPointerGetBlockNumber(tid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp));

	zhtuphdr = (ZHeapTupleHeader) PageGetItem(page, lp);

	trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtuphdr);
	/*
	 * Sanity check that the tuple really is a speculatively inserted tuple,
	 * inserted by us.
	 */
	out_slot_no = GetTransactionSlotInfo(buffer,
										 offnum,
										 trans_slot_id,
										 NULL,
										 &current_tup_xid,
										 NULL,
										 true,
										 false);

	/* As the transaction is still open, the slot can't be frozen. */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);
	Assert(current_tup_xid != InvalidTransactionId);

	if (current_tup_xid != xid)
		elog(ERROR, "attempted to kill a tuple inserted by another transaction");
	if (!(IsToastRelation(relation) || ZHeapTupleHeaderIsSpeculative(zhtuphdr)))
		elog(ERROR, "attempted to kill a non-speculative tuple");
	Assert(!IsZHeapTupleModified(zhtuphdr->t_infomask));

	START_CRIT_SECTION();

	/*
	 * The tuple will become DEAD immediately.  However, we mark it dead
	 * differently by keeping the trans_slot, to identify this is done
	 * during speculative abort only.  Flag that this page is a candidate
	 * for pruning.  The action here is exactly same as what we do for
	 * rolling back insert.
	 */
	ItemIdSetDeadExtended(lp, trans_slot_id);
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
		xlrec.trans_slot_id = trans_slot_id;

		XLogBeginInsert();

		XLogRegisterData((char *) &xlrec, SizeOfZHeapConfirm);
		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		/* No replica identity & replication origin logged */

		recptr = XLogInsert(RM_ZHEAP2_ID, XLOG_ZHEAP_CONFIRM);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

	if (ZHeapTupleHasExternal(tuple))
	{
		Assert(!IsToastRelation(relation));
		ztoast_delete(relation, tuple, true);
	}

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

	for (i = 0;; i++)		/* loop exit is at "break" */
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);

		if (ZHeapTupleHasNulls(tuple) && att_isnull(i, bp))
		{
			continue;		/* this cannot be the target att */
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
		memcpy(&ret_datum, tp + off, thisatt->attlen);
	else
		ret_datum = PointerGetDatum((char *) (tp + off));

	return ret_datum;
}

TransactionId
zheap_fetchinsertxid(ZHeapTuple zhtup, Buffer buffer)
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

	prev_trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
	blk = ItemPointerGetBlockNumber(&zhtup->t_self);
	offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
	(void) GetTransactionSlotInfo(buffer,
								  offnum,
								  prev_trans_slot_id,
								  NULL,
								  NULL,
								  &urec_ptr,
								  true,
								  false);
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
			if (urec->uur_type == UNDO_INSERT ||
				urec->uur_type == UNDO_MULTI_INSERT ||
				urec->uur_type == UNDO_INPLACE_UPDATE)
			{
				result = urec->uur_xid;
				UndoRecordRelease(urec);
				break;
			}

			undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id,
						 NULL, (undo_tup) == (zhtup) ? false : true,
						 BufferGetPage(buffer));

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
				(void) GetTransactionSlotInfo(buffer,
											  ItemPointerGetOffsetNumber(&undo_tup->t_self),
											  trans_slot_id,
											  NULL,
											  NULL,
											  &urec_ptr,
											  true,
											  true);
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
			/*
			 * Fixme - Need to check whether we need any handling of epoch here.
			 */
			uint64  epoch_xid;
			ZHeapTupleGetTransInfo(zhtup, buf, NULL, &epoch_xid, &xid,
								   NULL, NULL, false);

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
 * Check whether the value is unchanged after update of a projection
 * functional index.
 * This is same as ProjIndexIsUnchanged() except that it takes ZHeapTuple as
 * input.
 */
static bool
ZHeapProjIndexIsUnchanged(Relation relation, ZHeapTuple oldtup,
											 ZHeapTuple newtup)
{
	ListCell   *l;
	List	   *indexoidlist = RelationGetIndexList(relation);
	EState	   *estate = CreateExecutorState();
	ExprContext *econtext = GetPerTupleExprContext(estate);
	TupleTableSlot *slot = MakeSingleTupleTableSlot(RelationGetDescr(relation));
	bool		equals = true;
	Datum		old_values[INDEX_MAX_KEYS];
	bool		old_isnull[INDEX_MAX_KEYS];
	Datum		new_values[INDEX_MAX_KEYS];
	bool		new_isnull[INDEX_MAX_KEYS];
	int			indexno = 0;

	econtext->ecxt_scantuple = slot;

	foreach(l, indexoidlist)
	{
		if (bms_is_member(indexno, relation->rd_projidx))
		{
			Oid			indexOid = lfirst_oid(l);
			Relation	indexDesc = index_open(indexOid, AccessShareLock);
			IndexInfo  *indexInfo = BuildIndexInfo(indexDesc);
			int			i;

			ResetExprContext(econtext);
			ExecStoreZTuple(oldtup, slot, InvalidBuffer, false);
			FormIndexDatum(indexInfo,
						   slot,
						   estate,
						   old_values,
						   old_isnull);

			ExecStoreZTuple(newtup, slot, InvalidBuffer, false);
			FormIndexDatum(indexInfo,
						   slot,
						   estate,
						   new_values,
						   new_isnull);

			for (i = 0; i < indexInfo->ii_NumIndexAttrs; i++)
			{
				if (old_isnull[i] != new_isnull[i])
				{
					equals = false;
					break;
				}
				else if (!old_isnull[i])
				{
					Form_pg_attribute att = TupleDescAttr(RelationGetDescr(indexDesc), i);

					if (!datumIsEqual(old_values[i], new_values[i], att->attbyval, att->attlen))
					{
						equals = false;
						break;
					}
				}
			}
			index_close(indexDesc, AccessShareLock);

			if (!equals)
			{
				break;
			}
		}
		indexno += 1;
	}
	ExecDropSingleTupleTableSlot(slot);
	FreeExecutorState(estate);

	return equals;
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
 * GetTransactionSlotInfo - Get the required transaction slot info.  We also
 *	return the transaction slot number, if the transaction slot is in TPD entry.
 *
 * We can directly call this function to get transaction slot info if we are
 * sure that the corresponding tuple is not deleted or we don't care if the
 * tuple has multi-locker flag in which case we need to call
 * ZHeapTupleGetTransInfo.
 *
 * NoTPDBufLock - See TPDPageGetTransactionSlotInfo.
 * TPDSlot - true, if the passed transaction_slot_id is the slot number in TPD
 * entry.
 */
int
GetTransactionSlotInfo(Buffer buf, OffsetNumber offset, int trans_slot_id,
					   uint32 *epoch, TransactionId *xid,
					   UndoRecPtr *urec_ptr, bool NoTPDBufLock, bool TPDSlot)
{
	ZHeapPageOpaque	opaque;
	Page	page;
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	int		out_trans_slot_id = trans_slot_id;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Fetch the required information from the transaction slot. The
	 * transaction slot can either be on the heap page or TPD page.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN)
	{
		if (epoch)
			*epoch = 0;
		if (xid)
			*xid = InvalidTransactionId;
		if (urec_ptr)
			*urec_ptr = InvalidUndoRecPtr;
	}
	else if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
			 (trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
			 !ZHeapPageHasTPDSlot(phdr)))
	{
		if (epoch)
			*epoch = opaque->transinfo[trans_slot_id - 1].xid_epoch;
		if (xid)
			*xid = opaque->transinfo[trans_slot_id - 1].xid;
		if (urec_ptr)
			*urec_ptr = opaque->transinfo[trans_slot_id - 1].urec_ptr;
	}
	else
	{
		Assert((ZHeapPageHasTPDSlot(phdr)));
		if (TPDSlot)
		{
			/*
			 * The heap page's last transaction slot data is copied over to
			 * first slot in TPD entry, so we need fetch it from there.  See
			 * AllocateAndFormTPDEntry.
			 */
			if (trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS)
				trans_slot_id = ZHEAP_PAGE_TRANS_SLOTS + 1;
			out_trans_slot_id = TPDPageGetTransactionSlotInfo(buf,
															  trans_slot_id,
															  InvalidOffsetNumber,
															  epoch,
															  xid,
															  urec_ptr,
															  NoTPDBufLock,
															  false);
		}
		else
		{
			Assert(offset != InvalidOffsetNumber);
			out_trans_slot_id = TPDPageGetTransactionSlotInfo(buf,
															  trans_slot_id,
															  offset,
															  epoch,
															  xid,
															  urec_ptr,
															  NoTPDBufLock,
															  false);
		}
	}

	return out_trans_slot_id;
}

/*
 * PageSetUNDO - Set the transaction information pointer for a given
 *		transaction slot.
 */
void
PageSetUNDO(UnpackedUndoRecord undorecord, Buffer buffer, int trans_slot_id,
			bool set_tpd_map_slot, uint32 epoch, TransactionId xid,
			UndoRecPtr urecptr, OffsetNumber *usedoff, int ucnt)
{
	ZHeapPageOpaque	opaque;
	Page	page = BufferGetPage(buffer);
	PageHeader	phdr;

	Assert(trans_slot_id != InvalidXactSlotId);

	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Set the required information in the transaction slot. The transaction
	 * slot can either be on the heap page or TPD page.
	 *
	 * During recovery, we set the required information in TPD separately
	 * only if required.
	 */
	if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
		(trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
		 !ZHeapPageHasTPDSlot(phdr)))
	{
		opaque->transinfo[trans_slot_id - 1].xid_epoch = epoch;
		opaque->transinfo[trans_slot_id - 1].xid = xid;
		opaque->transinfo[trans_slot_id - 1].urec_ptr = urecptr;
	}
	/* TPD information is set separately during recovery. */
	else if (!InRecovery)
	{
		if (ucnt <= 0)
		{
			Assert(ucnt == 0);

			usedoff = &undorecord.uur_offset;
			ucnt++;
		}

		TPDPageSetUndo(buffer, trans_slot_id, set_tpd_map_slot, epoch, xid,
					   urecptr, usedoff, ucnt);
	}

	elog(DEBUG1, "undo record: TransSlot: %d, Epoch: %d, TransactionId: %d, urec: " UndoRecPtrFormat ", prev_urec: " UINT64_FORMAT ", block: %d, offset: %d, undo_op: %d, xid_tup: %d, reloid: %d",
				 trans_slot_id, epoch, xid, urecptr, undorecord.uur_blkprev, undorecord.uur_block, undorecord.uur_offset, undorecord.uur_type,
				 undorecord.uur_prevxid, undorecord.uur_reloid);
}

/*
 * PageSetTransactionSlotInfo - Set the transaction slot info for the given
 *			slot.
 *
 * This is similar to PageSetUNDO except that it doesn't need to update offset
 * map in TPD.
 */
void
PageSetTransactionSlotInfo(Buffer buf, int trans_slot_id, uint32 epoch,
						   TransactionId xid, UndoRecPtr urec_ptr)
{
	ZHeapPageOpaque	opaque;
	Page	page;
	PageHeader	phdr;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
		(trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
		 !ZHeapPageHasTPDSlot(phdr)))
	{
		opaque->transinfo[trans_slot_id - 1].xid_epoch = epoch;
		opaque->transinfo[trans_slot_id - 1].xid = xid;
		opaque->transinfo[trans_slot_id - 1].urec_ptr = urec_ptr;
	}
	else
	{
		TPDPageSetTransactionSlotInfo(buf, trans_slot_id, epoch, xid,
									  urec_ptr);
	}
}

/*
 * PageGetTransactionSlotId - Get the transaction slot for the given epoch and
 *			xid.
 *
 * If the slot is not in the TPD page but the caller has asked to lock the TPD
 * buffer than do so.  tpd_page_locked will be set to true if the required page
 * is locked, false, otherwise.
 */
int
PageGetTransactionSlotId(Relation rel, Buffer buf, uint32 epoch,
						 TransactionId xid, UndoRecPtr *urec_ptr,
						 bool keepTPDBufLock, bool locktpd,
						 bool *tpd_page_locked)
{
	ZHeapPageOpaque	opaque;
	Page	page;
	PageHeader	phdr;
	int		slot_no;
	int		total_slots_in_page;
	bool	check_tpd;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	if (ZHeapPageHasTPDSlot(phdr))
	{
		total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS - 1;
		check_tpd = true;
	}
	else
	{
		total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS;
		check_tpd = false;
	}

	/* Check if the required slot exists on the page. */
	for (slot_no = 0; slot_no < total_slots_in_page; slot_no++)
	{
		if (opaque->transinfo[slot_no].xid_epoch == epoch &&
			opaque->transinfo[slot_no].xid == xid)
		{
			*urec_ptr = opaque->transinfo[slot_no].urec_ptr;

			/* Check if TPD has page slot, then lock TPD page */
			if (locktpd && ZHeapPageHasTPDSlot(phdr))
			{
				Assert(tpd_page_locked);
				*tpd_page_locked = TPDPageLock(rel, buf);
			}

			return slot_no + 1;
		}
	}

	/* Check if the slot exists on the TPD page. */
	if (check_tpd)
	{
		int tpd_e_slot;

		tpd_e_slot = TPDPageGetSlotIfExists(rel, buf, InvalidOffsetNumber,
											epoch, xid, urec_ptr,
											keepTPDBufLock, false);
		if (tpd_e_slot != InvalidXactSlotId)
		{
			/*
			 * If we get the valid slot then the TPD page must be locked and
			 * the lock will be retained if asked for.
			 */
			if (tpd_page_locked)
				*tpd_page_locked = keepTPDBufLock;
			return tpd_e_slot;
		}
	}
	else
	{
		/*
		 * Lock the TPD page if the caller has instructed so and the page
		 * has tpd slot.
		 */
		if (locktpd && ZHeapPageHasTPDSlot(phdr))
		{
			Assert(tpd_page_locked);
			*tpd_page_locked = TPDPageLock(rel, buf);
		}
	}

	return InvalidXactSlotId;
}

/*
 * PageGetTransactionSlotInfo - Get the transaction slot info for the given
 *	slot no.
 */
void
PageGetTransactionSlotInfo(Buffer buf, int slot_no, uint32 *epoch,
						 TransactionId *xid, UndoRecPtr *urec_ptr,
						 bool keepTPDBufLock)
{
	ZHeapPageOpaque	opaque;
	Page	page;
	PageHeader	phdr;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Fetch the required information from the transaction slot. The
	 * transaction slot can either be on the heap page or TPD page.
	 */
	if (slot_no < ZHEAP_PAGE_TRANS_SLOTS ||
		(slot_no == ZHEAP_PAGE_TRANS_SLOTS &&
		 !ZHeapPageHasTPDSlot(phdr)))
	{
		if (epoch)
			*epoch = opaque->transinfo[slot_no - 1].xid_epoch;
		if (xid)
			*xid = opaque->transinfo[slot_no - 1].xid;
		if (urec_ptr)
			*urec_ptr = opaque->transinfo[slot_no - 1].urec_ptr;
	}
	else
	{
		Assert((ZHeapPageHasTPDSlot(phdr)));
		(void)TPDPageGetTransactionSlotInfo(buf,
											slot_no,
											InvalidOffsetNumber,
											epoch,
											xid,
											urec_ptr,
											false,
											true);
	}
}

/*
 *  MultiPageReserveTransSlot - Reserve the transaction slots on old and
 *		new buffer.
 *
 * Here, we need to ensure that we always first reserve slot in the page
 * which has corresponding lower numbered TPD page to avoid deadlocks
 * caused by locking ordering of TPD pages.
 */
void
MultiPageReserveTransSlot(Relation relation,
						  Buffer oldbuf, Buffer newbuf,
						  OffsetNumber oldbuf_offnum,
						  OffsetNumber newbuf_offnum,
						  uint32 epoch, TransactionId xid,
						  UndoRecPtr *oldbuf_prev_urecptr,
						  UndoRecPtr *newbuf_prev_urecptr,
						  int *oldbuf_trans_slot_id,
						  int *newbuf_trans_slot_id,
						  bool *lock_reacquired)
{
	Page		oldbuf_page, newbuf_page;
	bool		always_extend;
	bool		has_oldbuf_tpd, has_newbuf_tpd;
	bool		is_tpdblk_order_changed;
	int			slot_id;
	BlockNumber	oldbuf_tpd_blk = InvalidBlockNumber,
				newbuf_tpd_blk = InvalidBlockNumber;

retry_tpd_lock :

	/* Initialize flags with default values. */
	always_extend = false;
	is_tpdblk_order_changed = false;

	/* Get corresponding pages from old and new buffers. */
	oldbuf_page = BufferGetPage(oldbuf);
	newbuf_page = BufferGetPage(newbuf);

	/* Checking that buffer has TPD page. */
	has_oldbuf_tpd = ZHeapPageHasTPDSlot((PageHeader) oldbuf_page);
	has_newbuf_tpd = ZHeapPageHasTPDSlot((PageHeader) newbuf_page);

	/* If TPD exists, then get corresponding TPD block numbers. */
	if (has_oldbuf_tpd)
		oldbuf_tpd_blk = GetTPDBlockNumberFromHeapBuffer(oldbuf);
	if (has_newbuf_tpd)
		newbuf_tpd_blk = GetTPDBlockNumberFromHeapBuffer(newbuf);

	/*
	 * If both the buffers has TPD entry, then reserve the transaction slot in
	 * increasing order of corresponding TPD blocks to avoid deadlock.
	 */
	if (has_oldbuf_tpd && has_newbuf_tpd)
	{
		if (oldbuf_tpd_blk > newbuf_tpd_blk)
			is_tpdblk_order_changed = true;
	}

	/* Now reserve the slots in both the pages. */
	if (!is_tpdblk_order_changed)
	{
		/* Verify the transaction slot for old buffer. */
		slot_id = PageReserveTransactionSlot(relation,
											 oldbuf,
											 oldbuf_offnum,
											 epoch,
											 xid,
											 oldbuf_prev_urecptr,
											 lock_reacquired,
											 false);

		/* Try again if the buffer lock is released and reacquired. */
		if (*lock_reacquired)
			return;

		/*
		 * If old buffer has TPD page, then TPD block of old buffer should not
		 * change. Because already we have reserved a slot for old buffer.
		 */
		Assert((has_oldbuf_tpd &&
				(oldbuf_tpd_blk == GetTPDBlockNumberFromHeapBuffer(oldbuf))) ||
			   !has_oldbuf_tpd);

		/*
		 * If reserved transaction slot for old buffer is from TPD page, then
		 * for new buffer, we should not allow to use FSM TPD page, instead we
		 * will extend to get new TPD buffer with higher block number to avoid
		 * deadlock.
		 */
		if (slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			always_extend = true;

		/* Reserve the transaction slot for new buffer. */
		*newbuf_trans_slot_id = PageReserveTransactionSlot(relation,
														   newbuf,
														   newbuf_offnum + 1,
														   epoch,
														   xid,
														   newbuf_prev_urecptr,
														   lock_reacquired,
														   always_extend);
	}
	else
	{
		/* Reserve the transaction slot for new buffer. */
		*newbuf_trans_slot_id = PageReserveTransactionSlot(relation,
														   newbuf,
														   newbuf_offnum + 1,
														   epoch,
														   xid,
														   newbuf_prev_urecptr,
														   lock_reacquired,
														   false);

		/* Try again if the buffer lock is released and reacquired. */
		if (*lock_reacquired)
			return;

		/*
		 * If reserved transaction slot for new buffer is from TPD page, then
		 * we should check block number of TPD page.  Because, it is quite
		 * possible that if we don't have space in the current TPD page, we
		 * may get a new TPD page from FSM or by extending the relation that
		 * may have greater block number as compared to old buffer TPD block.
		 */
		if (*newbuf_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			/* Get TPD block of new buffer. */
			newbuf_tpd_blk = GetTPDBlockNumberFromHeapBuffer(newbuf);

			/*
			 * If TPD block of new buffer gets changed and becomes greater than
			 * old buffer TPD block, then we should release TPD buffer lock of
			 * new buffer and try again to avoid deadlock.
			 *
			 * For new buffer, there is no guarantee that we will get same TPD
			 * block after releasing TPD buffer lock, because vacuum can free
			 * that page, so always try again to reserve slot.
			 */
			if (newbuf_tpd_blk > oldbuf_tpd_blk)
			{
				/* Release lock to avoid deadlock. */
				ReleaseLastTPDBufferByTPDBlock(newbuf_tpd_blk);
				goto retry_tpd_lock;
			}
		}

		/* Get the transaction slot for old buffer. */
		slot_id = PageReserveTransactionSlot(relation,
											 oldbuf,
											 oldbuf_offnum,
											 epoch,
											 xid,
											 oldbuf_prev_urecptr,
											 lock_reacquired,
											 false);

		/*
		 * TPD block of old buffer must not change as we already have a
		 * reserved slot in the old buffer and for in-progress transactions,
		 * TPD block can't be pruned.
		 */
		Assert(oldbuf_tpd_blk == GetTPDBlockNumberFromHeapBuffer(oldbuf));
	}

	/*
	 * We should definetly get the slot for old page as we have reserved it
	 * previously, but it is possible that it might have moved to TPD in
	 * which case it's value will be previous_slot_number + 1.
	 */
	Assert((slot_id == *oldbuf_trans_slot_id) ||
		   (ZHeapPageHasTPDSlot((PageHeader) oldbuf_page) &&
			slot_id == (*oldbuf_trans_slot_id) + 1));

	*oldbuf_trans_slot_id = slot_id;
}

/*
 * GetTPDBlockNumberFromHeapBuffer - Return block number of TPD page.
 *
 * buffer - heap buffer.
 */
static int
GetTPDBlockNumberFromHeapBuffer(Buffer heapbuf)
{
	Page			page = BufferGetPage(heapbuf);
	ZHeapPageOpaque	zopaque;
	TransInfo		last_trans_slot_info;

	/* The last slot in page has the address of the required TPD entry. */
	zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
	last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

	return last_trans_slot_info.xid_epoch;
}

/*
 * PageReserveTransactionSlot - Reserve the transaction slot in page.
 *
 *	This function returns transaction slot number if either the page already
 *	has some slot that contains the transaction info or there is an empty
 *	slot or it manages to reuse some existing slot or it manages to get the
 *  slot in TPD; otherwise retruns InvalidXactSlotId.
 *
 *  Note that we always return array location of slot plus one as zeroth slot
 *  number is reserved for frozen slot number (ZHTUP_SLOT_FROZEN).
 */
int
PageReserveTransactionSlot(Relation relation, Buffer buf, OffsetNumber offset,
						   uint32 epoch, TransactionId xid,
						   UndoRecPtr *urec_ptr, bool *lock_reacquired,
						   bool always_extend)
{
	ZHeapPageOpaque	opaque;
	Page	page;
	PageHeader	phdr;
	int		latestFreeTransSlot = InvalidXactSlotId;
	int		slot_no;
	int		total_slots_in_page;
	bool	check_tpd;

	*lock_reacquired = false;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	if (ZHeapPageHasTPDSlot(phdr))
	{
		total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS - 1;
		check_tpd = true;
	}
	else
	{
		total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS;
		check_tpd = false;
	}

	/*
	 * For temp relations, we don't have to check all the slots since
	 * no other backend can access the same relation. If a slot is available,
	 * we return it from here. Else, we freeze the slot in PageFreezeTransSlots.
	 *
	 * XXX For temp tables, oldestXidWithEpochHavingUndo is not relevant as
	 * the undo for them can be discarded on commit.  Hence, comparing xid
	 * with oldestXidWithEpochHavingUndo during visibility checks can lead to
	 * incorrect behavior.  To avoid that, we can mark the tuple as frozen
	 * for any previous transaction id.  In that way, we don't have to
	 * compare the previous xid of tuple with oldestXidWithEpochHavingUndo.
	 */
	if (RELATION_IS_LOCAL(relation))
	{
		/*  We can't access temp tables of other backends. */
		Assert(!RELATION_IS_OTHER_TEMP(relation));

		slot_no = 0;
		if (opaque->transinfo[slot_no].xid_epoch == epoch &&
			opaque->transinfo[slot_no].xid == xid)
		{
			*urec_ptr = opaque->transinfo[slot_no].urec_ptr;
			return (slot_no + 1);
		}
		else if (opaque->transinfo[slot_no].xid == InvalidTransactionId &&
				 latestFreeTransSlot == InvalidXactSlotId)
			latestFreeTransSlot = slot_no;
	}
	else
	{
		for (slot_no = 0; slot_no < total_slots_in_page; slot_no++)
		{
			if (opaque->transinfo[slot_no].xid_epoch == epoch &&
				opaque->transinfo[slot_no].xid == xid)
			{
				*urec_ptr = opaque->transinfo[slot_no].urec_ptr;
				return (slot_no + 1);
			}
			else if (opaque->transinfo[slot_no].xid == InvalidTransactionId &&
					 latestFreeTransSlot == InvalidXactSlotId)
				latestFreeTransSlot = slot_no;
		}
	}

	/* Check if we already have a slot on the TPD page */
	if (check_tpd)
	{
		int tpd_e_slot;

		tpd_e_slot = TPDPageGetSlotIfExists(relation, buf, offset, epoch,
											xid, urec_ptr, true, true);
		if (tpd_e_slot != InvalidXactSlotId)
			return tpd_e_slot;
	}


	if (latestFreeTransSlot >= 0)
	{
		*urec_ptr = opaque->transinfo[latestFreeTransSlot].urec_ptr;
		return (latestFreeTransSlot + 1);
	}

	/* no transaction slot available, try to reuse some existing slot */
	if (PageFreezeTransSlots(relation, buf, lock_reacquired, NULL, 0))
	{
		/*
		 * If the lock is reacquired inside, then we allow callers to reverify
		 * the condition whether then can still perform the required
		 * operation.
		 */
		if (*lock_reacquired)
			return InvalidXactSlotId;

		/*
		 * TPD entry might get pruned in TPDPageGetSlotIfExists, so recheck
		 * it.
		 */
		if (ZHeapPageHasTPDSlot(phdr))
			total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS - 1;
		else
			total_slots_in_page = ZHEAP_PAGE_TRANS_SLOTS;

		for (slot_no = 0; slot_no < total_slots_in_page; slot_no++)
		{
			if (opaque->transinfo[slot_no].xid == InvalidTransactionId)
			{
				*urec_ptr = opaque->transinfo[slot_no].urec_ptr;
				return (slot_no + 1);
			}
		}

		/*
		 * After freezing transaction slots, we should get atleast one free
		 * slot.
		 */
		Assert(false);
	}
	Assert (!RELATION_IS_LOCAL(relation));

	/*
	 * Reserve the transaction slot in TPD.  First we check if there already
	 * exists an TPD entry for this page, then reserve in that, otherwise,
	 * allocate a new TPD entry and reserve the slot in it.
	 */
	if (ZHeapPageHasTPDSlot(phdr))
	{
		int tpd_e_slot;

		tpd_e_slot = TPDPageReserveTransSlot(relation, buf, offset,
											 urec_ptr, lock_reacquired,
											 always_extend);

		if (tpd_e_slot != InvalidXactSlotId)
			return tpd_e_slot;

		/*
		 * Fixme : We should allow to allocate bigger TPD entries or support
		 * chained TPD entries.
		 */
		return InvalidXactSlotId;
	}
	else
	{
		slot_no = TPDAllocateAndReserveTransSlot(relation, buf, offset,
												 urec_ptr,
												 always_extend);
		if (slot_no != InvalidXactSlotId)
			return slot_no;
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
zheap_freeze_or_invalidate_tuples(Buffer buf, int nSlots, int *slots,
								  bool isFrozen, bool TPDSlot)
{
	OffsetNumber offnum, maxoff;
	Page page = BufferGetPage(buf);
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

		/* If we are freezing TPD slot then get the actual slot from the TPD. */
		if (TPDSlot)
		{
			/* Tuple is not pointing to TPD slot so skip it. */
			if (trans_slot < ZHEAP_PAGE_TRANS_SLOTS)
				continue;

			/*
			 * If we come for freezing the TPD slot the fetch the exact slot
			 * info from the TPD.
			 */
			trans_slot = TPDPageGetTransactionSlotInfo(buf, trans_slot, offnum,
													   NULL, NULL, NULL, false,
													   false);

			/*
			 * The input slots array always stores the slot index which starts
			 * from 0, even for TPD slots, the index will start from 0.
			 * So convert it into the slot index.
			 */
			trans_slot -= (ZHEAP_PAGE_TRANS_SLOTS + 1);
		}
		else
		{
			/*
			 * The slot number on tuple is always array location of slot plus
			 * one, so we need to subtract one here before comparing it with
			 * frozen slots.  See PageReserveTransactionSlot.
			 */
			trans_slot -= 1;
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
					{
						tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
						ZHeapTupleHeaderSetXactSlot(tup_hdr, ZHTUP_SLOT_FROZEN);
					}
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
					{
						tup_hdr = (ZHeapTupleHeader) PageGetItem(page, itemid);
						tup_hdr->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
					}
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
			if (ZHeapTupleHasInvalidXact(tup_hdr->t_infomask))
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
bool
PageFreezeTransSlots(Relation relation, Buffer buf, bool *lock_reacquired,
					 TransInfo *transinfo, int num_slots)
{
	uint64	oldestXidWithEpochHavingUndo;
	int		slot_no;
	int		*frozen_slots = NULL;
	int		nFrozenSlots = 0;
	int		*completed_xact_slots = NULL;
	uint16	 nCompletedXactSlots = 0;
	int		*aborted_xact_slots = NULL;
	int		nAbortedXactSlots = 0;
	bool	TPDSlot;
	Page	page;
	bool	result = false;

	page = BufferGetPage(buf);

	/*
	 * If the num_slots is 0 then the caller wants to freeze the page slots so
	 * get the transaction slots information from the page.
	 */
	if (num_slots == 0)
	{
		PageHeader	phdr;
		ZHeapPageOpaque	opaque;

		phdr = (PageHeader) page;
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

		if (ZHeapPageHasTPDSlot(phdr))
			num_slots = ZHEAP_PAGE_TRANS_SLOTS - 1;
		else
			num_slots = ZHEAP_PAGE_TRANS_SLOTS;

		transinfo = opaque->transinfo;
		TPDSlot = false;
	}
	else
	{
		Assert(num_slots > 0);
		TPDSlot = true;
	}

	oldestXidWithEpochHavingUndo = pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo);

	frozen_slots = palloc0(num_slots * sizeof(int));

	/*
	 * Clear the slot information from tuples.  The basic idea is to collect
	 * all the transaction slots that can be cleared.  Then traverse the page
	 * to see if any tuple has marking for any of the slots, if so, just clear
	 * the slot information from the tuple.
	 *
	 * For temp relations, we can freeze the first slot since no other backend
	 * can access the same relation.
	 */
	if (RELATION_IS_LOCAL(relation))
		frozen_slots[nFrozenSlots++] = 0;
	else
	{
		for (slot_no = 0; slot_no < num_slots; slot_no++)
		{
			uint64	slot_xid_epoch = transinfo[slot_no].xid_epoch;
			TransactionId	slot_xid = transinfo[slot_no].xid;

			/*
			 * Transaction slot can be considered frozen if it belongs to previous
			 * epoch or transaction id is old enough that it is all visible.
			 */
			slot_xid_epoch = MakeEpochXid(slot_xid_epoch, slot_xid);

			if (slot_xid_epoch < oldestXidWithEpochHavingUndo)
				frozen_slots[nFrozenSlots++] = slot_no;
		}
	}

	if (nFrozenSlots > 0)
	{
		TransactionId	latestxid = InvalidTransactionId;
		int		i;
		int		slot_no;


		START_CRIT_SECTION();

		/* clear the transaction slot info on tuples */
		zheap_freeze_or_invalidate_tuples(buf, nFrozenSlots, frozen_slots,
										  true, TPDSlot);

		/* Initialize the frozen slots. */
		if (TPDSlot)
		{
			for (i = 0; i < nFrozenSlots; i++)
			{
				int	tpd_slot_id;

				slot_no = frozen_slots[i];

				/* Remember the latest xid. */
				if (TransactionIdFollows(transinfo[slot_no].xid, latestxid))
					latestxid = transinfo[slot_no].xid;

				/* Calculate the actual slot no. */
				tpd_slot_id = slot_no + ZHEAP_PAGE_TRANS_SLOTS + 1;

				/* Initialize the TPD slot. */
				TPDPageSetTransactionSlotInfo(buf, tpd_slot_id, 0,
											  InvalidTransactionId,
											  InvalidUndoRecPtr);
			}
		}
		else
		{
			for (i = 0; i < nFrozenSlots; i++)
			{
				slot_no = frozen_slots[i];

				/* Remember the latest xid. */
				if (TransactionIdFollows(transinfo[slot_no].xid, latestxid))
					latestxid = transinfo[slot_no].xid;

				transinfo[slot_no].xid_epoch = 0;
				transinfo[slot_no].xid = InvalidTransactionId;
				transinfo[slot_no].urec_ptr = InvalidUndoRecPtr;
			}
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
			xl_zheap_freeze_xact_slot xlrec = {0};
			XLogRecPtr	recptr;

			XLogBeginInsert();

			xlrec.nFrozen = nFrozenSlots;
			xlrec.lastestFrozenXid = latestxid;

			XLogRegisterData((char *) &xlrec, SizeOfZHeapFreezeXactSlot);

			/*
			 * Ideally we need the frozen slots information when WAL needs to be
			 * applied on the page, but in case of the TPD slots freeze we need
			 * the frozen slot information for both heap page as well as for the
			 * TPD page.  So the problem is that if we register with any one of
			 * the buffer it might happen that the data did not registered due
			 * to fpw of that buffer but we need that data for another buffer.
			 */
			XLogRegisterData((char *) frozen_slots, nFrozenSlots * sizeof(int));
			XLogRegisterBuffer(0, buf, REGBUF_STANDARD);
			if (TPDSlot)
				RegisterTPDBuffer(page, 1);

			recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_FREEZE_XACT_SLOT);
			PageSetLSN(page, recptr);

			if (TPDSlot)
				TPDPageSetLSN(page, recptr);
		}

		END_CRIT_SECTION();

		result = true;
		goto cleanup;
	}

	Assert(!RELATION_IS_LOCAL(relation));
	completed_xact_slots = palloc0(num_slots * sizeof(int));
	aborted_xact_slots = palloc0(num_slots * sizeof(int));

	/*
	 * Try to reuse transaction slots of committed/aborted transactions. This
	 * is just like above but it will maintain a link to the previous
	 * transaction undo record in this slot.  This is to ensure that if there
	 * is still any alive snapshot to which this transaction is not visible,
	 * it can fetch the record from undo and check the visibility.
	 */
	for (slot_no = 0; slot_no < num_slots; slot_no++)
	{
		if (!TransactionIdIsInProgress(transinfo[slot_no].xid))
		{
			if (TransactionIdDidCommit(transinfo[slot_no].xid))
				completed_xact_slots[nCompletedXactSlots++] = slot_no;
			else
				aborted_xact_slots[nAbortedXactSlots++] = slot_no;
		}
	}

	if (nCompletedXactSlots > 0)
	{
		int		i;
		int		slot_no;


		START_CRIT_SECTION();

		/* clear the transaction slot info on tuples */
		zheap_freeze_or_invalidate_tuples(buf, nCompletedXactSlots,
										  completed_xact_slots, false, TPDSlot);

		/*
		 * Clear the xid information from the slot but keep the undo record
		 * pointer as it is so that undo records of the transaction are
		 * accessible by traversing slot's undo chain even though the slots
		 * are reused.
		 */
		if (TPDSlot)
		{
			for (i = 0; i < nCompletedXactSlots; i++)
			{
				int tpd_slot_id;

				slot_no = completed_xact_slots[i];
				/* calculate the actual slot no. */
				tpd_slot_id = slot_no + ZHEAP_PAGE_TRANS_SLOTS + 1;

				/* Clear xid from the TPD slot but keep the urec_ptr intact. */
				TPDPageSetTransactionSlotInfo(buf, tpd_slot_id, 0,
											  InvalidTransactionId,
											  transinfo[slot_no].urec_ptr);
			}
		}
		else
		{
			for (i = 0; i < nCompletedXactSlots; i++)
			{
				slot_no = completed_xact_slots[i];
				transinfo[slot_no].xid_epoch = 0;
				transinfo[slot_no].xid = InvalidTransactionId;
			}
		}
		MarkBufferDirty(buf);

		/*
		 * Xlog Stuff
		 */
		if (RelationNeedsWAL(relation))
		{
			XLogRecPtr	recptr;

			XLogBeginInsert();


			/* See comments while registering frozen slot. */
			XLogRegisterData((char *) &nCompletedXactSlots, sizeof(uint16));
			XLogRegisterData((char *) completed_xact_slots, nCompletedXactSlots * sizeof(int));

			XLogRegisterBuffer(0, buf, REGBUF_STANDARD);

			if (TPDSlot)
				RegisterTPDBuffer(page, 1);

			recptr = XLogInsert(RM_ZHEAP_ID, XLOG_ZHEAP_INVALID_XACT_SLOT);
			PageSetLSN(page, recptr);

			if (TPDSlot)
				TPDPageSetLSN(page, recptr);
		}

		END_CRIT_SECTION();

		result = true;
		goto cleanup;
	}
	else if (nAbortedXactSlots)
	{
		int		i;
		int		slot_no;
		UndoRecPtr *urecptr = palloc(nAbortedXactSlots * sizeof(UndoRecPtr));
		TransactionId *xid = palloc(nAbortedXactSlots * sizeof(TransactionId));
		uint32 *epoch = palloc(nAbortedXactSlots * sizeof(uint32));

		/* Collect slot information before releasing the lock. */
		for (i = 0; i < nAbortedXactSlots; i++)
		{
			urecptr[i] = transinfo[aborted_xact_slots[i]].urec_ptr;
			xid[i] = transinfo[aborted_xact_slots[i]].xid;
			epoch[i] = transinfo[aborted_xact_slots[i]].xid_epoch;
		}

		/*
		 * We need to release and the lock before applying undo actions for a
		 * page as we might need to traverse the long undo chain for a page.
		 */
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

		/*
		 * Instead of just unlocking the TPD buffer like heap buffer its ok to
		 * unlock and release, because next time while trying to reserve the
		 * slot if we get the slot in TPD then anyway we will pin it again.
		 */
		if (TPDSlot)
			UnlockReleaseTPDBuffers();

		for (i = 0; i < nAbortedXactSlots; i++)
		{
			slot_no = aborted_xact_slots[i] + 1;
			process_and_execute_undo_actions_page(urecptr[i],
												  relation,
												  buf,
												  epoch[i],
												  xid[i],
												  slot_no);
		}
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
		*lock_reacquired = true;
		pfree(urecptr);
		pfree(xid);
		pfree(epoch);

		result = true;
		goto cleanup;
	}

cleanup:
	if (frozen_slots != NULL)
		pfree(frozen_slots);
	if (completed_xact_slots != NULL)
		pfree(completed_xact_slots);
	if (aborted_xact_slots != NULL)
		pfree(aborted_xact_slots);

	return result;
}

/*
 * ZHeapTupleGetCid - Retrieve command id from tuple's undo record.
 *
 * It is expected that the caller of this function has atleast read lock
 * on the buffer.
 */
CommandId
ZHeapTupleGetCid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
				 int trans_slot_id)
{
	UnpackedUndoRecord	*urec;
	UndoRecPtr	undo_rec_ptr;
	CommandId	current_cid;
	TransactionId	xid;
	uint64		epoch_xid;
	uint32		epoch;
	bool		TPDSlot = true;
	int			out_slot_no;

	/*
	 * For undo tuple caller will pass the valid slot id otherwise we can get it
	 * directly from the tuple.
	 */
	if (trans_slot_id == InvalidXactSlotId)
	{
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
		TPDSlot = false;
	}

	/*
	 * If urec_ptr is not provided, fetch the latest undo pointer from the page.
	 */
	if (!UndoRecPtrIsValid(urec_ptr))
	{
		out_slot_no = GetTransactionSlotInfo(buf,
											 ItemPointerGetOffsetNumber(&zhtup->t_self),
											 trans_slot_id,
											 &epoch,
											 &xid,
											 &undo_rec_ptr,
											 true,
											 TPDSlot);
	}
	else
	{
		out_slot_no =  GetTransactionSlotInfo(buf,
											  ItemPointerGetOffsetNumber(&zhtup->t_self),
											  trans_slot_id,
											  &epoch,
											  &xid,
											  NULL,
											  true,
											  TPDSlot);
		undo_rec_ptr = urec_ptr;
	}

	if (out_slot_no == ZHTUP_SLOT_FROZEN)
		return InvalidCommandId;

	epoch_xid = (uint64 ) epoch;
	epoch_xid = MakeEpochXid(epoch_xid, xid);

	if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return InvalidCommandId;

	Assert(UndoRecPtrIsValid(undo_rec_ptr));
	urec = UndoFetchRecord(undo_rec_ptr,
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
ZHeapTupleGetCtid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
				  ItemPointer ctid)
{
	*ctid = zhtup->t_self;
	ZHeapPageGetCtid(ZHeapTupleHeaderGetXactSlot(zhtup->t_data), buf,
					 urec_ptr, ctid);
}

/*
 * ZHeapTupleGetSubXid - Retrieve subtransaction id from tuple's undo record.
 *
 * It is expected that caller of this function has atleast read lock.
 *
 * Note that we don't handle ZHEAP_INVALID_XACT_SLOT as this function is only
 * called for in-progress transactions.  If we need to call it for some other
 * purpose, then we might need to deal with ZHEAP_INVALID_XACT_SLOT.
 */
void
ZHeapTupleGetSubXid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
					SubTransactionId *subxid)
{
	UnpackedUndoRecord	*urec;

	*subxid = InvalidSubTransactionId;

	Assert(UndoRecPtrIsValid(urec_ptr));
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self),
						   InvalidTransactionId,
						   NULL,
						   ZHeapSatisfyUndoRecord);

	/*
	 * We mostly expect urec here to be valid as it try to fetch
	 * subtransactionid of tuples that are visible to the snapshot, so
	 * corresponding undo record can't be discarded.
	 *
	 * In case when it is called while index creation, it might be possible
	 * that the transaction that updated the tuple is committed and is not
	 * present the calling transaction's snapshot (it uses snapshotany while
	 * index creation), hence undo is discarded.
	 */
	if (urec == NULL)
		return;

	if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SUBXACT)
	{
		Assert(urec->uur_payload.len > 0);

		/*
		 * For UNDO_UPDATE, we first store the CTID, then transaction slot
		 * and after that subtransaction id in payload.  For
		 * UNDO_XID_LOCK_ONLY, we first store the Lockmode, then transaction
		 * slot and after that subtransaction id.  So retrieve accordingly.
		 */
		if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
		{
			if (urec->uur_type == UNDO_UPDATE)
				*subxid = *(int *) ((char *) urec->uur_payload.data +
							sizeof(ItemPointerData) + sizeof(TransactionId));
			else if (urec->uur_type == UNDO_XID_LOCK_ONLY ||
					 urec->uur_type == UNDO_XID_LOCK_FOR_UPDATE ||
					 urec->uur_type == UNDO_XID_MULTI_LOCK_ONLY)
				*subxid = *(int *) ((char *) urec->uur_payload.data +
							sizeof(LockTupleMode) + sizeof(TransactionId));
			else
				*subxid = *(int *) ((char *) urec->uur_payload.data +
								sizeof(TransactionId));
		}
		else
		{
			if (urec->uur_type == UNDO_UPDATE)
				*subxid = *(int *) ((char *) urec->uur_payload.data +
													sizeof(ItemPointerData));
			else if (urec->uur_type == UNDO_XID_LOCK_ONLY ||
					 urec->uur_type == UNDO_XID_LOCK_FOR_UPDATE ||
					 urec->uur_type == UNDO_XID_MULTI_LOCK_ONLY)
				*subxid = *(int *) ((char *) urec->uur_payload.data +
												sizeof(LockTupleMode));
			else
				*subxid = *(SubTransactionId *) urec->uur_payload.data;
		}
	}

	UndoRecordRelease(urec);
}

/*
 * ZHeapTupleGetSpecToken - Retrieve speculative token from tuple's undo
 *			record.
 *
 * It is expected that caller of this function has atleast read lock
 * on the buffer.
 */
void
ZHeapTupleGetSpecToken(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
					   uint32 *specToken)
{
	UnpackedUndoRecord	*urec;

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
	UndoRecPtr	urec_ptr;
	uint64		epoch;
	uint32		tmp_epoch;
	TransactionId	xid = InvalidTransactionId;
	CommandId	cid;
	ItemId	lp;
	Page	page;
	ItemPointer tid = &(zhtup->t_self);
	int		trans_slot_id;
	OffsetNumber	offnum = ItemPointerGetOffsetNumber(tid);
	bool	is_invalid_slot = false;

	/*
	 * We are going to access special space in the page to retrieve the
	 * transaction information and that requires share lock on buffer.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	lp = PageGetItemId(page, offnum);
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
		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &tmp_epoch, &xid, &urec_ptr,
											   true, false);
		/*
		 * It is quite possible that the item is showing some
		 * valid transaction slot, but actual slot has been frozen.
		 * This can happen when the slot belongs to TPD entry and
		 * the corresponding TPD entry is pruned.
		 */
		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		if (ZHeapTupleHasInvalidXact(tuple->t_infomask))
			is_invalid_slot = true;
	}
	else
	{
		/*
		 * If it's deleted and pruned, we fetch the slot and undo information
		 * from the item pointer itself.
		 */
		trans_slot_id = ItemIdGetTransactionSlot(lp);
		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &tmp_epoch, &xid, &urec_ptr,
											   true, false);
		if (trans_slot_id == ZHTUP_SLOT_FROZEN)
			goto slot_is_frozen;
		if (ItemIdGetVisibilityInfo(lp) & ITEMID_XACT_INVALID)
			is_invalid_slot = true;
	}

	/*
	 * We need to fetch all the transaction related information from undo
	 * record for the tuples that point to a slot that gets invalidated for
	 * reuse at some point of time.  See PageFreezeTransSlots.
	 */
	if (is_invalid_slot)
	{
		xid = InvalidTransactionId;
		FetchTransInfoFromUndo(zhtup, &epoch, &xid, &cid, &urec_ptr, false);
	}
	else if (ZHeapTupleHasMultiLockers(tuple->t_infomask))
	{
		/*
		 * When we take a lock on the tuple, we never set locker's slot on the
		 * tuple.  However, we use the newly computed infomask for the tuple
		 * and write its current infomask in undo due to which
		 * INVALID_XACT_SLOT bit of the tuple will move to undo.  In such
		 * cases, if we need the previous inserter/updater's transaction id,
		 * we've to skip locker's undo records.
		 */
		xid = InvalidTransactionId;
		FetchTransInfoFromUndo(zhtup, &epoch, &xid, &cid, &urec_ptr, true);
	}
	else
	{
		if(cid_out && TransactionIdIsCurrentTransactionId(xid))
		{
			lp = PageGetItemId(page, offnum);
			if (!ItemIdIsDeleted(lp))
				cid = ZHeapTupleGetCid(zhtup, buf, InvalidUndoRecPtr, InvalidXactSlotId);
			else
				cid = ZHeapPageGetCid(buf, trans_slot_id, tmp_epoch, xid,
									  urec_ptr, offnum);
		}
		epoch = (uint64) tmp_epoch;
	}

	goto done;

slot_is_frozen:
	trans_slot_id = ZHTUP_SLOT_FROZEN;
	epoch = 0;
	xid = InvalidTransactionId;
	cid = InvalidCommandId;
	urec_ptr = InvalidUndoRecPtr;

done:
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
ZHeapPageGetCid(Buffer buf, int trans_slot, uint32 epoch, TransactionId xid,
				UndoRecPtr urec_ptr, OffsetNumber off)
{
	UnpackedUndoRecord	*urec;
	CommandId	current_cid;
	uint64		epoch_xid;

	epoch_xid = (uint64) epoch;
	epoch_xid = MakeEpochXid(epoch_xid, xid);

	if (epoch_xid < pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo))
		return InvalidCommandId;

	urec = UndoFetchRecord(urec_ptr,
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
ZHeapPageGetCtid(int trans_slot, Buffer buf, UndoRecPtr urec_ptr,
				 ItemPointer ctid)
{
	UnpackedUndoRecord	*urec;

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
	ZHeapTupleData	zhtup;
	UnpackedUndoRecord	*urec = NULL;
	UndoRecPtr		urec_ptr;
	ZHeapTuple	undo_tup = NULL;
	ItemPointer tid = &(tuple->t_self);
	ItemId		lp;
	Page		page;
	TransactionId	xid;
	TransactionId	prev_undo_xid = InvalidTransactionId;
	uint32		epoch;
	int	trans_slot_id = InvalidXactSlotId;
	int	prev_trans_slot_id;
	OffsetNumber	offnum;
	bool		valid = false;

	/*
	 * As we are going to access special space in the page to retrieve the
	 * transaction information share lock on buffer is required.
	 */
	if (nobuflock)
		LockBuffer(buf, BUFFER_LOCK_SHARE);

	page = BufferGetPage(buf);
	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);

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
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup.t_data);
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &epoch, &xid, &urec_ptr, true,
											   false);
	}
	else
	{
		ZHeapTuple vis_tuple;
		trans_slot_id = ItemIdGetTransactionSlot(lp);
		trans_slot_id = GetTransactionSlotInfo(buf, offnum, trans_slot_id,
											   &epoch, &xid, &urec_ptr, true,
											   false);

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

	/*
	 * Current xid on tuple must not precede oldestXidHavingUndo as it
	 * will be greater than priorXmax which was not visible to our
	 * snapshot.
	 */
	Assert(trans_slot_id != ZHTUP_SLOT_FROZEN);

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
		undo_tup = CopyTupleFromUndoRecord(urec, undo_tup, &trans_slot_id, NULL,
										   (undo_tup) == (&zhtup) ? false : true,
										   page);

		Assert(!TransactionIdPrecedes(urec->uur_prevxid, RecentGlobalXmin));

		prev_undo_xid = urec->uur_prevxid;

		/*
		 * Change the undo chain if the undo tuple is stamped with the different
		 * transaction slot.
		 */
		if (prev_trans_slot_id != trans_slot_id)
		{
			trans_slot_id =  GetTransactionSlotInfo(buf,
													ItemPointerGetOffsetNumber(&undo_tup->t_self),
													trans_slot_id,
													NULL,
													NULL,
													&urec_ptr,
													true,
													true);
		}
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
 * zheap_init_meta_page - Initialize the metapage.
 */
void
zheap_init_meta_page(Buffer metabuf, BlockNumber first_blkno,
					 BlockNumber last_blkno)
{
	ZHeapMetaPage metap;
	Page		page;

	page = BufferGetPage(metabuf);
	PageInit(page, BufferGetPageSize(metabuf), 0);

	metap = ZHeapPageGetMeta(page);
	metap->zhm_magic = ZHEAP_MAGIC;
	metap->zhm_version = ZHEAP_VERSION;
	metap->zhm_first_used_tpd_page = first_blkno;
	metap->zhm_last_used_tpd_page = last_blkno;

	/*
	 * Set pd_lower just past the end of the metadata.  This is essential,
	 * because without doing so, metadata will be lost if xlog.c compresses
	 * the page.
	 */
	((PageHeader) page)->pd_lower =
		((char *) metap + sizeof(ZHeapMetaPageData)) - (char *) page;
}

/*
 * ZheapInitMetaPage - Allocate and initialize the zheap metapage.
 */
void
ZheapInitMetaPage(Relation rel, ForkNumber forkNum)
{
	Buffer		buf;
	bool		use_wal;

	buf = ReadBufferExtended(rel, forkNum, P_NEW, RBM_NORMAL, NULL);
	if (BufferGetBlockNumber(buf) != ZHEAP_METAPAGE)
		elog(ERROR, "unexpected zheap relation size: %u, should be %u",
			 BufferGetBlockNumber(buf), ZHEAP_METAPAGE);
	LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

	START_CRIT_SECTION();

	zheap_init_meta_page(buf, InvalidBlockNumber, InvalidBlockNumber);
	MarkBufferDirty(buf);

	/*
	 * WAL log creation of metapage if the relation is persistent, or this is the
	 * init fork.  Init forks for unlogged relations always need to be WAL
	 * logged.
	 */
	use_wal = RelationNeedsWAL(rel) || forkNum == INIT_FORKNUM;

	if (use_wal)
		log_newpage_buffer(buf, true);

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buf);
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
		/* Skip metapage */
		if (scan->rs_startblock == ZHEAP_METAPAGE)
			scan->rs_startblock = ZHEAP_METAPAGE + 1;
	}
	else
	{
		scan->rs_syncscan = false;
		scan->rs_startblock = ZHEAP_METAPAGE + 1;
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
	scan->rs_startblock = 0;	/* set in initscan */
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

	if (!parallel_scan->phs_snapshot_any)
	{
		/* Snapshot was serialized -- restore it */
		snapshot = RestoreSnapshot(parallel_scan->phs_snapshot_data);
		RegisterSnapshot(snapshot);
	}
	else
	{
		/* SnapshotAny passed by caller (not serialized) */
		snapshot = SnapshotAny;
	}

	return zheap_beginscan_internal(relation, snapshot, 0, NULL, parallel_scan,
								   true, true, true, false, false,
								   !parallel_scan->phs_snapshot_any);
}

/*
 * zheapgetpage - Same as heapgetpage, but operate on zheap page and
 * in page-at-a-time mode, visible tuples are stored in rs_visztuples.
 *
 * It returns false, if we can't scan the page (like in case of TPD page),
 * otherwise, return true.
 */
bool
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
	uint8		vmstatus;
	Buffer		vmbuffer = InvalidBuffer;

	Assert(page < scan->rs_nblocks);
	Assert(page != ZHEAP_METAPAGE);

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

	/*
	 * We must hold share lock on the buffer content while examining tuple
	 * visibility.  Afterwards, however, the tuples we have found to be
	 * visible are guaranteed good as long as we hold the buffer pin.
	 */
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = BufferGetPage(buffer);

	/*
	 * Skip TPD pages. As of now, the size of special space in TPD pages is
	 * different from other zheap pages like metapage and regular zheap page,
	 * however, if that changes, we might need to explicitly store pagetype
	 * flag somewhere.
	 *
	 * Fixme - As an exception, the size of special space for zheap page
	 * with one transaction slot will match with TPD page's special size.
	 */
	if (PageGetSpecialSize(dp) == MAXALIGN(sizeof(TPDPageOpaqueData)))
	{
		UnlockReleaseBuffer(buffer);
		return false;
	}
	else if (!scan->rs_pageatatime)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		scan->rs_cbuf = buffer;
		return true;
	}

	snapshot = scan->rs_snapshot;

	/*
	 * Prune and repair fragmentation for the whole page, if possible.
	 * Fixme - Pruning is required in zheap for deletes, so we need to
	 * make it work.
	 */
	/* heap_page_prune_opt(scan->rs_rd, buffer); */

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
	 * page. That's how index-only scans work fine in hot standby.
	 */

	vmstatus = visibilitymap_get_status(scan->rs_rd, page, &vmbuffer);

	all_visible = (vmstatus & VISIBILITYMAP_ALL_VISIBLE) &&
				  !snapshot->takenDuringRecovery;

	if (BufferIsValid(vmbuffer))
	{
		ReleaseBuffer(vmbuffer);
		vmbuffer = InvalidBuffer;
	}

	for (lineoff = FirstOffsetNumber, lpp = PageGetItemId(dp, lineoff);
		 lineoff <= lines;
		 lineoff++, lpp++)
	{
		if (ItemIdIsNormal(lpp) || ItemIdIsDeleted(lpp))
		{
			ZHeapTuple	loctup = NULL;
			ZHeapTuple	resulttup = NULL;
			Size		loctup_len;
			bool		valid = false;
			ItemPointerData	tid;

			ItemPointerSet(&tid, page, lineoff);

			if (ItemIdIsDeleted(lpp))
			{
				if (all_visible)
				{
					valid = false;
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
				loctup_len = ItemIdGetLength(lpp);

				loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
				loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

				loctup->t_tableOid = RelationGetRelid(scan->rs_rd);
				loctup->t_len = loctup_len;
				loctup->t_self = tid;

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

			/*
			 * If any prior version is visible, we pass latest visible as
			 * true. The state of latest version of tuple is determined by
			 * the called function.
			 *
			 * Note that, it's possible that tuple is updated in-place and
			 * we're seeing some prior version of that. We handle that case
			 * in ZHeapTupleHasSerializableConflictOut.
			 */
			CheckForSerializableConflictOut(valid, scan->rs_rd, (void *) &tid,
											buffer, snapshot);

			if (valid)
				scan->rs_visztuples[ntup++] = resulttup;
		}
	}

	UnlockReleaseBuffer(buffer);

	Assert(ntup <= MaxZHeapTuplesPerPage);
	scan->rs_ntuples = ntup;

	return true;
}

/* ----------------
 *		zheapgettup_pagemode - fetch next zheap tuple in page-at-a-time mode
 *
 * Note that here we process only regular zheap pages, meta and tpd pages are
 * skipped.
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
	bool		valid;
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
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == ZHEAP_METAPAGE + 1)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				tuple = NULL;
				return tuple;
			}
			if (scan->rs_parallel != NULL)
			{
				heap_parallelscan_startblock_init(scan);

				page = heap_parallelscan_nextpage(scan);

				/* Skip metapage */
				if (page == ZHEAP_METAPAGE)
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
			valid = zheapgetpage(scan, page);
			if (!valid)
				goto get_next_page;

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
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == ZHEAP_METAPAGE + 1)
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
			if (scan->rs_startblock > ZHEAP_METAPAGE + 1)
				page = scan->rs_startblock - 1;
			else
				page = scan->rs_nblocks - 1;
			valid = zheapgetpage(scan, page);
			if (!valid)
				goto get_next_page;
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

get_next_tuple:
	/*
	 * advance the scan until we find a qualifying tuple or run out of stuff
	 * to scan
	 */
	while (linesleft > 0)
	{
		tuple = scan->rs_visztuples[lineindex];
		scan->rs_cindex = lineindex;
		return tuple;
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

get_next_page:
	for (;;)
	{
		if (backward)
		{
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);
			if (page == ZHEAP_METAPAGE + 1)
				page = scan->rs_nblocks;
			page--;
		}
		else if (scan->rs_parallel != NULL)
		{
			page = heap_parallelscan_nextpage(scan);
			/* Skip metapage */
			if (page == ZHEAP_METAPAGE)
				page = heap_parallelscan_nextpage(scan);
			finished = (page == InvalidBlockNumber);
		}
		else
		{
			page++;
			if (page >= scan->rs_nblocks)
				page = 0;

			if (page == ZHEAP_METAPAGE)
			{
				/*
				 * Since, we're skipping the metapage, we should update the scan
				 * location if sync scan is enabled.
				 */
				if (scan->rs_syncscan)
					ss_report_location(scan->rs_rd, page);
				page++;
			}

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

		valid = zheapgetpage(scan, page);
		if (!valid)
			continue;

		if (!scan->rs_inited)
			scan->rs_inited = true;
		lines = scan->rs_ntuples;
		linesleft = lines;
		if (backward)
			lineindex = lines - 1;
		else
			lineindex = 0;

		goto get_next_tuple;
	}
}

/*
 * Similar to heapgettup, but for fetching zheap tuple.
 *
 * Note that here we process only regular zheap pages, meta and tpd pages are
 * skipped.
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
	bool		valid;
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
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == ZHEAP_METAPAGE + 1)
			{
				Assert(!BufferIsValid(scan->rs_cbuf));
				return NULL;
			}
			if (scan->rs_parallel != NULL)
			{
				heap_parallelscan_startblock_init(scan);

				page = heap_parallelscan_nextpage(scan);

				/* Skip metapage */
				if (page == ZHEAP_METAPAGE)
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
			valid = zheapgetpage(scan, page);
			if (!valid)
				goto get_next_page;
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
			if (scan->rs_nblocks == ZHEAP_METAPAGE + 1 ||
				scan->rs_numblocks == ZHEAP_METAPAGE + 1)
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
			if (scan->rs_startblock > ZHEAP_METAPAGE + 1)
				page = scan->rs_startblock - 1;
			else
				page = scan->rs_nblocks - 1;
			valid = zheapgetpage(scan, page);
			if (!valid)
				goto get_next_page;
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

get_next_tuple:
	while (linesleft > 0)
	{
		if (ItemIdIsNormal(lpp))
		{
			ZHeapTuple	tuple = NULL;
			ZHeapTuple loctup = NULL;
			Size		loctup_len;
			bool		valid = false;
			ItemPointerData	tid;

			ItemPointerSet(&tid, page, lineoff);

			loctup_len = ItemIdGetLength(lpp);

			loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
			loctup->t_data = (ZHeapTupleHeader) ((char *) loctup + ZHEAPTUPLESIZE);

			loctup->t_tableOid = RelationGetRelid(scan->rs_rd);
			loctup->t_len = loctup_len;
			loctup->t_self = tid;

			/*
			 * We always need to make a copy of zheap tuple as once we release
			 * the buffer an in-place update can change the tuple.
			 */
			memcpy(loctup->t_data, ((ZHeapTupleHeader) PageGetItem((Page) dp, lpp)), loctup->t_len);

			tuple = ZHeapTupleSatisfiesVisibility(loctup, snapshot, scan->rs_cbuf, NULL);
			valid = tuple ? true : false;

			/*
			 * If any prior version is visible, we pass latest visible as
			 * true. The state of latest version of tuple is determined by
			 * the called function.
			 *
			 * Note that, it's possible that tuple is updated in-place and
			 * we're seeing some prior version of that. We handle that case
			 * in ZHeapTupleHasSerializableConflictOut.
			 */
			CheckForSerializableConflictOut(valid, scan->rs_rd, (void *) &tid,
											scan->rs_cbuf, snapshot);

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

get_next_page:
	for (;;)
	{
		/*
		 * advance to next/prior page and detect end of scan
		 */
		if (backward)
		{
			finished = (page == scan->rs_startblock) ||
				(scan->rs_numblocks != InvalidBlockNumber ? --scan->rs_numblocks == 0 : false);
			if (page == ZHEAP_METAPAGE + 1)
				page = scan->rs_nblocks;
			page--;
		}
		else if (scan->rs_parallel != NULL)
		{
			page = heap_parallelscan_nextpage(scan);
			/* Skip metapage */
			if (page == ZHEAP_METAPAGE)
				page = heap_parallelscan_nextpage(scan);
			finished = (page == InvalidBlockNumber);
		}
		else
		{
			page++;
			if (page >= scan->rs_nblocks)
				page = 0;

			if (page == ZHEAP_METAPAGE)
			{
				/*
				 * Since, we're skipping the metapage, we should update the scan
				 * location if sync scan is enabled.
				 */
				if (scan->rs_syncscan)
					ss_report_location(scan->rs_rd, page);
				page++;
			}

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

		valid = zheapgetpage(scan, page);
		if (!valid)
			continue;

		if (!scan->rs_inited)
			scan->rs_inited = true;

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

		goto get_next_tuple;
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

	/* Skip metapage */
	if (scan->rs_startblock == ZHEAP_METAPAGE)
		scan->rs_startblock = ZHEAP_METAPAGE + 1;

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
	ZHeapTuple	loctup = NULL;
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

	if (resulttup)
		PredicateLockTid(relation, &(resulttup->t_self), snapshot,
						 IsSerializableXact() ?
						 zheap_fetchinsertxid(resulttup, buffer) :
						 InvalidTransactionId);

	/*
	 * If any prior version is visible, we pass latest visible as
	 * true. The state of latest version of tuple is determined by
	 * the called function.
	 *
	 * Note that, it's possible that tuple is updated in-place and
	 * we're seeing some prior version of that. We handle that case
	 * in ZHeapTupleHasSerializableConflictOut.
	 */
	CheckForSerializableConflictOut((resulttup != NULL), relation, (void *) tid,
									buffer, snapshot);

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
	 * TID was obtained. Exit if this is metapage.
	 */
	offnum = ItemPointerGetOffsetNumber(tid);
	if (offnum < FirstOffsetNumber || offnum > PageGetMaxOffsetNumber(page) ||
		BufferGetBlockNumber(buffer) == ZHEAP_METAPAGE)
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

	*tuple = NULL;
	if (ItemIdIsDeleted(lp))
	{
		CommandId		tup_cid;
		TransactionId	tup_xid;

		resulttup = ZHeapGetVisibleTuple(offnum, snapshot, buffer, NULL);
		ctid = *tid;
		ZHeapPageGetNewCtid(buffer, &ctid, &tup_xid, &tup_cid);
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

	if (valid)
		PredicateLockTid(relation, &((resulttup)->t_self), snapshot,
						 IsSerializableXact() ?
						 zheap_fetchinsertxid(resulttup, buffer) :
						 InvalidTransactionId);

	/*
	 * If any prior version is visible, we pass latest visible as
	 * true. The state of latest version of tuple is determined by
	 * the called function.
	 *
	 * Note that, it's possible that tuple is updated in-place and
	 * we're seeing some prior version of that. We handle that case
	 * in ZHeapTupleHasSerializableConflictOut.
	 */
	CheckForSerializableConflictOut(valid, relation, (void *) tid,
									buffer, snapshot);

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
	UndoRecPtr	urec_ptr;
	ZHeapTuple	undo_tup;
	int			out_slot_no PG_USED_FOR_ASSERTS_ONLY;

	out_slot_no = GetTransactionSlotInfo(buffer,
										 ItemPointerGetOffsetNumber(tid),
										 ZHeapTupleHeaderGetXactSlot(ztuple->t_data),
										 NULL,
										 NULL,
										 &urec_ptr,
										 true,
										 false);

	/*
	 * See the Asserts below to know why the transaction slot can't be frozen.
	 */
	Assert(out_slot_no != ZHTUP_SLOT_FROZEN);

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

	undo_tup = CopyTupleFromUndoRecord(urec, NULL, NULL, NULL, false, NULL);
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
	/*
	 * Ignore tuples inserted by an aborted transaction.
	 *
	 * XXX we can ignore the tuple if it was non-in-place updated/deleted
	 * by the inserting transaction, but for that we need to traverse the
	 * complete undo chain to find the root tuple, is it really worth?
	 */
	if (TransactionIdDidCommit(xid))
	{
		Assert (tuple->t_infomask & ZHEAP_DELETED ||
				tuple->t_infomask & ZHEAP_UPDATED);
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
 *	be accomodated on a page and alignment for each item (Ideally, we don't
 *	need to align space between tuples as we always make the copy of tuple to
 *	support in-place updates.  However, there are places in zheap code where we
 *	access tuple header directly from page (ex. zheap_delete, zheap_update,
 *	etc.) for which we them to be aligned at two-byte boundary). It
 *	additionally handles the itemids that are marked as unused, but still
 *	can't be reused.
 *
 *	Callers passed a valid input_page only incase there are constructing the
 *	in-memory copy of tuples and then directly sync the page.
 */
OffsetNumber
ZPageAddItemExtended(Buffer buffer,
					 Page	input_page,
					 Item item,
					 Size size,
					 OffsetNumber offsetNumber,
					 int flags,
					 bool NoTPDBufLock)
{
	Page		page;
	Size		alignedSize;
	PageHeader	phdr;
	int			lower;
	int			upper;
	ItemId		itemId;
	OffsetNumber limit;
	bool		needshuffle = false;

	/* Either one of buffer or page could be valid. */
	if (BufferIsValid(buffer))
	{
		Assert(!PageIsValid(input_page));
		page = BufferGetPage(buffer);
	}
	else
	{
		Assert(PageIsValid(input_page));
		page = input_page;
	}

	phdr = (PageHeader) page;

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
						UndoRecPtr		urec_ptr;
						int		trans_slot_id = ItemIdGetTransactionSlot(itemId);
						uint32		epoch;

						/*
						 * We can't reach here for a valid input page as the
						 * callers passed it for the pages that wouldn't have
						 * been pruned.
						 */
						Assert(!PageIsValid(input_page));

						/*
						 * Here, we are relying on the transaction information in
						 * slot as if the corresponding slot has been reused, then
						 * transaction information from the entry would have been
						 * cleared.  See PageFreezeTransSlots.
						 */
						if (trans_slot_id == ZHTUP_SLOT_FROZEN)
							break;
						trans_slot_id = GetTransactionSlotInfo(buffer, offsetNumber,
															   trans_slot_id, &epoch, &xid,
															   &urec_ptr, NoTPDBufLock, false);
						/*
						 * It is quite possible that the item is showing some
						 * valid transaction slot, but actual slot has been frozen.
						 * This can happen when the slot belongs to TPD entry and
						 * the corresponding TPD entry is pruned.
						 */
						if (trans_slot_id == ZHTUP_SLOT_FROZEN)
							break;
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
	 * size > pd_upper.
	 */
	if (offsetNumber == limit || needshuffle)
		lower = phdr->pd_lower + sizeof(ItemIdData);
	else
		lower = phdr->pd_lower;

	alignedSize = SHORTALIGN(size);

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

	/* Add the tuple to the page.  Caller must ensure to have a TPD page lock. */
	offnum = ZPageAddItem(buffer, NULL, (Item) tuple->t_data, tuple->t_len,
						  InvalidOffsetNumber, false, true, false);

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
 *	trans_slot_id - If non-NULL, then populate it with the transaction slot of
 *			transaction that has modified the tuple.
 *  cid - output command id
 *	free_zhtup - if true, free the previous version of tuple.
 */
ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						int *trans_slot_id, CommandId *cid, bool free_zhtup,
						Page page)
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

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
						*trans_slot_id = *(int *) urec->uur_payload.data;
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}
				if (cid)
					*cid = urec->uur_cid;
			}
			break;
		case UNDO_XID_LOCK_ONLY:
		case UNDO_XID_LOCK_FOR_UPDATE:
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

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						/*
						 * We first store the Lockmode and then transaction slot in
						 * payload, so retrieve it accordingly.
						 */
						*trans_slot_id = *(int *) ((char *) urec->uur_payload.data + sizeof(LockTupleMode));
					}
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}
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

				/* Retrieve the TPD transaction slot from payload */
				if (trans_slot_id)
				{
					if (urec->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						/*
						 * For UNDO_UPDATE, we first store the CTID and then
						 * transaction slot, so retrieve it accordingly.
						 */
						if (urec->uur_type == UNDO_UPDATE)
							*trans_slot_id = *(int *) ((char *) urec->uur_payload.data + sizeof(ItemPointerData));
						else
							*trans_slot_id = *(int *) urec->uur_payload.data;
					}
					else
						*trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				}

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

	/*
	 * If the undo tuple is pointing to the last slot of the page and the page
	 * has TPD slots that means the last slot information must move to the
	 * first slot of the TPD page so change the slot number as per that.
	 */
	if (page && (*trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS) &&
		ZHeapPageHasTPDSlot((PageHeader) page))
		*trans_slot_id = ZHEAP_PAGE_TRANS_SLOTS + 1;

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
				Size needed_space = used_space + zheaptup->t_len + saveFreeSpace;

				/* Check if we can fit this tuple in the page */
				if (avail_space < needed_space)
				{
					/* No more space to insert tuples in this page */
					break;
				}

				used_space += zheaptup->t_len;
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
	 * max required offset number. We can decide the actual end offset for this
	 * range while inserting tuples in the buffer.
	 */
	if ((limit <= MaxZHeapTuplesPerPage) && (nthispage < ntuples))
	{
		ZHeapTuple zheaptup = tuples[nthispage];
		Size needed_space = used_space + sizeof(ItemIdData) +
						zheaptup->t_len + saveFreeSpace;

		/* Check if we can fit this tuple + a new offset in the page */
		if (avail_space >= needed_space)
		{
			OffsetNumber	max_required_offset;
			int				required_tuples = ntuples - nthispage;

			/*
			 * Choose minimum among MaxOffsetNumber and the maximum offsets
			 * required for tuples.
			 */
			max_required_offset = Min(MaxOffsetNumber, (limit + required_tuples));

			zfree_offset_ranges->nranges++;
			zfree_offset_ranges->startOffset[zfree_offset_ranges->nranges - 1] = limit;
			zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1] = max_required_offset;
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
	bool		skip_undo;

	needwal = RelationNeedsWAL(relation);
	saveFreeSpace = RelationGetTargetPageFreeSpace(relation,
												   HEAP_DEFAULT_FILLFACTOR);
	/*
	 * We can skip inserting undo records if the tuples are to be marked
	 * as frozen.
	 */
	skip_undo = (options & HEAP_INSERT_FROZEN);

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
		int		trans_slot_id = InvalidXactSlotId;
		int		ucnt = 0;
		UndoRecPtr	urecptr = InvalidUndoRecPtr,
								prev_urecptr = InvalidUndoRecPtr;
		UnpackedUndoRecord		*undorecord = NULL;
		ZHeapFreeOffsetRanges	*zfree_offset_ranges;
		OffsetNumber	usedoff[MaxOffsetNumber];
		OffsetNumber	max_required_offset;
		uint8		vm_status;

		CHECK_FOR_INTERRUPTS();

reacquire_buffer:
		/*
		 * Find buffer where at least the next tuple will fit.  If the page is
		 * all-visible, this will also pin the requisite visibility map page.
		 */
		if (BufferIsValid(vmbuffer))
		{
			ReleaseBuffer(vmbuffer);
			vmbuffer = InvalidBuffer;
		}

		buffer = RelationGetBufferForZTuple(relation, zheaptuples[ndone]->t_len,
											InvalidBuffer, options, bistate,
											&vmbuffer, NULL);
		page = BufferGetPage(buffer);

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

		max_required_offset =
			zfree_offset_ranges->endOffset[zfree_offset_ranges->nranges - 1];

		/*
		 * If we're not inserting an undo record, we don't have to reserve
		 * a transaction slot as well.
		 */
		if (!skip_undo)
		{
			/*
			 * The transaction information of tuple needs to be set in transaction
			 * slot, so needs to reserve the slot before proceeding with the actual
			 * operation.  It will be costly to wait for getting the slot, but we do
			 * that by releasing the buffer lock.
			 */
			trans_slot_id = PageReserveTransactionSlot(relation,
													   buffer,
													   max_required_offset,
													   epoch,
													   xid,
													   &prev_urecptr,
													   &lock_reacquired,
													   false);
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
			 * For every contiguous free or new offsets, we insert an undo record.
			 * In the payload data of each undo record, we store the start and end
			 * available offset for a contiguous range.
			 */
			undorecord = (UnpackedUndoRecord *) palloc(zfree_offset_ranges->nranges
													   * sizeof(UnpackedUndoRecord));
			/* Start UNDO prepare Stuff */
			urecptr = prev_urecptr;
			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				/* prepare an undo record */
				undorecord[i].uur_type = UNDO_MULTI_INSERT;
				undorecord[i].uur_info = 0;
				undorecord[i].uur_prevlen = 0;	/* Fixme - need to figure out how to set this value and then decide whether to WAL log it */
				undorecord[i].uur_reloid = relation->rd_id;
				undorecord[i].uur_prevxid = FrozenTransactionId;
				undorecord[i].uur_xid = xid;
				undorecord[i].uur_cid = cid;
				undorecord[i].uur_fork = MAIN_FORKNUM;
				undorecord[i].uur_blkprev = urecptr;
				undorecord[i].uur_block = BufferGetBlockNumber(buffer);
				undorecord[i].uur_tuple.len = 0;
				undorecord[i].uur_offset = 0;
				undorecord[i].uur_payload.len = 2 * sizeof(OffsetNumber);
			}

			UndoSetPrepareSize(undorecord, zfree_offset_ranges->nranges,
							   InvalidTransactionId,
							   UndoPersistenceForRelation(relation), NULL, &undometa);

			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				undorecord[i].uur_blkprev = urecptr;
				urecptr = PrepareUndoInsert(&undorecord[i],
											InvalidTransactionId,
											UndoPersistenceForRelation(relation),
											NULL,
											NULL);

				initStringInfo(&undorecord[i].uur_payload);
			}

			Assert(UndoRecPtrIsValid(urecptr));
			elog(DEBUG1, "Undo record prepared: %d for Block Number: %d",
				 zfree_offset_ranges->nranges, BufferGetBlockNumber(buffer));
			/* End UNDO prepare Stuff */
		}

		/*
		 * If there is a valid vmbuffer get its status.  The vmbuffer will not
		 * be valid if operated page is newly extended, see
		 * RelationGetBufferForZTupleand. Also, anyway by default vm status
		 * bits are clear for those pages hence no need to clear it again!
		 */
		vm_status = visibilitymap_get_status(relation,
										BufferGetBlockNumber(buffer), &vmbuffer);

		/*
		 * Lock the TPD page before starting critical section.  We might need
		 * to access it in ZPageAddItemExtended.  Note that if the transaction
		 * slot belongs to TPD entry, then the TPD page must be locked during
		 * slot reservation.
		 *
		 * XXX We can optimize this by avoid taking TPD page lock unless the page
		 * has some unused item which requires us to fetch the transaction
		 * information from TPD.
		 */
		if (trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
			ZHeapPageHasTPDSlot((PageHeader) page) &&
			PageHasFreeLinePointers((PageHeader) page))
			TPDPageLock(relation, buffer);

		/* NO EREPORT(ERROR) from here till changes are logged */
		START_CRIT_SECTION();

		/*
		 * RelationGetBufferForZTuple has ensured that the first tuple fits.
		 * Keep calm and put that on the page, and then as many other tuples
		 * as fit.
		 */
		nthispage = 0;
		for (i = 0; i < zfree_offset_ranges->nranges; i++)
		{
			OffsetNumber offnum;

			for (offnum = zfree_offset_ranges->startOffset[i];
				 offnum <= zfree_offset_ranges->endOffset[i];
				 offnum++)
			{
				ZHeapTuple	zheaptup;

				if (ndone + nthispage == ntuples)
					break;

				zheaptup = zheaptuples[ndone + nthispage];

				/* Make sure that the tuple fits in the page. */
				if (PageGetZHeapFreeSpace(page) < zheaptup->t_len + saveFreeSpace)
					break;

				if (!(options & HEAP_INSERT_FROZEN))
					ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, trans_slot_id);

				RelationPutZHeapTuple(relation, buffer, zheaptup);

				/*
				 * Let's make sure that we've decided the offset ranges
				 * correctly.
				 */
				Assert(offnum == ItemPointerGetOffsetNumber(&(zheaptup->t_self)));

				/* track used offsets */
				usedoff[ucnt++] = offnum;

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
			zfree_offset_ranges->endOffset[i] = offnum - 1;
			if (!skip_undo)
			{
				appendBinaryStringInfo(&undorecord[i].uur_payload,
										   (char *) &zfree_offset_ranges->startOffset[i],
										   sizeof(OffsetNumber));
				appendBinaryStringInfo(&undorecord[i].uur_payload,
										  (char *) &zfree_offset_ranges->endOffset[i],
										   sizeof(OffsetNumber));
			}
			elog(DEBUG1, "start offset: %d, end offset: %d",
				 zfree_offset_ranges->startOffset[i], zfree_offset_ranges->endOffset[i]);
		}

		if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) ||
			(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
		{
			all_visible_cleared = true;
			visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
								vmbuffer, VISIBILITYMAP_VALID_BITS);
		}

		/*
		 * XXX Should we set PageSetPrunable on this page ? See heap_insert()
		 */

		MarkBufferDirty(buffer);

		if (!skip_undo)
		{
			/* Insert the undo */
			InsertPreparedUndo();

			/*
			 * We're sending the undo record for debugging purpose. So, just send
			 * the last one.
			 */
			if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			{
				PageSetUNDO(undorecord[zfree_offset_ranges->nranges - 1],
							buffer,
							trans_slot_id,
							true,
							epoch,
							xid,
							urecptr,
							usedoff,
							ucnt);
			}
			else
			{
				PageSetUNDO(undorecord[zfree_offset_ranges->nranges - 1],
							buffer,
							trans_slot_id,
							true,
							epoch,
							xid,
							urecptr,
							NULL,
							0);
			}
		}

		/* XLOG stuff */
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
			xlundohdr.reloid = relation->rd_id;
			xlundohdr.urec_ptr = urecptr;
			xlundohdr.blkprev = prev_urecptr;

			/* allocate xl_zheap_multi_insert struct from the scratch area */
			xlrec = (xl_zheap_multi_insert *) scratchptr;
			xlrec->flags = all_visible_cleared ? XLZ_INSERT_ALL_VISIBLE_CLEARED : 0;
			if (skip_undo)
				xlrec->flags |= XLZ_INSERT_IS_FROZEN;
			xlrec->ntuples = nthispage;
			scratchptr += SizeOfZHeapMultiInsert;

			/* copy the offset ranges as well */
			memcpy((char *) scratchptr, (char *) &zfree_offset_ranges->nranges, sizeof(int));
			scratchptr += sizeof(int);
			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				memcpy((char *)scratchptr, (char *)&zfree_offset_ranges->startOffset[i], sizeof(OffsetNumber));
				scratchptr += sizeof(OffsetNumber);
				memcpy((char *)scratchptr, (char *)&zfree_offset_ranges->endOffset[i], sizeof(OffsetNumber));
				scratchptr += sizeof(OffsetNumber);
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

			/* If we've skipped undo insertion, we don't need a slot in page. */
			if (!skip_undo && trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			{
				xlrec->flags |= XLZ_INSERT_CONTAINS_TPD_SLOT;
				XLogRegisterData((char *) &trans_slot_id, sizeof(trans_slot_id));
			}
			XLogRegisterBuffer(0, buffer, REGBUF_STANDARD | bufflags);

			/* copy tuples in block data */
			XLogRegisterBufData(0, tupledata, totaldatalen);
			if (xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
				(void) RegisterTPDBuffer(page, 1);

			RegisterUndoLogBuffers(2);

			/* filtering by origin on a row level is much more efficient */
			XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

			recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr,
										doPageWrites);
			if (recptr == InvalidXLogRecPtr)
			{
				ResetRegisteredTPDBuffers();
				goto prepare_xlog;
			}

			PageSetLSN(page, recptr);
			if (xlrec->flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
				TPDPageSetLSN(page, recptr);
			UndoLogBuffersSetLSN(recptr);
		}

		END_CRIT_SECTION();

		/* be tidy */
		if (!skip_undo)
		{
			for (i = 0; i < zfree_offset_ranges->nranges; i++)
				pfree(undorecord[i].uur_payload.data);
			pfree(undorecord);
		}
		pfree(zfree_offset_ranges);

		UnlockReleaseBuffer(buffer);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		UnlockReleaseUndoBuffers();
		UnlockReleaseTPDBuffers();

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

	mask_page_lsn_and_checksum(page);

	mask_page_hint_bits(page);
	mask_unused_space(page);

	if (PageGetSpecialSize(page) == MAXALIGN(BLCKSZ))
	{
		ZHeapMetaPage metap PG_USED_FOR_ASSERTS_ONLY;
		metap = ZHeapPageGetMeta(page);
		/* It's a meta-page, no need to mask further. */
		Assert(metap->zhm_magic == ZHEAP_MAGIC);
		Assert(metap->zhm_version == ZHEAP_VERSION);
		return;
	}

	if (PageGetSpecialSize(page) == MAXALIGN(sizeof(TPDPageOpaqueData)))
	{
		/* It's a TPD page, no need to mask further. */
		return;
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
		ZHeapTuple	tp = NULL;
		ZHeapTuple	resulttup = NULL;
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
		 * Get the transaction which modified this tuple. Ideally we need to
		 * get this only when there is a ctid chain to follow. But since the
		 * visibility function frees the tuple, we have to do this here
		 * regardless of the existence of a ctid chain.
		 */
		ZHeapTupleGetTransInfo(tp, buffer, NULL, NULL, &priorXmax, NULL, NULL,
							   false);

		/*
		 * Check time qualification of tuple; if visible, set it as the new
		 * result candidate.
		 */
		ItemPointerSetInvalid(&new_ctid);
		resulttup = ZHeapTupleSatisfiesVisibility(tp, snapshot, buffer,
												  &new_ctid);

		/*
		 * If any prior version is visible, we pass latest visible as
		 * true. The state of latest version of tuple is determined by
		 * the called function.
		 *
		 * Note that, it's possible that tuple is updated in-place and
		 * we're seeing some prior version of that. We handle that case
		 * in ZHeapTupleHasSerializableConflictOut.
		 */
		CheckForSerializableConflictOut((resulttup != NULL), relation,
										(void *) &ctid,
										buffer, snapshot);

		/* Pass back the tuple ctid if it's visible */
		if (resulttup != NULL)
			*tid = ctid;

		/* If there's a valid ctid link, follow it, else we're done. */
		if (!ItemPointerIsValid(&new_ctid) ||
			ZHEAP_XID_IS_LOCKED_ONLY(infomask) ||
			ZHeapTupleIsMoved(infomask) ||
			ItemPointerEquals(&ctid, &new_ctid))
		{
			if (resulttup != NULL)
				zheap_freetuple(resulttup);
			UnlockReleaseBuffer(buffer);
			break;
		}

		ctid = new_ctid;

		if (resulttup != NULL)
			zheap_freetuple(resulttup);
		UnlockReleaseBuffer(buffer);
	}							/* end of loop */
}

/*
 * Perform XLogInsert for a zheap-visible operation. vm_buffer is the buffer
 * containing the corresponding visibility map block.  The vm_buffer should
 * have already been modified and dirtied.
 */
XLogRecPtr
log_zheap_visible(RelFileNode rnode, Buffer heap_buffer, Buffer vm_buffer,
				 TransactionId cutoff_xid, uint8 vmflags)
{
	xl_zheap_visible xlrec;
	XLogRecPtr	recptr;

	Assert(BufferIsValid(heap_buffer));
	Assert(BufferIsValid(vm_buffer));

	xlrec.cutoff_xid = cutoff_xid;
	xlrec.flags = vmflags;
	xlrec.heapBlk = BufferGetBlockNumber(heap_buffer);

	XLogBeginInsert();
	XLogRegisterData((char *) &xlrec, SizeOfZHeapVisible);

	XLogRegisterBuffer(0, vm_buffer, 0);

	recptr = XLogInsert(RM_ZHEAP2_ID, XLOG_ZHEAP_VISIBLE);

	return recptr;
}

/*
 * GetTransactionsSlotsForPage - returns transaction slots for a zheap page
 *
 * This method returns all the transaction slots for the input zheap page
 * including the corresponding TPD page. It also returns the corresponding
 * TPD buffer if there is one.
 */
TransInfo *
GetTransactionsSlotsForPage(Relation rel, Buffer buf, int *total_trans_slots,
							BlockNumber *tpd_blkno)
{
	Page	page;
	PageHeader	phdr;
	TransInfo *tpd_trans_slots;
	TransInfo *trans_slots = NULL;
	bool	tpd_e_pruned;

	*total_trans_slots = 0;
	if (tpd_blkno)
		*tpd_blkno = InvalidBlockNumber;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;

	if (ZHeapPageHasTPDSlot(phdr))
	{
		int		num_tpd_trans_slots;

		tpd_trans_slots = TPDPageGetTransactionSlots(rel,
													 buf,
													 InvalidOffsetNumber,
													 false,
													 false,
													 NULL,
													 &num_tpd_trans_slots,
													 NULL,
													 &tpd_e_pruned,
													 NULL);
		if (!tpd_e_pruned)
		{
			ZHeapPageOpaque	zopaque;
			TransInfo	last_trans_slot_info;

			zopaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
			last_trans_slot_info = zopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1];

			if (tpd_blkno)
				*tpd_blkno = last_trans_slot_info.xid_epoch;

			/*
			 * The last slot in page contains TPD information, so we don't need to
			 * include it.
			 */
			*total_trans_slots = num_tpd_trans_slots + ZHEAP_PAGE_TRANS_SLOTS - 1;
			trans_slots = (TransInfo *)
					palloc(*total_trans_slots * sizeof(TransInfo));
			/* Copy the transaction slots from the page. */
			memcpy(trans_slots, page + phdr->pd_special,
				   (ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo));
			/* Copy the transaction slots from the tpd entry. */
			memcpy((char *) trans_slots + ((ZHEAP_PAGE_TRANS_SLOTS - 1) * sizeof(TransInfo)),
				   tpd_trans_slots, num_tpd_trans_slots * sizeof(TransInfo));

			pfree(tpd_trans_slots);
		}
	}

	if (!ZHeapPageHasTPDSlot(phdr) || tpd_e_pruned)
	{
		Assert (trans_slots == NULL);

		*total_trans_slots = ZHEAP_PAGE_TRANS_SLOTS;
		trans_slots = (TransInfo *)
				palloc(*total_trans_slots * sizeof(TransInfo));
		memcpy(trans_slots, page + phdr->pd_special,
			   *total_trans_slots * sizeof(TransInfo));
	}

	Assert(*total_trans_slots >= ZHEAP_PAGE_TRANS_SLOTS);

	return trans_slots;
}

/*
 * CheckAndLockTPDPage - Check and lock the TPD page before starting critical
 * section.
 *
 * We might need to access it in ZPageAddItemExtended.  Note that if the
 * transaction slot belongs to TPD entry, then the TPD page must be locked during
 * slot reservation.  Also, if the old buffer and new buffer refers to the
 * same TPD page and the old transaction slot corresponds to a TPD slot,
 * the TPD page must be locked during slot reservation.
 *
 * XXX We can optimize this by avoid taking TPD page lock unless the page
 * has some unused item which requires us to fetch the transaction
 * information from TPD.
 */
static inline void
CheckAndLockTPDPage(Relation relation, int new_trans_slot_id, int old_trans_slot_id,
					Buffer newbuf, Buffer oldbuf)
{
	if (new_trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
		ZHeapPageHasTPDSlot((PageHeader) BufferGetPage(newbuf)) &&
		PageHasFreeLinePointers((PageHeader)BufferGetPage(newbuf)))
	{
		/*
		 * If the old buffer and new buffer refers to the same TPD page
		 * and the old transaction slot corresponds to a TPD slot,
		 * we must have locked the TPD page during slot reservation.
		 */
		if (ZHeapPageHasTPDSlot((PageHeader) BufferGetPage(oldbuf)) &&
			(old_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS))
		{
			Page oldpage, newpage;
			ZHeapPageOpaque oldopaque, newopaque;
			BlockNumber oldtpdblk, newtpdblk;

			oldpage = BufferGetPage(oldbuf);
			newpage = BufferGetPage(newbuf);
			oldopaque = (ZHeapPageOpaque) PageGetSpecialPointer(oldpage);
			newopaque = (ZHeapPageOpaque) PageGetSpecialPointer(newpage);

			oldtpdblk = oldopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid_epoch;
			newtpdblk = newopaque->transinfo[ZHEAP_PAGE_TRANS_SLOTS - 1].xid_epoch;

			if (oldtpdblk != newtpdblk)
				TPDPageLock(relation, newbuf);
		}
		else
			TPDPageLock(relation, newbuf);
	}
}
