/*-------------------------------------------------------------------------
 *
 * zheapam.c
 *	  zheap access method code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/zheapam.c
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
#include "access/relation.h"
#include "access/relscan.h"
#include "access/tableam.h"
#include "access/tpd.h"
#include "access/tuptoaster.h"
#include "access/undoinsert.h"
#include "access/undolog.h"
#include "access/undolog_xlog.h"
#include "access/undorecord.h"
#include "access/undorequest.h"
#include "access/visibilitymap.h"
#include "access/zheap.h"
#include "access/zhio.h"
#include "access/zhtup.h"
#include "access/zheapam_xlog.h"
#include "access/zheap.h"
#include "access/zheapscan.h"
#include "access/zmultilocker.h"
#include "catalog/catalog.h"
#include "executor/tuptable.h"
#include "miscadmin.h"
#include "nodes/tidbitmap.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "storage/predicate.h"
#include "storage/procarray.h"
#include "storage/itemid.h"
#include "storage/buf_internals.h"
#include "utils/datum.h"
#include "utils/expandeddatum.h"
#include "utils/inval.h"
#include "utils/memdebug.h"
#include "utils/rel.h"
#include "utils/ztqual.h"

extern bool synchronize_seqscans;

static bool zheap_delete_wait_helper(Relation relation,
						 Buffer buffer, ZHeapTuple zheaptup,
						 FullTransactionId fxid, TransactionId xwait,
						 int xwait_trans_slot, TransactionId xwait_subxid,
						 ItemId lp,
						 TransactionId tup_xid, bool *have_tuple_lock,
						 TransactionId *single_locker_xid,
						 bool *any_multi_locker_member_alive,
						 TM_Result *result);
static bool zheap_update_wait_helper(Relation relation,
						 Buffer buffer, ZHeapTuple zheaptup,
						 FullTransactionId fxid, TransactionId xwait,
						 int xwait_trans_slot, TransactionId xwait_subxid,
						 LockTupleMode lockmode, bool key_intact,
						 ItemId lp,
						 TransactionId tup_xid, bool *have_tuple_lock,
						 TransactionId *single_locker_xid,
						 bool *any_multi_locker_member_alive,
						 bool *checked_lockers, bool *locker_remains,
						 TM_Result *result, bool *item_is_deleted);
static ZHeapTuple zheap_prepare_insert(Relation relation, ZHeapTuple tup,
					 int options, uint32 specToken);
static TM_Result zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 FullTransactionId fxid, LockTupleMode mode, LockOper lockopr,
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
static void log_zheap_insert(ZHeapWALInfo *walinfo, Relation relation,
				 int options, bool skip_undo);
static void log_zheap_update(ZHeapWALInfo *oldinfo, ZHeapWALInfo *newinfo, bool inplace_update);
static void log_zheap_delete(ZHeapWALInfo *walinfo, bool changingPart,
				 SubTransactionId subxid, TransactionId tup_xid);
static void log_zheap_multi_insert(ZHeapMultiInsertWALInfo *walinfo, bool skip_undo, char *scratch);
static void log_zheap_lock_tuple(ZHeapWALInfo *walinfo, TransactionId tup_xid,
					 int trans_slot_id, bool hasSubXactLock, LockTupleMode mode);
static Bitmapset *ZHeapDetermineModifiedColumns(Relation relation, Bitmapset *interesting_cols,
							  ZHeapTuple oldtup, ZHeapTuple newtup);
static inline void CheckAndLockTPDPage(Relation relation, int new_trans_slot_id,
					int old_trans_slot_id, Buffer newbuf,
					Buffer oldbuf);
static bool RefetchAndCheckTupleStatus(Relation relation, Buffer buffer,
						   int old_infomask, TransactionId tup_xid,
						   TransactionId *single_locker_xid,
						   LockTupleMode *mode, ZHeapTupleData *zhtup);

/*
 * Subroutine for zheap_insert(). Prepares a tuple for insertion.
 *
 * This is similar to heap_prepare_insert except that we don't set
 * information in tuple header as that needs to be either set in
 * TPD entry or undorecord for this tuple.
 */
static ZHeapTuple
zheap_prepare_insert(Relation relation, ZHeapTuple tup, int options,
					 uint32 specToken)
{

	/*
	 * In zheap, we don't support the optimization for TABLE_INSERT_SKIP_WAL.
	 * If we skip writing/using WAL, we must force the relation down to disk
	 * (using heap_sync) before it's safe to commit the transaction. This
	 * requires writing out any dirty buffers of that relation and then doing
	 * a forced fsync. For zheap, we've to fsync the corresponding undo
	 * buffers as well. It is difficult to keep track of dirty undo buffers
	 * and fsync them at end of the operation in some function similar to
	 * heap_sync. But, if we're freezing the tuple during insertion, we can
	 * use the TABLE_INSERT_SKIP_WAL optimization since we don't write undo
	 * for the same. Thus just skip the optimization if only
	 * TABLE_INSERT_SKIP_WAL is specified.
	 */

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

	tup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	tup->t_data->t_infomask2 &= ~ZHEAP_XACT_SLOT;

	if (options & ZHEAP_INSERT_FROZEN)
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
		return ztoast_insert_or_update(relation, tup, NULL, options, specToken);
	else
		return tup;
}

/*
 * Given two versions of the same t_infomask for a tuple, compare them and
 * return whether the relevant status for a tuple xid has changed.  This is
 * used after a buffer lock has been released and reacquired: we want to ensure
 * that the tuple state continues to be the same it was when we previously
 * examined it.
 *
 * Note the xid field itself must be compared separately.
 */
static inline bool
xid_infomask_changed(uint16 new_infomask, uint16 old_infomask)
{
	const uint16 interesting =
	ZHEAP_MULTI_LOCKERS | ZHEAP_XID_LOCK_ONLY | ZHEAP_LOCK_MASK;

	if ((new_infomask & interesting) != (old_infomask & interesting))
		return true;

	return false;
}

/*
 * zheap_insert - insert tuple into a zheap
 *
 * The functionality related to the heap is quite similar to heap_insert.
 * Additionally this function inserts an undo record and updates the undo
 * pointer in the page header or in TPD entry for this page.
 *
 * We do need to clear the visibility map bit for this page if it is not
 * cleared already.
 */
void
zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate, uint32 specToken)
{
	FullTransactionId fxid = InvalidFullTransactionId;
	ZHeapTuple	zheaptup;
	UnpackedUndoRecord undorecord;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	bool		all_visible_cleared = false;
	int			trans_slot_id = InvalidXactSlotId;
	Page		page;
	UndoRecPtr	urecptr = InvalidUndoRecPtr,
				prev_urecptr = InvalidUndoRecPtr;
	xl_undolog_meta undometa;
	uint8		vm_status = 0;
	bool		lock_reacquired;
	bool		skip_undo;
	ZHeapPrepareUndoInfo zh_undo_info;

	/*
	 * We can skip inserting undo records if the tuples are to be marked as
	 * frozen.
	 */
	skip_undo = (options & ZHEAP_INSERT_FROZEN);

	/* We don't need a transaction id if we are skipping undo */
	if (!skip_undo)
		fxid = GetTopFullTransactionId();

	/*
	 * Fill in tuple header fields and toast the tuple if necessary.
	 *
	 * Note: below this point, zheaptup is the data we actually intend to
	 * store into the relation; tup is the caller's original untoasted data.
	 */
	zheaptup = zheap_prepare_insert(relation, tup, options, specToken);

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
		 * slot, so needs to reserve the slot before proceeding with the
		 * actual operation.  It will be costly to wait for getting the slot,
		 * but we do that by releasing the buffer lock.
		 *
		 * We don't yet know the offset number of the inserting tuple so just
		 * pass the 'max_offset_number + 1' so that if it need to get slot
		 * from the TPD it can ensure that the TPD has sufficient map entries.
		 */
		trans_slot_id = PageReserveTransactionSlot(relation,
												   buffer,
												   PageGetMaxOffsetNumber(page) + 1,
												   fxid,
												   &prev_urecptr,
												   &lock_reacquired,
												   false,
												   InvalidBuffer,
												   NULL);
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

	if (options & ZHEAP_INSERT_SPECULATIVE)
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
	 * See heap_insert to know why checking conflicts is important before
	 * actually inserting the tuple.
	 */
	CheckForSerializableConflictIn(relation, NULL, InvalidBuffer);

	if (!skip_undo)
	{
		/* Prepare an undo record for this operation. */
		zh_undo_info.reloid = relation->rd_id;
		zh_undo_info.blkno = BufferGetBlockNumber(buffer);
		zh_undo_info.offnum = InvalidOffsetNumber;
		zh_undo_info.prev_urecptr = prev_urecptr;
		zh_undo_info.fxid = fxid;
		zh_undo_info.cid = cid;
		zh_undo_info.undo_persistence = UndoPersistenceForRelation(relation);

		urecptr = zheap_prepare_undoinsert(&zh_undo_info, specToken,
										   (options & ZHEAP_INSERT_SPECULATIVE) ? true : false,
										   &undorecord, NULL, &undometa);
	}

	/*
	 * Get the page visibility status from visibility map.  If the page is
	 * all-visible, we need to clear it after inserting the tuple.  Note that,
	 * for newly added pages (vm buffer will be invalid, see
	 * RelationGetBufferForZTuple), vm status must be clear, so we don't need
	 * to do anything for them.
	 */
	if (BufferIsValid(vmbuffer))
		vm_status = visibilitymap_get_status(relation,
											 BufferGetBlockNumber(buffer),
											 &vmbuffer);

	/*
	 * Lock the TPD page before starting critical section.  We might need to
	 * access it in ZPageAddItemExtended.  Note that if the transaction slot
	 * belongs to TPD entry, then the TPD page must be locked during slot
	 * reservation.
	 *
	 * XXX We can optimize this by avoid taking TPD page lock unless the page
	 * has some unused item which requires us to fetch the transaction
	 * information from TPD.
	 */
	if (trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
		ZHeapPageHasTPDSlot((PageHeader) page) &&
		PageHasFreeLinePointers((PageHeader) page))
		TPDPageLock(relation, buffer);

	/* No ereport(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	if (!(options & ZHEAP_INSERT_FROZEN))
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
		PageSetUNDO(undorecord, buffer, trans_slot_id, true, fxid,
					urecptr, NULL, 0);
	}

	MarkBufferDirty(buffer);

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		ZHeapWALInfo ins_wal_info;

		ins_wal_info.buffer = buffer;
		ins_wal_info.ztuple = zheaptup;
		ins_wal_info.urecptr = urecptr;
		ins_wal_info.prev_urecptr = prev_urecptr;
		ins_wal_info.undometa = &undometa;
		ins_wal_info.new_trans_slot_id = trans_slot_id;
		ins_wal_info.prior_trans_slot_id = InvalidXactSlotId;
		ins_wal_info.all_visible_cleared = all_visible_cleared;
		ins_wal_info.undorecord = NULL;

		log_zheap_insert(&ins_wal_info, relation, options, skip_undo);
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
		 * Since in ZHeap we have speculative flag in the tuple header only,
		 * copy the speculative flag to the new tuple if required.
		 */
		if (ZHeapTupleHeaderIsSpeculative(zheaptup->t_data))
			tup->t_data->t_infomask |= ZHEAP_SPECULATIVE_INSERT;

		zheap_freetuple(zheaptup);
	}
}

/*
 * simple_zheap_delete - delete a zheap tuple
 *
 * This routine may be used to delete a tuple when concurrent updates of
 * the target tuple are not expected (for example, because we have a lock
 * on the relation associated with the tuple).  Any failure is reported
 * via ereport().
 */
void
simple_zheap_delete(Relation relation, ItemPointer tid, Snapshot snapshot)
{
	TM_Result	result;
	TM_FailureData tmfd;

	result = zheap_delete(relation, tid,
						  GetCurrentCommandId(true), InvalidSnapshot, snapshot,
						  true, /* wait for commit */
						  &tmfd, false /* changingPart */ );
	switch (result)
	{
		case TM_SelfModified:
			/* Tuple was already updated in current command? */
			elog(ERROR, "tuple already updated by self");
			break;

		case TM_Ok:
			/* done successfully */
			break;

		case TM_Updated:
			elog(ERROR, "tuple concurrently updated");
			break;

		case TM_Deleted:
			elog(ERROR, "tuple concurrently deleted");
			break;

		default:
			elog(ERROR, "unrecognized zheap_delete status: %u", result);
			break;
	}
}

/*
 * zheap_delete - delete a tuple
 *
 * The functionality related to heap is quite similar to heap_delete,
 * additionaly this function inserts an undo record and updates the undo
 * pointer in page header or in TPD entry for this page.
 *
 * We do need to clear the visibility map bit for this page if it is not
 * cleared already.
 */
TM_Result
zheap_delete(Relation relation, ItemPointer tid,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
			 TM_FailureData *tmfd, bool changingPart)
{
	TM_Result	result;
	FullTransactionId fxid = GetTopFullTransactionId();
	TransactionId xid = XidFromFullTransactionId(fxid);
	TransactionId oldestXidHavingUndo,
				single_locker_xid;
	SubTransactionId tup_subxid = InvalidSubTransactionId,
				subxid = InvalidSubTransactionId;
	ItemId		lp;
	ZHeapTupleData zheaptup;
	ZHeapPrepareUndoInfo zh_undo_info;
	UnpackedUndoRecord undorecord;
	Page		page;
	BlockNumber blkno;
	OffsetNumber offnum;
	Buffer		buffer;
	Buffer		vmbuffer = InvalidBuffer;
	UndoRecPtr	urecptr,
				prev_urecptr;
	ItemPointerData ctid;
	int			trans_slot_id,
				new_trans_slot_id,
				single_locker_trans_slot;
	uint16		new_infomask,
				temp_infomask;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		all_visible_cleared = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	xl_undolog_meta undometa;
	uint8		vm_status;
	ZHeapTupleTransInfo zinfo;

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

check_tup_satisfies_update:

	/*
	 * If TID is already delete marked due to pruning, then get new ctid, so
	 * that we can delete the new tuple.  We will get new ctid if the tuple
	 * was non-inplace-updated otherwise we will get same TID.
	 */
	if (ItemIdIsDeleted(lp))
	{
		ctid = *tid;
		ZHeapPageGetNewCtid(buffer, &ctid, &zinfo);
		result = TM_Updated;
		goto zheap_tuple_updated;
	}

	zheaptup.t_tableOid = RelationGetRelid(relation);
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);
	zheaptup.t_self = *tid;

	ctid = *tid;

	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(relation, &zheaptup, cid, buffer, &ctid,
									   &zinfo, &tup_subxid, &single_locker_xid,
									   &single_locker_trans_slot, false,
									   snapshot, &in_place_updated_or_locked);

	if (result == TM_Invisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to delete invisible tuple")));
	}
	else if ((result == TM_BeingModified ||
			  ((result == TM_Ok) &&
			   ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask))) &&
			 wait)
	{
		TransactionId xwait;
		int			xwait_trans_slot;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = zinfo.xid;
			xwait_trans_slot = zinfo.trans_slot;
		}

		if (!zheap_delete_wait_helper(relation, buffer, &zheaptup, fxid,
									  xwait, xwait_trans_slot, tup_subxid,
									  lp, zinfo.xid, &have_tuple_lock,
									  &single_locker_xid,
									  &any_multi_locker_member_alive, &result))
			goto check_tup_satisfies_update;
	}
	else if (result == TM_Updated
			 && ZHeapTupleHasMultiLockers(zheaptup.t_data->t_infomask))
	{
		/*
		 * Get the transaction slot and undo record pointer if we are already
		 * in a transaction.
		 */
		trans_slot_id = PageGetTransactionSlotId(relation, buffer, fxid,
												 &prev_urecptr, false, false,
												 NULL);

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 */
		if (trans_slot_id != InvalidXactSlotId &&
			ZCurrentXactHasTupleLockMode(&zheaptup, prev_urecptr,
										 LockTupleExclusive))
			result = TM_Ok;
	}

	if (crosscheck != InvalidSnapshot && result == TM_Ok)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleFetch(relation, buffer, offnum, crosscheck, NULL, NULL))
			result = TM_Updated;
	}

zheap_tuple_updated:
	if (result != TM_Ok)
	{
		Assert(result == TM_SelfModified ||
			   result == TM_Updated ||
			   result == TM_Deleted ||
			   result == TM_BeingModified);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(zheaptup.t_data->t_infomask));

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(zheaptup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&tmfd->ctid);
		else
			tmfd->ctid = ctid;
		tmfd->xmax = zinfo.xid;
		if (result == TM_SelfModified)
			tmfd->cmax = zinfo.cid;
		else
			tmfd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		tmfd->in_place_updated_or_locked = in_place_updated_or_locked;
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
		subxid = GetCurrentSubTransactionId();
		SubXactLockTableInsert(subxid);
	}

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	trans_slot_id = PageReserveTransactionSlot(relation, buffer,
											   PageGetMaxOffsetNumber(page),
											   fxid, &prev_urecptr,
											   &lock_reacquired, false, InvalidBuffer,
											   NULL);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);		/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(trans_slot_id != InvalidXactSlotId);

	/*
	 * It's possible that tuple slot is now marked as frozen. Hence, we
	 * refetch the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	zheaptup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zheaptup.t_len = ItemIdGetLength(lp);

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must
	 * be frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zheaptup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
		zinfo.xid = InvalidTransactionId;
	}

	temp_infomask = zheaptup.t_data->t_infomask;

	/*
	 * If all the members were lockers and are all gone, we can do away with
	 * the MULTI_LOCKERS bit.
	 */
	if (ZHeapTupleHasMultiLockers(temp_infomask) &&
		!any_multi_locker_member_alive)
		temp_infomask &= ~ZHEAP_MULTI_LOCKERS;

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&zheaptup, buffer, zinfo.xid, zinfo.trans_slot,
							 temp_infomask, xid, trans_slot_id,
							 single_locker_xid, LockTupleExclusive, ForUpdate,
							 &new_infomask, &new_trans_slot_id);

	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(new_trans_slot_id == trans_slot_id);

	/*
	 * If the last transaction that has updated the tuple is already too old,
	 * then consider it as frozen which means it is all-visible.  This ensures
	 * that we don't need to store epoch in the undo record to check if the
	 * undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file zheapam_visibility.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
											 pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(zinfo.xid, oldestXidHavingUndo))
		zinfo.xid = FrozenTransactionId;

	CheckForSerializableConflictIn(relation, &(zheaptup.t_self), buffer);

	/* Prepare an undo record for this operation. */
	zh_undo_info.reloid = relation->rd_id;
	zh_undo_info.blkno = blkno;
	zh_undo_info.offnum = offnum;
	zh_undo_info.prev_urecptr = prev_urecptr;
	zh_undo_info.fxid = fxid;
	zh_undo_info.cid = cid;
	zh_undo_info.undo_persistence = UndoPersistenceForRelation(relation);
	urecptr = zheap_prepare_undodelete(&zh_undo_info,
									   &zheaptup,
									   zinfo.xid,
									   zinfo.trans_slot,
									   subxid,
									   &undorecord, NULL, &undometa);

	/* We must have a valid vmbuffer. */
	Assert(BufferIsValid(vmbuffer));
	vm_status = visibilitymap_get_status(relation,
										 BufferGetBlockNumber(buffer), &vmbuffer);

	START_CRIT_SECTION();

	if ((vm_status & VISIBILITYMAP_ALL_VISIBLE) ||
		(vm_status & VISIBILITYMAP_POTENTIAL_ALL_VISIBLE))
	{
		all_visible_cleared = true;
		visibilitymap_clear(relation, BufferGetBlockNumber(buffer),
							vmbuffer, VISIBILITYMAP_VALID_BITS);
	}

	InsertPreparedUndo();
	PageSetUNDO(undorecord, buffer, trans_slot_id, true, fxid,
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

	/* do xlog stuff */
	if (RelationNeedsWAL(relation))
	{
		ZHeapWALInfo del_wal_info;

		del_wal_info.buffer = buffer;
		del_wal_info.ztuple = &zheaptup;
		del_wal_info.urecptr = urecptr;
		del_wal_info.prev_urecptr = prev_urecptr;
		del_wal_info.undometa = &undometa;
		del_wal_info.new_trans_slot_id = trans_slot_id;
		del_wal_info.prior_trans_slot_id = zinfo.trans_slot;
		del_wal_info.all_visible_cleared = all_visible_cleared;
		del_wal_info.undorecord = &undorecord;

		log_zheap_delete(&del_wal_info, changingPart, subxid, zinfo.xid);
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

	/* now we can release the buffer */
	ReleaseBuffer(buffer);
	UnlockReleaseTPDBuffers();

	/*
	 * Release the lmgr tuple lock, if we had it.
	 */
	if (have_tuple_lock)
		UnlockTupleTuplock(relation, &(zheaptup.t_self), LockTupleExclusive);

	pgstat_count_heap_delete(relation);

	return TM_Ok;
}

/*
 * zheap_delete_wait_helper
 *
 * This is a helper function that encapsulates some of the logic that
 * zheap_delete needs to wait for concurrent transactions.
 *
 * XXX. Can we name this function better?  What exactly is the remit of this
 * function vs. other parts of zheap_delete that also wait for stuff?
 *
 * XXX. The abstraction that this function provides is quite leaky -- it
 * should probably take fewer parameters.
 *
 * XXX. RefetchAndCheckTupleStatus frobs zheaptup. Yuck!
 *
 * XXX. zheap_update_wait_helper is very similar to this.
 */
static bool
zheap_delete_wait_helper(Relation relation, Buffer buffer, ZHeapTuple zheaptup,
						 FullTransactionId fxid, TransactionId xwait,
						 int xwait_trans_slot, TransactionId xwait_subxid,
						 ItemId lp,
						 TransactionId tup_xid, bool *have_tuple_lock,
						 TransactionId *single_locker_xid,
						 bool *any_multi_locker_member_alive,
						 TM_Result *result)
{
	List	   *mlmembers = NIL;
	uint16		infomask;
	bool		can_continue = false;
	bool		lock_reacquired = false;

	infomask = zheaptup->t_data->t_infomask;

	/*
	 * Sleep until concurrent transaction ends -- except when there's a single
	 * locker and it's our own transaction.  Note we don't care which lock
	 * mode the locker has, because we need the strongest one.
	 *
	 * Before sleeping, we need to acquire tuple lock to establish our
	 * priority for the tuple (see zheap_lock_tuple).  LockTuple will release
	 * us when we are next-in-line for the tuple.
	 *
	 * If we are forced to "start over" below, we keep the tuple lock; this
	 * arranges that we stay at the head of the line while rechecking tuple
	 * state.
	 */
	if (ZHeapTupleHasMultiLockers(infomask))
	{
		LockTupleMode old_lock_mode;
		TransactionId update_xact;
		bool		upd_xact_aborted = false;
		int			trans_slot_id;
		UndoRecPtr	prev_urecptr;

		/*
		 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
		 * transaction has already locked the tuple for update because of
		 * multilocker flag. In that case, we've to check whether the current
		 * transaction has already locked the tuple for update.
		 */

		/*
		 * Get the transaction slot and undo record pointer if we are already
		 * in a transaction.
		 */
		trans_slot_id = PageGetTransactionSlotId(relation, buffer, fxid,
												 &prev_urecptr, false, false,
												 NULL);

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 */
		if (trans_slot_id != InvalidXactSlotId &&
			ZCurrentXactHasTupleLockMode(zheaptup, prev_urecptr,
										 LockTupleExclusive))
		{
			*result = TM_Ok;
			return true;
		}

		old_lock_mode = get_old_lock_mode(infomask);

		/*
		 * For aborted updates, we must allow to reverify the tuple in case
		 * it's values got changed.  See the similar handling in zheap_update.
		 */
		if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup->t_data->t_infomask))
			update_xact = ZHeapTupleGetTransXID(zheaptup, buffer, false);
		else
			update_xact = InvalidTransactionId;

		if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
								HWLOCKMODE_from_locktupmode(LockTupleExclusive)))
		{
			/*
			 * There is a potential conflict.  It is quite possible that by
			 * this time the locker has already been committed. So we need to
			 * check for conflict with all the possible lockers and wait for
			 * each of them after releasing a buffer lock and acquiring a lock
			 * on a tuple.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			mlmembers = ZGetMultiLockMembers(relation, zheaptup, buffer,
											 true);

			/*
			 * If there is no multi-lock members apart from the current
			 * transaction then no need for tuplock, just go ahead.
			 */
			if (mlmembers != NIL)
			{
				heap_acquire_tuplock(relation, &(zheaptup->t_self), LockTupleExclusive,
									 LockWaitBlock, have_tuple_lock);
				ZMultiLockMembersWait(relation, mlmembers, zheaptup, buffer,
									  update_xact, LockTupleExclusive, false,
									  XLTW_Delete, NULL, &upd_xact_aborted);
			}
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * If the aborted xact is for update, then we need to reverify the
			 * tuple.
			 */
			if (upd_xact_aborted)
				return false;
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
		 * Wait for regular transaction to end; but first, acquire tuple lock.
		 */
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		heap_acquire_tuplock(relation, &(zheaptup->t_self), LockTupleExclusive,
							 LockWaitBlock, have_tuple_lock);
		if (xwait_subxid != InvalidSubTransactionId)
			SubXactLockTableWait(xwait, xwait_subxid, relation,
								 &zheaptup->t_self, XLTW_Delete);
		else
			XactLockTableWait(xwait, relation, &zheaptup->t_self,
							  XLTW_Delete);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		lock_reacquired = true;
	}

	if (lock_reacquired)
	{
		/*
		 * By the time, we require the lock on buffer, some other xact could
		 * have updated this tuple.  We need take care of the cases when page
		 * is pruned after we release the buffer lock.  If TID is already
		 * delete marked due to pruning, then tell caller to loop and update
		 * the new tuple.
		 *
		 * We also need to ensure that no new lockers have been added in the
		 * meantime, if there is any new locker, then start again.
		 */
		if (ItemIdIsDeleted(lp))
			return false;

		if (ZHeapTupleHasMultiLockers(infomask))
		{
			List	   *new_mlmembers;

			new_mlmembers = ZGetMultiLockMembers(relation, zheaptup,
												 buffer, false);

			/*
			 * Ensure, no new lockers have been added, if so, then start
			 * again.
			 */
			if (!ZMultiLockMembersSame(mlmembers, new_mlmembers))
			{
				list_free_deep(mlmembers);
				list_free_deep(new_mlmembers);
				return false;
			}

			*any_multi_locker_member_alive =
				ZIsAnyMultiLockMemberRunning(new_mlmembers, zheaptup,
											 buffer);
			list_free_deep(mlmembers);
			list_free_deep(new_mlmembers);
		}

		/*
		 * xwait is done, but if xwait had just locked the tuple then some
		 * other xact could update/lock this tuple before we get to this
		 * point.  Check for xid change, and start over if so.  We need to do
		 * some special handling for lockers because their xid is never stored
		 * on the tuples.  If there was a single locker on the tuple and that
		 * locker is gone and some new locker has locked the tuple, we won't
		 * be able to identify that by infomask/xid on the tuple, rather we
		 * need to fetch the locker xid.
		 */
		if (!RefetchAndCheckTupleStatus(relation, buffer, infomask,
										tup_xid,
										single_locker_xid, NULL, zheaptup))
			return false;

		/* Aborts of multi-lockers are already dealt above. */
		if (!ZHeapTupleHasMultiLockers(infomask))
		{
			bool		has_update = false;
			bool		isCommitted;

			if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup->t_data->t_infomask))
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
											xwait,
											NULL);

			if (!isCommitted)
			{
				/*
				 * For aborted updates, we must allow to reverify the tuple in
				 * case it's values got changed.
				 */
				if (has_update)
					return false;

				/*
				 * While executing the undo action we have released the buffer
				 * lock.  So if the tuple infomask got changed while applying
				 * the undo action then we must reverify the tuple.
				 */
				if (!RefetchAndCheckTupleStatus(relation, buffer, infomask,
												tup_xid,
												single_locker_xid,
												NULL, zheaptup))
					return false;
			}

			if (!has_update)
				can_continue = true;
		}
	}
	else
	{
		/*
		 * We can proceed with the delete, when there's a single locker and
		 * it's our own transaction.
		 */
		if (ZHEAP_XID_IS_LOCKED_ONLY(zheaptup->t_data->t_infomask))
			can_continue = true;
	}

	/*
	 * We may overwrite if previous xid is aborted or committed, but only
	 * locked the tuple without updating it. ZBORKED: This, and many other
	 * places, needs to return TM_Deleted if appropriate
	 */
	if (*result != TM_Ok)
		*result = can_continue ? TM_Ok : TM_Updated;
	return true;
}

/*
 * zheap_update - update a tuple
 *
 * This function either updates the tuple in-place or it deletes the old
 * tuple and new tuple for non-in-place updates.  Additionally this function
 * inserts an undo record and updates the undo pointer in page header or in
 * TPD entry for this page.
 *
 * We do need to clear the visibility map bit for this page if it is not
 * cleared already.
 *
 * For input and output values, see heap_update.
 */
TM_Result
zheap_update(Relation relation, ItemPointer otid, ZHeapTuple newtup,
			 CommandId cid, Snapshot crosscheck, Snapshot snapshot, bool wait,
			 TM_FailureData *tmfd, LockTupleMode *lockmode)
{
	TM_Result	result;
	FullTransactionId fxid = GetTopFullTransactionId();
	TransactionId xid = XidFromFullTransactionId(fxid);
	TransactionId save_tup_xid,
				oldestXidHavingUndo,
				single_locker_xid;
	SubTransactionId tup_subxid = InvalidSubTransactionId;
	Bitmapset  *inplace_upd_attrs = NULL;
	Bitmapset  *key_attrs = NULL;
	Bitmapset  *interesting_attrs = NULL;
	Bitmapset  *modified_attrs = NULL;
	ItemId		lp;
	ZHeapTupleData oldtup;
	ZHeapTuple	zheaptup;
	UndoRecPtr	urecptr,
				prev_urecptr,
				new_prev_urecptr;
	UndoRecPtr	new_urecptr = InvalidUndoRecPtr;
	UnpackedUndoRecord undorecord,
				new_undorecord;
	Page		page;
	BlockNumber block;
	ItemPointerData ctid;
	Buffer		buffer,
				newbuf,
				vmbuffer = InvalidBuffer,
				vmbuffer_new = InvalidBuffer;
	Size		newtupsize,
				oldtupsize,
				pagefree;
	int			oldtup_new_trans_slot,
				newtup_trans_slot,
				result_trans_slot_id,
				single_locker_trans_slot;
	uint16		old_infomask;
	uint16		new_infomask,
				temp_infomask;
	uint16		infomask_old_tuple = 0;
	uint16		infomask_new_tuple = 0;
	OffsetNumber old_offnum,
				max_offset;
	bool		all_visible_cleared = false;
	bool		new_all_visible_cleared = false;
	bool		have_tuple_lock = false;
	bool		is_index_updated = false;
	bool		use_inplace_update;
	bool		in_place_updated_or_locked = false;
	bool		key_intact = false;
	bool		checked_lockers = false;
	bool		locker_remains = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	bool		need_toast;
	bool		hasSubXactLock = false;
	xl_undolog_meta undometa;
	uint8		vm_status;
	uint8		vm_status_new = 0;
	bool		slot_reused_or_TPD_slot = false;
	ZHeapTupleTransInfo zinfo;

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
	inplace_upd_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_ALL);
	key_attrs = RelationGetIndexAttrBitmap(relation, INDEX_ATTR_BITMAP_KEY);

	block = ItemPointerGetBlockNumber(otid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);

	interesting_attrs = NULL;
	interesting_attrs = bms_add_members(interesting_attrs, inplace_upd_attrs);
	interesting_attrs = bms_add_members(interesting_attrs, key_attrs);

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
		ZHeapPageGetNewCtid(buffer, &ctid, &zinfo);
		result = TM_Updated;

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

	/* Determine columns modified by the update. */
	modified_attrs = ZHeapDetermineModifiedColumns(relation, interesting_attrs,
												   &oldtup, newtup);

	/*
	 * Similar to heap, if we're not updating any "key" column, we can grab a
	 * weaker lock type.  See heap_update.
	 */
	key_intact = !bms_overlap(modified_attrs, key_attrs);
	*lockmode = key_intact ? LockTupleNoKeyExclusive : LockTupleExclusive;

	/*
	 * ctid needs to be fetched from undo chain.  You might think that it will
	 * be always same as the passed in ctid as the old tuple is already
	 * visible out snapshot.  However, it is quite possible that after
	 * checking the visibility of old tuple, some concurrent session would
	 * have performed non in-place update and in such a case we need can only
	 * get it via undo.
	 */
	ctid = *otid;

check_tup_satisfies_update:
	checked_lockers = false;
	locker_remains = false;
	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(relation, &oldtup, cid, buffer, &ctid,
									   &zinfo, &tup_subxid,
									   &single_locker_xid,
									   &single_locker_trans_slot, false,
									   snapshot, &in_place_updated_or_locked);

	if (result == TM_Invisible)
	{
		UnlockReleaseBuffer(buffer);
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("attempted to update invisible tuple")));
	}
	else if ((result == TM_BeingModified ||
			  ((result == TM_Ok) &&
			   ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask))) &&
			 wait)
	{
		TransactionId xwait;
		int			xwait_trans_slot;
		bool		item_is_deleted = false;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = zinfo.xid;
			xwait_trans_slot = zinfo.trans_slot;
		}

		if (!zheap_update_wait_helper(relation, buffer, &oldtup, fxid,
									  xwait, xwait_trans_slot, tup_subxid,
									  *lockmode, key_intact, lp, zinfo.xid,
									  &have_tuple_lock, &single_locker_xid,
									  &any_multi_locker_member_alive,
									  &checked_lockers, &locker_remains,
									  &result, &item_is_deleted))
		{
			if (item_is_deleted)
			{
				ctid = *otid;
				ZHeapPageGetNewCtid(buffer, &ctid, &zinfo);
				result = TM_Updated;
				goto zheap_tuple_updated;
			}
			goto check_tup_satisfies_update;
		}
	}
	else if (result == TM_Ok)
	{
		/*
		 * There is no active locker on the tuple, so we avoid grabbing the
		 * lock on new tuple.
		 */
		checked_lockers = true;
		locker_remains = false;
	}
	else if (result == TM_Updated &&
			 ZHeapTupleHasMultiLockers(oldtup.t_data->t_infomask))
	{
		/*
		 * If a tuple is updated and is visible to our snapshot, we allow to
		 * update it;  Else, we return TM_Updated and visit EvalPlanQual path
		 * to check whether the quals still match.  In that path, we also lock
		 * the tuple so that nobody can update it before us.
		 *
		 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
		 * transaction has already locked the tuple for update because of
		 * multilocker flag. In that case, we've to check whether the current
		 * transaction has already locked the tuple for update.
		 */

		/*
		 * Get the transaction slot and undo record pointer if we are already
		 * in a transaction.
		 */
		oldtup_new_trans_slot = PageGetTransactionSlotId(relation, buffer, fxid,
														 &prev_urecptr, false, false,
														 NULL);

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 */
		if (oldtup_new_trans_slot != InvalidXactSlotId &&
			ZCurrentXactHasTupleLockMode(&oldtup, prev_urecptr,
										 *lockmode))
		{
			result = TM_Ok;
			checked_lockers = true;
			locker_remains = false;
		}
	}

	if (crosscheck != InvalidSnapshot && result == TM_Ok)
	{
		/* Perform additional check for transaction-snapshot mode RI updates */
		if (!ZHeapTupleFetch(relation, buffer, old_offnum, crosscheck, NULL,
							 NULL))
			result = TM_Updated;
	}

zheap_tuple_updated:
	if (result != TM_Ok)
	{
		Assert(result == TM_SelfModified ||
			   result == TM_Updated ||
			   result == TM_Deleted ||
			   result == TM_BeingModified);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(oldtup.t_data->t_infomask));

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(oldtup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&tmfd->ctid);
		else
			tmfd->ctid = ctid;
		tmfd->xmax = zinfo.xid;
		if (result == TM_SelfModified)
			tmfd->cmax = zinfo.cid;
		else
			tmfd->cmax = InvalidCommandId;
		UnlockReleaseBuffer(buffer);
		tmfd->in_place_updated_or_locked = in_place_updated_or_locked;
		if (have_tuple_lock)
			UnlockTupleTuplock(relation, &(oldtup.t_self), *lockmode);
		if (vmbuffer != InvalidBuffer)
			ReleaseBuffer(vmbuffer);
		bms_free(inplace_upd_attrs);
		bms_free(key_attrs);
		return result;
	}

	/* the new tuple is ready, except for this: */
	newtup->t_tableOid = RelationGetRelid(relation);

	is_index_updated = bms_overlap(modified_attrs, inplace_upd_attrs);

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
	 * An in-place update is only possible if there are no index column
	 * updates and no attribute that have been moved to an external TOAST
	 * table.  If the new tuple is no larger than the old one, that's enough;
	 * otherwise, we also need sufficient free space to be available in the
	 * page.
	 */
	if (is_index_updated || need_toast)
		use_inplace_update = false;
	else if (newtupsize <= oldtupsize)
		use_inplace_update = true;
	else
	{
		/* Pass delta space required to accommodate the new tuple. */
		use_inplace_update =
			zheap_page_prune_opt(relation, buffer, old_offnum,
								 newtupsize - oldtupsize);

		/* The page might have been modified, so refresh t_data */
		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
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

	max_offset = PageGetMaxOffsetNumber(BufferGetPage(buffer));
	pagefree = PageGetZHeapFreeSpace(page);

	/*
	 * In case of the non in-place update we also need to reserve a map for
	 * the new tuple.
	 */
	if (!use_inplace_update)
		max_offset += 1;

	/*
	 * The transaction information of tuple needs to be set in transaction
	 * slot, so needs to reserve the slot before proceeding with the actual
	 * operation.  It will be costly to wait for getting the slot, but we do
	 * that by releasing the buffer lock.
	 */
	oldtup_new_trans_slot = PageReserveTransactionSlot(relation, buffer, max_offset,
													   fxid, &prev_urecptr,
													   &lock_reacquired, false, InvalidBuffer,
													   &slot_reused_or_TPD_slot);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (oldtup_new_trans_slot == InvalidXactSlotId)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);		/* 10 ms */
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
			ZHeapPageGetNewCtid(buffer, &ctid, &zinfo);
			result = TM_Updated;
			goto zheap_tuple_updated;
		}

		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		oldtup.t_len = ItemIdGetLength(lp);

		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before adding tuple to page */
	Assert(oldtup_new_trans_slot != InvalidXactSlotId);

	/*
	 * It's possible that tuple slot is now marked as frozen. Hence, we
	 * refetch the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	oldtup.t_len = ItemIdGetLength(lp);

	/*
	 * Using a transaction slot of transaction that is still not all-visible
	 * will lead to undo access during tuple visibility checks and that sucks
	 * the performance.  To avoid accessing undo, we perform non-inplace
	 * updates so as to distribute the tuple across pages so that we don't
	 * face scarcity of transaction slots on the page.  However, we must have
	 * a hard limit for this optimization, else the number of blocks will
	 * increase without any bound.
	 *
	 * Note that the similar optimization applies when we use TPD slots as
	 * that will also lead to another hop during visibility checks.
	 */
	if (slot_reused_or_TPD_slot)
	{
		BlockNumber nblocks = RelationGetNumberOfBlocks(relation);

		if (nblocks <= NUM_BLOCKS_FOR_NON_INPLACE_UPDATES)
			use_inplace_update = false;
		else
			slot_reused_or_TPD_slot = false;
	}

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must
	 * be frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (oldtup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
		zinfo.xid = InvalidTransactionId;
	}

	/*
	 * Save the xid that has updated the tuple to compute infomask for tuple.
	 */
	save_tup_xid = zinfo.xid;

	/*
	 * If the last transaction that has updated the tuple is already too old,
	 * then consider it as frozen which means it is all-visible.  This ensures
	 * that we don't need to store epoch in the undo record to check if the
	 * undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file zheapam_visibility.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
											 pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(zinfo.xid, oldestXidHavingUndo))
		zinfo.xid = FrozenTransactionId;

	/*
	 * updated tuple doesn't fit on current page or the toaster needs to be
	 * activated or transaction slot has been reused.
	 */
	Assert(!slot_reused_or_TPD_slot || !use_inplace_update);
	if (slot_reused_or_TPD_slot ||
		(!use_inplace_update && newtupsize > pagefree) ||
		need_toast)
	{
		uint16		lock_old_infomask;
		BlockNumber oldblk,
					newblk;

		/*
		 * To prevent concurrent sessions from updating the tuple, we have to
		 * temporarily mark it locked, while we release the lock.
		 */
		undorecord.uur_rmid = RM_ZHEAP_ID;
		undorecord.uur_info = 0;
		undorecord.uur_reloid = relation->rd_id;
		undorecord.uur_prevxid = zinfo.xid;
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
		 * the slot belongs to TPD entry.  We can always get the current
		 * tuple's transaction slot number by referring offset->slot map in
		 * TPD entry, however that won't be true for tuple in undo.
		 */
		if (zinfo.trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &zinfo.trans_slot,
								   sizeof(zinfo.trans_slot));
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
									InvalidFullTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									&undometa);

		temp_infomask = oldtup.t_data->t_infomask;

		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */
		if (ZHeapTupleHasMultiLockers(temp_infomask) &&
			!any_multi_locker_member_alive)
			temp_infomask &= ~ZHEAP_MULTI_LOCKERS;

		/* Compute the new xid and infomask to store into the tuple. */
		compute_new_xid_infomask(&oldtup, buffer, save_tup_xid,
								 zinfo.trans_slot, temp_infomask,
								 xid, oldtup_new_trans_slot, single_locker_xid,
								 *lockmode, LockForUpdate, &lock_old_infomask,
								 &result_trans_slot_id);

		if (ZHeapTupleHasMultiLockers(lock_old_infomask))
			undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
		else
			undorecord.uur_type = UNDO_XID_LOCK_FOR_UPDATE;

		START_CRIT_SECTION();

		InsertPreparedUndo();

		/*
		 * For lockers, we only set the slot on tuple when the lock mode is
		 * LockForUpdate and the tuple doesn't have multilocker flag.  In that
		 * case, pass set_tpd_map_slot as true, false otherwise.  In this case
		 * the lockmode is always LockForUpdate.
		 */
		PageSetUNDO(undorecord, buffer, oldtup_new_trans_slot,
					ZHeapTupleHasMultiLockers(lock_old_infomask) ? false : true,
					fxid, urecptr, NULL, 0);

		ZHeapTupleHeaderSetXactSlot(oldtup.t_data, result_trans_slot_id);

		oldtup.t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
		oldtup.t_data->t_infomask |= lock_old_infomask;

		/* Set prev_urecptr to the latest undo record in the slot. */
		prev_urecptr = urecptr;

		MarkBufferDirty(buffer);

		/* do xlog stuff */
		if (RelationNeedsWAL(relation))
		{
			ZHeapWALInfo lock_wal_info;

			lock_wal_info.buffer = buffer;
			lock_wal_info.ztuple = &oldtup;
			lock_wal_info.urecptr = urecptr;
			lock_wal_info.prev_urecptr = undorecord.uur_blkprev;
			lock_wal_info.undometa = &undometa;
			lock_wal_info.new_trans_slot_id = result_trans_slot_id;
			lock_wal_info.prior_trans_slot_id = zinfo.trans_slot;
			lock_wal_info.all_visible_cleared = false;
			lock_wal_info.undorecord = &undorecord;

			log_zheap_lock_tuple(&lock_wal_info, zinfo.xid,
								 oldtup_new_trans_slot, hasSubXactLock, *lockmode);

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
			zheaptup = ztoast_insert_or_update(relation, newtup, &oldtup, 0,
											   0);
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

		/*
		 * If we have reused the transaction slot, we must use new page to
		 * perform non-inplace update in a separate page so as to reduce
		 * contention on transaction slots.
		 */
		if (slot_reused_or_TPD_slot || newtupsize > pagefree)
		{
			Assert(!use_inplace_update);
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
			newtup_trans_slot = PageReserveTransactionSlot(relation,
														   newbuf,
														   max_offset + 1,
														   fxid,
														   &new_prev_urecptr,
														   &lock_reacquired,
														   false,
														   true,
														   NULL);

			/*
			 * We must get a valid slot and wouldn't have reacquired the
			 * buffer lock as we already have a reserved slot.
			 */
			Assert(!lock_reacquired);
			Assert(newtup_trans_slot != InvalidXactSlotId);

			/*
			 * We should get the same slot what we reserved previously because
			 * our transaction information should already be there.  But,
			 * there is possibility that our slot might have moved to the TPD
			 * in such case we should get previous slot_no + 1.
			 */
			Assert((newtup_trans_slot == oldtup_new_trans_slot) ||
				   (ZHeapPageHasTPDSlot((PageHeader) page) &&
					newtup_trans_slot == oldtup_new_trans_slot + 1));

			oldtup_new_trans_slot = newtup_trans_slot;
		}
		else
			MultiPageReserveTransSlot(relation, buffer, newbuf,
									  old_offnum, max_offset, fxid,
									  &prev_urecptr, &new_prev_urecptr,
									  &oldtup_new_trans_slot, &newtup_trans_slot,
									  &lock_reacquired);

		if (lock_reacquired || (newtup_trans_slot == InvalidXactSlotId))
		{
			/*
			 * If non in-place update is happening on two different buffers,
			 * then release the new buffer, and release the lock on old
			 * buffer. Else, only release the lock on old buffer.
			 */
			if (buffer != newbuf)
			{
				/*
				 * If we have reacquired the lock while reserving a slot, then
				 * we would have already released lock on the old buffer.  See
				 * other_buf handling in PageFreezeTransSlots.
				 */
				if (!lock_reacquired)
					LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
				else
				{
					BufferDesc *buf_hdr PG_USED_FOR_ASSERTS_ONLY;

					/*
					 * Old buffer should be valid and should not locked
					 * because we already released lock on the old buffer in
					 * PageFreezeTransSlots.
					 */
					Assert(BufferIsValid(buffer));
					buf_hdr = GetBufferDescriptor(buffer - 1);
					Assert(!(LWLockHeldByMeInMode(BufferDescriptorGetContentLock(buf_hdr),
												  LW_EXCLUSIVE)));
				}

				/* Release the new buffer. */
				UnlockReleaseBuffer(newbuf);
			}
			else
				LockBuffer(buffer, BUFFER_LOCK_UNLOCK);

			/* Release all the TPD buffer. */
			UnlockReleaseTPDBuffers();

			if (newtup_trans_slot == InvalidXactSlotId)
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
		 * is no harm in refreshing it for the sake of consistency of code.
		 */
		oldtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		oldtup.t_len = ItemIdGetLength(lp);

		/*
		 * If the computed infomask for the updated tuple doesn't contain a
		 * multilocker flag, we must have stored current transaction slot on
		 * the tuple (due to LockForUpdate). In that case, we should update
		 * the tuple xid as well.
		 *
		 * Also note that, there is possibility that our slot might have moved
		 * to the TPD; in such case we should get previous slot_no + 1.
		 */
		if (!ZHeapTupleHasMultiLockers(lock_old_infomask))
		{
			Assert((result_trans_slot_id == oldtup_new_trans_slot) ||
				   (ZHeapPageHasTPDSlot((PageHeader) page) &&
					result_trans_slot_id + 1 == oldtup_new_trans_slot));
			zinfo.trans_slot = oldtup_new_trans_slot;
			zinfo.xid = xid;
			save_tup_xid = zinfo.xid;
		}
	}
	else
	{
		/* No TOAST work needed, and it'll fit on same page */
		newbuf = buffer;
		newtup_trans_slot = oldtup_new_trans_slot;
		zheaptup = newtup;
	}

	CheckForSerializableConflictIn(relation, &(oldtup.t_self), buffer);

	/*
	 * Prepare an undo record for old tuple.  We need to separately store the
	 * latest transaction id that has changed the tuple to ensure that we
	 * don't try to process the tuple in undo chain that is already discarded.
	 * See GetTupleFromUndo.
	 */
	undorecord.uur_rmid = RM_ZHEAP_ID;
	undorecord.uur_info = 0;
	undorecord.uur_reloid = relation->rd_id;
	undorecord.uur_prevxid = zinfo.xid;
	undorecord.uur_xid = xid;
	undorecord.uur_cid = cid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_blkprev = prev_urecptr;
	undorecord.uur_block = ItemPointerGetBlockNumber(&(oldtup.t_self));
	undorecord.uur_offset = ItemPointerGetOffsetNumber(&(oldtup.t_self));
	undorecord.uur_payload.len = 0;

	initStringInfo(&undorecord.uur_tuple);

	/*
	 * Copy the entire old tuple into the undo record. We need this to
	 * reconstruct the old tuple if current tuple is not visible to some other
	 * transaction.  We choose to write the complete tuple in undo record for
	 * update operation so that we can reuse the space of old tuples for
	 * non-inplace-updates after the transaction performing the operation
	 * commits.
	 */
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) oldtup.t_data,
						   oldtup.t_len);

	if (use_inplace_update)
	{
		bool		hasPayload = false;

		undorecord.uur_type = UNDO_INPLACE_UPDATE;

		/*
		 * Store the transaction slot number for undo tuple in undo record, if
		 * the slot belongs to TPD entry.  We can always get the current
		 * tuple's transaction slot number by referring offset->slot map in
		 * TPD entry, however that won't be true for tuple in undo.
		 */
		if (zinfo.trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			initStringInfo(&undorecord.uur_payload);
			appendBinaryStringInfo(&undorecord.uur_payload,
								   (char *) &zinfo.trans_slot,
								   sizeof(zinfo.trans_slot));
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
									InvalidFullTransactionId,
									UndoPersistenceForRelation(relation),
									NULL,
									&undometa);
	}
	else
	{
		Size		payload_len;
		UnpackedUndoRecord undorec[2];

		undorecord.uur_type = UNDO_UPDATE;

		/*
		 * we need to initialize the length of payload before actually knowing
		 * the value to ensure that the required space is reserved in undo.
		 */
		payload_len = sizeof(ItemPointerData);
		if (zinfo.trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
		{
			undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			payload_len += sizeof(zinfo.trans_slot);
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
		new_undorecord.uur_rmid = RM_ZHEAP_ID;
		new_undorecord.uur_type = UNDO_INSERT;
		new_undorecord.uur_info = 0;
		new_undorecord.uur_reloid = relation->rd_id;
		new_undorecord.uur_prevxid = xid;
		new_undorecord.uur_xid = xid;
		new_undorecord.uur_cid = cid;
		new_undorecord.uur_fork = MAIN_FORKNUM;
		new_undorecord.uur_block = BufferGetBlockNumber(newbuf);
		new_undorecord.uur_payload.len = 0;
		new_undorecord.uur_tuple.len = 0;

		if (newtup_trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
		{
			new_undorecord.uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
			initStringInfo(&new_undorecord.uur_payload);
			appendBinaryStringInfo(&new_undorecord.uur_payload,
								   (char *) &newtup_trans_slot,
								   sizeof(newtup_trans_slot));
		}
		else
			new_undorecord.uur_payload.len = 0;

		undorec[0] = undorecord;
		undorec[1] = new_undorecord;
		UndoSetPrepareSize(undorec, 2, InvalidFullTransactionId,
						   UndoPersistenceForRelation(relation), NULL, &undometa);

		/* copy updated record (uur_info might got updated ) */
		undorecord = undorec[0];
		new_undorecord = undorec[1];

		urecptr = PrepareUndoInsert(&undorecord,
									InvalidFullTransactionId,
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
										InvalidFullTransactionId,
										UndoPersistenceForRelation(relation),
										NULL,
										NULL);

		/* Check and lock the TPD page before starting critical section. */
		CheckAndLockTPDPage(relation, newtup_trans_slot, oldtup_new_trans_slot,
							newbuf, buffer);

	}

	temp_infomask = oldtup.t_data->t_infomask;

	/*
	 * We can't rely on any_multi_locker_member_alive to clear the multi
	 * locker bit, if the lock on the buffer is released in between.
	 */
	if (buffer == newbuf)
	{
		/*
		 * If all the members were lockers and are all gone, we can do away
		 * with the MULTI_LOCKERS bit.
		 */
		if (ZHeapTupleHasMultiLockers(temp_infomask) &&
			!any_multi_locker_member_alive)
			temp_infomask &= ~ZHEAP_MULTI_LOCKERS;
	}

	/* Compute the new xid and infomask to store into the tuple. */
	compute_new_xid_infomask(&oldtup, buffer, save_tup_xid, zinfo.trans_slot,
							 temp_infomask, xid, oldtup_new_trans_slot,
							 single_locker_xid, *lockmode, ForUpdate,
							 &old_infomask, &result_trans_slot_id);

	/*
	 * There must not be any stronger locker than the current operation,
	 * otherwise it would have waited for it to finish.
	 */
	Assert(result_trans_slot_id == oldtup_new_trans_slot);

	/*
	 * Propagate the lockers information to the new tuple.  Since we're doing
	 * an update, the only possibility is that the lockers had FOR KEY SHARE
	 * lock.  For in-place updates, we are not creating any new version, so we
	 * don't need to propagate anything.
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
	 * visibilitymap is reset already, hence, need not to clear anything.
	 */
	if (newbuf != buffer && BufferIsValid(vmbuffer_new))
		vm_status_new = visibilitymap_get_status(relation,
												 BufferGetBlockNumber(newbuf), &vmbuffer_new);

	/*
	 * Make sure we have space to register regular pages, a couple of TPD
	 * pages and undo log pages, before we enter the critical section. TODO:
	 * what is the maximum number of pages we could touch?
	 */
	XLogEnsureRecordSpace(8, 0);

	START_CRIT_SECTION();

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
	ZHeapTupleHeaderSetXactSlot(zheaptup->t_data, newtup_trans_slot);
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
		if (zinfo.trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
			appendBinaryStringInfoNoExtend(&undorecord.uur_payload,
										   (char *) &zinfo.trans_slot,
										   sizeof(zinfo.trans_slot));
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
		PageSetUNDO(undorecord, buffer, oldtup_new_trans_slot, true,
					fxid, urecptr, NULL, 0);
	else
	{
		if (newbuf == buffer)
		{
			OffsetNumber usedoff[2];

			usedoff[0] = undorecord.uur_offset;
			usedoff[1] = new_undorecord.uur_offset;

			PageSetUNDO(undorecord, buffer, oldtup_new_trans_slot, true,
						fxid, new_urecptr, usedoff, 2);
		}
		else
		{
			/* set transaction slot information for old page */
			PageSetUNDO(undorecord, buffer, oldtup_new_trans_slot, true,
						fxid, urecptr, NULL, 0);
			/* set transaction slot information for new page */
			PageSetUNDO(new_undorecord,
						newbuf,
						newtup_trans_slot,
						true,
						fxid,
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
		ZHeapWALInfo oldup_wal_info,
					newup_wal_info;

		/*
		 * For logical decoding we need combocids to properly decode the
		 * catalog.
		 */
		if (RelationIsAccessibleInLogicalDecoding(relation))
		{
			/*
			 * Fixme: This won't work as it needs to access cmin/cmax which we
			 * probably needs to retrieve from UNDO.
			 */
			/*
			 * log_heap_new_cid(relation, &oldtup); log_heap_new_cid(relation,
			 * heaptup);
			 */
		}
		oldup_wal_info.buffer = buffer;
		oldup_wal_info.ztuple = &oldtup;
		oldup_wal_info.urecptr = urecptr;
		oldup_wal_info.prev_urecptr = InvalidUndoRecPtr;
		oldup_wal_info.undometa = NULL;
		oldup_wal_info.new_trans_slot_id = oldtup_new_trans_slot;
		oldup_wal_info.prior_trans_slot_id = zinfo.trans_slot;
		oldup_wal_info.all_visible_cleared = all_visible_cleared;
		oldup_wal_info.undorecord = &undorecord;

		newup_wal_info.buffer = newbuf;
		newup_wal_info.ztuple = zheaptup;
		newup_wal_info.urecptr = new_urecptr;
		newup_wal_info.undometa = &undometa;
		newup_wal_info.new_trans_slot_id = newtup_trans_slot;
		newup_wal_info.all_visible_cleared = new_all_visible_cleared;
		newup_wal_info.undorecord = &new_undorecord;
		newup_wal_info.prev_urecptr = InvalidUndoRecPtr;
		newup_wal_info.prior_trans_slot_id = InvalidXactSlotId;

		log_zheap_update(&oldup_wal_info, &newup_wal_info,
						 use_inplace_update);
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
	{
		/*
		 * If we've performed non-inplace update because of
		 * slot_reused_or_TPD_slot optimization, we shouldn't increase the
		 * update stats else, it'll trigger autovacuum unnecessarily. But, we
		 * want to autoanalyze the table periodically.  Hence, we increase the
		 * insert count.
		 */
		if (!slot_reused_or_TPD_slot)
			pgstat_count_heap_update(relation, false);
		else
			pgstat_count_heap_insert(relation, 1);
	}
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
	bms_free(interesting_attrs);
	bms_free(modified_attrs);

	bms_free(key_attrs);
	return TM_Ok;
}

/*
 * zheap_update_wait_helper
 *
 * This is a helper function that encapsulates some of the logic that
 * zheap_update needs to wait for concurrent transactions.
 *
 * XXX. This is very similar to zheap_delete_wait_helper, q.v.
 */
static bool
zheap_update_wait_helper(Relation relation,
						 Buffer buffer, ZHeapTuple zheaptup,
						 FullTransactionId fxid, TransactionId xwait,
						 int xwait_trans_slot, TransactionId xwait_subxid,
						 LockTupleMode lockmode, bool key_intact,
						 ItemId lp,
						 TransactionId tup_xid, bool *have_tuple_lock,
						 TransactionId *single_locker_xid,
						 bool *any_multi_locker_member_alive,
						 bool *checked_lockers, bool *locker_remains,
						 TM_Result *result, bool *item_is_deleted)
{
	List	   *mlmembers;
	uint16		infomask;
	bool		can_continue = false;

	/* must copy state data before unlocking buffer */
	infomask = zheaptup->t_data->t_infomask;

	if (ZHeapTupleHasMultiLockers(infomask))
	{
		TransactionId update_xact;
		LockTupleMode old_lock_mode;
		int			remain = 0;
		bool		isAborted;
		bool		upd_xact_aborted = false;
		int			trans_slot_id;
		UndoRecPtr	prev_urecptr;

		/*
		 * In ZHeapTupleSatisfiesUpdate, it's not possible to know if current
		 * transaction has already locked the tuple for update because of
		 * multilocker flag. In that case, we've to check whether the current
		 * transaction has already locked the tuple for update.
		 */

		/*
		 * Get the transaction slot and undo record pointer if we are already
		 * in a transaction.
		 */
		trans_slot_id =
			PageGetTransactionSlotId(relation, buffer, fxid,
									 &prev_urecptr, false, false, NULL);

		/*
		 * If any subtransaction of the current top transaction already holds
		 * a lock as strong as or stronger than what we're requesting, we
		 * effectively hold the desired lock already.  We *must* succeed
		 * without trying to take the tuple lock, else we will deadlock
		 * against anyone wanting to acquire a stronger lock.
		 */
		if (trans_slot_id != InvalidXactSlotId &&
			ZCurrentXactHasTupleLockMode(zheaptup, prev_urecptr, lockmode))
		{
			*result = TM_Ok;
			*checked_lockers = true;
			*locker_remains = true;
			return true;
		}

		old_lock_mode = get_old_lock_mode(infomask);

		/*
		 * For the conflicting lockers, we need to be careful about applying
		 * pending undo actions for aborted transactions; if we leave any
		 * transaction whether locker or updater, it can lead to
		 * inconsistency.  Basically, in such a case after waiting for all the
		 * conflicting transactions we might clear the multilocker flag and
		 * proceed with update and it is quite possible that after the update,
		 * undo worker rollbacks some of the previous locker which can
		 * overwrite the tuple (Note, till multilocker bit is set, the
		 * rollback actions won't overwrite the tuple).
		 *
		 * OTOH for non-conflicting lockers, as we don't clear the
		 * multi-locker flag, there is no urgency to perform undo actions for
		 * aborts of lockers.  The work involved in finding and aborting
		 * lockers is non-trivial (w.r.t performance), so it is better to
		 * avoid it.
		 *
		 * After abort, if it is only a locker, then it will be completely
		 * gone; but if it is an update, then after applying pending actions,
		 * the tuple might get changed and we must allow to reverify the tuple
		 * in case it's values got changed.
		 */
		if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup->t_data->t_infomask))
			update_xact = ZHeapTupleGetTransXID(zheaptup, buffer, false);
		else
			update_xact = InvalidTransactionId;

		if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
								HWLOCKMODE_from_locktupmode(lockmode)))
		{
			/*
			 * There is a potential conflict.  It is quite possible that by
			 * this time the locker has already been committed. So we need to
			 * check for conflict with all the possible lockers and wait for
			 * each of them after releasing a buffer lock and acquiring a lock
			 * on a tuple.
			 */
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			mlmembers = ZGetMultiLockMembers(relation, zheaptup, buffer,
											 true);

			/*
			 * If there is no multi-lock members apart from the current
			 * transaction then no need for tuplock, just go ahead.
			 */
			if (mlmembers != NIL)
			{
				heap_acquire_tuplock(relation, &(zheaptup->t_self), lockmode,
									 LockWaitBlock, have_tuple_lock);
				ZMultiLockMembersWait(relation, mlmembers, zheaptup, buffer,
									  update_xact, lockmode, false,
									  XLTW_Update, &remain,
									  &upd_xact_aborted);
			}
			*checked_lockers = true;
			*locker_remains = (remain != 0);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * If the aborted xact is for update, then we need to reverify the
			 * tuple.
			 */
			if (upd_xact_aborted)
				return false;

			/*
			 * Also take care of cases when page is pruned after we release
			 * the buffer lock. For this we check if ItemId is not deleted and
			 * refresh the tuple offset position in page.  If TID is already
			 * delete marked due to pruning, then get new ctid, so that we can
			 * update the new tuple.
			 *
			 * We also need to ensure that no new lockers have been added in
			 * the meantime, if there is any new locker, then start again.
			 */
			if (ItemIdIsDeleted(lp))
			{
				*item_is_deleted = true;
				return false;
			}

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				List	   *new_mlmembers;

				new_mlmembers = ZGetMultiLockMembers(relation, zheaptup,
													 buffer, false);

				/*
				 * Ensure, no new lockers have been added, if so, then start
				 * again.
				 */
				if (!ZMultiLockMembersSame(mlmembers, new_mlmembers))
				{
					list_free_deep(mlmembers);
					list_free_deep(new_mlmembers);
					return false;
				}

				*any_multi_locker_member_alive =
					ZIsAnyMultiLockMemberRunning(new_mlmembers, zheaptup,
												 buffer);
				list_free_deep(mlmembers);
				list_free_deep(new_mlmembers);
			}

			if (!RefetchAndCheckTupleStatus(relation, buffer, infomask, tup_xid,
											single_locker_xid, NULL, zheaptup))
				return false;
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
											xwait_trans_slot, xwait, NULL))
				return false;
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
		 * The only locker is ourselves; we can avoid grabbing the tuple lock
		 * here, but must preserve our locking information.
		 */
		*checked_lockers = true;
		*locker_remains = true;
		can_continue = true;
	}
	else if (ZHEAP_XID_IS_KEYSHR_LOCKED(infomask) && key_intact)
	{
		/*
		 * If it's just a key-share locker, and we're not changing the key
		 * columns, we don't need to wait for it to end; but we need to
		 * preserve it as locker.
		 */
		*checked_lockers = true;
		*locker_remains = true;
		can_continue = true;
	}
	else
	{
		bool		isCommitted;
		bool		has_update = false;

		/*
		 * Wait for regular transaction to end; but first, acquire tuple lock.
		 */
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		heap_acquire_tuplock(relation, &(zheaptup->t_self), lockmode,
							 LockWaitBlock, have_tuple_lock);
		if (xwait_subxid != InvalidSubTransactionId)
			SubXactLockTableWait(xwait, xwait_subxid, relation,
								 &zheaptup->t_self, XLTW_Update);
		else
			XactLockTableWait(xwait, relation, &zheaptup->t_self,
							  XLTW_Update);
		*checked_lockers = true;
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
			*item_is_deleted = true;
			return false;
		}

		/*
		 * xwait is done, but if xwait had just locked the tuple then some
		 * other xact could update/lock this tuple before we get to this
		 * point.  Check for xid change, and start over if so.  We need to do
		 * some special handling for lockers because their xid is never stored
		 * on the tuples.  If there was a single locker on the tuple and that
		 * locker is gone and some new locker has locked the tuple, we won't
		 * be able to identify that by infomask/xid on the tuple, rather we
		 * need to fetch the locker xid.
		 */
		if (!RefetchAndCheckTupleStatus(relation, buffer, infomask, tup_xid,
										single_locker_xid, NULL, zheaptup))
			return false;

		if (!ZHEAP_XID_IS_LOCKED_ONLY(zheaptup->t_data->t_infomask))
			has_update = true;

		/*
		 * We may overwrite if previous xid is aborted, or if it is committed
		 * but only locked the tuple without updating it.
		 */
		isCommitted = TransactionIdDidCommit(xwait);

		/*
		 * For aborted transaction, if the undo actions are not applied yet,
		 * then apply them before modifying the page.
		 */
		if (!isCommitted)
			zheap_exec_pending_rollback(relation, buffer, xwait_trans_slot,
										xwait, NULL);

		if (!isCommitted)
		{
			/*
			 * For aborted updates, we must allow to reverify the tuple in
			 * case it's values got changed.
			 */
			if (has_update)
				return false;

			/*
			 * While executing the undo action we have released the buffer
			 * lock.  So if the tuple infomask got changed while applying the
			 * undo action then we must reverify the tuple.
			 */
			if (!RefetchAndCheckTupleStatus(relation, buffer, infomask, tup_xid,
											single_locker_xid, NULL, zheaptup))
				return false;
		}

		if (!has_update)
			can_continue = true;
	}

	/*
	 * We may overwrite if previous xid is aborted or committed, but only
	 * locked the tuple without updating it.
	 */
	if (*result != TM_Ok)
		*result = can_continue ? TM_Ok : TM_Updated;
	return true;
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
TM_Result
zheap_lock_tuple(Relation relation, ItemPointer tid,
				 CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy,
				 bool follow_updates, bool eval, Snapshot snapshot,
				 ZHeapTuple tuple, Buffer *buffer, TM_FailureData *tmfd)
{
	TM_Result	result;
	ZHeapTupleData zhtup;
	UndoRecPtr	prev_urecptr;
	ItemId		lp;
	Page		page;
	ItemPointerData ctid;
	FullTransactionId fxid = GetTopFullTransactionId();
	TransactionId xid,
				single_locker_xid;
	SubTransactionId tup_subxid = InvalidSubTransactionId;
	UndoRecPtr	urec_ptr = InvalidUndoRecPtr;
	uint32		epoch;
	int			trans_slot_id,
				single_locker_trans_slot;
	OffsetNumber offnum;
	LockOper	lockopr;
	bool		require_sleep;
	bool		have_tuple_lock = false;
	bool		in_place_updated_or_locked = false;
	bool		any_multi_locker_member_alive = false;
	bool		lock_reacquired;
	bool		rollback_and_relocked;
	ZHeapTupleTransInfo zinfo;

	xid = XidFromFullTransactionId(fxid);
	epoch = EpochFromFullTransactionId(fxid);
	lockopr = eval ? LockForUpdate : LockOnly;

	*buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));

	LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

	page = BufferGetPage(*buffer);
	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp) || ItemIdIsDeleted(lp));

	/*
	 * If TID is already delete marked due to pruning, then get new ctid, so
	 * that we can lock the new tuple.  We will get new ctid if the tuple was
	 * non-inplace-updated otherwise we will get same TID.
	 */
check_tup_satisfies_update:
	if (ItemIdIsDeleted(lp))
	{
		ctid = *tid;
		ZHeapPageGetNewCtid(*buffer, &ctid, &zinfo);
		result = TM_Updated;
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
	trans_slot_id = PageGetTransactionSlotId(relation, *buffer, fxid,
											 &urec_ptr, false, false, NULL);

	/*
	 * ctid needs to be fetched from undo chain.  See zheap_update.
	 */
	ctid = *tid;

	any_multi_locker_member_alive = true;
	result = ZHeapTupleSatisfiesUpdate(relation, &zhtup, cid, *buffer, &ctid,
									   &zinfo, &tup_subxid,
									   &single_locker_xid,
									   &single_locker_trans_slot, eval,
									   snapshot, &in_place_updated_or_locked);
	if (result == TM_Invisible)
	{
		tuple->t_tableOid = RelationGetRelid(relation);
		tuple->t_len = zhtup.t_len;
		tuple->t_self = zhtup.t_self;
		tuple->t_data = palloc0(tuple->t_len);
		memcpy(tuple->t_data, zhtup.t_data, zhtup.t_len);

		/* Give caller an opportunity to throw a more specific error. */
		result = TM_Invisible;
		goto out_locked;
	}
	else if (result == TM_BeingModified ||
			 result == TM_Updated ||
			 (result == TM_Ok &&
			  ZHeapTupleHasMultiLockers(zhtup.t_data->t_infomask)))
	{
		TransactionId xwait;
		SubTransactionId xwait_subxid;
		int			xwait_trans_slot;
		uint16		infomask;

		xwait_subxid = tup_subxid;

		if (TransactionIdIsValid(single_locker_xid))
		{
			xwait = single_locker_xid;
			xwait_trans_slot = single_locker_trans_slot;
		}
		else
		{
			xwait = zinfo.xid;
			xwait_trans_slot = zinfo.trans_slot;
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
		tuple->t_data = palloc0(tuple->t_len);
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
			if (trans_slot_id != InvalidXactSlotId &&
				ZCurrentXactHasTupleLockMode(&zhtup, urec_ptr, mode))
			{
				result = TM_Ok;
				goto out_unlocked;
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
						result = TM_Ok;
						goto out_unlocked;
					}
					break;
				case LockTupleShare:
					if (ZHEAP_XID_IS_SHR_LOCKED(infomask) ||
						ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = TM_Ok;
						goto out_unlocked;
					}
					break;
				case LockTupleNoKeyExclusive:
					if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) ||
						ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = TM_Ok;
						goto out_unlocked;
					}
					break;
				case LockTupleExclusive:
					if (ZHEAP_XID_IS_EXCL_LOCKED(infomask))
					{
						result = TM_Ok;
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
						TM_Result	res;

						res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
													   fxid, mode, lockopr, cid,
													   &rollback_and_relocked);

						/*
						 * If the update was by some aborted transaction and
						 * its pending undo actions are applied now, then
						 * check the latest copy of the tuple.
						 */
						if (rollback_and_relocked)
						{
							LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
							goto check_tup_satisfies_update;
						}
						else if (res != TM_Ok)
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
				 * Also take care of cases when page is pruned after we
				 * release the buffer lock. For this we check if ItemId is not
				 * deleted and refresh the tuple offset position in page.  If
				 * TID is already delete marked due to pruning, then get new
				 * ctid, so that we can lock the new tuple.
				 */
				if (ItemIdIsDeleted(lp))
					goto check_tup_satisfies_update;

				if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
												zinfo.xid, &single_locker_xid,
												&mode, &zhtup))
					goto check_tup_satisfies_update;

				/* Skip sleeping */
				require_sleep = false;
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
				 * Also take care of cases when page is pruned after we
				 * release the buffer lock. For this we check if ItemId is not
				 * deleted and refresh the tuple offset position in page.  If
				 * TID is already delete marked due to pruning, then get new
				 * ctid, so that we can lock the new tuple.
				 */
				if (ItemIdIsDeleted(lp))
					goto check_tup_satisfies_update;

				if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
												zinfo.xid, &single_locker_xid,
												&mode, &zhtup))
					goto check_tup_satisfies_update;

				/* Skip sleeping */
				require_sleep = false;
			}
		}
		else if (mode == LockTupleNoKeyExclusive)
		{
			LockTupleMode old_lock_mode;
			bool		buf_lock_reacquired = false;

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
				 * Also take care of cases when page is pruned after we
				 * release the buffer lock. For this we check if ItemId is not
				 * deleted and refresh the tuple offset position in page.  If
				 * TID is already delete marked due to pruning, then get new
				 * ctid, so that we can lock the new tuple.
				 */
				if (ItemIdIsDeleted(lp))
					goto check_tup_satisfies_update;

				if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
												zinfo.xid, &single_locker_xid,
												&mode, &zhtup))
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
		 * lock stronger than we are requesting are already handled above by
		 * not doing anything.
		 */
		if (require_sleep &&
			!ZHeapTupleHasMultiLockers(infomask) &&
			TransactionIdIsCurrentTransactionId(xwait))
		{
			/*
			 * If the xid changed in the meantime, start over.
			 *
			 * Also take care of cases when page is pruned after we release
			 * the buffer lock. For this we check if ItemId is not deleted and
			 * refresh the tuple offset position in page.  If TID is already
			 * delete marked due to pruning, then get new ctid, so that we can
			 * lock the new tuple.
			 */
			LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
			if (ItemIdIsDeleted(lp))
				goto check_tup_satisfies_update;

			if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
											zinfo.xid, &single_locker_xid,
											NULL, &zhtup))
				goto check_tup_satisfies_update;
			require_sleep = false;
		}

		if (require_sleep && result == TM_Updated)
		{
			LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
			goto failed;
		}
		else if (require_sleep)
		{
			List	   *mlmembers = NIL;
			bool		upd_xact_aborted = false;

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
				result = TM_WouldBlock;
				/* recovery code expects to have buffer lock held */
				LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
				goto failed;
			}

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				LockTupleMode old_lock_mode;
				TransactionId update_xact;

				old_lock_mode = get_old_lock_mode(infomask);

				/*
				 * For aborted updates, we must allow to reverify the tuple in
				 * case it's values got changed.
				 */
				if (!ZHEAP_XID_IS_LOCKED_ONLY(infomask))
					update_xact = ZHeapTupleGetTransXID(&zhtup, *buffer, true);
				else
					update_xact = InvalidTransactionId;

				if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_lock_mode),
										HWLOCKMODE_from_locktupmode(mode)))
				{
					/*
					 * There is a potential conflict.  It is quite possible
					 * that by this time the locker has already been
					 * committed. So we need to check for conflict with all
					 * the possible lockers and wait for each of them.
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
								result = TM_WouldBlock;

								/*
								 * recovery code expects to have buffer lock
								 * held
								 */
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
								result = TM_WouldBlock;

								/*
								 * recovery code expects to have buffer lock
								 * held
								 */
								LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);
								goto failed;
							}
						}
						else if (!ConditionalXactLockTableWait(xwait))
						{
							result = TM_WouldBlock;
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
				TM_Result	res;

				if (!ZHeapTupleIsMoved(zhtup.t_data->t_infomask) &&
					!ItemPointerEquals(&zhtup.t_self, &ctid))
				{
					res = zheap_lock_updated_tuple(relation, &zhtup, &ctid,
												   fxid, mode, lockopr, cid,
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
					else if (res != TM_Ok)
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
				goto check_tup_satisfies_update;

			if (ZHeapTupleHasMultiLockers(infomask))
			{
				List	   *new_mlmembers;

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
			if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
											zinfo.xid, &single_locker_xid,
											NULL, &zhtup))
				goto check_tup_satisfies_update;
		}

		if (TransactionIdIsValid(xwait) && TransactionIdDidAbort(xwait))
		{
			/*
			 * For aborted transaction, if the undo actions are not applied
			 * yet, then apply them before modifying the page.
			 */
			if (!TransactionIdIsCurrentTransactionId(xwait))
				zheap_exec_pending_rollback(relation, *buffer, xwait_trans_slot,
											xwait, NULL);

			if (!RefetchAndCheckTupleStatus(relation, *buffer, infomask,
											zinfo.xid, &single_locker_xid,
											NULL, &zhtup))
				goto check_tup_satisfies_update;
		}

		/*
		 * We may lock if previous xid committed or aborted but only locked
		 * the tuple without updating it; or if we didn't have to wait at all
		 * for whatever reason.
		 */
		if (!require_sleep ||
			ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask) ||
			result == TM_Ok)
			result = TM_Ok;
		else
			result = TM_Updated;
	}
	else if (result == TM_Ok)
	{
		TransactionId xwait;
		uint16		infomask;

		if (TransactionIdIsValid(single_locker_xid))
			xwait = single_locker_xid;
		else
			xwait = zinfo.xid;

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
			if (trans_slot_id != InvalidXactSlotId &&
				ZCurrentXactHasTupleLockMode(&zhtup, urec_ptr, mode))
			{
				result = TM_Ok;
				goto out_locked;
			}
		}
		else if (TransactionIdIsCurrentTransactionId(xwait))
		{
			tuple->t_tableOid = RelationGetRelid(relation);
			tuple->t_len = zhtup.t_len;
			tuple->t_self = zhtup.t_self;
			tuple->t_data = palloc0(tuple->t_len);
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
	if (result != TM_Ok)
	{
		Assert(result == TM_SelfModified || result == TM_Deleted ||
			   result == TM_Updated || result == TM_WouldBlock);
		Assert(ItemIdIsDeleted(lp) ||
			   IsZHeapTupleModified(zhtup.t_data->t_infomask));

		/* If item id is deleted, tuple can't be marked as moved. */
		if (!ItemIdIsDeleted(lp) &&
			ZHeapTupleIsMoved(zhtup.t_data->t_infomask))
			ItemPointerSetMovedPartitions(&tmfd->ctid);
		else
			tmfd->ctid = ctid;

		/*
		 * If item id is deleted, tuple won't be initialized.  In that case,
		 * we should set t_self with the tuple tid and the length as zero to
		 * let the caller know that the item id is deleted.
		 */
		if (ItemIdIsDeleted(lp))
		{
			tuple->t_self = *tid;
			tuple->t_len = 0;
			tuple->t_tableOid = RelationGetRelid(relation);
		}

		tmfd->xmax = zinfo.xid;
		if (result == TM_SelfModified)
			tmfd->cmax = zinfo.cid;
		else
			tmfd->cmax = InvalidCommandId;
		tmfd->in_place_updated_or_locked = in_place_updated_or_locked;
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
											   fxid, &prev_urecptr,
											   &lock_reacquired, false, InvalidBuffer,
											   NULL);
	if (lock_reacquired)
		goto check_tup_satisfies_update;

	if (trans_slot_id == InvalidXactSlotId)
	{
		LockBuffer(*buffer, BUFFER_LOCK_UNLOCK);

		pgstat_report_wait_start(PG_WAIT_PAGE_TRANS_SLOT);
		pg_usleep(10000L);		/* 10 ms */
		pgstat_report_wait_end();

		LockBuffer(*buffer, BUFFER_LOCK_EXCLUSIVE);

		goto check_tup_satisfies_update;
	}

	/* transaction slot must be reserved before locking a tuple */
	Assert(trans_slot_id != InvalidXactSlotId);

	/*
	 * It's possible that tuple slot is now marked as frozen. Hence, we
	 * refetch the tuple here.
	 */
	Assert(!ItemIdIsDeleted(lp));
	zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zhtup.t_len = ItemIdGetLength(lp);

	/*
	 * If the slot is marked as frozen, the latest modifier of the tuple must
	 * be frozen.
	 */
	if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zhtup.t_data)) == ZHTUP_SLOT_FROZEN)
	{
		zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
		zinfo.xid = InvalidTransactionId;
	}

	/*
	 * If all the members were lockers and are all gone, we can do away with
	 * the MULTI_LOCKERS bit.
	 */
	zheap_lock_tuple_guts(relation, *buffer, &zhtup, zinfo.xid, xid, mode,
						  lockopr, epoch, zinfo.trans_slot, trans_slot_id,
						  single_locker_xid, single_locker_trans_slot,
						  prev_urecptr, cid, !any_multi_locker_member_alive);

	tuple->t_tableOid = RelationGetRelid(relation);
	tuple->t_len = zhtup.t_len;
	tuple->t_self = zhtup.t_self;
	tuple->t_data = palloc0(tuple->t_len);

	memcpy(tuple->t_data, zhtup.t_data, zhtup.t_len);

	result = TM_Ok;

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
 * TM_Ok is returned.  To notify the caller if some pending
 * rollback is applied, rollback_and_relocked is set to true.
 */
static TM_Result
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
		return TM_SelfModified;
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
			OffsetNumber offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);

			*needwait = true;
			if (subxid)
				ZHeapTupleGetSubXid(buf, offnum, urec_ptr, subxid);
		}

		/*
		 * If we set needwait above, then this value doesn't matter;
		 * otherwise, this value signals to caller that it's okay to proceed.
		 */
		return TM_Ok;
	}
	else if (TransactionIdDidAbort(xid))
	{
		/*
		 * For aborted transaction, if the undo actions are not applied yet,
		 * then apply them before modifying the page.
		 */
		zheap_exec_pending_rollback(rel, buf, trans_slot_id, xid, NULL);

		/*
		 * If it was only a locker, then the lock is completely gone now and
		 * we can return success; but if it was an update, then after applying
		 * pending actions, the tuple might have changed and we must report
		 * error to the caller.  It will allow caller to reverify the tuple in
		 * case it's values got changed.
		 */

		*rollback_and_relocked = true;

		return TM_Ok;
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
			return TM_Ok;

		if (DoLockModesConflict(HWLOCKMODE_from_locktupmode(old_mode),
								HWLOCKMODE_from_locktupmode(required_mode)))
			/* bummer */
			return TM_Updated;

		return TM_Ok;
	}

	/* Not in progress, not aborted, not committed -- must have crashed */
	return TM_Ok;
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
static TM_Result
zheap_lock_updated_tuple(Relation rel, ZHeapTuple tuple, ItemPointer ctid,
						 FullTransactionId fxid, LockTupleMode mode,
						 LockOper lockopr, CommandId cid,
						 bool *rollback_and_relocked)
{
	TM_Result	result;
	ZHeapTuple	mytup;
	UndoRecPtr	prev_urecptr;
	Buffer		buf;
	Page		page;
	ItemPointerData tupid;
	TransactionId priorXmax = InvalidTransactionId;
	TransactionId xid = XidFromFullTransactionId(fxid);
	uint32		epoch = EpochFromFullTransactionId(fxid);
	int			trans_slot_id;
	bool		lock_reacquired;
	OffsetNumber offnum;
	ZHeapTupleTransInfo zinfo;

	ItemPointerCopy(ctid, &tupid);

	if (rollback_and_relocked)
		*rollback_and_relocked = false;

	for (;;)
	{
		ZHeapTupleData zhtup;
		ItemId		lp;
		uint16		old_infomask;
		UndoRecPtr	urec_ptr;

		if (!zheap_fetch(rel, SnapshotAny, ctid, &mytup, &buf, false))
		{
			/*
			 * if we fail to find the updated version of the tuple, it's
			 * because it was vacuumed/pruned/rolled back away after its
			 * creator transaction aborted.  So behave as if we got to the end
			 * of the chain, and there's no further tuple to lock: return
			 * success to caller.
			 */
			if (mytup == NULL)
				return TM_Ok;

			/*
			 * If we reached the end of the chain, we're done, so return
			 * success.  See EvalPlanQualZFetch for detailed reason.
			 */
			if (TransactionIdIsValid(priorXmax) &&
				!ValidateTuplesXact(rel, mytup, SnapshotAny, buf,
									priorXmax, true))
				return TM_Ok;

			/* deleted or moved to another partition, so forget about it */
			if (ZHeapTupleIsMoved(mytup->t_data->t_infomask) ||
				ItemPointerEquals(&(mytup->t_self), ctid))
				return TM_Ok;

			/* updated row should have xid matching this xmax */
			priorXmax = ZHeapTupleGetTransXID(mytup, buf, true);

			/* continue to lock the next version of tuple */
			continue;
		}

lock_tuple:
		urec_ptr = InvalidUndoRecPtr;

		CHECK_FOR_INTERRUPTS();

		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * If we reached the end of the chain, we're done, so return success.
		 * See EvalPlanQualZFetch for detailed reason.
		 */
		if (TransactionIdIsValid(priorXmax) &&
			!ValidateTuplesXact(rel, mytup, SnapshotAny,
								buf, priorXmax, false))
		{
			UnlockReleaseBuffer(buf);
			return TM_Ok;
		}

		/*
		 * Since we've reacquired the buffer lock, we should refetch the
		 * tuple.
		 */
		page = BufferGetPage(buf);
		offnum = ItemPointerGetOffsetNumber(&mytup->t_self);
		lp = PageGetItemId(page, offnum);

		/* free the old tuple */
		zheap_freetuple(mytup);

		/*
		 * If this tuple was created by an aborted (sub)transaction and its
		 * rollback got applied, then we already locked the last live one in
		 * the chain, thus we're done, so return success. If tuple is dead,
		 * then there is no need to lock it.
		 */
		if (!ItemIdIsUsed(lp) || ItemIdIsDead(lp))
		{
			result = TM_Ok;
			goto out_locked;
		}
		else if (ItemIdIsDeleted(lp))
		{
			/* There is no point of locking a deleted and pruned tuple. */
			ZHeapTupleFetch(rel, buf, offnum, SnapshotAny, &mytup, NULL);
			ctid = &mytup->t_self;
			ZHeapPageGetNewCtid(buf, ctid, &zinfo);
			goto next;
		}
		else
			mytup = zheap_gettuple(rel, buf, offnum);

		ZHeapTupleGetTransInfo(buf, offnum, &zinfo);
		urec_ptr = zinfo.urec_ptr;
		old_infomask = mytup->t_data->t_infomask;

		/*
		 * If this tuple was created by an aborted (sub)transaction, then we
		 * already locked the last live one in the chain, thus we're done, so
		 * return success.
		 */
		if (!IsZHeapTupleModified(old_infomask) &&
			TransactionIdDidAbort(zinfo.xid))
		{
			result = TM_Ok;
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
			SubTransactionId subxid = InvalidSubTransactionId;
			LockTupleMode old_lock_mode;
			bool		needwait;
			bool		has_update = false;

			if (ZHeapTupleHasMultiLockers(old_infomask))
			{
				List	   *mlmembers;
				ListCell   *lc;
				TransactionId update_xact = InvalidTransactionId;

				/*
				 * As we always maintain strongest lock mode on the tuple, it
				 * must be pointing to the transaction id of the updater.
				 */
				if (!ZHEAP_XID_IS_LOCKED_ONLY(old_infomask))
					update_xact = zinfo.xid;

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
					 * Now, notify the caller to check for the latest copy of
					 * the tuple.
					 */
					if (*rollback_and_relocked)
					{
						list_free_deep(mlmembers);
						goto out_locked;
					}

					if (result == TM_SelfModified)
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
					if (result != TM_Ok)
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
					Assert(!(zinfo.trans_slot == ZHTUP_SLOT_FROZEN ||
							 FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid)));

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
													old_lock_mode, zinfo.xid,
													zinfo.trans_slot, mode,
													has_update, &subxid,
													&needwait,
													rollback_and_relocked);

				/*
				 * If the update was by some aborted transaction with pending
				 * rollback, then it's undo actions are applied. Now, notify
				 * the caller to check for the latest copy of the tuple.
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
				if (result == TM_SelfModified)
					goto next;

				if (needwait)
				{
					LockBuffer(buf, BUFFER_LOCK_UNLOCK);
					if (subxid != InvalidSubTransactionId)
						SubXactLockTableWait(zinfo.xid, subxid, rel,
											 &mytup->t_self,
											 XLTW_LockUpdated);
					else
						XactLockTableWait(zinfo.xid, rel, &mytup->t_self,
										  XLTW_LockUpdated);
					goto lock_tuple;
				}
				if (result != TM_Ok)
				{
					goto out_locked;
				}
			}
		}

		offnum = ItemPointerGetOffsetNumber(&mytup->t_self);

		/*
		 * The transaction information of tuple needs to be set in transaction
		 * slot, so needs to reserve the slot before proceeding with the
		 * actual operation.  It will be costly to wait for getting the slot,
		 * but we do that by releasing the buffer lock.
		 */
		trans_slot_id = PageReserveTransactionSlot(rel, buf, offnum,
												   fxid, &prev_urecptr,
												   &lock_reacquired, false,
												   InvalidBuffer, NULL);
		if (lock_reacquired)
		{
			LockBuffer(buf, BUFFER_LOCK_UNLOCK);
			goto lock_tuple;
		}

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
		 * It's possible that tuple slot is now marked as frozen. Hence, we
		 * refetch the tuple here.
		 */
		zhtup.t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
		zhtup.t_len = ItemIdGetLength(lp);
		zhtup.t_tableOid = mytup->t_tableOid;
		zhtup.t_self = mytup->t_self;

		/*
		 * If the slot is marked as frozen, the latest modifier of the tuple
		 * must be frozen.
		 */
		if (ZHeapTupleHeaderGetXactSlot((ZHeapTupleHeader) (zhtup.t_data)) == ZHTUP_SLOT_FROZEN)
		{
			zinfo.trans_slot = ZHTUP_SLOT_FROZEN;
			zinfo.xid = InvalidTransactionId;
		}

		zheap_lock_tuple_guts(rel, buf, &zhtup, zinfo.xid, xid, mode, lockopr,
							  epoch, zinfo.trans_slot, trans_slot_id,
							  InvalidTransactionId, InvalidXactSlotId,
							  prev_urecptr, cid, false);

next:

		/*
		 * if we find the end of update chain, or if the transaction that has
		 * updated the tuple is aborter, we're done.
		 */
		if (TransactionIdDidAbort(zinfo.xid) ||
			ZHeapTupleIsMoved(zhtup.t_data->t_infomask) ||
			ItemPointerEquals(&zhtup.t_self, ctid) ||
			ZHEAP_XID_IS_LOCKED_ONLY(zhtup.t_data->t_infomask))
		{
			result = TM_Ok;
			goto out_locked;
		}

		/*
		 * Updated row should have xid matching this xmax.
		 *
		 * XXX Using zinfo.xid will work as this must be the xid of updater if
		 * any on the tuple; that is because we always maintain the strongest
		 * locker information on the tuple.
		 */
		priorXmax = zinfo.xid;

		/*
		 * As we still hold a snapshot to which priorXmax is not visible,
		 * neither the transaction slot on tuple can be marked as frozen nor
		 * the corresponding undo be discarded.
		 */
		Assert(TransactionIdIsValid(priorXmax));

		/* be tidy */
		zheap_freetuple(mytup);
		UnlockReleaseBuffer(buf);
	}

	result = TM_Ok;

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
	UnpackedUndoRecord undorecord;
	int			new_trans_slot_id;
	uint16		old_infomask;
	uint16		new_infomask = 0;
	xl_undolog_meta undometa;
	bool		hasSubXactLock = false;

	/* Compute the new xid and infomask to store into the tuple. */
	old_infomask = zhtup->t_data->t_infomask;

	/*
	 * If all the members were lockers and are all gone, we can do away with
	 * the MULTI_LOCKERS bit.
	 */
	if (ZHeapTupleHasMultiLockers(old_infomask) && clear_multi_locker)
		old_infomask &= ~ZHEAP_MULTI_LOCKERS;

	compute_new_xid_infomask(zhtup, buf, tup_xid, tup_trans_slot_id,
							 old_infomask, xid, trans_slot_id,
							 single_locker_xid, mode, lockopr,
							 &new_infomask, &new_trans_slot_id);

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
	 * If the last transaction that has updated the tuple is already too old,
	 * then consider it as frozen which means it is all-visible.  This ensures
	 * that we don't need to store epoch in the undo record to check if the
	 * undo tuple belongs to previous epoch and hence all-visible.  See
	 * comments atop of file zheapam_visibility.c.
	 */
	oldestXidHavingUndo = GetXidFromEpochXid(
											 pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));
	if (TransactionIdPrecedes(tup_xid, oldestXidHavingUndo))
		tup_xid = FrozenTransactionId;

	/*
	 * Prepare an undo record.  We need to separately store the latest
	 * transaction id that has changed the tuple to ensure that we don't try
	 * to process the tuple in undo chain that is already discarded. See
	 * GetTupleFromUndo.
	 */
	undorecord.uur_rmid = RM_ZHEAP_ID;
	if (ZHeapTupleHasMultiLockers(new_infomask))
		undorecord.uur_type = UNDO_XID_MULTI_LOCK_ONLY;
	else if (lockopr == LockForUpdate)
		undorecord.uur_type = UNDO_XID_LOCK_FOR_UPDATE;
	else
		undorecord.uur_type = UNDO_XID_LOCK_ONLY;
	undorecord.uur_info = 0;
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
	 * Store subtransaction id in undo record.  See SubXactLockTableWait to
	 * know why we need to store subtransaction id in undo.
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
								InvalidFullTransactionId,
								UndoPersistenceForRelation(rel),
								NULL,
								&undometa);

	START_CRIT_SECTION();

	InsertPreparedUndo();

	/*
	 * For lockers, we only set the slot on tuple when the lock mode is
	 * LockForUpdate and the tuple doesn't have multilocker flag.  In that
	 * case, pass set_tpd_map_slot as true, false otherwise.
	 */
	PageSetUNDO(undorecord, buf, trans_slot_id,
				(undorecord.uur_type == UNDO_XID_LOCK_FOR_UPDATE),
				FullTransactionIdFromEpochAndXid(epoch, xid),
				urecptr, NULL, 0);

	ZHeapTupleHeaderSetXactSlot(zhtup->t_data, new_trans_slot_id);
	zhtup->t_data->t_infomask &= ~ZHEAP_VIS_STATUS_MASK;
	zhtup->t_data->t_infomask |= new_infomask;

	MarkBufferDirty(buf);

	/* do xlog stuff */
	if (RelationNeedsWAL(rel))
	{
		ZHeapWALInfo lock_wal_info;

		lock_wal_info.buffer = buf;
		lock_wal_info.ztuple = zhtup;
		lock_wal_info.urecptr = urecptr;
		lock_wal_info.prev_urecptr = prev_urecptr;
		lock_wal_info.undometa = &undometa;
		lock_wal_info.new_trans_slot_id = new_trans_slot_id;
		lock_wal_info.prior_trans_slot_id = tup_trans_slot_id;
		lock_wal_info.all_visible_cleared = false;
		lock_wal_info.undorecord = &undorecord;

		log_zheap_lock_tuple(&lock_wal_info, tup_xid, trans_slot_id,
							 hasSubXactLock, mode);
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
 * tuple (aka locks via EvalPlanQual mechanism).  This is because for visibility
 * checks, we only need inserter/updater's xact information.  Keeping their
 * slot on the tuple avoids the overheads of fetching xact information from
 * undo during visibility checks.  Also, note that the latest inserter/updater
 * can be an aborted transaction whose rollback actions are still pending.
 *
 * For example, say after a committed insert/update, a new request arrives to
 * lock the tuple in key share mode, we will keep the inserter's/updater's slot
 * on the tuple and set the multi-locker and key-share bit.  If the inserter/
 * updater is already known to be having a frozen slot (visible to every one),
 * we will set the key-share locker bit and the tuple will indicate a frozen
 * slot.  Similarly, for a new updater, if the tuple has a single locker, then
 * the undo will have a frozen tuple and for multi-lockers, the undo of updater
 * will have previous inserter/updater slot; in both cases the new tuple will
 * point to the updaters slot.  Now, the rollback of a single locker will set
 * the frozen slot on tuple and the rollback of multi-locker won't change slot
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
						  &mode, &old_tuple_has_update, lockoper);
	}
	else if (!is_update &&
			 TransactionIdIsInProgress(single_locker_xid))
	{
		LockTupleMode old_mode;

		/*
		 * When there is a single in-progress locker on the tuple and previous
		 * inserter/updater became all visible, we've to set multi-locker flag
		 * and highest lock mode. If current transaction tries to reacquire a
		 * lock, we don't set multi-locker flag.
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
		 * keep the transaction slot of original tuple as that will allow us
		 * to check the visibility of tuple by just referring the current
		 * transaction slot.
		 */
		Assert((tup_xid == add_to_xid) || (mode == LockTupleKeyShare));

		if (tup_xid != add_to_xid)
			new_infomask |= ZHEAP_MULTI_LOCKERS;

		new_trans_slot = tup_trans_slot;
	}
	else if (!is_update &&
			 tup_trans_slot == ZHTUP_SLOT_FROZEN)
	{
		/*
		 * It's a frozen update or insert, so the locker must not change the
		 * slot on a tuple.  The lockmode to be used on tuple is computed
		 * below. There could be a single committed/aborted locker
		 * (multilocker case is handled in the first condition). In that case,
		 * we can ignore the locker. If the locker is still in progress, it'll
		 * be handled in above case.
		 */
		new_trans_slot = ZHTUP_SLOT_FROZEN;
	}
	else if (!is_update &&
			 !ZHEAP_XID_IS_LOCKED_ONLY(old_infomask) &&
			 tup_trans_slot != ZHTUP_SLOT_FROZEN)
	{
		/*
		 * It's a committed update/insert or an aborted update whose rollback
		 * action is still pending, so we gotta preserve him as updater of the
		 * tuple.  Also, indicate that tuple has multiple lockers.
		 *
		 * Note that tuple xid could be invalid if the undo records
		 * corresponding to the tuple transaction is discarded.  In that case,
		 * it can be considered as committed.
		 */
		new_infomask |= ZHEAP_MULTI_LOCKERS;
		old_tuple_has_update = true;

		if (ZHeapTupleIsInPlaceUpdated(old_infomask))
			new_infomask |= ZHEAP_INPLACE_UPDATED;
		else if (ZHeapTupleIsUpdated(old_infomask))
			new_infomask |= ZHEAP_UPDATED;
		else
		{
			/* This is a freshly inserted tuple. */
			old_tuple_has_update = false;
		}

		if (!old_tuple_has_update)
		{
			/*
			 * This is a freshly inserted tuple, allow to set the requested
			 * lock mode on tuple.
			 */
		}
		else
		{
			LockTupleMode old_mode;

			if (ZHEAP_XID_IS_EXCL_LOCKED(old_infomask))
				old_mode = LockTupleExclusive;
			else if (ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(old_infomask))
				old_mode = LockTupleNoKeyExclusive;
			else
			{
				/*
				 * Tuple must not be locked in any other mode as we are here
				 * because either the tuple is updated or inserted and the
				 * corresponding transaction is committed.
				 */
				Assert(!(ZHEAP_XID_IS_KEYSHR_LOCKED(old_infomask) ||
						 ZHEAP_XID_IS_SHR_LOCKED(old_infomask)));

				old_mode = LockTupleNoKeyExclusive;
			}

			if (mode < old_mode)
				mode = old_mode;
		}

		new_trans_slot = tup_trans_slot;
	}
	else if (!is_update &&
			 ZHEAP_XID_IS_LOCKED_ONLY(old_infomask) &&
			 tup_trans_slot != ZHTUP_SLOT_FROZEN)
	{
		LockTupleMode old_mode;

		/*
		 * This case arises for committed/aborted non-inplace updates where
		 * the newly inserted tuple is marked as locked-only, but multi-locker
		 * bit is not set.
		 *
		 * Note that tuple xid could be invalid if the undo records
		 * corresponding to the tuple transaction is discarded.  In that case,
		 * it can be considered as committed.
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
	else if (is_update &&
			 TransactionIdIsValid(single_locker_xid) &&
			 !TransactionIdDidCommit(single_locker_xid))
	{
		LockTupleMode old_mode;

		/*
		 * There can be a non-conflicting in-progress key share locker on the
		 * tuple and we want to update the tuple in no-key exclusive mode.  In
		 * that case, we should set the multilocker flag as well.
		 *
		 * Note that, the single locker xid can be aborted whose rollback
		 * actions are still pending.  The scenario should be handled in the
		 * same way as an in-progress single locker, i.e., we should set the
		 * multilocker flag accordingly.  Else, the rollback of single locker
		 * might resotre the infomask of the tuple incorrectly.
		 */
		Assert(ZHEAP_XID_IS_LOCKED_ONLY(old_infomask));
		if (single_locker_xid != add_to_xid)
		{
			new_infomask |= ZHEAP_MULTI_LOCKERS;

			/*
			 * If the tuple has multilocker and we're locking the tuple for
			 * update, we insert multilocker type of undo instead of
			 * lock-for-update undo.  For multilocker undo, we keep the old
			 * tuple slot as it is.
			 */
			if (lockoper == LockForUpdate)
				new_trans_slot = tup_trans_slot;
		}

		old_mode = get_old_lock_mode(old_infomask);

		/* Acquire the strongest of both. */
		Assert(single_locker_xid == add_to_xid || mode > old_mode);
		if (mode < old_mode)
			mode = old_mode;
	}

	/*
	 * For LockOnly mode and LockForUpdate mode with multilocker flag on the
	 * tuple, we keep the old transaction slot as it is.  Since we're not
	 * changing the xid slot in the tuple, we shouldn't remove the existing
	 * (if any) invalid xact flag from the tuple.
	 */
	if (!is_update ||
		((lockoper == LockForUpdate) && ZHeapTupleHasMultiLockers(new_infomask)))
	{
		if (ZHeapTupleHasInvalidXact(old_infomask))
			new_infomask |= ZHEAP_INVALID_XACT_SLOT;
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
		if (lockoper != ForUpdate && !old_tuple_has_update)
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

	*result_infomask = new_infomask;

	if (result_trans_slot)
		*result_trans_slot = new_trans_slot;

	/*
	 * We store the reserved transaction slot only when we update the tuple.
	 * For lock only, we keep the old transaction slot in the tuple.
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
zheap_finish_speculative(Relation relation, ItemPointer tid)
{
	Buffer		buffer;
	Page		page;
	OffsetNumber offnum;
	ItemId		lp = NULL;
	ZHeapTupleHeader zhtup;

	buffer = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	page = (Page) BufferGetPage(buffer);

	offnum = ItemPointerGetOffsetNumber(tid);
	if (PageGetMaxOffsetNumber(page) >= offnum)
		lp = PageGetItemId(page, offnum);

	if (PageGetMaxOffsetNumber(page) < offnum || !ItemIdIsNormal(lp))
		elog(ERROR, "invalid lp");

	zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);

	/* No ereport(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	Assert(ZHeapTupleHeaderIsSpeculative(zhtup));

	MarkBufferDirty(buffer);

	/* Clear the speculative insertion marking from the tuple. */
	zhtup->t_infomask &= ~ZHEAP_SPECULATIVE_INSERT;

	/* XLOG stuff */
	if (RelationNeedsWAL(relation))
	{
		xl_zheap_confirm xlrec;
		XLogRecPtr	recptr;

		xlrec.offnum = ItemPointerGetOffsetNumber(tid);
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
zheap_abort_speculative(Relation relation, ItemPointer tid)
{
	TransactionId xid = GetTopTransactionId();
	ItemId		lp;
	ZHeapTupleData tp;
	ZHeapTupleHeader zhtuphdr;
	Page		page;
	BlockNumber block;
	Buffer		buffer;
	OffsetNumber offnum;
	int			trans_slot_id;
	ZHeapTupleTransInfo zinfo;

	Assert(ItemPointerIsValid(tid));

	block = ItemPointerGetBlockNumber(tid);
	buffer = ReadBuffer(relation, block);
	page = BufferGetPage(buffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	offnum = ItemPointerGetOffsetNumber(tid);
	lp = PageGetItemId(page, offnum);
	Assert(ItemIdIsNormal(lp));

	zhtuphdr = (ZHeapTupleHeader) PageGetItem(page, lp);

	tp.t_tableOid = RelationGetRelid(relation);
	tp.t_data = zhtuphdr;
	tp.t_len = ItemIdGetLength(lp);
	tp.t_self = *tid;

	trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtuphdr);

	/*
	 * Sanity check that the tuple really is a speculatively inserted tuple,
	 * inserted by us.
	 */
	GetTransactionSlotInfo(buffer, offnum, trans_slot_id, true, false,
						   &zinfo);

	/* As the transaction is still open, the slot can't be frozen. */
	Assert(zinfo.trans_slot != ZHTUP_SLOT_FROZEN);
	Assert(zinfo.xid != InvalidTransactionId);

	if (zinfo.xid != xid)
		elog(ERROR, "attempted to kill a tuple inserted by another transaction");
	if (!(IsToastRelation(relation) || ZHeapTupleHeaderIsSpeculative(zhtuphdr)))
		elog(ERROR, "attempted to kill a non-speculative tuple");
	Assert(!IsZHeapTupleModified(zhtuphdr->t_infomask));

	START_CRIT_SECTION();

	/*
	 * The tuple will become DEAD immediately.  However, we mark it dead
	 * differently by keeping the trans_slot, to identify this is done during
	 * speculative abort only.  Flag that this page is a candidate for
	 * pruning.  The action here is exactly same as what we do for rolling
	 * back insert.
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

		xlrec.offnum = ItemPointerGetOffsetNumber(tid);
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

	if (ZHeapTupleHasExternal(&tp))
	{
		Assert(!IsToastRelation(relation));
		ztoast_delete(relation, &tp, true);
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

TransactionId
zheap_fetchinsertxid(ZHeapTuple zhtup, Buffer buffer)
{
	int			trans_slot_id = InvalidXactSlotId;
	TransactionId result;
	BlockNumber blk;
	OffsetNumber offnum;
	UnpackedUndoRecord *urec;
	ZHeapTupleHeaderData hdr;
	ZHeapTupleTransInfo zinfo;

	zinfo.trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
	blk = ItemPointerGetBlockNumber(&zhtup->t_self);
	offnum = ItemPointerGetOffsetNumber(&zhtup->t_self);
	GetTransactionSlotInfo(buffer, offnum, zinfo.trans_slot, true, false,
						   &zinfo);
	memcpy(&hdr, zhtup->t_data, SizeofZHeapTupleHeader);
	zinfo.xid = InvalidTransactionId;

	while (true)
	{
		urec = UndoFetchRecord(zinfo.urec_ptr, blk, offnum, zinfo.xid, NULL,
							   ZHeapSatisfyUndoRecord);
		if (urec == NULL)
		{
			/*
			 * Undo record could be null only when it's undo log is/about to
			 * be discarded. We cannot use any assert for checking is the log
			 * is actually discarded, since UndoFetchRecord can return NULL
			 * for the records which are not yet discarded but are about to be
			 * discarded.
			 */
			result = FrozenTransactionId;
			break;
		}

		/*
		 * If we have valid undo record, then check if we have reached the
		 * insert log and return the corresponding transaction id.
		 */
		if (urec->uur_type == UNDO_INSERT ||
			urec->uur_type == UNDO_MULTI_INSERT ||
			urec->uur_type == UNDO_INPLACE_UPDATE)
		{
			result = urec->uur_xid;
			UndoRecordRelease(urec);
			break;
		}

		trans_slot_id =
			UpdateTupleHeaderFromUndoRecord(urec, &hdr, BufferGetPage(buffer));

		zinfo.xid = urec->uur_prevxid;
		zinfo.urec_ptr = urec->uur_blkprev;
		UndoRecordRelease(urec);
		if (!UndoRecPtrIsValid(zinfo.urec_ptr))
		{
			result = FrozenTransactionId;
			break;
		}


		/*
		 * Change the undo chain if the undo tuple is stamped with the
		 * different transaction slot.
		 */
		if (trans_slot_id != zinfo.trans_slot)
			ZHeapUpdateTransactionSlotInfo(trans_slot_id,
										   buffer, offnum,
										   &zinfo);
	}

	return result;
}

/*
 * zheap_prepare_undoinsert - prepare the undo record for zheap insert
 *	operation.
 *
 * Returns the undo record pointer (aka location) where the undo record
 * will be inserted in undo log.  This function prepares and allocates
 * additional memory required for undorecord.  The caller can modify the
 * record fields, but can't allocate any new memory for it.
 */
UndoRecPtr
zheap_prepare_undoinsert(ZHeapPrepareUndoInfo *zh_undo_info,
						 uint32 specToken, bool specIns,
						 UnpackedUndoRecord *undorecord,
						 XLogReaderState *xlog_record,
						 xl_undolog_meta *undometa)
{
	UndoRecPtr	urecptr = InvalidUndoRecPtr;

	/*
	 * Prepare an undo record.  Unlike other operations, insert operation
	 * doesn't have a prior version to store in undo, so we don't need to
	 * store any additional information like UREC_INFO_PAYLOAD_CONTAINS_SLOT
	 * for TPD entries.
	 */
	undorecord->uur_rmid = RM_ZHEAP_ID;
	undorecord->uur_type = UNDO_INSERT;
	undorecord->uur_info = 0;
	undorecord->uur_prevlen = 0;
	undorecord->uur_reloid = zh_undo_info->reloid;
	undorecord->uur_prevxid = FrozenTransactionId;
	undorecord->uur_xid = XidFromFullTransactionId(zh_undo_info->fxid);
	undorecord->uur_cid = zh_undo_info->cid;
	undorecord->uur_fork = MAIN_FORKNUM;
	undorecord->uur_blkprev = zh_undo_info->prev_urecptr;
	undorecord->uur_block = zh_undo_info->blkno;
	undorecord->uur_offset = zh_undo_info->offnum;
	undorecord->uur_tuple.len = 0;

	/*
	 * Store the speculative insertion token in undo, so that we can retrieve
	 * it during visibility check of the speculatively inserted tuples.
	 *
	 * Note that we don't need to WAL log this value as this is a temporary
	 * information required only on master node to detect conflicts for Insert
	 * .. On Conflict.
	 */
	if (specIns)
	{
		undorecord->uur_payload.len = sizeof(uint32);
		initStringInfo(&undorecord->uur_payload);
		appendBinaryStringInfo(&undorecord->uur_payload,
							   (char *) &specToken,
							   sizeof(uint32));
	}
	else
		undorecord->uur_payload.len = 0;

	urecptr = PrepareUndoInsert(undorecord,
								zh_undo_info->fxid,
								zh_undo_info->undo_persistence,
								xlog_record,
								undometa);

	return urecptr;
}

/*
 * zheap_prepare_undodelete - prepare the undo record for zheap delete
 *	operation.
 *
 * Returns the undo record pointer (aka location) where the undo record
 * will be inserted in undo log.
 */
UndoRecPtr
zheap_prepare_undodelete(ZHeapPrepareUndoInfo *zhUndoInfo, ZHeapTuple zhtup,
						 TransactionId tup_xid, int tup_trans_slot_id,
						 SubTransactionId subxid,
						 UnpackedUndoRecord *undorecord,
						 XLogReaderState *xlog_record,
						 xl_undolog_meta *undometa)
{
	UndoRecPtr	urecptr = InvalidUndoRecPtr;
	bool		hasPayload = false;

	/*
	 * Prepare an undo record.  We need to separately store the latest
	 * transaction id that has changed the tuple to ensure that we don't try
	 * to process the tuple in undo chain that is already discarded. See
	 * GetTupleFromUndo.
	 */
	undorecord->uur_rmid = RM_ZHEAP_ID;
	undorecord->uur_type = UNDO_DELETE;
	undorecord->uur_info = 0;
	undorecord->uur_reloid = zhUndoInfo->reloid;
	undorecord->uur_prevxid = tup_xid;
	undorecord->uur_xid = XidFromFullTransactionId(zhUndoInfo->fxid);
	undorecord->uur_cid = zhUndoInfo->cid;
	undorecord->uur_fork = MAIN_FORKNUM;
	undorecord->uur_blkprev = zhUndoInfo->prev_urecptr;
	undorecord->uur_block = zhUndoInfo->blkno;
	undorecord->uur_offset = zhUndoInfo->offnum;

	initStringInfo(&undorecord->uur_tuple);

	/*
	 * Copy the entire old tuple into the undo record. We need this to
	 * reconstruct the tuple if current tuple is not visible to some other
	 * transaction.  We choose to write the complete tuple in undo record for
	 * delete operation so that we can reuse the space after the transaction
	 * performing the operation commits.
	 */
	appendBinaryStringInfo(&undorecord->uur_tuple,
						   (char *) zhtup->t_data,
						   zhtup->t_len);

	/*
	 * Store the transaction slot number for undo tuple in undo record, if the
	 * slot belongs to TPD entry.  We can always get the current tuple's
	 * transaction slot number by referring offset->slot map in TPD entry,
	 * however that won't be true for tuple in undo.
	 */
	if (tup_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		undorecord->uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SLOT;
		initStringInfo(&undorecord->uur_payload);
		appendBinaryStringInfo(&undorecord->uur_payload,
							   (char *) &tup_trans_slot_id,
							   sizeof(tup_trans_slot_id));
		hasPayload = true;
	}

	/*
	 * Store subtransaction id in undo record.  See SubXactLockTableWait to
	 * know why we need to store subtransaction id in undo.
	 */
	if (subxid != InvalidSubTransactionId)
	{
		if (!hasPayload)
		{
			initStringInfo(&undorecord->uur_payload);
			hasPayload = true;
		}

		undorecord->uur_info |= UREC_INFO_PAYLOAD_CONTAINS_SUBXACT;
		appendBinaryStringInfo(&undorecord->uur_payload,
							   (char *) &subxid,
							   sizeof(subxid));
	}

	if (!hasPayload)
		undorecord->uur_payload.len = 0;

	urecptr = PrepareUndoInsert(undorecord,
								zhUndoInfo->fxid,
								zhUndoInfo->undo_persistence,
								xlog_record,
								undometa);

	return urecptr;
}

/*
 * log_zheap_insert - Perform XLogInsert for a zheap-insert operation.
 *
 * We need to store enough information in the WAL record so that undo records
 * can be regenerated at the WAL replay time.
 *
 * Caller must already have modified the buffer(s) and marked them dirty.
 */
static void
log_zheap_insert(ZHeapWALInfo *walinfo, Relation relation,
				 int options, bool skip_undo)
{
	xl_undo_header xlundohdr;
	xl_zheap_insert xlrec;
	xl_zheap_header xlhdr;
	XLogRecPtr	recptr;
	Page		page = BufferGetPage(walinfo->buffer);
	uint8		info = XLOG_ZHEAP_INSERT;
	int			bufflags = 0;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;

	/* zheap doesn't support catalog relations. */
	Assert(!RelationIsAccessibleInLogicalDecoding(relation));

	/*
	 * If this is the single and first tuple on page, we can reinit the page
	 * instead of restoring the whole thing.  Set flag, and hide buffer
	 * references from XLogInsert.
	 */
	if (ItemPointerGetOffsetNumber(&(walinfo->ztuple->t_self)) == FirstOffsetNumber &&
		PageGetMaxOffsetNumber(page) == FirstOffsetNumber)
	{
		info |= XLOG_ZHEAP_INIT_PAGE;
		bufflags |= REGBUF_WILL_INIT;
	}

	/*
	 * Store the information required to generate undo record during replay if
	 * required.
	 */
	if (!skip_undo)
	{
		xlundohdr.reloid = relation->rd_id;
		xlundohdr.urec_ptr = walinfo->urecptr;
		xlundohdr.blkprev = walinfo->prev_urecptr;
	}

	/* Heap related part. */
	xlrec.offnum = ItemPointerGetOffsetNumber(&walinfo->ztuple->t_self);
	xlrec.flags = 0;

	if (walinfo->all_visible_cleared)
		xlrec.flags |= XLZ_INSERT_ALL_VISIBLE_CLEARED;
	if (options & ZHEAP_INSERT_SPECULATIVE)
		xlrec.flags |= XLZ_INSERT_IS_SPECULATIVE;
	if (skip_undo)
		xlrec.flags |= XLZ_INSERT_IS_FROZEN;
	Assert(ItemPointerGetBlockNumber(&(walinfo->ztuple->t_self)) == BufferGetBlockNumber(walinfo->buffer));

	/*
	 * For logical decoding, we need the tuple even if we're doing a full page
	 * write, so make sure it's included even if we take a full-page image.
	 * (XXX We could alternatively store a pointer into the FPW).
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
		LogUndoMetaData(walinfo->undometa);
	}

	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

	XLogBeginInsert();
	XLogRegisterData((char *) &xlrec, SizeOfZHeapInsert);

	/* Register undo data only if required. */
	if (!skip_undo)
		XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);

	if (walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		/*
		 * We can't have a valid transaction slot when we are skipping undo.
		 */
		Assert(!skip_undo);
		xlrec.flags |= XLZ_INSERT_CONTAINS_TPD_SLOT;
		XLogRegisterData((char *) &walinfo->new_trans_slot_id,
						 sizeof(walinfo->new_trans_slot_id));
	}

	xlhdr.t_infomask2 = walinfo->ztuple->t_data->t_infomask2;
	xlhdr.t_infomask = walinfo->ztuple->t_data->t_infomask;
	xlhdr.t_hoff = walinfo->ztuple->t_data->t_hoff;

	/*
	 * note we mark xlhdr as belonging to buffer; if XLogInsert decides to
	 * write the whole page to the xlog, we don't need to store xl_heap_header
	 * in the xlog.
	 */
	XLogRegisterBuffer(0, walinfo->buffer, REGBUF_STANDARD | bufflags);
	XLogRegisterBufData(0, (char *) &xlhdr, SizeOfZHeapHeader);
	/* write bitmap + data */
	XLogRegisterBufData(0,
						(char *) walinfo->ztuple->t_data + SizeofZHeapTupleHeader,
						walinfo->ztuple->t_len - SizeofZHeapTupleHeader);
	if (xlrec.flags & XLZ_INSERT_CONTAINS_TPD_SLOT)
		(void) RegisterTPDBuffer(page, 1);
	RegisterUndoLogBuffers(2);

	/* filtering by origin on a row level is much more efficient */
	XLogSetRecordFlags(XLOG_INCLUDE_ORIGIN);

	recptr = XLogInsertExtended(RM_ZHEAP_ID, info, RedoRecPtr, doPageWrites);
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

/*
 * log_zheap_update - Perform XLogInsert for a zheap-update operation.
 *
 * We need to store enough information in the WAL record so that undo records
 * can be regenerated at the WAL replay time.
 *
 * Caller must already have modified the buffer(s) and marked them dirty.
 *
 * old_walinfo has the necessary wal information about the existing tuple which is being updated.
 *
 * new_walinfo has the necessary wal information about the new tuple which
 * is inserted in case of a non-inplace update.
 */
static void
log_zheap_update(ZHeapWALInfo *old_walinfo, ZHeapWALInfo *new_walinfo,
				 bool inplace_update)
{
	xl_undo_header xlundohdr,
				xlnewundohdr;
	xl_zheap_header xlundotuphdr,
				xlhdr;
	xl_zheap_update xlrec;
	ZHeapTuple	difftup;
	ZHeapTupleHeader zhtuphdr;
	uint16		prefix_suffix[2];
	uint16		prefixlen = 0,
				suffixlen = 0;
	XLogRecPtr	recptr;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;
	char	   *oldp = NULL;
	char	   *newp = NULL;
	int			oldlen,
				newlen;
	int			bufflags = REGBUF_STANDARD;
	uint8		info = XLOG_ZHEAP_UPDATE;

	zhtuphdr = (ZHeapTupleHeader) old_walinfo->undorecord->uur_tuple.data;

	if (inplace_update)
	{
		/*
		 * For inplace updates the old tuple is in undo record and the new
		 * tuple is replaced in page where old tuple was present.
		 */
		oldp = (char *) zhtuphdr + zhtuphdr->t_hoff;
		oldlen = old_walinfo->undorecord->uur_tuple.len - zhtuphdr->t_hoff;
		newp = (char *) old_walinfo->ztuple->t_data + old_walinfo->ztuple->t_data->t_hoff;
		newlen = old_walinfo->ztuple->t_len - old_walinfo->ztuple->t_data->t_hoff;

		difftup = old_walinfo->ztuple;
	}
	else if (old_walinfo->buffer == new_walinfo->buffer)
	{
		oldp = (char *) old_walinfo->ztuple->t_data + old_walinfo->ztuple->t_data->t_hoff;
		oldlen = old_walinfo->ztuple->t_len - old_walinfo->ztuple->t_data->t_hoff;
		newp = (char *) new_walinfo->ztuple->t_data + new_walinfo->ztuple->t_data->t_hoff;
		newlen = new_walinfo->ztuple->t_len - new_walinfo->ztuple->t_data->t_hoff;

		difftup = new_walinfo->ztuple;
	}
	else
	{
		difftup = new_walinfo->ztuple;
	}

	/*
	 * See log_heap_update to know under what some circumstances we can use
	 * prefix-suffix compression.
	 */
	if (old_walinfo->buffer == new_walinfo->buffer
		&& !XLogCheckBufferNeedsBackup(new_walinfo->buffer))
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
	 * Store the information required to generate undo record during replay.
	 */
	xlundohdr.reloid = old_walinfo->undorecord->uur_reloid;
	xlundohdr.urec_ptr = old_walinfo->urecptr;
	xlundohdr.blkprev = old_walinfo->undorecord->uur_blkprev;

	xlrec.prevxid = old_walinfo->undorecord->uur_prevxid;
	xlrec.old_offnum = ItemPointerGetOffsetNumber(&old_walinfo->ztuple->t_self);
	xlrec.old_infomask = old_walinfo->ztuple->t_data->t_infomask;
	xlrec.old_trans_slot_id = old_walinfo->new_trans_slot_id;
	xlrec.new_offnum = ItemPointerGetOffsetNumber(&difftup->t_self);
	xlrec.flags = 0;
	if (old_walinfo->all_visible_cleared)
		xlrec.flags |= XLZ_UPDATE_OLD_ALL_VISIBLE_CLEARED;
	if (new_walinfo->all_visible_cleared)
		xlrec.flags |= XLZ_UPDATE_NEW_ALL_VISIBLE_CLEARED;
	if (prefixlen > 0)
		xlrec.flags |= XLZ_UPDATE_PREFIX_FROM_OLD;
	if (suffixlen > 0)
		xlrec.flags |= XLZ_UPDATE_SUFFIX_FROM_OLD;
	if (old_walinfo->undorecord->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SUBXACT)
		xlrec.flags |= XLZ_UPDATE_CONTAINS_SUBXACT;

	if (!inplace_update)
	{
		Page		page = BufferGetPage(new_walinfo->buffer);

		xlrec.flags |= XLZ_NON_INPLACE_UPDATE;

		xlnewundohdr.reloid = new_walinfo->undorecord->uur_reloid;
		xlnewundohdr.urec_ptr = new_walinfo->urecptr;
		xlnewundohdr.blkprev = new_walinfo->undorecord->uur_blkprev;

		Assert(new_walinfo->ztuple);
		/* If new tuple is the single and first tuple on page... */
		if (ItemPointerGetOffsetNumber(&(new_walinfo->ztuple->t_self)) == FirstOffsetNumber &&
			PageGetMaxOffsetNumber(page) == FirstOffsetNumber)
		{
			info |= XLOG_ZHEAP_INIT_PAGE;
			bufflags |= REGBUF_WILL_INIT;
		}
	}

	/*
	 * If full_page_writes is enabled, and the buffer image is not included in
	 * the WAL then we can rely on the tuple in the page to regenerate the
	 * undo tuple during recovery.  For detail comments related to handling of
	 * full_page_writes get changed at run time, refer comments in
	 * zheap_delete.
	 */
prepare_xlog:
	/* LOG undolog meta if this is the first WAL after the checkpoint. */
	LogUndoMetaData(new_walinfo->undometa);

	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
	if (!doPageWrites || XLogCheckBufferNeedsBackup(old_walinfo->buffer))
	{
		xlrec.flags |= XLZ_HAS_UPDATE_UNDOTUPLE;

		xlundotuphdr.t_infomask2 = zhtuphdr->t_infomask2;
		xlundotuphdr.t_infomask = zhtuphdr->t_infomask;
		xlundotuphdr.t_hoff = zhtuphdr->t_hoff;
	}

	XLogBeginInsert();
	XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
	XLogRegisterData((char *) &xlrec, SizeOfZHeapUpdate);
	if (old_walinfo->prior_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		xlrec.flags |= XLZ_UPDATE_OLD_CONTAINS_TPD_SLOT;
		XLogRegisterData((char *) &(old_walinfo->prior_trans_slot_id),
						 sizeof(old_walinfo->prior_trans_slot_id));
	}
	if (!inplace_update)
	{
		XLogRegisterData((char *) &xlnewundohdr, SizeOfUndoHeader);
		if (new_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			xlrec.flags |= XLZ_UPDATE_NEW_CONTAINS_TPD_SLOT;
			XLogRegisterData((char *) &new_walinfo->new_trans_slot_id,
							 sizeof(new_walinfo->new_trans_slot_id));
		}
	}
	if (xlrec.flags & XLZ_HAS_UPDATE_UNDOTUPLE)
	{
		XLogRegisterData((char *) &xlundotuphdr, SizeOfZHeapHeader);
		/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
		XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
						 old_walinfo->undorecord->uur_tuple.len - SizeofZHeapTupleHeader);
	}

	XLogRegisterBuffer(0, new_walinfo->buffer, bufflags);
	if (old_walinfo->buffer != new_walinfo->buffer)
	{
		uint8		block_id;

		XLogRegisterBuffer(1, old_walinfo->buffer, REGBUF_STANDARD);
		block_id = 2;
		if (old_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			block_id = RegisterTPDBuffer(BufferGetPage(old_walinfo->buffer), block_id);
		if (new_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			RegisterTPDBuffer(BufferGetPage(new_walinfo->buffer), block_id);
	}
	else
	{
		if (old_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			/*
			 * Block id '1' is reserved for old_walinfo->buffer if that is
			 * different from new_walinfo->buffer.
			 */
			RegisterTPDBuffer(BufferGetPage(old_walinfo->buffer), 2);
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

	if (new_walinfo->buffer != old_walinfo->buffer)
	{
		PageSetLSN(BufferGetPage(new_walinfo->buffer), recptr);
		if (new_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			TPDPageSetLSN(BufferGetPage(new_walinfo->buffer), recptr);
	}
	PageSetLSN(BufferGetPage(old_walinfo->buffer), recptr);
	if (old_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		TPDPageSetLSN(BufferGetPage(old_walinfo->buffer), recptr);
	UndoLogBuffersSetLSN(recptr);
}


/*
 * log_zheap_delete - Perform XLogInsert for a zheap-delete operation.
 */
static void
log_zheap_delete(ZHeapWALInfo *walinfo, bool changingPart,
				 SubTransactionId subxid, TransactionId tup_xid)
{
	ZHeapTupleHeader zhtuphdr = NULL;
	xl_undo_header xlundohdr;
	xl_zheap_delete xlrec;
	xl_zheap_header xlhdr;
	XLogRecPtr	recptr;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;
	Page		page = BufferGetPage(walinfo->buffer);

	/* Store the information required to generate undo record during replay. */
	xlundohdr.reloid = walinfo->undorecord->uur_reloid;
	xlundohdr.urec_ptr = walinfo->urecptr;
	xlundohdr.blkprev = walinfo->prev_urecptr;

	xlrec.prevxid = tup_xid;
	xlrec.offnum = ItemPointerGetOffsetNumber(&walinfo->ztuple->t_self);
	xlrec.infomask = walinfo->ztuple->t_data->t_infomask;
	xlrec.trans_slot_id = walinfo->new_trans_slot_id;
	xlrec.flags = walinfo->all_visible_cleared ? XLZ_DELETE_ALL_VISIBLE_CLEARED : 0;

	if (changingPart)
		xlrec.flags |= XLZ_DELETE_IS_PARTITION_MOVE;
	if (subxid != InvalidSubTransactionId)
		xlrec.flags |= XLZ_DELETE_CONTAINS_SUBXACT;

	/*
	 * If full_page_writes is enabled, and the buffer image is not included in
	 * the WAL then we can rely on the tuple in the page to regenerate the
	 * undo tuple during recovery as the tuple state must be same as now,
	 * otherwise we need to store it explicitly.
	 *
	 * Since we don't yet have the insert lock, including the page image
	 * decision could change later and in that case we need prepare the WAL
	 * record again.
	 */
prepare_xlog:
	/* LOG undolog meta if this is the first WAL after the checkpoint. */
	LogUndoMetaData(walinfo->undometa);

	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
	if (!doPageWrites || XLogCheckBufferNeedsBackup(walinfo->buffer))
	{
		xlrec.flags |= XLZ_HAS_DELETE_UNDOTUPLE;

		zhtuphdr = (ZHeapTupleHeader) walinfo->undorecord->uur_tuple.data;

		xlhdr.t_infomask2 = zhtuphdr->t_infomask2;
		xlhdr.t_infomask = zhtuphdr->t_infomask;
		xlhdr.t_hoff = zhtuphdr->t_hoff;
	}
	if (walinfo->prior_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		xlrec.flags |= XLZ_DELETE_CONTAINS_TPD_SLOT;

	XLogBeginInsert();
	XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
	XLogRegisterData((char *) &xlrec, SizeOfZHeapDelete);
	if (xlrec.flags & XLZ_DELETE_CONTAINS_TPD_SLOT)
		XLogRegisterData((char *) &walinfo->prior_trans_slot_id,
						 sizeof(walinfo->prior_trans_slot_id));
	if (xlrec.flags & XLZ_HAS_DELETE_UNDOTUPLE)
	{
		XLogRegisterData((char *) &xlhdr, SizeOfZHeapHeader);
		/* PG73FORMAT: write bitmap [+ padding] [+ oid] + data */
		XLogRegisterData((char *) zhtuphdr + SizeofZHeapTupleHeader,
						 walinfo->undorecord->uur_tuple.len - SizeofZHeapTupleHeader);
	}

	XLogRegisterBuffer(0, walinfo->buffer, REGBUF_STANDARD);
	if (walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
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
	if (walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		TPDPageSetLSN(page, recptr);
	UndoLogBuffersSetLSN(recptr);
}

/*
 * log_zheap_multi_insert
 * Perform XLogInsert for a zheap multi-insert operation.
 *
 * We need to store enough information in the WAL record so that undo records
 * can be regenerated at the WAL replay time.
 *
 * Caller must already have modified the buffer(s) and marked them dirty.
 *
 * multi_walinfo - all the information required to insert WAL
 * skip_undo - is undo insertion skipped?
 * scratch - pre-allocated scratch space for WAL construction
 */
static void
log_zheap_multi_insert(ZHeapMultiInsertWALInfo *multi_walinfo, bool skip_undo,
					   char *scratch)
{
	xl_undo_header xlundohdr;
	XLogRecPtr	recptr;
	xl_zheap_multi_insert *xlrec;
	uint8		info = XLOG_ZHEAP_MULTI_INSERT;
	char	   *tupledata;
	char	   *scratchptr = scratch;
	int			bufflags = 0,
				i,
				totaldatalen;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites,
				init,
				need_tuple_data = RelationIsLogicallyLogged(multi_walinfo->relation);
	Page		page = BufferGetPage(multi_walinfo->gen_walinfo->buffer);

	/*
	 * Store the information required to generate undo record during replay.
	 * All undo records have same information apart from the payload data.
	 * Hence, we can copy the same from the last record.
	 */
	xlundohdr.reloid = multi_walinfo->relation->rd_id;
	xlundohdr.urec_ptr = multi_walinfo->gen_walinfo->urecptr;
	xlundohdr.blkprev = multi_walinfo->gen_walinfo->prev_urecptr;

	/* allocate xl_zheap_multi_insert struct from the scratch area */
	xlrec = (xl_zheap_multi_insert *) scratchptr;
	xlrec->flags = multi_walinfo->gen_walinfo->all_visible_cleared ?
		XLZ_INSERT_ALL_VISIBLE_CLEARED : 0;
	if (skip_undo)
		xlrec->flags |= XLZ_INSERT_IS_FROZEN;
	xlrec->ntuples = multi_walinfo->curpage_ntuples;
	scratchptr += SizeOfZHeapMultiInsert;

	/* copy the offset ranges as well */
	memcpy((char *) scratchptr,
		   (char *) &multi_walinfo->zfree_offsets->nranges,
		   sizeof(int));
	scratchptr += sizeof(int);
	for (i = 0; i < multi_walinfo->zfree_offsets->nranges; i++)
	{
		memcpy((char *) scratchptr,
			   (char *) &multi_walinfo->zfree_offsets->startOffset[i],
			   sizeof(OffsetNumber));
		scratchptr += sizeof(OffsetNumber);
		memcpy((char *) scratchptr,
			   (char *) &multi_walinfo->zfree_offsets->endOffset[i],
			   sizeof(OffsetNumber));
		scratchptr += sizeof(OffsetNumber);
	}

	/* the rest of the scratch space is used for tuple data */
	tupledata = scratchptr;

	/*
	 * Write out an xl_multi_insert_tuple and the tuple data itself for each
	 * tuple.
	 */
	for (i = 0; i < multi_walinfo->curpage_ntuples; i++)
	{
		ZHeapTuple	zheaptup = multi_walinfo->ztuples[multi_walinfo->ndone + i];
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
	 * Signal that this is the last xl_zheap_multi_insert record emitted by
	 * this call to zheap_multi_insert(). Needed for logical decoding so it
	 * knows when to cleanup temporary data.
	 */
	if (multi_walinfo->ndone + multi_walinfo->curpage_ntuples ==
		multi_walinfo->ntuples)
		xlrec->flags |= XLZ_INSERT_LAST_IN_MULTI;

	/*
	 * If the page was previously empty, we can reinitialize the page instead
	 * of restoring the whole thing.
	 */
	init = (ItemPointerGetOffsetNumber(&(multi_walinfo->ztuples[multi_walinfo->ndone]->t_self)) ==
			FirstOffsetNumber &&
			PageGetMaxOffsetNumber(page) ==
			FirstOffsetNumber + multi_walinfo->curpage_ntuples - 1);

	if (init)
	{
		info |= XLOG_ZHEAP_INIT_PAGE;
		bufflags |= REGBUF_WILL_INIT;
	}

	/*
	 * If we're doing logical decoding, include the new tuple data even if we
	 * take a full-page image of the page.
	 */
	if (need_tuple_data)
		bufflags |= REGBUF_KEEP_DATA;

prepare_xlog:
	/* LOG undolog meta if this is the first WAL after the checkpoint. */
	LogUndoMetaData(multi_walinfo->gen_walinfo->undometa);
	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);

	XLogBeginInsert();
	/* copy undo related info in maindata */
	XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
	/* copy xl_multi_insert_tuple in maindata */
	XLogRegisterData((char *) xlrec, tupledata - scratch);

	/* If we've skipped undo insertion, we don't need a slot in page. */
	if (!skip_undo &&
		multi_walinfo->gen_walinfo->new_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
	{
		xlrec->flags |= XLZ_INSERT_CONTAINS_TPD_SLOT;
		XLogRegisterData((char *) &multi_walinfo->gen_walinfo->new_trans_slot_id,
						 sizeof(multi_walinfo->gen_walinfo->new_trans_slot_id));
	}
	XLogRegisterBuffer(0, multi_walinfo->gen_walinfo->buffer,
					   REGBUF_STANDARD | bufflags);

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

/*
 * log_zheap_lock_tuple
 * Used in zheap_lock_tuple_guts and zheap_update to perform XLogInsert of lock.
 *
 * We need to store enough information in the WAL record so that undo records
 * can be regenerated at the WAL replay time.
 */
static void
log_zheap_lock_tuple(ZHeapWALInfo *walinfo, TransactionId tup_xid,
					 int trans_slot_id, bool hasSubXactLock, LockTupleMode mode)
{
	Page		page = BufferGetPage(walinfo->buffer);
	xl_zheap_lock xlrec;
	xl_undo_header xlundohdr;
	XLogRecPtr	recptr;
	XLogRecPtr	RedoRecPtr;
	bool		doPageWrites;

	/* Store the information required to generate undo record during replay. */
	xlundohdr.reloid = walinfo->undorecord->uur_reloid;
	xlundohdr.urec_ptr = walinfo->urecptr;
	xlundohdr.blkprev = walinfo->prev_urecptr;

	xlrec.prev_xid = tup_xid;
	xlrec.offnum = ItemPointerGetOffsetNumber(&(walinfo->ztuple->t_self));
	xlrec.infomask = walinfo->ztuple->t_data->t_infomask;
	xlrec.trans_slot_id = walinfo->new_trans_slot_id;
	xlrec.flags = 0;
	if (walinfo->new_trans_slot_id != trans_slot_id)
	{
		Assert(walinfo->new_trans_slot_id == walinfo->prior_trans_slot_id);
		xlrec.flags |= XLZ_LOCK_TRANS_SLOT_FOR_UREC;
	}
	else if (walinfo->prior_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		xlrec.flags |= XLZ_LOCK_CONTAINS_TPD_SLOT;

	if (hasSubXactLock)
		xlrec.flags |= XLZ_LOCK_CONTAINS_SUBXACT;

	if (walinfo->undorecord->uur_type == UNDO_XID_LOCK_FOR_UPDATE)
		xlrec.flags |= XLZ_LOCK_FOR_UPDATE;

prepare_xlog:
	/* LOG undolog meta if this is the first WAL after the checkpoint. */
	LogUndoMetaData(walinfo->undometa);

	GetFullPageWriteInfo(&RedoRecPtr, &doPageWrites);
	XLogBeginInsert();
	XLogRegisterBuffer(0, walinfo->buffer, REGBUF_STANDARD);
	if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		(void) RegisterTPDBuffer(page, 1);
	XLogRegisterData((char *) &xlundohdr, SizeOfUndoHeader);
	XLogRegisterData((char *) &xlrec, SizeOfZHeapLock);
	RegisterUndoLogBuffers(2);

	/*
	 * We always include old tuple header for undo in WAL record irrespective
	 * of full page image is taken or not. This is done since savings for not
	 * including a zheap tuple header are less compared to code complexity.
	 * However in future, if required we can do it similar to what we have
	 * done in zheap_update or zheap_delete.
	 */
	XLogRegisterData((char *) walinfo->undorecord->uur_tuple.data,
					 SizeofZHeapTupleHeader);
	XLogRegisterData((char *) &mode, sizeof(LockTupleMode));

	if (xlrec.flags & XLZ_LOCK_TRANS_SLOT_FOR_UREC)
		XLogRegisterData((char *) &trans_slot_id, sizeof(trans_slot_id));
	else if (xlrec.flags & XLZ_LOCK_CONTAINS_TPD_SLOT)
		XLogRegisterData((char *) &(walinfo->prior_trans_slot_id),
						 sizeof(walinfo->prior_trans_slot_id));

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

/*
 * ZHeapDetermineModifiedColumns - Check which columns are being updated.
 *	This is same as HeapDetermineModifiedColumns except that it takes
 *	ZHeapTuple as input.
 */
static Bitmapset *
ZHeapDetermineModifiedColumns(Relation relation, Bitmapset *interesting_cols,
							  ZHeapTuple oldtup, ZHeapTuple newtup)
{
	return zheap_tuple_attr_equals(RelationGetDescr(relation),
								   interesting_cols,
								   oldtup,
								   newtup);
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
void
GetTransactionSlotInfo(Buffer buf, OffsetNumber offset, int trans_slot_id,
					   bool NoTPDBufLock, bool TPDSlot,
					   ZHeapTupleTransInfo *zinfo)
{
	ZHeapPageOpaque opaque;
	Page		page;
	PageHeader	phdr PG_USED_FOR_ASSERTS_ONLY;
	uint32		epoch = 0;

	zinfo->trans_slot = trans_slot_id;
	zinfo->cid = InvalidCommandId;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Fetch the required information from the transaction slot. The
	 * transaction slot can either be on the heap page or TPD page.
	 */
	if (trans_slot_id == ZHTUP_SLOT_FROZEN)
	{
		zinfo->xid = InvalidTransactionId;
		zinfo->urec_ptr = InvalidUndoRecPtr;
	}
	else if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
			 (trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
			  !ZHeapPageHasTPDSlot(phdr)))
	{
		TransInfo  *thistrans = &opaque->transinfo[trans_slot_id - 1];

		epoch = EpochFromFullTransactionId(thistrans->fxid);
		zinfo->xid = XidFromFullTransactionId(thistrans->fxid);
		zinfo->urec_ptr = thistrans->urec_ptr;
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
			zinfo->trans_slot =
				TPDPageGetTransactionSlotInfo(buf,
											  trans_slot_id,
											  InvalidOffsetNumber,
											  &epoch,
											  &zinfo->xid,
											  &zinfo->urec_ptr,
											  NoTPDBufLock,
											  false);
		}
		else
		{
			Assert(offset != InvalidOffsetNumber);
			zinfo->trans_slot =
				TPDPageGetTransactionSlotInfo(buf,
											  trans_slot_id,
											  offset,
											  &epoch,
											  &zinfo->xid,
											  &zinfo->urec_ptr,
											  NoTPDBufLock,
											  false);
		}
	}

	zinfo->epoch_xid = FullTransactionIdFromEpochAndXid(epoch, zinfo->xid);
}

/*
 * PageSetUNDO - Set the transaction information pointer for a given
 *		transaction slot.
 */
void
PageSetUNDO(UnpackedUndoRecord undorecord, Buffer buffer, int trans_slot_id,
			bool set_tpd_map_slot, FullTransactionId fxid,
			UndoRecPtr urecptr, OffsetNumber *usedoff, int ucnt)
{
	ZHeapPageOpaque opaque;
	Page		page = BufferGetPage(buffer);
	PageHeader	phdr;

	Assert(trans_slot_id != InvalidXactSlotId);

	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/*
	 * Set the required information in the transaction slot. The transaction
	 * slot can either be on the heap page or TPD page.
	 *
	 * During recovery, we set the required information in TPD separately only
	 * if required.
	 */
	if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
		(trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
		 !ZHeapPageHasTPDSlot(phdr)))
	{
		TransInfo  *thistrans = &opaque->transinfo[trans_slot_id - 1];

		thistrans->fxid = fxid;
		thistrans->urec_ptr = urecptr;
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

		TPDPageSetUndo(buffer, trans_slot_id, set_tpd_map_slot, fxid,
					   urecptr, usedoff, ucnt);
	}

	elog(DEBUG1, "undo record: TransSlot: %d, Epoch: %d, TransactionId: %d, urec: " UndoRecPtrFormat ", prev_urec: " UndoRecPtrFormat ", block: %d, offset: %d, undo_op: %d, xid_tup: %d, reloid: %d",
		 trans_slot_id, EpochFromFullTransactionId(fxid),
		 XidFromFullTransactionId(fxid),
		 urecptr, undorecord.uur_blkprev, undorecord.uur_block, undorecord.uur_offset, undorecord.uur_type,
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
	ZHeapPageOpaque opaque;
	Page		page;
	PageHeader	phdr;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	if (trans_slot_id < ZHEAP_PAGE_TRANS_SLOTS ||
		(trans_slot_id == ZHEAP_PAGE_TRANS_SLOTS &&
		 !ZHeapPageHasTPDSlot(phdr)))
	{
		TransInfo  *thistrans = &opaque->transinfo[trans_slot_id - 1];

		thistrans->fxid = FullTransactionIdFromEpochAndXid(epoch, xid);
		thistrans->urec_ptr = urec_ptr;
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
 * buffer then do so.  tpd_page_locked will be set to true if the required page
 * is locked, false, otherwise.
 */
int
PageGetTransactionSlotId(Relation rel, Buffer buf, FullTransactionId fxid,
						 UndoRecPtr *urec_ptr, bool keepTPDBufLock,
						 bool locktpd, bool *tpd_page_locked)
{
	ZHeapPageOpaque opaque;
	Page		page;
	PageHeader	phdr;
	int			slot_no;
	int			total_slots_in_page;
	bool		check_tpd;

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
		TransInfo  *thistrans = &opaque->transinfo[slot_no];

		if (FullTransactionIdEquals(thistrans->fxid, fxid))
		{
			*urec_ptr = thistrans->urec_ptr;

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
		int			tpd_e_slot;

		tpd_e_slot = TPDPageGetSlotIfExists(rel, buf, InvalidOffsetNumber,
											fxid, urec_ptr,
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
		 * Lock the TPD page if the caller has instructed so and the page has
		 * tpd slot.
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
	ZHeapPageOpaque opaque;
	Page		page;
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
		TransInfo  *thistrans = &opaque->transinfo[slot_no - 1];

		if (epoch)
			*epoch = EpochFromFullTransactionId(thistrans->fxid);
		if (xid)
			*xid = XidFromFullTransactionId(thistrans->fxid);
		if (urec_ptr)
			*urec_ptr = thistrans->urec_ptr;
	}
	else
	{
		Assert((ZHeapPageHasTPDSlot(phdr)));
		(void) TPDPageGetTransactionSlotInfo(buf,
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
						  FullTransactionId fxid,
						  UndoRecPtr *oldbuf_prev_urecptr,
						  UndoRecPtr *newbuf_prev_urecptr,
						  int *oldbuf_trans_slot_id,
						  int *newbuf_trans_slot_id,
						  bool *lock_reacquired)
{
	bool		always_extend;
	bool		is_tpdblk_order_changed;
	int			slot_id;
	BlockNumber tmp_new_tpd_blk,
				tmp_old_tpd_blk;
	BlockNumber oldbuf_tpd_blk PG_USED_FOR_ASSERTS_ONLY = InvalidBlockNumber;
	Page		old_heap_page,
				new_heap_page;

	old_heap_page = BufferGetPage(oldbuf);
	new_heap_page = BufferGetPage(newbuf);

	/*
	 * If previously reserved slot is from TPD then we should have TPD page
	 * into heap buffer.
	 */
	Assert(*oldbuf_trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS ||
		   ZHeapPageHasTPDSlot((PageHeader) old_heap_page));

	/* If TPD exist, then get corresponding TPD block number for old buffer. */
	if (ZHeapPageHasTPDSlot((PageHeader) old_heap_page))
		GetTPDBlockAndOffset(old_heap_page, &oldbuf_tpd_blk, NULL);
	tmp_old_tpd_blk = oldbuf_tpd_blk;

retry_tpd_lock:

	/* Initialize flags with default values. */
	always_extend = false;
	is_tpdblk_order_changed = false;

	/*
	 * Only if previously reserved slot is from TPD or last slot and now we
	 * have TPD, then we will check that we can verify slot on old buffer
	 * first or we should get slot for new buffer first.
	 */
	if (*oldbuf_trans_slot_id >= ZHEAP_PAGE_TRANS_SLOTS &&
		ZHeapPageHasTPDSlot((PageHeader) old_heap_page))
	{
		/*
		 * If TPD exists on both the buffers then reserve the slot in the
		 * increasing order of TPD blocks to avoid deadlock.
		 */
		if (ZHeapPageHasTPDSlot((PageHeader) new_heap_page))
		{
			GetTPDBlockAndOffset(new_heap_page, &tmp_new_tpd_blk, NULL);

			/*
			 * If both the buffers has TPD entry, then reserve the transaction
			 * slot in increasing order of corresponding TPD blocks to avoid
			 * deadlock.
			 */
			if (tmp_old_tpd_blk > tmp_new_tpd_blk)
				is_tpdblk_order_changed = true;
		}
	}

	/* Now reserve the slots in both the pages. */
	if (!is_tpdblk_order_changed)
	{
		/* Verify the transaction slot for old buffer. */
		slot_id = PageReserveTransactionSlot(relation,
											 oldbuf,
											 oldbuf_offnum,
											 fxid,
											 oldbuf_prev_urecptr,
											 lock_reacquired,
											 false,
											 InvalidBuffer,
											 NULL);

		/*
		 * If old buffer has TPD page, then TPD block of old buffer should not
		 * change. We must get a valid slot and wouldn't have reacquired the
		 * buffer lock as we already have a reserved slot.
		 */
		if (oldbuf_tpd_blk != InvalidBlockNumber)
			GetTPDBlockAndOffset(old_heap_page, &tmp_old_tpd_blk, NULL);

		Assert(!(*lock_reacquired));
		Assert(slot_id != InvalidXactSlotId);
		Assert(oldbuf_tpd_blk == InvalidBlockNumber ||
			   oldbuf_tpd_blk == tmp_old_tpd_blk);

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
														   fxid,
														   newbuf_prev_urecptr,
														   lock_reacquired,
														   always_extend,
														   oldbuf,
														   NULL);
	}
	else
	{
		/* Reserve the transaction slot for new buffer. */
		*newbuf_trans_slot_id = PageReserveTransactionSlot(relation,
														   newbuf,
														   newbuf_offnum + 1,
														   fxid,
														   newbuf_prev_urecptr,
														   lock_reacquired,
														   false,
														   oldbuf,
														   NULL);

		/*
		 * Try again if the buffer lock is released and reacquired. Or if we
		 * are not able to reserve any slot.
		 */
		if (*lock_reacquired || (*newbuf_trans_slot_id == InvalidXactSlotId))
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
			GetTPDBlockAndOffset(new_heap_page, &tmp_new_tpd_blk, NULL);

			/*
			 * If TPD block of new buffer gets changed and becomes greater
			 * than old buffer TPD block, then we should release TPD buffer
			 * lock of new buffer and try again to avoid deadlock.
			 *
			 * For new buffer, there is no guarantee that we will get same TPD
			 * block after releasing TPD buffer lock, because vacuum can free
			 * that page, so always try again to reserve slot.
			 */
			if (tmp_new_tpd_blk > tmp_old_tpd_blk)
			{
				/* Release lock to avoid deadlock. */
				ReleaseLastTPDBufferByTPDBlock(tmp_new_tpd_blk);
				goto retry_tpd_lock;
			}
		}

		/* Get the transaction slot for old buffer. */
		slot_id = PageReserveTransactionSlot(relation,
											 oldbuf,
											 oldbuf_offnum,
											 fxid,
											 oldbuf_prev_urecptr,
											 lock_reacquired,
											 false,
											 InvalidBuffer,
											 NULL);

		/*
		 * TPD block of old buffer must not change as we already have a
		 * reserved slot in the old buffer and for in-progress transactions,
		 * TPD block can't be pruned.  Due to the same reason, we must get a
		 * valid slot and wouldn't have reacquired the buffer lock.
		 */
		GetTPDBlockAndOffset(old_heap_page, &tmp_old_tpd_blk, NULL);
		Assert(!(*lock_reacquired));
		Assert(slot_id != InvalidXactSlotId);
		Assert(oldbuf_tpd_blk == tmp_old_tpd_blk);
	}

	/*
	 * We should definitely get the slot for old page as we have reserved it
	 * previously, but it is possible that it might have moved to TPD in which
	 * case it's value will be previous_slot_number + 1.
	 */
	Assert((slot_id == *oldbuf_trans_slot_id) ||
		   (ZHeapPageHasTPDSlot((PageHeader) old_heap_page) &&
			slot_id == (*oldbuf_trans_slot_id) + 1));

	*oldbuf_trans_slot_id = slot_id;
}

/*
 * PageReserveTransactionSlot - Reserve the transaction slot in page.
 *
 *	This function returns transaction slot number if either the page already
 *	has some slot that contains the transaction info or there is an empty
 *	slot or it manages to reuse some existing slot or it manages to get the
 *  slot in TPD; otherwise returns InvalidXactSlotId.
 *
 *  Note that we always return array location of slot plus one as zeroth slot
 *  number is reserved for frozen slot number (ZHTUP_SLOT_FROZEN).
 *
 *  If we've reserved a transaction slot of a committed but not all-visible
 *  transaction or a transaction slot from a TPD page, we set slot_reused_or_TPD_slot
 *  as true, false otherwise.
 */
int
PageReserveTransactionSlot(Relation relation, Buffer buf, OffsetNumber offset,
						   FullTransactionId fxid,
						   UndoRecPtr *urec_ptr, bool *lock_reacquired,
						   bool always_extend, Buffer other_buf,
						   bool *slot_reused_or_TPD_slot)
{
	ZHeapPageOpaque opaque;
	Page		page;
	PageHeader	phdr;
	int			latestFreeTransSlot = InvalidXactSlotId;
	int			slot_no;
	int			total_slots_in_page;
	bool		check_tpd;

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
	 * For temp relations, we don't have to check all the slots since no other
	 * backend can access the same relation. If a slot is available, we return
	 * it from here. Else, we freeze the slot in PageFreezeTransSlots.
	 *
	 * XXX For temp tables, oldestXidWithEpochHavingUndo is not relevant as
	 * the undo for them can be discarded on commit.  Hence, comparing xid
	 * with oldestXidWithEpochHavingUndo during visibility checks can lead to
	 * incorrect behavior.  To avoid that, we can mark the tuple as frozen for
	 * any previous transaction id.  In that way, we don't have to compare the
	 * previous xid of tuple with oldestXidWithEpochHavingUndo.
	 */
	if (RELATION_IS_LOCAL(relation))
	{
		TransInfo  *thistrans;

		/* We can't access temp tables of other backends. */
		Assert(!RELATION_IS_OTHER_TEMP(relation));

		slot_no = 0;
		thistrans = &opaque->transinfo[slot_no];

		if (FullTransactionIdEquals(thistrans->fxid, fxid))
		{
			*urec_ptr = thistrans->urec_ptr;
			return (slot_no + 1);
		}
		else if (!FullTransactionIdIsValid(thistrans->fxid))
			latestFreeTransSlot = slot_no;
	}
	else
	{
		for (slot_no = 0; slot_no < total_slots_in_page; slot_no++)
		{
			TransInfo  *thistrans = &opaque->transinfo[slot_no];

			if (FullTransactionIdEquals(thistrans->fxid, fxid))
			{
				*urec_ptr = thistrans->urec_ptr;
				return (slot_no + 1);
			}
			else if (!FullTransactionIdIsValid(thistrans->fxid) &&
					 latestFreeTransSlot == InvalidXactSlotId)
				latestFreeTransSlot = slot_no;
		}
	}

	/* Check if we already have a slot on the TPD page */
	if (check_tpd)
	{
		int			tpd_e_slot;

		tpd_e_slot = TPDPageGetSlotIfExists(relation, buf, offset,
											fxid, urec_ptr, true, true);
		if (tpd_e_slot != InvalidXactSlotId)
			return tpd_e_slot;
	}


	if (latestFreeTransSlot >= 0)
	{
		*urec_ptr = opaque->transinfo[latestFreeTransSlot].urec_ptr;
		return (latestFreeTransSlot + 1);
	}

	/* no transaction slot available, try to reuse some existing slot */
	if (PageFreezeTransSlots(relation, buf, lock_reacquired, NULL, 0,
							 other_buf))
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
			TransInfo  *thistrans = &opaque->transinfo[slot_no];

			if (!FullTransactionIdIsValid(thistrans->fxid))
			{
				*urec_ptr = thistrans->urec_ptr;
				if (slot_reused_or_TPD_slot && *urec_ptr != InvalidUndoRecPtr)
					*slot_reused_or_TPD_slot = true;
				return (slot_no + 1);
			}
		}

		/*
		 * After freezing transaction slots, we should get at least one free
		 * slot.
		 */
		Assert(false);
	}
	Assert(!RELATION_IS_LOCAL(relation));

	/*
	 * Reserve the transaction slot in TPD.  First we check if there already
	 * exists an TPD entry for this page, then reserve in that, otherwise,
	 * allocate a new TPD entry and reserve the slot in it.
	 */
	if (ZHeapPageHasTPDSlot(phdr))
	{
		int			tpd_e_slot;

		tpd_e_slot = TPDPageReserveTransSlot(relation, buf, offset,
											 urec_ptr, lock_reacquired,
											 always_extend, other_buf);

		if (tpd_e_slot != InvalidXactSlotId)
		{
			if (slot_reused_or_TPD_slot)
				*slot_reused_or_TPD_slot = true;
			return tpd_e_slot;
		}

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
		{
			if (slot_reused_or_TPD_slot)
				*slot_reused_or_TPD_slot = true;
			return slot_no;
		}
	}

	/* no transaction slot available */
	return InvalidXactSlotId;
}

/*
 * zheap_freeze_or_invalidate_tuples - Clear the slot information or set
 *									   invalid_xact flags.
 *
 * 	Process all the tuples on the page and match their transaction slot with
 *	the input slot array, if tuple is pointing to the slot then set the tuple
 *  slot as ZHTUP_SLOT_FROZEN if is frozen is true otherwise set
 *  ZHEAP_INVALID_XACT_SLOT flag on the tuple
 */
void
zheap_freeze_or_invalidate_tuples(Buffer buf, int nSlots, int *slots,
								  bool isFrozen, bool TPDSlot)
{
	OffsetNumber offnum,
				maxoff;
	Page		page = BufferGetPage(buf);
	int			i;

	/* clear the slot info from tuples */
	maxoff = PageGetMaxOffsetNumber(page);

	for (offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
	{
		ZHeapTupleHeader tup_hdr;
		ItemId		itemid;
		int			trans_slot;

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
			 * from 0, even for TPD slots, the index will start from 0. So
			 * convert it into the slot index.
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
						/*
						 * This must be unused entry which has xact
						 * information.
						 */
						Assert(ItemIdHasPendingXact(itemid));

						/*
						 * The pending xact must be committed if the
						 * corresponding slot is being marked as frozen.  So,
						 * clear the pending xact and transaction slot
						 * information from itemid.
						 */
						ItemIdSetUnused(itemid);
					}
					else if (ItemIdIsDeleted(itemid))
					{
						/*
						 * The deleted item must not be visible to anyone if
						 * the corresponding slot is being marked as frozen.
						 * So, marking it as dead.
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
					 * We just append the invalid xact flag in the
					 * tuple/itemid to indicate that for this tuple/itemid we
					 * need to fetch the transaction information from undo
					 * record.  Also, we ensure to clear the transaction
					 * information from unused itemid.
					 */
					if (!ItemIdIsUsed(itemid))
					{
						/*
						 * This must be unused entry which has xact
						 * information.
						 */
						Assert(ItemIdHasPendingXact(itemid));

						/*
						 * The pending xact is committed.  So, clear the
						 * pending xact and transaction slot information from
						 * itemid.
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
 * PageFreezeTransSlots - Make the transaction slots available for reuse.
 *
 *	This function tries to free up some existing transaction slots so that
 *	they can be reused.  To reuse the slot, it needs to ensure one of the below
 *	conditions:
 *	(a) the xid is committed, all-visible and doesn't have pending rollback
 *	to perform.
 *	(b) if the xid is committed, then ensure to mark a special flag on the
 *	tuples that are modified by that xid on the current page.
 *	(c) if the xid is rolled back, then ensure that rollback is performed or
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
 *	zheap i.e. the tuple always reflect the current state.
 *
 *	We don't need any special handling for the tuples that are locked by
 *	multiple transactions (aka tuples that have MULTI_LOCKERS bit set).
 *	Basically, we always maintain either strongest lockers or latest lockers
 *	(when all the lockers are of same mode) transaction slot on the tuple.
 *	In either case, we should be able to detect the visibility of tuple based
 *	on the latest locker information.
 *
 *	use_aborted_slot indicates whether we can reuse the slot of aborted
 *  transaction or not.
 *
 *	This function assumes that the caller already has Exclusive lock on the
 *	buffer.
 *
 *	other_buf will be valid only in case of non in-place update in two
 *	different buffers and other_buf will be old buffer.  Caller of
 *	MultiPageReserveTransSlot will not try to release lock again.
 *
 *	This function returns true if it manages to free some transaction slot,
 *	false otherwise.
 */
bool
PageFreezeTransSlots(Relation relation, Buffer buf, bool *lock_reacquired,
					 TransInfo *transinfo, int num_slots, Buffer other_buf)
{
	FullTransactionId oldestXidWithEpochHavingUndo;
	int			slot_no;
	int		   *frozen_slots = NULL;
	int			nFrozenSlots = 0;
	int		   *completed_xact_slots = NULL;
	uint16		nCompletedXactSlots = 0;
	int		   *aborted_xact_slots = NULL;
	int			nAbortedXactSlots = 0;
	bool		TPDSlot;
	Page		page;
	bool		result = false;

	page = BufferGetPage(buf);

	/*
	 * If the num_slots is 0 then the caller wants to freeze the page slots so
	 * get the transaction slots information from the page.
	 */
	if (num_slots == 0)
	{
		PageHeader	phdr;
		ZHeapPageOpaque opaque;

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

	oldestXidWithEpochHavingUndo = FullTransactionIdFromU64(
															pg_atomic_read_u64(&ProcGlobal->oldestXidWithEpochHavingUndo));

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
			FullTransactionId slot_fxid = transinfo[slot_no].fxid;

			/*
			 * Transaction slot can be considered frozen if it belongs to
			 * transaction id is old enough that it is all visible.
			 */
			if (FullTransactionIdPrecedes(slot_fxid, oldestXidWithEpochHavingUndo))
				frozen_slots[nFrozenSlots++] = slot_no;
		}
	}

	if (nFrozenSlots > 0)
	{
		FullTransactionId latestfxid = InvalidFullTransactionId;
		int			i;
		int			slot_no;


		START_CRIT_SECTION();

		/* clear the transaction slot info on tuples */
		zheap_freeze_or_invalidate_tuples(buf, nFrozenSlots, frozen_slots,
										  true, TPDSlot);

		/* Initialize the frozen slots. */
		if (TPDSlot)
		{
			for (i = 0; i < nFrozenSlots; i++)
			{
				TransInfo  *thistrans;
				int			tpd_slot_id;

				slot_no = frozen_slots[i];
				thistrans = &transinfo[slot_no];

				/* Remember the latest xid. */
				if (FullTransactionIdFollows(thistrans->fxid, latestfxid))
					latestfxid = thistrans->fxid;

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
				TransInfo  *thistrans;

				slot_no = frozen_slots[i];
				thistrans = &transinfo[slot_no];

				/* Remember the latest xid. */
				if (FullTransactionIdFollows(thistrans->fxid, latestfxid))
					latestfxid = thistrans->fxid;

				thistrans->fxid = InvalidFullTransactionId;
				thistrans->urec_ptr = InvalidUndoRecPtr;
			}
		}

		MarkBufferDirty(buf);

		/*
		 * xlog Stuff
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
			xlrec.lastestFrozenXid = XidFromFullTransactionId(latestfxid);

			XLogRegisterData((char *) &xlrec, SizeOfZHeapFreezeXactSlot);

			/*
			 * Ideally we need the frozen slots information when WAL needs to
			 * be applied on the page, but in case of the TPD slots freeze we
			 * need the frozen slot information for both heap page as well as
			 * for the TPD page.  So the problem is that if we register with
			 * any one of the buffer it might happen that the data did not
			 * registered due to fpw of that buffer but we need that data for
			 * another buffer.
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
		TransactionId slot_xid =
		XidFromFullTransactionId(transinfo[slot_no].fxid);

		if (!TransactionIdIsInProgress(slot_xid))
		{
			if (TransactionIdDidCommit(slot_xid))
				completed_xact_slots[nCompletedXactSlots++] = slot_no;
			else
				aborted_xact_slots[nAbortedXactSlots++] = slot_no;
		}
	}

	if (nCompletedXactSlots > 0)
	{
		int			i;
		int			slot_no;


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
				int			tpd_slot_id;

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
				transinfo[slot_no].fxid = InvalidFullTransactionId;
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
		int			i;
		int			slot_no;
		UndoRecPtr *urecptr = palloc(nAbortedXactSlots * sizeof(UndoRecPtr));
		FullTransactionId *fxid = palloc(nAbortedXactSlots * sizeof(FullTransactionId));

		/* Collect slot information before releasing the lock. */
		for (i = 0; i < nAbortedXactSlots; i++)
		{
			TransInfo  *thistrans = &transinfo[aborted_xact_slots[i]];

			urecptr[i] = thistrans->urec_ptr;
			fxid[i] = thistrans->fxid;
		}

		/*
		 * We need to release and the lock before applying undo actions for a
		 * page as we might need to traverse the long undo chain for a page.
		 */
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

		/*
		 * Release the lock on the other buffer to avoid deadlock as we need
		 * to relock the new buffer again.  We could optimize here by
		 * releasing the lock on old buffer conditionally (when the old block
		 * number is bigger than new block number), but that would complicate
		 * the handling.  If we ever want to deal with it, we need to ensure
		 * that after reacquiring lock on new page, it is still a heap page
		 * and also we need to pass this information to the caller.
		 */
		if (BufferIsValid(other_buf))
			LockBuffer(other_buf, BUFFER_LOCK_UNLOCK);

		/*
		 * XXX We release the TPD buffers here even when we are operating on
		 * heap page slots as we might need to require them during the
		 * processing of undo actions.  We can optimize it by passing some
		 * flag, but that seems over complication as we anyway need to release
		 * and reacquire the lock on TPD buffers after processing the undo
		 * actions.
		 *
		 * It is okay to release all the TPD buffers here as the callers will
		 * anyway reacquire the lock heap and tpd buffers again.
		 *
		 * Instead of just unlocking the TPD buffer like heap buffer its okay
		 * to unlock and release, because next time while trying to reserve
		 * the slot if we get the slot in TPD then anyway we will pin it
		 * again.
		 *
		 * Releasing all TPD buffers can release the TPD buffer which was not
		 * used for current heap page (in case of non-in-place updates via
		 * MultiPageReserveTransSlot), but that is okay because we anyway need
		 * to reacquire heap and TPD buffer locks by the caller. This also
		 * avoids the risk of deadlock where someone acquires the lock on heap
		 * page before we can reacquire it and waits for the TPD lock held by
		 * us, so we will wait on that process to release the lock on heap
		 * page and that process will wait on use.
		 */
		UnlockReleaseTPDBuffers();

		for (i = 0; i < nAbortedXactSlots; i++)
		{
			slot_no = aborted_xact_slots[i] + 1;
			process_and_execute_undo_actions_page(urecptr[i],
												  relation,
												  buf,
												  fxid[i],
												  slot_no);
		}

		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);
		*lock_reacquired = true;

		pfree(urecptr);
		pfree(fxid);

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
 * It is expected that the caller of this function has at least read lock
 * on the buffer.
 */
CommandId
ZHeapTupleGetCid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
				 int trans_slot_id)
{
	UnpackedUndoRecord *urec;
	CommandId	current_cid;
	bool		TPDSlot = true;
	ZHeapTupleTransInfo zinfo;

	/*
	 * For undo tuple caller will pass the valid slot id otherwise we can get
	 * it directly from the tuple.
	 */
	if (trans_slot_id == InvalidXactSlotId)
	{
		trans_slot_id = ZHeapTupleHeaderGetXactSlot(zhtup->t_data);
		TPDSlot = false;
	}

	/*
	 * If urec_ptr is not provided, fetch the latest undo pointer from the
	 * page.
	 */
	if (!UndoRecPtrIsValid(urec_ptr))
	{
		GetTransactionSlotInfo(buf,
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   trans_slot_id,
							   true,
							   TPDSlot,
							   &zinfo);
	}
	else
	{
		GetTransactionSlotInfo(buf,
							   ItemPointerGetOffsetNumber(&zhtup->t_self),
							   trans_slot_id,
							   true,
							   TPDSlot,
							   &zinfo);
		zinfo.urec_ptr = urec_ptr;
	}

	if (zinfo.trans_slot == ZHTUP_SLOT_FROZEN)
		return InvalidCommandId;

	if (FullTransactionIdOlderThanAllUndo(zinfo.epoch_xid))
		return InvalidCommandId;

	Assert(UndoRecPtrIsValid(zinfo.urec_ptr));
	urec = UndoFetchRecord(zinfo.urec_ptr,
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
 * ZHeapTupleGetSubXid - Retrieve subtransaction id from tuple's undo record.
 *
 * It is expected that caller of this function has at least read lock.
 *
 * Note that we don't handle ZHEAP_INVALID_XACT_SLOT as this function is only
 * called for in-progress transactions.  If we need to call it for some other
 * purpose, then we might need to deal with ZHEAP_INVALID_XACT_SLOT.
 */
void
ZHeapTupleGetSubXid(Buffer buf, OffsetNumber offnum, UndoRecPtr urec_ptr,
					SubTransactionId *subxid)
{
	UnpackedUndoRecord *urec;

	*subxid = InvalidSubTransactionId;

	Assert(UndoRecPtrIsValid(urec_ptr));
	urec = UndoFetchRecord(urec_ptr,
						   BufferGetBlockNumber(buf),
						   offnum,
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
		 * For UNDO_UPDATE, we first store the CTID, then transaction slot and
		 * after that subtransaction id in payload.  For UNDO_XID_LOCK_ONLY,
		 * we first store the Lockmode, then transaction slot and after that
		 * subtransaction id.  So retrieve accordingly.
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
 * It is expected that caller of this function has at least read lock
 * on the buffer.
 */
void
ZHeapTupleGetSpecToken(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr,
					   uint32 *specToken)
{
	UnpackedUndoRecord *urec;

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
 * ZHeapTupleHeaderAdvanceLatestRemovedXid - Advance the latestRemovedXid, if
 * tuple is deleted by a transaction greater than latestRemovedXid.  This is
 * required to generate conflicts on hot standby.
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
	 * XXX we can ignore the tuple if it was non-in-place updated/deleted by
	 * the inserting transaction, but for that we need to traverse the
	 * complete undo chain to find the root tuple, is it really worth?
	 */
	if (TransactionIdDidCommit(xid))
	{
		Assert(tuple->t_infomask & ZHEAP_DELETED ||
			   tuple->t_infomask & ZHEAP_UPDATED);
		if (TransactionIdFollows(xid, *latestRemovedXid))
			*latestRemovedXid = xid;
	}

	/* *latestRemovedXid may still be invalid at end */
}

/*
 * zheap_multi_insert	- insert multiple tuple into a zheap
 *
 * Similar to heap_multi_insert(), but inserts zheap tuples.
 */
void
zheap_multi_insert(Relation relation, TupleTableSlot **slots, int ntuples,
				   CommandId cid, int options, BulkInsertState bistate)
{
	ZHeapTuple *zheaptuples;
	int			i;
	int			ndone;
	char	   *scratch = NULL;
	Page		page;
	bool		needwal;
	bool		need_cids = RelationIsAccessibleInLogicalDecoding(relation);
	Size		saveFreeSpace;
	FullTransactionId fxid = GetTopFullTransactionId();
	TransactionId xid = XidFromFullTransactionId(fxid);
	xl_undolog_meta undometa;
	bool		lock_reacquired;
	bool		skip_undo;

	needwal = RelationNeedsWAL(relation);
	saveFreeSpace = RelationGetTargetPageFreeSpace(relation,
												   HEAP_DEFAULT_FILLFACTOR);

	/*
	 * We can skip inserting undo records if the tuples are to be marked as
	 * frozen.
	 */
	skip_undo = (options & ZHEAP_INSERT_FROZEN);

	/* Toast and set header data in all the tuples */
	zheaptuples = palloc(ntuples * sizeof(ZHeapTuple));
	for (i = 0; i < ntuples; i++)
	{
		zheaptuples[i] = zheap_prepare_insert(relation,
											  ExecGetZHeapTupleFromSlot(slots[i]), options, 0);

		if (slots[i]->tts_tableOid != InvalidOid)
			zheaptuples[i]->t_tableOid = slots[i]->tts_tableOid;
	}

	/*
	 * Allocate some memory to use for constructing the WAL record. Using
	 * palloc() within a critical section is not safe, so we allocate this
	 * beforehand. This has consideration that offset ranges and tuples to be
	 * stored in page will have size lesser than BLCKSZ. This is true since a
	 * zheap page contains page header and transaction slots in special area
	 * which are not stored in scratch area. In future, if we reduce the
	 * number of transaction slots to one, we may need to allocate twice the
	 * BLCKSZ of scratch area.
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
		Buffer		buffer;
		Buffer		vmbuffer = InvalidBuffer;
		bool		all_visible_cleared = false;
		int			nthispage = 0;
		int			trans_slot_id = InvalidXactSlotId;
		int			ucnt = 0;
		UndoRecPtr	urecptr = InvalidUndoRecPtr,
					prev_urecptr = InvalidUndoRecPtr;
		UnpackedUndoRecord *undorecord = NULL;
		ZHeapFreeOffsetRanges *zfree_offset_ranges;
		OffsetNumber usedoff[MaxOffsetNumber];
		OffsetNumber max_required_offset;
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
		 * If we're not inserting an undo record, we don't have to reserve a
		 * transaction slot as well.
		 */
		if (!skip_undo)
		{
			/*
			 * The transaction information of tuple needs to be set in
			 * transaction slot, so needs to reserve the slot before
			 * proceeding with the actual operation.  It will be costly to
			 * wait for getting the slot, but we do that by releasing the
			 * buffer lock.
			 */
			trans_slot_id = PageReserveTransactionSlot(relation,
													   buffer,
													   max_required_offset,
													   fxid,
													   &prev_urecptr,
													   &lock_reacquired,
													   false,
													   InvalidBuffer,
													   NULL);
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
			 * For every contiguous free or new offsets, we insert an undo
			 * record. In the payload data of each undo record, we store the
			 * start and end available offset for a contiguous range.
			 */
			undorecord = (UnpackedUndoRecord *) palloc(zfree_offset_ranges->nranges
													   * sizeof(UnpackedUndoRecord));
			/* Start UNDO prepare Stuff */
			urecptr = prev_urecptr;
			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				/* prepare an undo record */
				undorecord[i].uur_rmid = RM_ZHEAP_ID;
				undorecord[i].uur_type = UNDO_MULTI_INSERT;
				undorecord[i].uur_info = 0;
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
							   InvalidFullTransactionId,
							   UndoPersistenceForRelation(relation), NULL, &undometa);

			for (i = 0; i < zfree_offset_ranges->nranges; i++)
			{
				undorecord[i].uur_blkprev = urecptr;
				urecptr = PrepareUndoInsert(&undorecord[i],
											InvalidFullTransactionId,
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
		 * Get the page visibility status from visibility map.  If the page is
		 * all-visible, we need to clear it after inserting the tuple.  Note
		 * that, for newly added pages (vm buffer will be invalid, see
		 * RelationGetBufferForZTuple), vm status must be clear, so we don't
		 * need to do anything for them.
		 */
		if (BufferIsValid(vmbuffer))
			vm_status = visibilitymap_get_status(relation,
												 BufferGetBlockNumber(buffer),
												 &vmbuffer);
		else
			vm_status = 0;

		/*
		 * Lock the TPD page before starting critical section.  We might need
		 * to access it in ZPageAddItemExtended.  Note that if the transaction
		 * slot belongs to TPD entry, then the TPD page must be locked during
		 * slot reservation.
		 *
		 * XXX We can optimize this by avoid taking TPD page lock unless the
		 * page has some unused item which requires us to fetch the
		 * transaction information from TPD.
		 */
		if (trans_slot_id <= ZHEAP_PAGE_TRANS_SLOTS &&
			ZHeapPageHasTPDSlot((PageHeader) page) &&
			PageHasFreeLinePointers((PageHeader) page))
			TPDPageLock(relation, buffer);

		/* No ereport(ERROR) from here till changes are logged */
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

				if (!(options & ZHEAP_INSERT_FROZEN))
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
				 * better be prepared... Fixme: This won't work as it needs to
				 * access cmin/cmax which we probably needs to retrieve from
				 * TPD or UNDO.
				 */
				if (needwal && need_cids)
				{
					/* log_heap_new_cid(relation, heaptup); */
				}
				nthispage++;
			}

			/*
			 * Store the offset ranges in undo payload. We've not calculated
			 * the end offset for the last range previously. Hence, we set it
			 * to offnum - 1. There is no harm in doing the same for previous
			 * undo records as well.
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
			 * We're sending the undo record for debugging purpose. So, just
			 * send the last one.
			 */
			if (trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
			{
				PageSetUNDO(undorecord[zfree_offset_ranges->nranges - 1],
							buffer,
							trans_slot_id,
							true,
							fxid,
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
							fxid,
							urecptr,
							NULL,
							0);
			}
		}

		/* XLOG stuff */
		if (needwal)
		{
			ZHeapMultiInsertWALInfo ins_wal_info;
			ZHeapWALInfo gen_wal_info;

			gen_wal_info.buffer = buffer;
			gen_wal_info.ztuple = NULL;
			gen_wal_info.urecptr = urecptr;
			gen_wal_info.prev_urecptr = prev_urecptr;
			gen_wal_info.undometa = &undometa;
			gen_wal_info.new_trans_slot_id = trans_slot_id;
			gen_wal_info.prior_trans_slot_id = InvalidXactSlotId;
			gen_wal_info.all_visible_cleared = all_visible_cleared;
			gen_wal_info.undorecord = NULL;

			ins_wal_info.gen_walinfo = &gen_wal_info;
			ins_wal_info.relation = relation;
			ins_wal_info.ztuples = zheaptuples;
			ins_wal_info.zfree_offsets = zfree_offset_ranges;
			ins_wal_info.ntuples = ntuples;
			ins_wal_info.curpage_ntuples = nthispage;
			ins_wal_info.ndone = ndone;

			log_zheap_multi_insert(&ins_wal_info, skip_undo, scratch);
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
	 * Copy t_self fields back to the caller's original tuples. This does
	 * nothing for untoasted tuples (tuples[i] == heaptuples[i)], but it's
	 * probably faster to always copy than check.
	 */
	for (i = 0; i < ntuples; i++)
		slots[i]->tts_tid = zheaptuples[i]->t_self;

	pgstat_count_heap_insert(relation, ntuples);
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
		 * We always need to make a copy of zheap tuple; if an older version
		 * is returned from the undo record, the passed in tuple gets freed.
		 */
		tp = zheap_gettuple(relation, buffer, offnum);

		/* Save the infomask. The tuple might get freed, as mentioned above */
		infomask = tp->t_data->t_infomask;

		/*
		 * Ensure that the tuple is same as what we are expecting.  If the
		 * current or any prior version of tuple doesn't contain the effect of
		 * priorXmax, then the slot must have been recycled and reused for an
		 * unrelated tuple.  This implies that the latest version of the row
		 * was deleted, so we need do nothing.
		 */
		if (TransactionIdIsValid(priorXmax) &&
			!ValidateTuplesXact(relation, tp, snapshot,
								buffer, priorXmax, false))
		{
			UnlockReleaseBuffer(buffer);
			break;
		}

		/*
		 * Get the transaction which modified this tuple. Ideally we need to
		 * get this only when there is a ctid chain to follow.
		 */
		priorXmax = ZHeapTupleGetTransXID(tp, buffer, false);
		pfree(tp);

		/*
		 * Check time qualification of tuple; if visible, set it as the new
		 * result candidate.
		 */
		ItemPointerSetInvalid(&new_ctid);
		ZHeapTupleFetch(relation, buffer, offnum, snapshot,
						&resulttup, &new_ctid);

		/*
		 * If any prior version is visible, we pass latest visible as true.
		 * The state of latest version of tuple is determined by the called
		 * function.
		 *
		 * Note that, it's possible that tuple is updated in-place and we're
		 * seeing some prior version of that. We handle that case in
		 * ZHeapTupleHasSerializableConflictOut.
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
 *
 * The caller should hold a buffer content lock on the zheap buffer.
 */
TransInfo *
GetTransactionsSlotsForPage(Relation rel, Buffer buf, int *total_trans_slots,
							BlockNumber *tpd_blkno)
{
	Page		page;
	PageHeader	phdr;
	TransInfo  *tpd_trans_slots;
	TransInfo  *trans_slots = NULL;
	bool		tpd_e_pruned;

	*total_trans_slots = 0;
	if (tpd_blkno)
		*tpd_blkno = InvalidBlockNumber;

	page = BufferGetPage(buf);
	phdr = (PageHeader) page;

	if (ZHeapPageHasTPDSlot(phdr))
	{
		int			num_tpd_trans_slots;

		/*
		 * TPD entry can be cleaned only if the zheap buffer is locked in
		 * exclusive mode. But, in this path, the zheap buffer can be locked
		 * in shared mode as well (see ZGetMultiLockMembers()).  Hence, we
		 * pass clean_tpd_loc as false.
		 */
		tpd_trans_slots = TPDPageGetTransactionSlots(rel,
													 buf,
													 InvalidOffsetNumber,
													 false,
													 false,
													 NULL,
													 &num_tpd_trans_slots,
													 NULL,
													 &tpd_e_pruned,
													 NULL,
													 false);

		/* TPD location should not be cleaned from the zheap buffer page. */
		Assert(!tpd_e_pruned);
		if (num_tpd_trans_slots > 0)
		{
			GetTPDBlockAndOffset(page, tpd_blkno, NULL);

			/*
			 * The last slot in page contains TPD information, so we don't
			 * need to include it.
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
			Assert(*total_trans_slots >= ZHEAP_PAGE_TRANS_SLOTS);
			return trans_slots;
		}
		else if (num_tpd_trans_slots == 0)
		{
			*total_trans_slots = ZHEAP_PAGE_TRANS_SLOTS - 1;
			trans_slots = (TransInfo *)
				palloc(*total_trans_slots * sizeof(TransInfo));
			memcpy(trans_slots, page + phdr->pd_special,
				   *total_trans_slots * sizeof(TransInfo));
			return trans_slots;
		}
	}

	Assert(!ZHeapPageHasTPDSlot(phdr) || tpd_e_pruned);
	Assert(trans_slots == NULL);

	*total_trans_slots = ZHEAP_PAGE_TRANS_SLOTS;
	trans_slots = (TransInfo *)
		palloc(*total_trans_slots * sizeof(TransInfo));
	memcpy(trans_slots, page + phdr->pd_special,
		   *total_trans_slots * sizeof(TransInfo));

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
		PageHasFreeLinePointers((PageHeader) BufferGetPage(newbuf)))
	{
		BlockNumber oldbuf_tpd_blk = InvalidBlockNumber,
					newbuf_tpd_blk;

		/*
		 * If TPD exists for old buffer, then get the corresponding TPD block
		 * number.
		 */
		if (ZHeapPageHasTPDSlot((PageHeader) BufferGetPage(oldbuf)))
			GetTPDBlockAndOffset(BufferGetPage(oldbuf), &oldbuf_tpd_blk, NULL);
		GetTPDBlockAndOffset(BufferGetPage(newbuf), &newbuf_tpd_blk, NULL);

		/*
		 * If the old buffer and new buffer refers to the same TPD page and
		 * the old transaction slot corresponds to a TPD slot, we must have
		 * locked the TPD page during slot reservation.
		 */
		if (old_trans_slot_id > ZHEAP_PAGE_TRANS_SLOTS)
		{
			/* old page must point to valid TPD block */
			Assert(oldbuf_tpd_blk != InvalidBlockNumber);

			/*
			 * To avoid deadlock, we need to ensure that we always lock the
			 * lower numbered TPD block first.
			 *
			 * Releasing and reacquiring the lock on higher numbered TPD block
			 * is safe because we have reserved the transaction slot in that
			 * block which will avoid pruning the TPD entry. We also have lock
			 * on the heap page, so no one can extend the TPD entry.
			 */
			if (newbuf_tpd_blk < oldbuf_tpd_blk)
			{
				ReleaseLastTPDBufferByTPDBlock(oldbuf_tpd_blk);
				TPDPageLock(relation, newbuf);
				TPDPageLock(relation, oldbuf);
			}
			else if (newbuf_tpd_blk > oldbuf_tpd_blk)
				TPDPageLock(relation, newbuf);
		}
		else
			TPDPageLock(relation, newbuf);
	}
}

/*
 * copy_zrelation_data - copy zheap data
 *
 * In this method, we copy the main fork of a zheap relation block by block.
 * Here is the algorithm for the same:
 * For each zheap page,
 * a. If it's a meta page, copy it as it is.
 * b. If it's a TPD page, copy it as it is.
 * c. If it's a zheap data page, apply pending aborts, copy the page and
 *    the corresponding TPD page (if any).
 *
 * Please note that we may copy a tpd page multiple times. The reason is one
 * tpd page can be referred by multiple zheap pages. While applying pending
 * aborts on a zheap page, we also need to modify the transaction and undo
 * information in the corresponding TPD page, hence, we need to copy it again
 * to reflect the changes.
 */
void
copy_zrelation_data(Relation srcRel, SMgrRelation dst)
{
	Page		page;
	bool		use_wal;
	BlockNumber nblocks;
	BlockNumber blkno;
	SMgrRelation src = srcRel->rd_smgr;
	char		relpersistence = srcRel->rd_rel->relpersistence;

	/*
	 * We need to log the copied data in WAL iff WAL archiving/streaming is
	 * enabled AND it's a permanent relation.
	 */
	use_wal = XLogIsNeeded() && (relpersistence == RELPERSISTENCE_PERMANENT);

	nblocks = smgrnblocks(src, MAIN_FORKNUM);

	for (blkno = 0; blkno < nblocks; blkno++)
	{
		BlockNumber target_blkno = InvalidBlockNumber;
		BlockNumber tpd_blkno = InvalidBlockNumber;
		Buffer		buffer = InvalidBuffer;

		/* If we got a cancel signal during the copy of the data, quit */
		CHECK_FOR_INTERRUPTS();

		if (blkno != ZHEAP_METAPAGE)
		{
			buffer = ReadBuffer(srcRel, blkno);

			/* If it's a zheap page, apply the pending undo actions */
			if (PageGetSpecialSize(BufferGetPage(buffer)) !=
				MAXALIGN(sizeof(TPDPageOpaqueData)))
				zheap_exec_pending_rollback(srcRel, buffer, InvalidXactSlotId,
											InvalidTransactionId, &tpd_blkno);
		}

		target_blkno = blkno;

copy_buffer:
		/* Read the buffer if not already done. */
		if (!BufferIsValid(buffer))
			buffer = ReadBuffer(srcRel, target_blkno);
		page = (Page) BufferGetPage(buffer);

		/*
		 * WAL-log the copied page. Unfortunately we don't know what kind of a
		 * page this is, so we have to log the full page including any unused
		 * space.
		 */
		if (use_wal)
			log_newpage(&dst->smgr_rnode.node, MAIN_FORKNUM, target_blkno, page, false);

		PageSetChecksumInplace(page, target_blkno);

		/*
		 * Now write the page.  We say isTemp = true even if it's not a temp
		 * rel, because there's no need for smgr to schedule an fsync for this
		 * write; we'll do it ourselves below.
		 */
		smgrextend(dst, MAIN_FORKNUM, target_blkno, page, true);

		ReleaseBuffer(buffer);

		/*
		 * If we have rolled back some transaction from TPD of the target page
		 * and the TPD block number is lesser than the target block number, we
		 * have to write the TPD page again.
		 */
		if (BlockNumberIsValid(tpd_blkno) && tpd_blkno < target_blkno)
		{
			target_blkno = tpd_blkno;
			tpd_blkno = InvalidBlockNumber;
			buffer = InvalidBuffer;
			goto copy_buffer;
		}
	}

	/*
	 * If the rel is WAL-logged, must fsync before commit.  We use heap_sync
	 * to ensure that the toast table gets fsync'd too.  (For a temp or
	 * unlogged rel we don't care since the data will be gone after a crash
	 * anyway.)
	 *
	 * It's obvious that we must do this when not WAL-logging the copy. It's
	 * less obvious that we have to do it even if we did WAL-log the copied
	 * pages. The reason is that since we're copying outside shared buffers, a
	 * CHECKPOINT occurring during the copy has no way to flush the previously
	 * written data to disk (indeed it won't know the new rel even exists).  A
	 * crash later on would replay WAL from the checkpoint, therefore it
	 * wouldn't replay our earlier WAL entries. If we do not fsync those pages
	 * here, they might still not be on disk when the crash occurs.
	 */
	if (relpersistence == RELPERSISTENCE_PERMANENT)
		smgrimmedsync(dst, MAIN_FORKNUM);
}

/*
 * Get the latestRemovedXid from the zheap pages pointed at by the index
 * tuples being deleted.
 *
 * This puts the work for calculating latestRemovedXid into the recovery path
 * rather than the primary path.
 *
 * It's possible that this generates a fair amount of I/O, since an index
 * block may have hundreds of tuples being deleted. To amortize that cost to
 * some degree, this uses prefetching and combines repeat accesses to the same
 * block.
 *
 * XXX: might be worth being smarter about looking up transaction information
 * in bulk too.
 */
TransactionId
zheap_compute_xid_horizon_for_tuples(Relation rel,
									 ItemPointerData *tids,
									 int nitems)
{
	TransactionId latestRemovedXid = InvalidTransactionId;
	BlockNumber hblkno;
	Buffer		buf = InvalidBuffer;
	Page		hpage;

	/*
	 * Sort to avoid repeated lookups for the same page, and to make it more
	 * likely to access items in an efficient order. In particular this
	 * ensures that if there are multiple pointers to the same page, they all
	 * get processed looking up and locking the page just once.
	 */
	qsort((void *) tids, nitems, sizeof(ItemPointerData),
		  (int (*) (const void *, const void *)) ItemPointerCompare);

	/* prefetch all pages */
#ifdef USE_PREFETCH
	hblkno = InvalidBlockNumber;
	for (int i = 0; i < nitems; i++)
	{
		ItemPointer htid = &tids[i];

		if (hblkno == InvalidBlockNumber ||
			ItemPointerGetBlockNumber(htid) != hblkno)
		{
			hblkno = ItemPointerGetBlockNumber(htid);

			PrefetchBuffer(rel, MAIN_FORKNUM, hblkno);
		}
	}
#endif

	/* Iterate over all tids, and check their horizon */
	hblkno = InvalidBlockNumber;
	for (int i = 0; i < nitems; i++)
	{
		ItemPointer htid = &tids[i];
		ItemId		hitemid;
		OffsetNumber hoffnum;

		/*
		 * Read zheap buffer, but avoid refetching if it's the same block as
		 * required for the last tid.
		 */
		if (hblkno == InvalidBlockNumber ||
			ItemPointerGetBlockNumber(htid) != hblkno)
		{
			/* release old buffer */
			if (BufferIsValid(buf))
			{
				LockBuffer(buf, BUFFER_LOCK_UNLOCK);
				ReleaseBuffer(buf);
			}

			hblkno = ItemPointerGetBlockNumber(htid);

			buf = ReadBuffer(rel, hblkno);
			hpage = BufferGetPage(buf);

			LockBuffer(buf, BUFFER_LOCK_SHARE);
		}

		hoffnum = ItemPointerGetOffsetNumber(htid);
		hitemid = PageGetItemId(hpage, hoffnum);

		/*
		 * If the zheap item has storage, then read the header and use that to
		 * set latestRemovedXid.
		 *
		 * We have special handling for zheap tuples that are deleted and
		 * don't have storage.
		 *
		 * Some LP_DEAD items may not be accessible, so we ignore them.
		 */
		if (ItemIdIsDeleted(hitemid))
		{
			TransactionId xid;
			ZHeapTupleData ztup;

			ztup.t_self = *htid;
			ztup.t_len = ItemIdGetLength(hitemid);
			ztup.t_tableOid = InvalidOid;
			ztup.t_data = NULL;
			xid = ZHeapTupleGetTransXID(&ztup, buf, false);
			if (TransactionIdDidCommit(xid) &&
				TransactionIdFollows(xid, latestRemovedXid))
				latestRemovedXid = xid;
		}
		else if (ItemIdHasStorage(hitemid))
		{
			ZHeapTupleHeader ztuphdr;
			ZHeapTupleData ztup;

			ztuphdr = (ZHeapTupleHeader) PageGetItem(hpage, hitemid);
			ztup.t_self = *htid;
			ztup.t_len = ItemIdGetLength(hitemid);
			ztup.t_tableOid = InvalidOid;
			ztup.t_data = ztuphdr;

			if (ztuphdr->t_infomask & ZHEAP_DELETED
				|| ztuphdr->t_infomask & ZHEAP_UPDATED)
			{
				TransactionId xid;

				xid = ZHeapTupleGetTransXID(&ztup, buf, false);
				ZHeapTupleHeaderAdvanceLatestRemovedXid(ztuphdr, xid, &latestRemovedXid);
			}
		}
		else if (ItemIdIsDead(hitemid))
		{
			/*
			 * Conjecture: if hitemid is dead then it had xids before the xids
			 * marked on LP_NORMAL items. So we just ignore this item and move
			 * onto the next, for the purposes of calculating
			 * latestRemovedxids.
			 */
		}
		else
			Assert(!ItemIdIsUsed(hitemid));

	}

	if (BufferIsValid(buf))
	{
		LockBuffer(buf, BUFFER_LOCK_UNLOCK);
		ReleaseBuffer(buf);
	}

	return latestRemovedXid;
}

/*
 * RefetchAndCheckTupleStatus - refetch and check whether the tuple infomask or
 * xid has been changed while the buffer lock has been released.
 *
 * single_locker_xid - This is an INOUT parameter. For key share lock and
 * share lock mode, if a new locker has come, it must be compatible
 * with the current lock mode. In that case, we don't have to perform the
 * conflict check again, but we return the single locker xid that'll be used in
 * compute_new_xid_infomask later.
 * mode - If not NULL, mode specific status checks are performed.
 */
static bool
RefetchAndCheckTupleStatus(Relation relation,
						   Buffer buffer,
						   int old_infomask,
						   TransactionId tup_xid,
						   TransactionId *single_locker_xid,
						   LockTupleMode *mode,
						   ZHeapTupleData *zhtup)
{
	ItemId		lp;
	Page		page;
	TransactionId current_tup_xid = InvalidTransactionId;

	page = BufferGetPage(buffer);
	lp = PageGetItemId(page, ItemPointerGetOffsetNumber(&(zhtup->t_self)));
	Assert(ItemIdIsNormal(lp));

	/* Refetch the tuple */
	zhtup->t_data = (ZHeapTupleHeader) PageGetItem(page, lp);
	zhtup->t_len = ItemIdGetLength(lp);

	/*
	 * If some lockmode has been specified, perform some early checks to
	 * determine whether the tuple has been modified by some other xacts and a
	 * conflict check is again needed.
	 */
	if (mode)
	{
		if (*mode == LockTupleKeyShare)
		{
			/*
			 * Make sure it's still an appropriate lock, else start over.
			 * Also, if it wasn't updated before we released the lock, but is
			 * updated now, we start over too; the reason is that we now need
			 * to follow the update chain to lock the new versions.
			 */
			if (!ZHEAP_XID_IS_LOCKED_ONLY(zhtup->t_data->t_infomask) &&
				(ZHEAP_XID_IS_EXCL_LOCKED(zhtup->t_data->t_infomask) ||
				 ZHEAP_XID_IS_LOCKED_ONLY(old_infomask)))
				return false;
		}
		else if (*mode == LockTupleShare)
		{

			/* Make sure it's still an appropriate lock, else start over. */
			if (!ZHEAP_XID_IS_LOCKED_ONLY(zhtup->t_data->t_infomask) ||
				ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(zhtup->t_data->t_infomask) ||
				ZHEAP_XID_IS_EXCL_LOCKED(zhtup->t_data->t_infomask))
				return false;
		}
	}

	if (xid_infomask_changed(zhtup->t_data->t_infomask, old_infomask))
		return false;

	/*
	 * Other updaters/lock-for-update operations could have modified it before
	 * we grabbed the buffer lock.  In that case, we've to go back and perform
	 * the conflict check again, so return false.
	 */
	current_tup_xid = ZHeapTupleGetTransXID(zhtup, buffer, false);

	if (!TransactionIdEquals(current_tup_xid, tup_xid))
		return false;

	/*
	 * Other lockers that don't change the slot on the tuple could have
	 * modified it before we grabbed the buffer lock.  In that case, we've to
	 * go back and perform the conflict check again, so return false.
	 */
	if (ZHEAP_XID_IS_LOCKED_ONLY(zhtup->t_data->t_infomask) &&
		!ZHeapTupleHasMultiLockers(zhtup->t_data->t_infomask))
	{
		TransactionId current_single_locker_xid;

		GetLockerTransInfo(relation, &zhtup->t_self, buffer,
						   NULL, &current_single_locker_xid);

		if (mode && (*mode == LockTupleKeyShare || *mode == LockTupleShare))
		{
			/*
			 * For key share lock and share lock mode, even if a new locker
			 * has come, it must be compatible with the current lock mode.  In
			 * that case, we don't have to perform the conflict check again,
			 * but we should update the single locker xid that'll be used in
			 * compute_new_xid_infomask later.
			 */
			*single_locker_xid = current_single_locker_xid;
		}
		else if (!TransactionIdEquals(current_single_locker_xid,
									  *single_locker_xid))
			return false;
	}

	return true;
}
