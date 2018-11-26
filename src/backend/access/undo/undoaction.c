/*-------------------------------------------------------------------------
 *
 * undoaction.c
 *	  execute undo actions
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undoaction.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undoaction_xlog.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/xact.h"
#include "nodes/pg_list.h"
#include "postmaster/undoloop.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "miscadmin.h"
#include "storage/shmem.h"
#include "access/undodiscard.h"
#include "utils/hsearch.h"

#define ROLLBACK_HT_SIZE	1024

static bool execute_undo_actions_page(List *luinfo, UndoRecPtr urec_ptr,
					 Oid reloid, TransactionId xid, BlockNumber blkno,
					 bool blk_chain_complete, bool norellock);
static inline void undo_action_insert(Relation rel, Page page, OffsetNumber off,
									  TransactionId xid);

/* This is the hash table to store all the rollabck requests. */
static HTAB *RollbackHT;

/* undo record information */
typedef struct UndoRecInfo
{
	UndoRecPtr	urp;	/* undo recptr (undo record location). */
	UnpackedUndoRecord	*uur;	/* actual undo record. */
} UndoRecInfo;

/*
 * execute_undo_actions - Execute the undo actions
 *
 * from_urecptr - undo record pointer from where to start applying undo action.
 * to_urecptr	- undo record pointer upto which point apply undo action.
 * nopartial	- true if rollback is for complete transaction.
 * rewind		- whether to rewind the insert location of the undo log or not.
 *				  Only the backend executed the transaction can rewind, but
 *				  any other process e.g. undo worker should not rewind it.
 *				  Because, if the backend have already inserted new undo records
 *				  for the next transaction and if we rewind then we will loose
 *				  the undo record inserted for the new transaction.
 * 	rellock	  -	  if the caller already has the lock on the required relation,
 *				  then this flag is false, i.e. we do not need to acquire any
 *				  lock here. If the flag is true then we need to acquire lock
 *				  here itself, because caller will not be having any lock.
 *				  When we are performing undo actions for prepared transactions,
 *			      or for rollback to savepoint, we need not to lock as we already
 *				  have the lock on the table. In cases like error or when
 *				  rollbacking from the undo worker we need to have proper locks.
 */
void
execute_undo_actions(UndoRecPtr from_urecptr, UndoRecPtr to_urecptr,
					 bool nopartial, bool rewind, bool rellock)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr;
	UndoRecPtr	save_urec_ptr;
	Oid			reloid;
	Oid			prev_reloid = InvalidOid;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber	prev_block = InvalidBlockNumber;
	List	   *luinfo = NIL;
	bool		more_undo;
	TransactionId xid = InvalidTransactionId;
	UndoRecInfo	*urec_info;

	Assert(from_urecptr != InvalidUndoRecPtr);
	/*
	 * If the location upto which rollback need to be done is not provided,
	 * then rollback the complete transaction.
	 * FIXME: this won't work if undolog crossed the limit of 1TB, because
	 * then from_urecptr and to_urecptr will be from different lognos.
	 */
	if (to_urecptr == InvalidUndoRecPtr)
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(from_urecptr);
		to_urecptr = UndoLogGetLastXactStartPoint(logno);
	}

	save_urec_ptr = urec_ptr = from_urecptr;

	while (urec_ptr >= to_urecptr)
	{
		uint16	urec_prevlen;

		more_undo = true;

		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
						 InvalidOffsetNumber, InvalidTransactionId, NULL, NULL);
		/*
		 * If the record is already discarded by undo worker,
		 * then we cannot fetch record successfully.
		 * Hence, exit quietly.
		 */
		if(uur == NULL)
		{
			/* release the undo records for which action has been replayed */
			while (luinfo)
			{
				UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

				UndoRecordRelease(urec_info->uur);
				pfree(urec_info);
				luinfo = list_delete_first(luinfo);
			}
			return;
		}

		reloid = RelidByRelfilenode(uur->uur_tsid, uur->uur_relfilenode);
		xid = uur->uur_xid;

		/* Collect the undo records that belong to the same page. */
		if (!OidIsValid(prev_reloid) ||
			(prev_reloid == reloid &&
			 prev_fork == uur->uur_fork &&
			 prev_block == uur->uur_block))
		{
			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;

			/* Prepare an undo record information element. */
			urec_info = palloc(sizeof(UndoRecInfo));
			urec_info->urp = urec_ptr;
			urec_info->uur = uur;

			luinfo = lappend(luinfo, urec_info);
			urec_prevlen = uur->uur_prevlen;
			save_urec_ptr = uur->uur_blkprev;

			/* The undo chain must continue till we reach to_urecptr */
			if (urec_prevlen)
			{
				urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen);
				if (urec_ptr >= to_urecptr)
					continue;
				else
					more_undo = false;
			}
			else
				more_undo = false;
		}
		else
		{
			more_undo = true;
		}

		/*
		 * If no more undo is left to be processed and we are rolling back the
		 * complete transaction, then we can consider that the undo chain for a
		 * block is complete.
		 */
		if (!more_undo && nopartial)
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, true, rellock);
		}
		else
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, false, rellock);
		}

		/* release the undo records for which action has been replayed */
		while (luinfo)
		{
			UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

			UndoRecordRelease(urec_info->uur);
			pfree(urec_info);
			luinfo = list_delete_first(luinfo);
		}

		/*
		 * There are still more records to process, so keep moving backwards
		 * in the chain.
		 */
		if (more_undo)
		{
			/* Prepare an undo record information element. */
			urec_info = palloc(sizeof(UndoRecInfo));
			urec_info->urp = urec_ptr;
			urec_info->uur = uur;
			luinfo = lappend(luinfo, urec_info);

			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;
			save_urec_ptr = uur->uur_blkprev;

			/*
			 * Continue to process the records if this is not the last undo
			 * record in chain.
			 */
			urec_prevlen = uur->uur_prevlen;
			if (urec_prevlen)
				urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen);
			else
				break;
		}
		else
			break;
	}

	/* Apply the undo actions for the remaining records. */
	if (list_length(luinfo))
	{
		execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
								xid, prev_block, nopartial ? true : false,
								rellock);

		/* release the undo records for which action has been replayed */
		while (luinfo)
		{
			UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

			UndoRecordRelease(urec_info->uur);
			pfree(urec_info);
			luinfo = list_delete_first(luinfo);
		}
	}

	if (rewind)
	{
		/* Read the prevlen from the first record of this transaction. */
		uur = UndoFetchRecord(to_urecptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId,
							  NULL, NULL);
		/*
		 * If undo is already discarded before we rewind, then do nothing.
		 */
		if (uur == NULL)
			return;


		/*
		* Rewind the insert location to start of this transaction.  This is
		* to avoid reapplying some intermediate undo. We do not need to wal
		* log this information here, because if the system crash before we
		* rewind the insert pointer then after recovery we can identify
		* whether the undo is already applied or not from the slot undo record
		* pointer. Also set the correct prevlen value (what we have fetched
		* from the undo).
		*/
		UndoLogRewind(to_urecptr, uur->uur_prevlen);

		UndoRecordRelease(uur);
	}
}

/*
 * process_and_execute_undo_actions_page
 *
 * Collect all the undo for the input buffer and execute.  Here, we don't know
 * the to_urecptr and we can not collect from undo meta data also like we do in
 * execute_undo_actions, because we might be applying undo of some old
 * transaction and may be from different undo log as well.
 *
 * from_urecptr - undo record pointer from where to start applying the undo.
 * rel			- relation descriptor for which undo to be applied.
 * buffer		- buffer for which unto to be processed.
 * xid			- aborted transaction id whose effects needs to be reverted.
 * slot_no		- transaction slot number of xid.
 */
void
process_and_execute_undo_actions_page(UndoRecPtr from_urecptr, Relation rel,
									  Buffer buffer, TransactionId xid,
									  int slot_no)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr = from_urecptr;
	List	   *luinfo = NIL;
	Page		page;
	ZHeapPageOpaque	opaque;
	UndoRecInfo	*urec_info;
	bool	actions_applied = false;

	Assert(TransactionIdDidAbort(xid));

	/*
	 * Process and collect the undo for the block until we reach the first
	 * record of the transaction.
	 *
	 * Fixme: This can lead to unbounded use of memory, so we should collect
	 * the undo in chunks based on work_mem or some other memory unit.
	 */
	do
	{
		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId,
							  NULL, NULL);
		/*
		 * If the record is already discarded by undo worker, or the xid we
		 * want to rollback has already applied its undo actions then just
		 * cleanup the slot and exit.
		 */
		if(uur == NULL || uur->uur_xid != xid)
		{
			if (uur != NULL)
				UndoRecordRelease(uur);
			break;
		}

		/* Prepare an undo element. */
		urec_info = palloc(sizeof(UndoRecInfo));
		urec_info->urp = urec_ptr;
		urec_info->uur = uur;

		/* Collect the undo records. */
		luinfo = lappend(luinfo, urec_info);
		urec_ptr = uur->uur_blkprev;

		/*
		 * If we have exhausted the undo chain for the slot, then we are done.
		 */
		if (!UndoRecPtrIsValid(urec_ptr))
			break;
	} while (true);

	if (list_length(luinfo))
		actions_applied = execute_undo_actions_page(luinfo, urec_ptr,
													rel->rd_id, xid,
													BufferGetBlockNumber(buffer),
													true,
													false);
	/* Release undo records and undo elements*/
	while (luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

		UndoRecordRelease(urec_info->uur);
		pfree(urec_info);
		luinfo = list_delete_first(luinfo);
	}

	/*
	 * Clear the transaction id from the slot.  We expect that if the undo
	 * actions are applied by execute_undo_actions_page then it would have
	 * cleared the xid, otherwise we will cleare it here.
	 */
	if (!actions_applied)
	{
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);
		opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);
		if (opaque->transinfo[slot_no].xid == xid)
		{
			START_CRIT_SECTION();
			opaque->transinfo[slot_no].xid_epoch = 0;
			opaque->transinfo[slot_no].xid = InvalidTransactionId;

			/* XLOG stuff */
			if (RelationNeedsWAL(rel))
			{
				XLogRecPtr	recptr;

				XLogBeginInsert();

				XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);
				XLogRegisterBufData(0, (char *) &slot_no, sizeof(int));

				recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_RESET_XID);

				PageSetLSN(page, recptr);
			}
			END_CRIT_SECTION();
		}
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	}
}

/*
 * undo_action_insert - perform the undo action for insert
 *
 *	This will mark the tuple as dead so that the future access to it can't see
 *	this tuple.  We mark it as unused if there is no other index pointing to
 *	it, otherwise mark it as dead.
 */
static inline void
undo_action_insert(Relation rel, Page page, OffsetNumber off,
				   TransactionId xid)
{
	ItemId		lp;
	bool		relhasindex;

	/*
	 * This will mark the tuple as dead so that the future
	 * access to it can't see this tuple.  We mark it as
	 * unused if there is no other index pointing to it,
	 * otherwise mark it as dead.
	*/
	relhasindex = RelationGetForm(rel)->relhasindex;
	lp = PageGetItemId(page, off);
	Assert(ItemIdIsNormal(lp));
	if (relhasindex)
	{
		ItemIdSetDead(lp);
	}
	else
	{
		ItemIdSetUnused(lp);
		/* Set hint bit for ZPageAddItem */
		PageSetHasFreeLinePointers(page);
	}

	ZPageSetPrunable(page, xid);
}

/*
 * execute_undo_actions_page - Execute the undo actions for a page
 *
 *	After applying all the undo actions for a page, we clear the transaction
 *	slot on a page if the undo chain for block is complete, otherwise just
 *	rewind the undo pointer to the last record for that block that precedes
 *	the last undo record for which action is replayed.
 *
 *	luinfo - list of undo records (along with their location) for which undo
 *			 action needs to be replayed.
 *	urec_ptr - undo record pointer to which we need to rewind.
 *	reloid	- OID of relation on which undo actions needs to be applied.
 *	blkno	- block number on which undo actions needs to be applied.
 *	blk_chain_complete - indicates whether the undo chain for block is
 *						 complete.
 *	nopartial - true if rollback is for complete transaction. If we are not
 *				rolling back the complete transaction then we need to apply the
 *				undo action for UNDO_INVALID_XACT_SLOT also because in such
 *				case we will rewind the insert undo location.
 *	rellock	  -	if the caller already has the lock on the required relation,
 *				then this flag is false, i.e. we do not need to acquire any
 *				lock here. If the flag is true then we need to acquire lock
 *				here itself, because caller will not be having any lock.
 *				When we are performing undo actions for prepared transactions,
 *				or for rollback to savepoint, we need not to lock as we already
 *				have the lock on the table. In cases like error or when
 *				rollbacking from the undo worker we need to have proper locks.
 *
 *	returns true, if successfully applied the undo actions, otherwise, false.
 */
static bool
execute_undo_actions_page(List *luinfo, UndoRecPtr urec_ptr, Oid reloid,
						  TransactionId xid, BlockNumber blkno,
						  bool blk_chain_complete, bool rellock)
{
	ListCell   *l_iter;
	Relation	rel;
	Buffer		buffer;
	Page		page;
	ZHeapPageOpaque	opaque;
	int			slot_no = 0;
	UndoRecPtr	slot_urp;
	UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

	/*
	 * FIXME: If reloid is not valid then we have nothing to do. In future,
	 * we might want to do it differently for transactions that perform both
	 * DDL and DML operations.
	 */
	if (!OidIsValid(reloid))
	{
		elog(LOG, "ignoring undo for invalid reloid");
		return false;
	}

	/*
	 * If the action is executed by backend as a result of rollback, we must
	 * already have an appropriate lock on relation.
	 */
	if (rellock)
		rel = heap_open(reloid, RowExclusiveLock);
	else
		rel = heap_open(reloid, NoLock);

	if (RelationGetNumberOfBlocks(rel) <= blkno)
	{
		/*
		 * This is possible if the underlying relation is truncated just before
		 * taking the relation lock above.
		 */
		heap_close(rel, NoLock);
		return false;
	}

	buffer = ReadBuffer(rel, blkno);
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	page = BufferGetPage(buffer);
	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(page);

	/* Identify the slot number for this transaction */
	while (slot_no < ZHEAP_PAGE_TRANS_SLOTS &&
		   !(TransactionIdEquals(xid, opaque->transinfo[slot_no].xid)))
		slot_no++;

	/*
	 * If undo action has been already applied for this page then skip
	 * the process altogether.
	 *
	 * The logno of slot's undo record pointer must be same as the logno
	 * of undo record to be applied.
	 */
	slot_urp = opaque->transinfo[slot_no].urec_ptr;
	if (slot_no == ZHEAP_PAGE_TRANS_SLOTS ||
	   (UndoRecPtrGetLogNo(slot_urp) != UndoRecPtrGetLogNo(urec_info->urp)) ||
	   (UndoRecPtrGetLogNo(slot_urp) == UndoRecPtrGetLogNo(urec_ptr) &&
		slot_urp <= urec_ptr))
	{
		UnlockReleaseBuffer(buffer);
		heap_close(rel, NoLock);
		return false;
	}

	START_CRIT_SECTION();

	foreach(l_iter, luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) lfirst(l_iter);
		UnpackedUndoRecord *uur = urec_info->uur;

		/* Skip already applied undo. */
		if (opaque->transinfo[slot_no].urec_ptr < urec_info->urp)
			continue;

		switch (uur->uur_type)
		{
			case UNDO_INSERT:
				{
					int			i,
								nline;
					ItemId		lp;
					bool		need_init = true;

					undo_action_insert(rel, page, uur->uur_offset, xid);

					nline = PageGetMaxOffsetNumber(page);

					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}

					/*
					 * In zheap_xlog_insert we see insert of first and only
					 * tuple on the page we re-initialize the page. Force
					 * ZheapInitPage on insert or multi insert rollback if
					 * all line pointers in it is unused to satisfy wal
					 * consistency check on standby.
					 */
					if (need_init)
						ZheapInitPage(page, (Size)BLCKSZ);
				}
				break;
			case UNDO_MULTI_INSERT:
				{
					OffsetNumber	start_offset;
					OffsetNumber	end_offset;
					OffsetNumber	iter_offset;
					int				i,
									nline;
					ItemId			lp;
					bool			need_init = true;

					start_offset = ((OffsetNumber *) uur->uur_payload.data)[0];
					end_offset = ((OffsetNumber *) uur->uur_payload.data)[1];

					for (iter_offset = start_offset;
						 iter_offset <= end_offset;
						 iter_offset++)
					{
						undo_action_insert(rel, page, iter_offset, xid);
					}

					nline = PageGetMaxOffsetNumber(page);
					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}

					/*
					 * In zheap_xlog_insert we see insert of first and only
					 * tuple on the page we re-initialize the page. Force
					 * ZheapInitPage on insert or multi insert rollback if
					 * all line pointers in it is unused to satisfy wal
					 * consistency check on standby.
					 */
					if (need_init)
						ZheapInitPage(page, (Size)BLCKSZ);
				}
				break;
			case UNDO_DELETE:
			case UNDO_UPDATE:
			case UNDO_INPLACE_UPDATE:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup;
					Size		offset = 0;
					uint32		undo_tup_len;
					int			trans_slot;
					uint16		infomask;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);
					infomask = zhtup->t_infomask;
					trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

					undo_tup_len = *((uint32 *) &uur->uur_tuple.data[offset]);
					ItemIdChangeLen(lp, undo_tup_len);
					/* skip ctid and tableoid stored in undo tuple */
					offset += sizeof(uint32) + sizeof(ItemPointerData) + sizeof(Oid);
					memcpy(zhtup,
						   (ZHeapTupleHeader) &uur->uur_tuple.data[offset],
						   undo_tup_len);

					/*
					 * We always need to retain the strongest locker
					 * information on the the tuple (as part of infomask and
					 * infomask2) if there are multiple lockers on a tuple.
					 * This is because the conflict detection mechanism works
					 * based on strongest locker.  See
					 * zheap_update/zheap_delete.  Now, even if we want to
					 * remove strongest locker information, we don't have
					 * second strongest locker information handy.
					 */
					if (ZHeapTupleHasMultiLockers(infomask))
					{
						ZHeapTupleHeaderSetXactSlot(zhtup, trans_slot);
						zhtup->t_infomask |= ZHEAP_MULTI_LOCKERS;
						zhtup->t_infomask &= ~(zhtup->t_infomask & ZHEAP_LOCK_MASK);
						zhtup->t_infomask |= infomask & ZHEAP_LOCK_MASK;

						/*
						 * If the tuple originally has INVALID_XACT_SLOT set,
						 * then we need to retain it as that must be the information
						 * of strongest locker.
						 */
						if (ZHeapTupleHasInvalidXact(infomask))
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
					}
					else
					{
						if (TransactionIdEquals(uur->uur_prevxid,
												FrozenTransactionId))
						{
							/*
							 * If the previous xid is frozen, then we can safely
							 * mark the tuple as frozen.
							 */
							ZHeapTupleHeaderSetXactSlot(zhtup, ZHTUP_SLOT_FROZEN);
						}
						else if (trans_slot != ZHTUP_SLOT_FROZEN &&
							uur->uur_prevxid != opaque->transinfo[trans_slot].xid)
						{
							/*
							 * If the transaction slot to which tuple point got reused
							 * by this time, then we need to mark the tuple with a
							 * special flag.  See comments atop PageFreezeTransSlots.
							 */
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
						}
					}
				}
				break;
			case UNDO_XID_LOCK_ONLY:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup, undo_tup_hdr;
					uint16		infomask;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);
					infomask = zhtup->t_infomask;

					/*
					 * Override the tuple header values with values retrieved
					 * from undo record except when there are multiple
					 * lockers.  In such cases, we want to retain the strongest
					 * locker information present in infomask and infomask2.
					 */
					undo_tup_hdr = (ZHeapTupleHeader) uur->uur_tuple.data;
					zhtup->t_hoff = undo_tup_hdr->t_hoff;

					if (!(ZHeapTupleHasMultiLockers(infomask)))
					{
						int			trans_slot;

						zhtup->t_infomask2 = undo_tup_hdr->t_infomask2;
						zhtup->t_infomask = undo_tup_hdr->t_infomask;

						trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

						if (TransactionIdEquals(uur->uur_prevxid,
												FrozenTransactionId))
						{
							/*
							 * If the previous xid is frozen, then we can safely
							 * mark the tuple as frozen.
							 */
							ZHeapTupleHeaderSetXactSlot(zhtup, ZHTUP_SLOT_FROZEN);
						}
						else if (trans_slot != ZHTUP_SLOT_FROZEN &&
							uur->uur_prevxid != opaque->transinfo[trans_slot].xid)
						{
							/*
							 * If the transaction slot to which tuple point got reused
							 * by this time, then we need to mark the tuple with a
							 * special flag.  See comments atop PageFreezeTransSlots.
							 */
							zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
						}
					}
				}
				break;
			case UNDO_XID_MULTI_LOCK_ONLY:
				break;
			case UNDO_ITEMID_UNUSED:
				{
					int item_count, i;
					OffsetNumber *unused;

					unused = ((OffsetNumber *) uur->uur_payload.data);
					item_count = (uur->uur_payload.len / sizeof(OffsetNumber));

					/*
					 * We need to preserve all the unused items in heap so
					 * that they can't be reused till the corresponding index
					 * entries are removed.  So, marking them dead is
					 * a sufficient indication for the index to remove the
					 * entry in index.
					 */
					for (i = 0; i < item_count; i++)
					{
						ItemId		itemid;

						itemid = PageGetItemId(page, unused[i]);
						ItemIdSetDead(itemid);
					}
				}
				break;
			default:
				elog(ERROR, "unsupported undo record type");
		}
	}

	/*
	 * If the undo chain for the block is complete then set the xid in the slot
	 * as InvalidTransactionId.  But, rewind the slot urec_ptr to the previous
	 * urec_ptr in the slot.  This is to make sure if any transaction reuse the
	 * transaction slot and rollback then put back the previous transaction's
	 * urec_ptr.
	 */
	if (blk_chain_complete)
	{
		opaque->transinfo[slot_no].xid_epoch = 0;
		opaque->transinfo[slot_no].xid = InvalidTransactionId;
	}

	opaque->transinfo[slot_no].urec_ptr = urec_ptr;

	MarkBufferDirty(buffer);

	/*
	 * We are logging the complete page for undo actions, so we don't need to
	 * record the data for individual operations.  We can optimize it by
	 * recording the data for individual operations, but again if there are
	 * multiple operations, then it might be better to log the complete page.
	 * So we can have some threshold above which we always log the complete
	 * page.
	 */
	if (RelationNeedsWAL(rel))
	{
		XLogRecPtr	recptr;

		XLogBeginInsert();

		XLogRegisterBuffer(0, buffer, REGBUF_FORCE_IMAGE | REGBUF_STANDARD);

		recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_PAGE);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buffer);

	heap_close(rel, NoLock);

	return true;
}

/*
 * To return the size of the hash-table for rollbacks.
 */
int
RollbackHTSize(void)
{
	return ROLLBACK_HT_SIZE;
}

/*
 * To initialize the hash-table for rollbacks in shared memory
 * for the given size.
 */
void
InitRollbackHashTable(void)
{
	int ht_size = RollbackHTSize();
	HASHCTL info;
	MemSet(&info, 0, sizeof(info));

	info.keysize = sizeof(TransactionId);
	info.entrysize = sizeof(RollbackHashEntry);
	info.hash = tag_hash;

	RollbackHT = ShmemInitHash("Undo actions Lookup Table",
								ht_size, ht_size, &info,
								HASH_ELEM | HASH_FUNCTION);
}

/*
 * To push the rollback requests from backend to the hash-table.
 * Return true if the request is successfully added, else false
 * and the caller may execute undo actions itself.
 */
bool
PushRollbackReq(UndoRecPtr start_urec_ptr, UndoRecPtr end_urec_ptr)
{
	bool found = false;
	RollbackHashEntry *rh;

	Assert(UndoRecPtrIsValid(start_urec_ptr));

	/* If there is no space to accomodate new request, then we can't proceed. */
	if (RollbackHTIsFull())
		return false;

	if(!UndoRecPtrIsValid(end_urec_ptr))
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(start_urec_ptr);
		end_urec_ptr = UndoLogGetLastXactStartPoint(logno);
	}

	LWLockAcquire(RollbackHTLock, LW_EXCLUSIVE);

	rh = (RollbackHashEntry *) hash_search(RollbackHT, &start_urec_ptr,
										   HASH_ENTER_NULL, &found);
	if (!rh)
	{
		LWLockRelease(RollbackHTLock);
		return false;
	}
	/* We shouldn't try to push the same rollback request again. */
	Assert(!found);

	rh->start_urec_ptr = start_urec_ptr;
	rh->end_urec_ptr = end_urec_ptr;

	LWLockRelease(RollbackHTLock);

	return true;
}

/*
 * To perform the undo actions for the transactions whose rollback
 * requests are in hash table. Sequentially, scan the hash-table
 * and perform the undo-actions for the respective transactions.
 * Once, the undo-actions are applied, remove the entry from the
 * hash table.
 */
void
RollbackFromHT(bool *hibernate)
{
	UndoRecPtr start[ROLLBACK_HT_SIZE];
	UndoRecPtr end[ROLLBACK_HT_SIZE];
	RollbackHashEntry *rh;
	HASH_SEQ_STATUS status;
	bool found;
	int i = 0;

	/* Fetch the rollback requests */
	LWLockAcquire(RollbackHTLock, LW_SHARED);
	hash_seq_init(&status, RollbackHT);
	while (RollbackHT != NULL &&
		  (rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL)
	{
		start[i] = rh->start_urec_ptr;
		end[i] = rh->end_urec_ptr;
	}
	LWLockRelease(RollbackHTLock);

	/* Don't sleep, if there is work to do. */
	if (i > 0)
		*hibernate = false;

	/* Execute the rollback requests */
	while(--i >= 0)
	{
		Assert(UndoRecPtrIsValid(start[i]));
		Assert(UndoRecPtrIsValid(end[i]));

		StartTransactionCommand();
		execute_undo_actions(end[i], start[i], true, false, true);
		CommitTransactionCommand();

		LWLockAcquire(RollbackHTLock, LW_EXCLUSIVE);
		(void) hash_search(RollbackHT, &start[i], HASH_REMOVE, &found);
		LWLockRelease(RollbackHTLock);
	}
}

/*
 * To check if the rollback requests in the hash table are all
 * completed or not. This is required because we don't not want to
 * expose RollbackHT in xact.c, where it is required to ensure
 * that we push the resuests only when there is some space in
 * the hash-table.
 */
bool
RollbackHTIsFull(void)
{
	RollbackHashEntry *rh;
	HASH_SEQ_STATUS status;
	bool result = true;

	LWLockAcquire(RollbackHTLock, LW_SHARED);
	hash_seq_init(&status, RollbackHT);

	if (hash_get_num_entries(RollbackHT) == 0 ||
		((rh = (RollbackHashEntry *) hash_seq_search(&status)) != NULL))
		result =  false;

	hash_seq_term(&status);
	LWLockRelease(RollbackHTLock);

	return result;
}
