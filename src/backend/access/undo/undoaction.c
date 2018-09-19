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

#include "access/tpd.h"
#include "access/undoaction_xlog.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "access/visibilitymap.h"
#include "access/xact.h"
#include "access/zheap.h"
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
					 bool blk_chain_complete, bool norellock, int options);
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
	UndoRecPtr	urec_ptr, prev_urec_ptr;
	UndoRecPtr	save_urec_ptr;
	Oid			prev_reloid = InvalidOid;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber	prev_block = InvalidBlockNumber;
	List	   *luinfo = NIL;
	bool		more_undo;
	int			options = 0;
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

	prev_urec_ptr = InvalidUndoRecPtr;
	while (prev_urec_ptr != to_urecptr)
	{
		Oid			reloid = InvalidOid;
		uint16		urec_prevlen;

		more_undo = true;

		prev_urec_ptr = urec_ptr;

		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
						 InvalidOffsetNumber, InvalidTransactionId, NULL, NULL);

		if (uur != NULL)
			reloid = RelidByRelfilenode(uur->uur_tsid, uur->uur_relfilenode);

		/*
		 * If the record is already discarded by undo worker or if the relation
		 * is dropped or truncated, then we cannot fetch record successfully.
		 * Hence, exit quietly.
		 *
		 * Note: reloid remains InvalidOid for a discarded record.
		 */
		if (!OidIsValid(reloid))
		{
			/* release the undo records for which action has been replayed */
			while (luinfo)
			{
				UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);

				UndoRecordRelease(urec_info->uur);
				pfree(urec_info);
				luinfo = list_delete_first(luinfo);
			}

			/* Release the just-fetched record */
			if (uur != NULL)
				UndoRecordRelease(uur);

			return;
		}

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

			if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
				options |= UNDO_ACTION_UPDATE_TPD;

			/* The undo chain must continue till we reach to_urecptr */
			if (urec_prevlen > 0 && urec_ptr != to_urecptr)
			{
				urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen);
				continue;
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
		 * If the previous undo pointer in the page is invalid, then also the
		 * undo chain for the current block is completed.
		 */
		if ((!more_undo && nopartial) || !UndoRecPtrIsValid(save_urec_ptr))
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, true, rellock, options);
			/* Done with the page so reset the options. */
			options = 0;
		}
		else
		{
			execute_undo_actions_page(luinfo, save_urec_ptr, prev_reloid,
									  xid, prev_block, false, rellock, options);
			/* Done with the page so reset the options. */
			options = 0;
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

			if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
				options |= UNDO_ACTION_UPDATE_TPD;

			/*
			 * Continue to process the records if this is not the last undo
			 * record in chain.
			 */
			urec_prevlen = uur->uur_prevlen;
			if (urec_prevlen > 0 && urec_ptr != to_urecptr)
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
								rellock, options);

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
 * epoch		- epoch of the xid passed.
 * xid			- aborted transaction id whose effects needs to be reverted.
 * slot_no		- transaction slot number of xid.
 */
void
process_and_execute_undo_actions_page(UndoRecPtr from_urecptr, Relation rel,
									  Buffer buffer, uint32 epoch,
									  TransactionId xid, int slot_no)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr = from_urecptr;
	List	   *luinfo = NIL;
	Page		page;
	UndoRecInfo	*urec_info;
	bool	actions_applied = false;
	int		options = 0;

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

		if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
			options |= UNDO_ACTION_UPDATE_TPD;

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
													false,
													options);
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
	 * cleared the xid, otherwise we will clear it here.
	 */
	if (!actions_applied)
	{
		int		slot_no;

		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		page = BufferGetPage(buffer);
		slot_no = PageGetTransactionSlotId(rel, buffer, epoch, xid, &urec_ptr,
										   true, false);
		/*
		 * If someone has already cleared the transaction info, then we don't
		 * need to do anything.
		 */
		if (slot_no != InvalidXactSlotId)
		{
			START_CRIT_SECTION();

			/* Clear the epoch and xid from the slot. */
			PageSetTransactionSlotInfo(buffer, slot_no, 0,
									   InvalidTransactionId, urec_ptr);
			MarkBufferDirty(buffer);

			/* XLOG stuff */
			if (RelationNeedsWAL(rel))
			{
				XLogRecPtr	recptr;
				xl_undoaction_reset_slot	xlrec;

				xlrec.flags = 0;
				xlrec.urec_ptr = urec_ptr;
				xlrec.trans_slot_id = slot_no;

				XLogBeginInsert();

				XLogRegisterData((char *) &xlrec, SizeOfUndoActionResetSlot);
				XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

				/* Register tpd buffer if the slot belongs to tpd page. */
				if (slot_no > ZHEAP_PAGE_TRANS_SLOTS)
				{
					xlrec.flags |= XLU_RESET_CONTAINS_TPD_SLOT;
					RegisterTPDBuffer(page, 1);
				}

				recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_RESET_SLOT);

				PageSetLSN(page, recptr);
				if (xlrec.flags & XLU_RESET_CONTAINS_TPD_SLOT)
					TPDPageSetLSN(page, recptr);
			}

			END_CRIT_SECTION();
		}

		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		UnlockReleaseTPDBuffers();
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
 * options	 -  options for executing undo actions.
 *
 *	returns true, if successfully applied the undo actions, otherwise, false.
 */
static bool
execute_undo_actions_page(List *luinfo, UndoRecPtr urec_ptr, Oid reloid,
						  TransactionId xid, BlockNumber blkno,
						  bool blk_chain_complete, bool rellock, int options)
{
	ListCell   *l_iter;
	Relation	rel;
	Buffer		buffer;
	Page		page;
	UndoRecPtr	slot_urec_ptr;
	uint32		epoch;
	int			slot_no = 0;
	int			tpd_map_size = 0;
	char	   *tpd_offset_map = NULL;
	UndoRecInfo *urec_info = (UndoRecInfo *) linitial(luinfo);
	Buffer		vmbuffer = InvalidBuffer;
	bool		need_init = false;

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

	/*
	 * If there is a undo action of type UNDO_ITEMID_UNUSED then might need
	 * to clear visibility_map. Since we cannot call visibilitymap_pin or
	 * visibilitymap_status within a critical section it shall be called
	 * here and let it be before taking the buffer lock on page.
	 */
	foreach(l_iter, luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) lfirst(l_iter);
		UnpackedUndoRecord *uur = urec_info->uur;

		if (uur->uur_type == UNDO_ITEMID_UNUSED)
		{
			visibilitymap_pin(rel, blkno, &vmbuffer);
			break;
		}
	}

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	page = BufferGetPage(buffer);

	/*
	 * Identify the slot number for this transaction.  As we never allow undo
	 * more than 2-billion transactions, we can compute epoch from xid.
	 */
	epoch = GetEpochForXid(xid);
	slot_no = PageGetTransactionSlotId(rel, buffer, epoch, xid,
							&slot_urec_ptr, true,
							options & UNDO_ACTION_UPDATE_TPD ? true : false);

	/*
	 * If undo action has been already applied for this page then skip
	 * the process altogether.  If we didn't find a slot corresponding to
	 * xid, we consider the transaction is already rolledback.
	 *
	 * The logno of slot's undo record pointer must be same as the logno
	 * of undo record to be applied.
	 */
	if (slot_no == InvalidXactSlotId ||
	   (UndoRecPtrGetLogNo(slot_urec_ptr) != UndoRecPtrGetLogNo(urec_info->urp)) ||
	   (UndoRecPtrGetLogNo(slot_urec_ptr) == UndoRecPtrGetLogNo(urec_ptr) &&
		slot_urec_ptr <= urec_ptr))
	{
		UnlockReleaseBuffer(buffer);
		heap_close(rel, NoLock);
		return false;
	}

	/*
	 * If we are going to update the TPD offset map then get the size of the
	 * offset map and allocate the memory to fetch that outside the critical
	 * section.  It is quite possible that the TPD entry is already pruned
	 * by this time, in which case, we will mark the slot as frozen.
	 */
	if ((options & UNDO_ACTION_UPDATE_TPD) != 0)
	{
		tpd_map_size = TPDPageGetOffsetMapSize(buffer);
		if (tpd_map_size > 0)
			tpd_offset_map = palloc(tpd_map_size);
	}

	START_CRIT_SECTION();

	foreach(l_iter, luinfo)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) lfirst(l_iter);
		UnpackedUndoRecord *uur = urec_info->uur;

		/* Skip already applied undo. */
		if (slot_urec_ptr < urec_info->urp)
			continue;

		switch (uur->uur_type)
		{
			case UNDO_INSERT:
				{
					int			i,
								nline;
					ItemId		lp;

					undo_action_insert(rel, page, uur->uur_offset, xid);

					nline = PageGetMaxOffsetNumber(page);
					need_init = true;
					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}
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

					start_offset = ((OffsetNumber *) uur->uur_payload.data)[0];
					end_offset = ((OffsetNumber *) uur->uur_payload.data)[1];

					for (iter_offset = start_offset;
						 iter_offset <= end_offset;
						 iter_offset++)
					{
						undo_action_insert(rel, page, iter_offset, xid);
					}

					nline = PageGetMaxOffsetNumber(page);
					need_init = true;
					for (i = FirstOffsetNumber; i <= nline; i++)
					{
						lp = PageGetItemId(page, i);
						if (ItemIdIsUsed(lp) || ItemIdHasPendingXact(lp))
						{
							need_init = false;
							break;
						}
					}
				}
				break;
			case UNDO_DELETE:
			case UNDO_UPDATE:
			case UNDO_INPLACE_UPDATE:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup;
					TransactionId	slot_xid;
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
					 * If the previous version of the tuple points to a TPD
					 * slot then we need to update the slot in the offset map
					 * of the TPD entry.  But, only if we still have a valid
					 * TPD entry for the page otherwise the old tuple version
					 * must be all visible and we can mark the slot as frozen.
					 */
					if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT &&
						tpd_offset_map)
					{
						int prev_trans_slot;

						/* Fetch TPD slot from the undo. */
						if (uur->uur_type == UNDO_UPDATE)
							prev_trans_slot = *(int *) ((char *) uur->uur_payload.data +
												sizeof(ItemPointerData));
						else
							prev_trans_slot = *(int *) uur->uur_payload.data;

						TPDPageSetOffsetMapSlot(buffer, prev_trans_slot,
												uur->uur_offset);
					}
					else if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
					{
						ZHeapTupleHeaderSetXactSlot(zhtup, ZHTUP_SLOT_FROZEN);
					}

					/*
					 * We always need to retain the strongest locker
					 * information on the the tuple (as part of infomask and
					 * infomask2), if there are multiple lockers on a tuple.
					 * This is because the conflict detection mechanism works
					 * based on strongest locker.  See
					 * zheap_update/zheap_delete.  We have allowed to override
					 * the transaction slot information with whatever is
					 * present in undo as we have taken care during DO
					 * operation that it contains previous strongest locker
					 * information.  See compute_new_xid_infomask.
					 */
					if (ZHeapTupleHasMultiLockers(infomask))
					{
						/* ZHeapTupleHeaderSetXactSlot(zhtup, trans_slot); */
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

					trans_slot = GetTransactionSlotInfo(buffer,
														uur->uur_offset,
														trans_slot,
														NULL,
														&slot_xid,
														NULL,
														false,
														false);

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
								uur->uur_prevxid != slot_xid)
					{
						/*
						 * If the transaction slot to which tuple point got reused
						 * by this time, then we need to mark the tuple with a
						 * special flag.  See comments atop PageFreezeTransSlots.
						 */
						zhtup->t_infomask |= ZHEAP_INVALID_XACT_SLOT;
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
						int			prev_trans_slot PG_USED_FOR_ASSERTS_ONLY;
						TransactionId	slot_xid;

						zhtup->t_infomask2 = undo_tup_hdr->t_infomask2;
						zhtup->t_infomask = undo_tup_hdr->t_infomask;

						/*
						 * Set the slot in the tpd offset map. for detailed
						 * comments refer undo actions of update/delete.
						 */
						if ((uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT) &&
							tpd_offset_map)
						{
							prev_trans_slot = *(int *) ((char *) uur->uur_payload.data +
												sizeof(LockTupleMode));
							TPDPageSetOffsetMapSlot(buffer, prev_trans_slot,
													uur->uur_offset);
						}
						else if (uur->uur_info & UREC_INFO_PAYLOAD_CONTAINS_SLOT)
							prev_trans_slot = ZHTUP_SLOT_FROZEN;
						else
							prev_trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);

						trans_slot = ZHeapTupleHeaderGetXactSlot(zhtup);
						trans_slot = GetTransactionSlotInfo(buffer,
															uur->uur_offset,
															trans_slot,
															NULL,
															&slot_xid,
															NULL,
															false,
															false);

						/*
						 * For a non multi locker case, the slot in undo (and
						 * hence on tuple) must be either a frozen slot or the
						 * previous slot. Generally, we always set the multi-locker
						 * bit on the tuple whenever the tuple slot is not frozen.
						 * But, if the tuple is inserted/modified by the same
						 * transaction that later takes a lock on it, we keep the
						 * transaction slot as it is.
						 * See compute_new_xid_infomask for details. 
						 */
						Assert(trans_slot == ZHTUP_SLOT_FROZEN ||
							   trans_slot == prev_trans_slot);
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
					 * We need to preserve all the unused items in zheap so
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

					/* clear visibility map */
					Assert(BufferIsValid(vmbuffer));
					visibilitymap_clear(rel, blkno, vmbuffer,
										VISIBILITYMAP_VALID_BITS);

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
		epoch = 0;
		xid = InvalidTransactionId;
	}

	PageSetTransactionSlotInfo(buffer, slot_no, epoch, xid, urec_ptr);

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
		uint8	flags = 0;

		if (slot_no > ZHEAP_PAGE_TRANS_SLOTS)
			flags |= XLU_PAGE_CONTAINS_TPD_SLOT;
		if (BufferIsValid(vmbuffer))
			flags |= XLU_PAGE_CLEAR_VISIBILITY_MAP;
		if (tpd_offset_map)
			flags |= XLU_CONTAINS_TPD_OFFSET_MAP;
		if (need_init)
			flags |= XLU_INIT_PAGE;

		XLogBeginInsert();

		XLogRegisterData((char *) &flags, sizeof(uint8));
		XLogRegisterBuffer(0, buffer, REGBUF_FORCE_IMAGE | REGBUF_STANDARD);

		/* Log the TPD details, if the transaction slot belongs to TPD. */
		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT)
		{
			xl_undoaction_page	xlrec;

			xlrec.urec_ptr = urec_ptr;
			xlrec.xid = xid;
			xlrec.trans_slot_id = slot_no;
			XLogRegisterData((char *) &xlrec, SizeOfUndoActionPage);
		}

		/*
		 * Log the TPD offset map if we have modified it.
		 *
		 * XXX Another option could be that we track all the offset map entries
		 * of TPD which got modified while applying the undo and only log those
		 * information into the WAL.
		 */
		if (flags & XLU_CONTAINS_TPD_OFFSET_MAP)
		{
			/* Fetch the TPD offset map and write into the WAL record. */
			TPDPageGetOffsetMap(buffer, tpd_offset_map, tpd_map_size);
			XLogRegisterData((char *) &tpd_offset_map, tpd_map_size);
		}

		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
			flags & XLU_CONTAINS_TPD_OFFSET_MAP)
		{
			RegisterTPDBuffer(page, 1);
		}

		recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_PAGE);

		PageSetLSN(page, recptr);
		if (flags & XLU_PAGE_CONTAINS_TPD_SLOT ||
			flags & XLU_CONTAINS_TPD_OFFSET_MAP)
			TPDPageSetLSN(page, recptr);
	}

	/*
	 * During rollback, if all the itemids are marked as unused, we need
	 * to initialize the page, so that the next insertion can see the
	 * page as initialized.  This serves two purposes (a) On next insertion,
	 * we can safely set the XLOG_ZHEAP_INIT_PAGE flag in WAL (OTOH, if we
	 * don't initialize the page here and set the flag, wal consistency
	 * checker can complain), (b) we don't accumulate the dead space in the
	 * page.
	 *
	 * Note that we initialize the page after writing WAL because the TPD
	 * routines use last slot in page to determine TPD block number.
	 */
	if (need_init)
		ZheapInitPage(page, (Size) BLCKSZ);

	END_CRIT_SECTION();


	/*
	 * Release any remaining pin on visibility map page.
	 */
	if (BufferIsValid(vmbuffer))
		ReleaseBuffer(vmbuffer);

	UnlockReleaseBuffer(buffer);
	UnlockReleaseTPDBuffers();

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

	/*
	 * If the location upto which rollback need to be done is not provided,
	 * then rollback the complete transaction.
	 */
	if (start_urec_ptr == InvalidUndoRecPtr)
	{
		UndoLogNumber logno = UndoRecPtrGetLogNo(end_urec_ptr);
		start_urec_ptr = UndoLogGetLastXactStartPoint(logno);
	}

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
