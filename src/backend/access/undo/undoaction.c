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
#include "nodes/pg_list.h"
#include "postmaster/undoloop.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "miscadmin.h"

static void execute_undo_actions_page(List *luur, Oid reloid, BlockNumber blkno);
static inline void undo_action_insert(Relation rel, Page page, OffsetNumber off);

/*
 * execute_undo_actions - Execute the undo actions
 */
void
execute_undo_actions(UndoRecPtr from_urecptr, UndoRecPtr to_urecptr)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr;
	Oid			reloid;
	Oid			prev_reloid = InvalidOid;
	ForkNumber	prev_fork = InvalidForkNumber;
	BlockNumber	prev_block = InvalidBlockNumber;
	List	   *luur = NIL;
	bool		more_undo;

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

	urec_ptr = from_urecptr;

	while (urec_ptr >= to_urecptr)
	{
		uint16	urec_prevlen;

		more_undo = true;

		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId);
		Assert(uur != NULL);

		reloid = RelidByRelfilenode(uur->uur_tsid, uur->uur_relfilenode);

		/* Collect the undo records that belong to the same page. */
		if (!OidIsValid(prev_reloid) ||
			(prev_reloid == reloid &&
			 prev_fork == uur->uur_fork &&
			 prev_block == uur->uur_block))
		{
			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;

			luur = lappend(luur, uur);
			urec_prevlen = uur->uur_prevlen;

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

		execute_undo_actions_page(luur, prev_reloid, prev_block);

		/* release the undo records for which action has been replayed */
		while (luur)
		{
			UnpackedUndoRecord *uur = (UnpackedUndoRecord *) linitial(luur);
			UndoRecordRelease(uur);
			luur = list_delete_first(luur);
		}

		/*
		 * There are still more records to process, so keep moving backwards
		 * in the chain.
		 */
		if (more_undo)
		{
			luur = lappend(luur, uur);
			prev_reloid = reloid;
			prev_fork = uur->uur_fork;
			prev_block = uur->uur_block;

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
	if (list_length(luur))
	{
		execute_undo_actions_page(luur, prev_reloid, prev_block);

		/* release the undo records for which action has been replayed */
		while (luur)
		{
			UnpackedUndoRecord *uur = (UnpackedUndoRecord *) linitial(luur);
			UndoRecordRelease(uur);
			luur = list_delete_first(luur);
		}
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
undo_action_insert(Relation rel, Page page, OffsetNumber off)
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
}

/*
 * execute_undo_actions - Execute the undo actions for a page
 */
static void
execute_undo_actions_page(List *luur, Oid reloid, BlockNumber blkno)
{
	ListCell   *l_iter;
	Relation	rel;
	Buffer		buffer;
	Page		page;

	/*
	 * If the action is executed by backend as a result of rollback, we must
	 * already have an appropriate lock on relation.
	 */
	rel = heap_open(reloid, NoLock);

	buffer = ReadBuffer(rel, blkno);
	page = BufferGetPage(buffer);
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	START_CRIT_SECTION();

	foreach(l_iter, luur)
	{
		UnpackedUndoRecord *uur = (UnpackedUndoRecord *) lfirst(l_iter);

		switch (uur->uur_type)
		{
			case UNDO_INSERT:
				{
					undo_action_insert(rel, page, uur->uur_offset);
				}
				break;
			case UNDO_MULTI_INSERT:
				{
					OffsetNumber	start_offset;
					OffsetNumber	end_offset;
					OffsetNumber	iter_offset;

					start_offset = ((OffsetNumber *) uur->uur_payload.data)[0];
					end_offset = ((OffsetNumber *) uur->uur_payload.data)[1];

					for (iter_offset = start_offset;
						 iter_offset <= end_offset;
						 iter_offset++)
					{
						undo_action_insert(rel, page, iter_offset);
					}
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

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);

					undo_tup_len = *((uint32 *) &uur->uur_tuple.data[offset]);
					ItemIdChangeLen(lp, undo_tup_len);
					/* skip ctid and tableoid stored in undo tuple */
					offset += sizeof(uint32) + sizeof(ItemPointerData) + sizeof(Oid);
					memcpy(zhtup,
						   (ZHeapTupleHeader) &uur->uur_tuple.data[offset],
						   undo_tup_len);
				}
				break;
			case UNDO_XID_LOCK_ONLY:
				{
					ItemId		lp;
					ZHeapTupleHeader zhtup, undo_tup_hdr;

					/* Copy the entire tuple from undo. */
					lp = PageGetItemId(page, uur->uur_offset);
					Assert(ItemIdIsNormal(lp));
					zhtup = (ZHeapTupleHeader) PageGetItem(page, lp);

					/*
					 * Override the tuple header values with values retrieved
					 * from undo record.
					 */
					undo_tup_hdr = (ZHeapTupleHeader) uur->uur_tuple.data;
					zhtup->t_infomask2 = undo_tup_hdr->t_infomask2;
					zhtup->t_infomask = undo_tup_hdr->t_infomask;
					zhtup->t_hoff = undo_tup_hdr->t_hoff;
				}
				break;
			case UNDO_INVALID_XACT_SLOT:
				break;
			default:
				elog(ERROR, "unsupported undo record type");
		}
	}

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
}
