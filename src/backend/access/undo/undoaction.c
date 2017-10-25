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
#include "postmaster/undoloop.h"
#include "storage/block.h"
#include "storage/buf.h"
#include "storage/bufmgr.h"
#include "utils/relfilenodemap.h"
#include "miscadmin.h"

/*
 * undo_insert - delete the tuple
 *
 * This will mark the tuple as dead so that the future access to it can't see
 * this tuple.  We mark it as unused if there is no other index pointing to
 * it, otherwise mark it as dead.
 */
static void
undo_insert(Oid tblspcid, Oid relfilenode, BlockNumber blkno, OffsetNumber off)
{
	Relation	rel;
	Buffer		buffer;
	Page		page;
	ItemId		lp;
	Oid			reloid;
	bool		relhasindex;

	reloid = RelidByRelfilenode(tblspcid, relfilenode);

	Assert(OidIsValid(reloid));

	/*
	 * If the action is executed by backend as a result of rollback, we must
	 * already have an appropriate lock on relation.
	 */
	rel = heap_open(reloid, NoLock);

	buffer = ReadBuffer(rel, blkno);
	page = BufferGetPage(buffer);

	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	lp = PageGetItemId(page, off);
	Assert(ItemIdIsNormal(lp));

	relhasindex = RelationGetForm(rel)->relhasindex;

	START_CRIT_SECTION();

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

	MarkBufferDirty(buffer);

	/* WAL stuff */
	if (RelationNeedsWAL(rel))
	{
		xl_undo_insert	xlrec;
		XLogRecPtr	recptr;

		xlrec.offnum = off;
		xlrec.relhasindex = relhasindex;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfUndoInsert);

		XLogRegisterBuffer(0, buffer, REGBUF_STANDARD);

		recptr = XLogInsert(RM_UNDOACTION_ID, XLOG_UNDO_INSERT);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buffer);

	heap_close(rel, NoLock);
}

/*
 * execute_undo_actions - Execute the undo actions
 */
void
execute_undo_actions(UndoRecPtr from_urecptr, UndoRecPtr to_urecptr)
{
	UnpackedUndoRecord *uur = NULL;
	UndoRecPtr	urec_ptr;

	Assert(from_urecptr != InvalidUndoRecPtr);
	Assert(to_urecptr != InvalidUndoRecPtr);

	urec_ptr = from_urecptr;

	while (urec_ptr >= to_urecptr)
	{
		uint16	urec_prevlen;

		/* Fetch the undo record for given undo_recptr. */
		uur = UndoFetchRecord(urec_ptr, InvalidBlockNumber,
							  InvalidOffsetNumber, InvalidTransactionId);
		Assert(uur != NULL);

		switch (uur->uur_type)
		{
			case UNDO_INSERT:
				undo_insert(uur->uur_tsid,
							uur->uur_relfilenode,
							uur->uur_block,
							uur->uur_offset);
				break;
			default:
				elog(ERROR, "unsupported undo record type");
		}

		urec_prevlen = uur->uur_prevlen;
		UndoRecordRelease(uur);

		/* Get the previous record to process. */
		if (urec_prevlen != 0)
		{
			urec_ptr = UndoGetPrevUndoRecptr(urec_ptr, urec_prevlen);
		}
		else
		{
			/* We have reached at the end of chain. */
			break;
		}
	}
}
