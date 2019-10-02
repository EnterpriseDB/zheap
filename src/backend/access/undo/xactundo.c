/*-------------------------------------------------------------------------
 *
 * xactundo.c
 *	  management of undo record sets for transactions
 *
 * Undo records that need to be applied after a transaction or
 * subtransaction abort should be inserted using the functions defined
 * in this file; thus, every table or index access method that wants to
 * use undo for post-abort cleanup should invoke these interfaces.
 *
 * The reason for this design is that we want to pack all of the undo
 * records for a single transaction into one place, regardless of the
 * AM which generated them. That way, we can apply the undo actions
 * which pertain to that transaction in the correct order; namely,
 * backwards as compared with the order in which the records were
 * generated.
 *
 * Actually, we may use up to three undo record sets per transaction,
 * one per persistence level (permanent, unlogged, temporary). We
 * assume that it's OK to apply the undo records for each persistence
 * level independently of the others. At least insofar as undo records
 * describe page modifications to relations with a persistence level
 * matching the undo log in which undo pertaining to those modifications
 * is stored, this assumption seems safe, since the modifications
 * must necessarily touch disjoint sets of pages.
 *
 * All undo record sets of type URST_TRANSACTION are managed here;
 * the undo system supports at most one such record set per persistence
 * level per transaction.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/xactundo.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undolog.h"
#include "access/undorecordset.h"
#include "access/xactundo.h"
#include "catalog/pg_class.h"

static UndoRecordSet *xact_undo_record_set[NPersistenceLevels];

static void
EnsureUndoRequest(void)
{
	// DUMMY: replace with UndoState stuff
}

static void
SerializeUndoData(StringInfo buf, UndoNode *undo_node)
{
	// DUMMY: replace with magic stuff from Andres
	appendStringInfo(buf, "hi mom");
}

/*
 * Prepare to insert transactional undo data.
 */
UndoRecPtr
PrepareXactUndoData(XactUndoContext *ctx, char persistence,
					UndoNode *undo_node)
{
	int		index = UndoPersistenceIndex(persistence);
	UndoRecordSet *urs;

	/*
	 * Unless we're writing temporary undo, we must ensure that an UndoRequest
	 * has been allocated to this transaction, so that if this transaction
	 * aborts, any undo that it generated is certain to get processed even
	 * if our session is not around any longer.
	 *
	 * (For temporary undo, we don't need this, because if our session ceases
	 * to exist, then it's not important to apply undo that affects only
	 * session-local objects; moreover, no other backend could do so anyway,
	 * since no other backend can read our local buffers.)
	 */
	if (persistence != RELPERSISTENCE_TEMP)
		EnsureUndoRequest();

	/*
	 * Make sure we have an UndoRecordSet of the appropriate type open for
	 * this persistence level.
	 *
	 * These record sets are always associated with the toplevel transaction,
	 * not a subtransaction, in order to avoid fragmentation.
	 */
	urs = xact_undo_record_set[index];
	if (urs == NULL)
	{
		urs = UndoCreate(URST_TRANSACTION, persistence, 1);
		xact_undo_record_set[index] = urs;
	}

	/* Remember persistence level. */
	ctx->persistence = persistence;

	/* Prepare serialized undo data. */
	initStringInfo(&ctx->data);
	SerializeUndoData(&ctx->data, undo_node);

	/*
	 * Find sufficient space for this undo insertion and lock the necessary
	 * buffers.
	 */
	return UndoAllocate(urs, ctx->data.len);
}

/*
 * Insert transactional undo data.
 */
void
InsertXactUndoData(XactUndoContext *ctx, uint8 first_block_id)
{
	int		index = UndoPersistenceIndex(ctx->persistence);
	UndoRecordSet *urs = xact_undo_record_set[index];

	Assert(urs != NULL);
	UndoInsert(urs, first_block_id, ctx->data.data, ctx->data.len);
}

/*
 * Set page LSNs for just-inserted transactional undo data.
 */
void
SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn)
{
	int		index = UndoPersistenceIndex(ctx->persistence);
	UndoRecordSet *urs = xact_undo_record_set[index];

	Assert(urs != NULL);
	UndoPageSetLSN(urs, lsn);
}

/*
 * Clean up after inserting transactional undo data.
 */
void
CleanupXactUndoInsertion(XactUndoContext *ctx)
{
	int		index = UndoPersistenceIndex(ctx->persistence);
	UndoRecordSet *urs = xact_undo_record_set[index];

	UndoRelease(urs);
	pfree(ctx->data.data);
}
