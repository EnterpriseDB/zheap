/*-------------------------------------------------------------------------
 *
 * undotest.c
 *	  undo test api code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/undo/undotest.c
 *
 * NOTES
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/transam.h"
#include "access/undoaccess.h"
#include "access/undotest.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "miscadmin.h"

static void undotest_xlog_insert(XLogReaderState *record);

static void
undotest_xlog_insert(XLogReaderState *record)
{
	UndoRecordInsertContext context = {{0}};
	FullTransactionId   fxid = XLogRecGetFullXid(record);
	UndoLogCategory category = UNDO_PERMANENT;
	char	*data = "test_data";
	int		 len = strlen(data);
	UnpackedUndoRecord	undorecord = {0};
	UndoRecPtr	undo_ptr;
	xl_undotest_insert *xlrec = (xl_undotest_insert *) XLogRecGetData(record);

	undorecord.uur_rmid = RM_UNDOTEST_ID;
	undorecord.uur_type = UNDOTEST_INSERT;
	undorecord.uur_info = 0;
	undorecord.uur_fxid = fxid;
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_prevundo = InvalidUndoRecPtr;
	undorecord.uur_block = xlrec->blockno;
	undorecord.uur_offset = xlrec->offset;
	undorecord.uur_reloid = xlrec->reloid;

	initStringInfo(&undorecord.uur_tuple);

	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, category, 1, record);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, xlrec->dbid);

	Assert(undo_ptr == xlrec->undo_ptr);

	elog(LOG, "Insert undo record: urec: " UndoRecPtrFormat ", "
		 "block: %d, offset: %d, undo_op: %d, "
		 "xid: %d, reloid: %d",
		 undo_ptr, undorecord.uur_block,
		 undorecord.uur_offset, undorecord.uur_type,
		 XidFromFullTransactionId(undorecord.uur_fxid), undorecord.uur_reloid);

	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);
}

void undotest_insert(Oid reloid, BlockNumber blkno, OffsetNumber offset,
					 int per_level)
{
	UndoRecordInsertContext context = {{0}};
	TransactionId xid = GetTopTransactionId();
	UndoLogCategory category = per_level;
	char	*data = "test_data";
	int		 len = strlen(data);
	UnpackedUndoRecord	undorecord = {0};
	UndoRecPtr	undo_ptr;
	bool	needs_wal = (per_level == UNDO_PERMANENT);

	undorecord.uur_rmid = RM_UNDOTEST_ID;
	undorecord.uur_type = UNDOTEST_INSERT;
	undorecord.uur_info = 0;
	undorecord.uur_fxid = FullTransactionIdFromEpochAndXid(0, xid);
	undorecord.uur_fork = MAIN_FORKNUM;
	undorecord.uur_prevundo = InvalidUndoRecPtr;
	undorecord.uur_block = blkno;
	undorecord.uur_offset = offset;
	undorecord.uur_reloid = reloid;

	initStringInfo(&undorecord.uur_tuple);

	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, category, 1, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/*
	 * We can't print the undo record pointer in the notice as it may get
	 * changed and some regression tests may fail.
	 */
	elog(NOTICE, "Insert undo record: block: %d, offset: %d, undo_op: %d, "
		 "reloid: %d",
		 undorecord.uur_block, undorecord.uur_offset, undorecord.uur_type,
		 undorecord.uur_reloid);
	elog(DEBUG1, "Insert undo record: urec: " UndoRecPtrFormat ", "
		 "block: %d, offset: %d, undo_op: %d, "
		 "xid: %d, reloid: %d",
		 undo_ptr, undorecord.uur_block,
		 undorecord.uur_offset, undorecord.uur_type,
		 XidFromFullTransactionId(undorecord.uur_fxid), undorecord.uur_reloid);

	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* No ereport(ERROR) from here till changes are logged */
	START_CRIT_SECTION();

	/* XLOG stuff */
	if (needs_wal)
	{
		XLogRecPtr	lsn;
		xl_undotest_insert xlrec;

		xlrec.undo_ptr = undo_ptr;
		xlrec.blockno = undorecord.uur_block;
		xlrec.offset = undorecord.uur_offset;
		xlrec.dbid = MyDatabaseId;
		xlrec.reloid = undorecord.uur_reloid;

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, SizeOfUndoTestInsert);

		RegisterUndoLogBuffers(&context, 1);
		lsn = XLogInsert(RM_UNDOTEST_ID, XLOG_UNDOTEST_INSERT);
		UndoLogBuffersSetLSN(&context, lsn);
	}

	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);
}

void
undotest_undo_actions(int nrecords, UndoRecInfo *urp_array)
{
	int i;

	START_CRIT_SECTION();

	for (i = 0; i < nrecords; i++)
	{
		UndoRecInfo *urec_info = (UndoRecInfo *) urp_array + i;
		UnpackedUndoRecord *uur = urec_info->uur;

		/*
		 * We can't print the undo record pointer in the notice as it may get
		 * changed and some regression tests may fail.
		 */
		elog(NOTICE, "Rollback undo record: block: %d, offset: %d, undo_op: %d, "
			 "reloid: %d",
			 uur->uur_block, uur->uur_offset, uur->uur_type, uur->uur_reloid);
		elog(DEBUG1, "Rollback undo record: urec: " UndoRecPtrFormat ", "
			 "block: %d, offset: %d, undo_op: %d, "
			 "xid: %d, reloid: %d",
			 urec_info->urp, uur->uur_block,
			 uur->uur_offset, uur->uur_type,
			 XidFromFullTransactionId(uur->uur_fxid), uur->uur_reloid);
	}

	END_CRIT_SECTION();
}

void
undotest_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info & XLOG_UNDOTEST_OPMASK)
	{
		case XLOG_UNDOTEST_INSERT:
			undotest_xlog_insert(record);
			break;
		default:
			elog(PANIC, "undotest_redo: unknown op code %u", info);
	}
}
