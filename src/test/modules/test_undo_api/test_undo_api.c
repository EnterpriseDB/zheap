#include "postgres.h"

#include "access/transam.h"
#include "access/undoaccess.h"
#include "access/xact.h"
#include "catalog/pg_class.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"

#include <stdlib.h>
#include <unistd.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(test_undo_api);

static void
compare_undo_record(UnpackedUndoRecord *urp1, UnpackedUndoRecord *urp2)
{
	int	header_size = offsetof(UnpackedUndoRecord, uur_fxid) + sizeof(uint64);

	/* mask uur_info */
	urp1->uur_info = urp2->uur_info = 0;

	/* Compare undo record header. */
	if (strncmp((char *) urp1, (char *) urp2, header_size) != 0)
		elog(ERROR, "undo header did not match");

	/* Compare payload and tuple length. */
	if (urp1->uur_payload.len != urp2->uur_payload.len)
		elog(ERROR, "payload data length did not match");

	if (urp1->uur_tuple.len != urp2->uur_tuple.len)
		elog(ERROR, "tuple data length did not match");

	/* Compare undo record payload data. */
	if (strncmp(urp1->uur_payload.data, urp2->uur_payload.data, urp1->uur_tuple.len) != 0)
		elog(ERROR, "undo payload data did not match");

	/* Compare undo record tuple data. */
	if (strncmp(urp1->uur_tuple.data, urp2->uur_tuple.data, urp1->uur_tuple.len) != 0)
		elog(ERROR, "undo tuple data did not match");

	/* Compare undo record rmid. */
	if (urp1->uur_rmid != urp2->uur_rmid)
		elog(ERROR, "undo record's rmid did not match");

	/* Compare undo record reloid. */
	if (urp1->uur_reloid != urp2->uur_reloid)
		elog(ERROR, "undo record's reloid did not match");

	/* Compare undo record xid. */
	if (!FullTransactionIdEquals(urp1->uur_fxid,urp2->uur_fxid))
		elog(ERROR, "undo record's xid did not match");

	/* Compare undo record cid. */
	if (urp1->uur_cid != urp2->uur_cid)
		elog(ERROR, "undo record's cid did not match");
}

static void
initialize_undo_record(UnpackedUndoRecord *undorecord, char *data,
			char initdata, int len, int txid)
{
	undorecord->uur_rmid = 1;
	undorecord->uur_type = 2;
	undorecord->uur_info = 0;
	undorecord->uur_fxid = FullTransactionIdFromEpochAndXid(0, txid);
	undorecord->uur_cid = 1;
	undorecord->uur_fork = MAIN_FORKNUM;
	undorecord->uur_prevundo = 10;
	undorecord->uur_block = 1;
	undorecord->uur_offset = 10;

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord->uur_tuple);
	memset(data, initdata, len);
	appendBinaryStringInfo(&undorecord->uur_tuple,
						(char *) data,
						len);
	initStringInfo(&undorecord->uur_payload);
	appendBinaryStringInfo(&undorecord->uur_payload,
						(char *) data,
						len);
}

/*
 * test_insert_and_fetch - test simple insert and fetch undo record API
 */
static void
test_insert_and_fetch()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[5000];
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 3000, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 1, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_2nd_undo - the 2nd undo must not store rmid/reloid/xid/cid, it should get this
 * information from first und record
 */
static void
test_insert_and_fetch_2nd_undo()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[200];
	int		 len = 200;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_diff_rmid - the 2nd undo record will have different rmid
 */
static void
test_insert_and_fetch_diff_rmid()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[200];
	int		 len = 200;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert 2nd undo */
	undorecord.uur_rmid = 2;

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_diff_reloid - the 2nd undo record will have different reloid
 */
static void
test_insert_and_fetch_diff_reloid()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[200];
	int		 len = 200;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert 2nd undo with different reloid*/
	undorecord.uur_reloid = 10001;

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_diff_cid - the 2nd undo record will have different cid
 */
static void
test_insert_and_fetch_diff_cid()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[200];
	int		 len = 200;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert 2nd undo with different cid*/
	undorecord.uur_cid = 2;

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_diff_cid - the 2nd undo record will have different xid
 */
static void
test_insert_and_fetch_diff_xid()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[200];
	int		 len = 200;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert 2nd undo with different xid*/
	undorecord.uur_fxid = FullTransactionIdFromEpochAndXid(0, 101);

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

/*
 * test_insert_and_fetch_undo_curr_rec_spill_next_page- the undo record is spilling to next page
 */
static void
test_insert_and_fetch_undo_curr_rec_spill_next_page()
{
	UndoRecordInsertContext context = {{0}};
	UndoRecordFetchContext	fcontext;
	UndoLogCategory persistence = UNDO_PERMANENT;
	char	data[7000];
	int		 len = 4100;
	UnpackedUndoRecord	undorecord = {0};
	UnpackedUndoRecord *undorecord_out;
	UndoRecPtr	undo_ptr;

	/* Prepare dummy undo record*/
	initialize_undo_record(&undorecord, &data[0], 'a', 200, 100);

	/* Prepare undo record. */
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'b', 100);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   100);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   100);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	/* Insert large data so that record get split across pages. */
	initStringInfo(&undorecord.uur_tuple);
	memset(data, 'c', len);
	appendBinaryStringInfo(&undorecord.uur_tuple,
						   (char *) data,
						   len);
	initStringInfo(&undorecord.uur_payload);
	appendBinaryStringInfo(&undorecord.uur_payload,
						   (char *) data,
						   len);
	/* Prepare undo record. */
	memset(&context, 0, sizeof(UndoRecordInsertContext));
	undorecord.uur_info = 0;
	BeginUndoRecordInsert(&context, persistence, 2, NULL);
	undo_ptr = PrepareUndoInsert(&context, &undorecord, MyDatabaseId);

	/* Insert prepared undo record under critical section. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	/* Fetch inserted undo record. */
	BeginUndoFetch(&fcontext);
	undorecord_out = UndoFetchRecord(&fcontext, undo_ptr);
	FinishUndoFetch(&fcontext);
	/* compare undo records. */
	compare_undo_record(&undorecord, undorecord_out);

	UndoRecordRelease(undorecord_out);
	pfree(undorecord.uur_tuple.data);
}

#define MAX_UNDO_RECORD 10
/*
 * test_bulk_fetch - test the bulk fetch API.
 */
static void
test_bulk_fetch()
{
	int i;
	UndoRecordInsertContext context = {{0}};
	UndoLogCategory persistence = UNDO_PERMANENT;
	UndoRecInfo	urp_in_array[MAX_UNDO_RECORD];
	UndoRecInfo *urp_out_array;
	UnpackedUndoRecord	uur[MAX_UNDO_RECORD] = {{0}};
	UndoRecPtr	undo_ptr;
	int			nrecords = 0;

	for (i = 0; i < MAX_UNDO_RECORD; i++)
	{
		uur[i].uur_rmid = 1;
		uur[i].uur_reloid = 20000;
		uur[i].uur_cid = 1;
		uur[i].uur_type = 2;
		uur[i].uur_info = 0;
		uur[i].uur_fxid = FullTransactionIdFromEpochAndXid(0, 100);
		uur[i].uur_cid = 1;
		uur[i].uur_fork = MAIN_FORKNUM;
		uur[i].uur_prevundo = 10;
		uur[i].uur_block = i;
		uur[i].uur_offset = i + 1;
		urp_in_array[i].uur = &uur[i];
	}

	/* Prepare multiple undo records. */
	BeginUndoRecordInsert(&context, persistence, MAX_UNDO_RECORD, NULL);
	for (i = 0; i < MAX_UNDO_RECORD; i++)
	{
		undo_ptr = PrepareUndoInsert(&context, &uur[i], MyDatabaseId);
		urp_in_array[i].urp = undo_ptr;
	}

	/* Insert them all in one shot. */
	START_CRIT_SECTION();
	InsertPreparedUndo(&context);
	END_CRIT_SECTION();

	/* Release undo buffers. */
	FinishUndoRecordInsert(&context);

	undo_ptr = urp_in_array[MAX_UNDO_RECORD - 1].urp;

	/*
	 * Perform the bulk fetch. 2000 bytes are enough to hold 10 records.  Later
	 * we can enhance this to test the fetch in multi batch by increasing the
	 * record counts or reducing undo_apply_size to smaller value.
	 */
	urp_out_array = UndoBulkFetchRecord(&undo_ptr, urp_in_array[0].urp, 2000,
								&nrecords, false);
	/* Check whether we have got all the record we inserted. */
	if (nrecords != MAX_UNDO_RECORD)
		elog(ERROR, "undo record count did not match");

	/* Compare all records we have fetch using bulk fetch API*/
	for (i = 0; i < MAX_UNDO_RECORD; i++)
	{
		if (urp_in_array[i].urp != urp_out_array[MAX_UNDO_RECORD - 1 - i].urp)
			elog(ERROR, "undo record pointer did not match");
		compare_undo_record(urp_in_array[i].uur, urp_out_array[MAX_UNDO_RECORD - 1 - i].uur);
		UndoRecordRelease(urp_out_array[MAX_UNDO_RECORD - 1 - i].uur);
	}
}
/*
 * Undo API test module
 */
Datum
test_undo_api(PG_FUNCTION_ARGS)
{
	/*
	 * xact block already started?
	 */
	if (IsTransactionBlock())
		ereport(ERROR,
				(errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),
				 errmsg("test_undo_api cannot run inside a transaction block")));

	/* Test simple insert and fetch record. */
	test_insert_and_fetch();

	/* Test multiple insert and fetch record. */
	test_insert_and_fetch_2nd_undo();

	/* Test multiple insert with different rmid and fetch record. */
	test_insert_and_fetch_diff_rmid();

	/* Test multiple insert with different reloid and fetch record. */
	test_insert_and_fetch_diff_reloid();

	/* Test multiple insert with different xid and fetch record. */
	test_insert_and_fetch_diff_xid();

	/* Test multiple insert with different cid and fetch record. */
	test_insert_and_fetch_diff_cid();

	/* Test multiple insert with undo record spilling to next page */
	test_insert_and_fetch_undo_curr_rec_spill_next_page();

	/* Test undo record bulk fetch API*/
	test_bulk_fetch();

	PG_RETURN_VOID();
}
