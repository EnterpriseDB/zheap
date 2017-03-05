/*--------------------------------------------------------------------------
 *
 * test_undorecord.c
 *		Throw-away test code for undo records.
 *
 * Copyright (c) 2013-2017, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		src/test/modules/test_undorecord.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undorecord.h"
#include "fmgr.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(test_undo_insert);

Datum
test_undo_insert(PG_FUNCTION_ARGS)
{
	UnpackedUndoRecord	uur;
	char	pages[2 * BLCKSZ];
	Page	p1 = (Page) &pages;
	Page	p2 = (Page) &pages[BLCKSZ];
	int		aw = 0;

	memset(&uur, 0, sizeof(UnpackedUndoRecord));
	uur.uur_type = 0xaa;
	uur.uur_prevlen = 0xbbbb;
	uur.uur_relfilenode = 0xdeadbeef;
	uur.uur_tsid = PG_GETARG_INT32(0);
	uur.uur_fork = PG_GETARG_INT32(1);
	uur.uur_blkprev = 0x0123456789abcdef;
	uur.uur_block = PG_GETARG_INT32(2);
	uur.uur_offset = 0xcc;

	if (!PG_ARGISNULL(3))
	{
		bytea *varlena = PG_GETARG_BYTEA_PP(3);
		uur.uur_payload.len = VARSIZE_ANY_EXHDR(varlena);
		uur.uur_payload.data = VARDATA_ANY(varlena);
	}

	if (!PG_ARGISNULL(4))
	{
		bytea *varlena = PG_GETARG_BYTEA_PP(4);
		uur.uur_tuple.len = VARSIZE_ANY_EXHDR(varlena);
		uur.uur_tuple.data = VARDATA_ANY(varlena);
	}

	memset(pages, 0, 2 * BLCKSZ);
	if (!InsertUndoRecord(&uur, p1, PG_GETARG_INT32(5), &aw) &&
		!InsertUndoRecord(&uur, p2, MAXALIGN(sizeof(PageHeaderData)), &aw))
		elog(NOTICE, "couldn't fit in 2 pages?!");

	PG_RETURN_BYTEA_P(cstring_to_text_with_len(pages, sizeof pages));
}
