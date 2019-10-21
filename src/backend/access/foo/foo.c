/*
 * A test module that appends user-supplied text strings to UndoRecordSets.
 * This can't be done as an extension because it requires its own RMGR
 * integration (ID, callbacks) and UndoRecordSet integration
 * (UndoRecordSetType, callbacks).
 */

#include "postgres.h"

#include "access/foo_xlog.h"
#include "access/undolog.h"
#include "access/undorecordset.h"
#include "access/xact.h"
#include "access/xloginsert.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/varlena.h"

PG_FUNCTION_INFO_V1(foo_create);
PG_FUNCTION_INFO_V1(foo_write);
PG_FUNCTION_INFO_V1(foo_close);

PG_FUNCTION_INFO_V1(foo_createwriteclose);

static void foo_xact_callback(XactEvent event, void *arg);
static void foo_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
								 SubTransactionId parentSubid, void *arg);

static UndoRecordSet *current_urs = NULL;
static SubTransactionId current_urs_subid = InvalidSubTransactionId;
static bool xact_callbacks_registered = false;

Datum
foo_create(PG_FUNCTION_ARGS)
{
	char	urs_header[] = "Foo1";
	const char *persistence;
	MemoryContext old_context;

	if (PG_ARGISNULL(0))
		elog(ERROR, "persistence level required");

	persistence = text_to_cstring(PG_GETARG_TEXT_PP(0));

	if (*persistence != 'p' &&
		*persistence != 't' &&
		*persistence != 'u')
		elog(ERROR, "unknown persistence level");

	if (current_urs != NULL)
		elog(ERROR, "an UndoRecordSet is already active");

	if (!xact_callbacks_registered)
	{
		RegisterXactCallback(foo_xact_callback, NULL);
		RegisterSubXactCallback(foo_subxact_callback, NULL);
		xact_callbacks_registered = true;
	}

	old_context = MemoryContextSwitchTo(TopMemoryContext);
	current_urs = UndoCreate(URST_FOO, *persistence,
							 GetCurrentTransactionNestLevel(),
							 4, urs_header);
	current_urs_subid = GetCurrentSubTransactionId();
	MemoryContextSwitchTo(old_context);

	PG_RETURN_VOID();
}

Datum
foo_close(PG_FUNCTION_ARGS)
{
	XLogRecPtr lsn;
	int record = 42;		/* bogus record payload */

	if (current_urs == NULL)
		elog(ERROR, "no active UndoRecordSet");

	/*
	 * To close a URS, you need to insert a WAL record -- any WAL record will
	 * do.  The closed-marking will piggy-back on that WAL record.  Here the
	 * entirely empty and useless 'PING' record is used.  The intention is
	 * that XLOG_XACT_COMMIT and friends would be used, for transactions.  For
	 * non-transactional information such as multixacts, a single WAL record
	 * might create, insert and close in one go.
	 *
	 * However, if UndoPrepareToMarkClosed returns false, then no data has
	 * been written and we don't need to write any WAL.
	 */

	if (UndoPrepareToMarkClosed(current_urs))
	{
		START_CRIT_SECTION();
		XLogBeginInsert();
		UndoMarkClosed(current_urs);
		XLogRegisterData((char *) &record, sizeof(record));
		lsn = XLogInsert(RM_FOO_ID, XLOG_FOO_PING);
		UndoPageSetLSN(current_urs, lsn);
		END_CRIT_SECTION();
	}

	UndoDestroy(current_urs);

	current_urs = NULL;

	PG_RETURN_VOID();
}

Datum
foo_write(PG_FUNCTION_ARGS)
{
	char *string = text_to_cstring(PG_GETARG_TEXT_PP(0));
	size_t length = strlen(string);
	UndoRecPtr urp;
	XLogRecPtr lsn;

	if (current_urs == NULL)
		elog(ERROR, "there is no active UndoRecordSet; call foo_create() first");

	/*
	 * Make sure that we can write the undo data without errors.  After this
	 * runs, physical space is reserved and the buffers we need are all
	 * pinned and locked.
	 */
	urp = UndoAllocate(current_urs, length + 1);

	START_CRIT_SECTION();

	XLogBeginInsert();

	/*
	 * Write the string into the undo log.  We do this first, because it
	 * registers the undo buffers with the following WAL record.
	 */
	UndoInsert(current_urs, 0, string, length + 1);

	/* Write the string into the WAL so we can replay this. */
	XLogRegisterData((char *) string, length + 1);
	lsn = XLogInsert(RM_FOO_ID, XLOG_FOO_STRING);

	/* Update the undo pages' LSN so that the WAL will be flushed first. */
	UndoPageSetLSN(current_urs, lsn);

	END_CRIT_SECTION();

	/* Unlock and unpin undo buffers. */
	UndoRelease(current_urs);

	/*
	 * Since we don't have an appropriate type for UndoRecPtr yet, we'll
	 * return a string representation.
	 */
	PG_RETURN_TEXT_P(cstring_to_text(psprintf(UndoRecPtrFormat, urp)));
}

Datum
foo_createwriteclose(PG_FUNCTION_ARGS)
{
	char *string = text_to_cstring(PG_GETARG_TEXT_PP(0));
	size_t length = strlen(string);
	UndoRecPtr urp;
	XLogRecPtr lsn;
	UndoRecordSet *urs;
	char	urs_header[] = "Foo2";

	/* We can do all of these things with a single WAL record. */

	urs = UndoCreate(URST_FOO, 'p', GetCurrentTransactionNestLevel(),
					 4, urs_header);
	urp = UndoAllocate(urs, length + 1);
	UndoPrepareToMarkClosed(urs);

	START_CRIT_SECTION();
	XLogBeginInsert();
	UndoInsert(urs, 0, string, length + 1);
	UndoMarkClosed(urs);
	XLogRegisterData((char *) string, length + 1);
	lsn = XLogInsert(RM_FOO_ID, XLOG_FOO_CREATEWRITECLOSE);
	UndoPageSetLSN(urs, lsn);
	END_CRIT_SECTION();

	UndoDestroy(urs);

	PG_RETURN_TEXT_P(cstring_to_text(psprintf(UndoRecPtrFormat, urp)));
}

static void
foo_xlog_string(XLogReaderState *record)
{
	char *string = XLogRecGetData(record);

	UndoInsertInRecovery(record, string, strlen(string) + 1);
}

static void
foo_xlog_ping(XLogReaderState *record)
{
	UndoUpdateInRecovery(record);
}

static void
foo_xlog_createwriteclose(XLogReaderState *record)
{
	char *string = XLogRecGetData(record);

	UndoInsertInRecovery(record, string, strlen(string) + 1);
	UndoUpdateInRecovery(record);
}

void
foo_redo(XLogReaderState *record)
{
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info)
	{
		case XLOG_FOO_STRING:
			foo_xlog_string(record);
			break;
		case XLOG_FOO_PING:
			foo_xlog_ping(record);
			break;
		case XLOG_FOO_CREATEWRITECLOSE:
			foo_xlog_createwriteclose(record);
			break;
		default:
			elog(PANIC, "foo_redo: unknown op code %u", info);
	}
}

static void
foo_xact_callback(XactEvent event, void *arg)
{
	if (event == XACT_EVENT_COMMIT || event == XACT_EVENT_ABORT ||
		event == XACT_EVENT_PREPARE)
		current_urs = NULL;
}

static void
foo_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
					 SubTransactionId parentSubid, void *arg)
{
	if ((event == SUBXACT_EVENT_COMMIT_SUB ||
		 event == SUBXACT_EVENT_ABORT_SUB) &&
		current_urs_subid == mySubid)
	{
		current_urs = NULL;
		current_urs_subid = InvalidSubTransactionId;
	}
}
