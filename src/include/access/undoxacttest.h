/*-------------------------------------------------------------------------
 *
 * undoxacttest.h
 *	  test module
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undoxacttest.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UNDOXACTTEST_H
#define UNDOXACTTEST_H

#include "access/xlogreader.h"
#include "access/xlog_internal.h"
#include "lib/stringinfo.h"
#include "storage/buf.h"
#include "utils/relcache.h"


/*
 * WAL records for undoxacttest
 */
#define XLOG_UNDOXACTTEST_MOD		0x00

typedef struct xl_undoxacttest_mod
{
	int64 newval;
	int64 debug_mod;
	int64 debug_oldval;
} xl_undoxacttest_mod;


/*
 * UNDO records for undoxacttest
 */
typedef struct xu_undoxactest_mod
{
	Oid reloid;
	int64 mod;
} xu_undoxactest_mod;


/* rmgr integration */
extern void undoxacttest_redo(XLogReaderState *record);
extern void undoxacttest_desc(StringInfo buf,XLogReaderState *record);
extern const char *undoxacttest_identify(uint8 info);
extern const RmgrUndoHandler* undoxacttest_undo_handler(void);

/* functions to be called by SQL UDFs */
int64 undoxacttest_log_execute_mod(Relation rel, Buffer buf, int64 *counter, int64 mod, bool is_undo);

void undoxacttest_undo_mod(const xu_undoxactest_mod *uxt_r);

#endif /* UNDOXACTTEST */
