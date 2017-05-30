/*-------------------------------------------------------------------------
 *
 * ztqual.c
 *	  POSTGRES "time qualification" code, ie, ztuple visibility rules.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/time/ztqual.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xact.h"
#include "storage/bufmgr.h"
#include "utils/tqual.h"
#include "utils/ztqual.h"


/*
 * ZHeapTupleSatisfiesMVCC
 *		True iff zheap tuple is valid for the given MVCC snapshot.
 */
ZHeapTuple
ZHeapTupleSatisfiesMVCC(ZHeapTuple zhtup, Snapshot snapshot,
						Buffer buffer)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		if (ZHeapTupleHeaderGetCid(tuple, buffer) >= snapshot->curcid)
			return NULL;	/* inserted after scan started */
	}
	else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
		return NULL;
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		;
	else
		return NULL;

	return zhtup;
}
