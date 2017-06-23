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
#include "storage/procarray.h"
#include "utils/tqual.h"
#include "utils/ztqual.h"


/*
 * CopyTupleFromUndoRecord
 *	Extract the tuple from undo record.  Deallocate the previous version
 *	of tuple and form the new version.
 *
 *	free_zhtup - if true, free the previous version of tuple.
 */
static ZHeapTuple
CopyTupleFromUndoRecord(UnpackedUndoRecord	*urec, ZHeapTuple zhtup,
						bool free_zhtup)
{
	ZHeapTuple	undo_tup;

	switch (urec->uur_type)
	{
		case UNDO_DELETE:
			{
				ZHeapTupleHeader	undo_tup_hdr;

				undo_tup_hdr = (ZHeapTupleHeader) urec->uur_tuple.data;

				/*
				 * For deletes, undo tuple data is always same as prior tuple's data
				 * as we don't modify the same in delete operation.
				 */
				undo_tup = palloc(ZHEAPTUPLESIZE + zhtup->t_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				undo_tup->t_tableOid = zhtup->t_tableOid;
				undo_tup->t_len = zhtup->t_len;
				undo_tup->t_self = zhtup->t_self;
				memcpy(undo_tup->t_data, zhtup->t_data, zhtup->t_len);

				/*
				 * Free the previous version of tuple, see comments in
				 * UNDO_INPLACE_UPDATE case.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);

				/*
				 * override the tuple header values with values fetched from
				 * undo record
				 */
				undo_tup->t_data->t_infomask2 = undo_tup_hdr->t_infomask2;
				undo_tup->t_data->t_infomask = undo_tup_hdr->t_infomask;
				undo_tup->t_data->t_hoff = undo_tup_hdr->t_hoff;
			}
			break;
		case UNDO_INPLACE_UPDATE:
			{
				Size		offset = 0;
				uint32		undo_tup_len;

				/*
				 * After this point, the previous version of tuple won't be used.
				 * If we don't free the previous version, then we might accumulate
				 * lot of memory when many prior versions needs to be traversed.
				 *
				 * XXX One way to save deallocation and allocation of memory is to
				 * only make a copy of prior version of tuple when it is determined
				 * that the version is visible to current snapshot.  In practise,
				 * we don't need to traverse many prior versions, so let's be tidy.
				 */
				if (free_zhtup)
					zheap_freetuple(zhtup);

				undo_tup_len = *((uint32 *) &urec->uur_tuple.data[offset]);

				undo_tup = palloc(ZHEAPTUPLESIZE + undo_tup_len);
				undo_tup->t_data = (ZHeapTupleHeader) ((char *) undo_tup + ZHEAPTUPLESIZE);

				memcpy(&undo_tup->t_len, &urec->uur_tuple.data[offset], sizeof(uint32));
				offset += sizeof(uint32);

				memcpy(&undo_tup->t_self, &urec->uur_tuple.data[offset], sizeof(ItemPointerData));
				offset += sizeof(ItemPointerData);

				memcpy(&undo_tup->t_tableOid, &urec->uur_tuple.data[offset], sizeof(Oid));
				offset += sizeof(Oid);

				memcpy(undo_tup->t_data, (ZHeapTupleHeader) &urec->uur_tuple.data[offset], undo_tup_len);
			}
			break;
		default:
			elog(ERROR, "unsupported undo record type");
	}

	return undo_tup;
}

/*
 * GetTupleFromUndo
 *
 *	Fetch the record from undo and determine if previous version of tuple
 *	is visible for the given snapshot.  If there exists a visible version
 *	of tuple in undo, then return the same, else return NULL.
 */
static ZHeapTuple
GetTupleFromUndo(UndoRecPtr urec_ptr, ZHeapTuple zhtup, Snapshot snapshot,
				 Buffer buffer)
{
	UnpackedUndoRecord	*urec;
	ZHeapPageOpaque	opaque;
	ZHeapTuple	undo_tup;
	UndoRecPtr	prev_urec_ptr = -1;
	int	trans_slot_id = InvalidXactSlotId;
	int	undo_oper = -1;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	/*
	 * deleted or updated after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self));

	switch (urec->uur_type)
	{
		case UNDO_DELETE:
			{
				undo_tup = CopyTupleFromUndoRecord(urec, zhtup, true);
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				prev_urec_ptr = urec->uur_blkprev;

				if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
				{
					undo_oper = ZHEAP_INPLACE_UPDATED;
				}
				else
				{
					/* we can't further operate on deleted tuple */
					Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
				}

				UndoRecordRelease(urec);
			}
			break;
		case UNDO_INPLACE_UPDATE:
			{
				undo_tup = CopyTupleFromUndoRecord(urec, zhtup, true);
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				prev_urec_ptr = urec->uur_blkprev;

				if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
				{
					undo_oper = ZHEAP_INPLACE_UPDATED;
				}
				else
				{
					/* we can't further operate on deleted tuple */
					Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
				}

				UndoRecordRelease(urec);
			}
			break;
		default:
			elog(ERROR, "unsupported undo record type");
	}

	if (undo_oper == ZHEAP_INPLACE_UPDATED)
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapPageGetRawCommandId(trans_slot_id, opaque) >= snapshot->curcid)
			{
				/* updated after scan started */
				return GetTupleFromUndo(prev_urec_ptr,
										undo_tup,
										snapshot,
										buffer);
			}
			else
				return undo_tup;	/* updated before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapPageGetRawXid(trans_slot_id, opaque), snapshot))
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return undo_tup;
		else
			return GetTupleFromUndo(prev_urec_ptr,
									undo_tup,
									snapshot,
									buffer);
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapPageGetRawCommandId(trans_slot_id, opaque) >= snapshot->curcid)
				return NULL;	/* inserted after scan started */
			else
				return undo_tup;	/* inserted before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapPageGetRawXid(trans_slot_id, opaque), snapshot))
			return NULL;
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return undo_tup;
		else
			return NULL;
	}
}

/*
 * UndoTupleSatisfiesUpdate
 *
 *	Returns true, if there exists a visible version of zhtup in undo,
 *	false otherwise.
 *
 *	This function returns ctid for the undo tuple which will be always
 *	same as the ctid of zhtup except for non-in-place update case.
 */
static bool
UndoTupleSatisfiesUpdate(UndoRecPtr urec_ptr, ZHeapTuple zhtup,
						 CommandId curcid, Buffer buffer,
						 ItemPointer ctid, bool free_zhtup)
{
	UnpackedUndoRecord	*urec;
	ZHeapPageOpaque	opaque;
	ZHeapTuple	undo_tup = NULL;
	UndoRecPtr	prev_urec_ptr = -1;
	int	trans_slot_id = InvalidXactSlotId;
	int	undo_oper = -1;
	bool result = false;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	/*
	 * deleted or updated after the scan is started, fetch the prior record
	 * from undo to see if it is visible.
	 */
	urec = UndoFetchRecord(urec_ptr,
						   ItemPointerGetBlockNumber(&zhtup->t_self),
						   ItemPointerGetOffsetNumber(&zhtup->t_self));

	switch (urec->uur_type)
	{
		case UNDO_DELETE:
			{
				undo_tup = CopyTupleFromUndoRecord(urec, zhtup, free_zhtup);
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				prev_urec_ptr = urec->uur_blkprev;
				*ctid = undo_tup->t_self;

				if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
				{
					undo_oper = ZHEAP_INPLACE_UPDATED;
				}
				else
				{
					/* we can't further operate on deleted tuple */
					Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
				}

				UndoRecordRelease(urec);
			}
			break;
		case UNDO_INPLACE_UPDATE:
			{
				undo_tup = CopyTupleFromUndoRecord(urec, zhtup, free_zhtup);
				trans_slot_id = ZHeapTupleHeaderGetXactSlot(undo_tup->t_data);
				prev_urec_ptr = urec->uur_blkprev;
				*ctid = undo_tup->t_self;

				if (undo_tup->t_data->t_infomask & ZHEAP_INPLACE_UPDATED)
				{
					undo_oper = ZHEAP_INPLACE_UPDATED;
				}
				else
				{
					/* we can't further operate on deleted tuple */
					Assert(!(undo_tup->t_data->t_infomask & ZHEAP_DELETED));
				}

				UndoRecordRelease(urec);
			}
			break;
		default:
			elog(ERROR, "unsupported undo record type");
	}

	if (undo_oper == ZHEAP_INPLACE_UPDATED)
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapPageGetRawCommandId(trans_slot_id, opaque) >= curcid)
			{
				/* updated after scan started */
				return UndoTupleSatisfiesUpdate(prev_urec_ptr,
												undo_tup,
												curcid,
												buffer,
												ctid,
												true);
			}
			else
				result = true;	/* updated before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			return UndoTupleSatisfiesUpdate(prev_urec_ptr,
											undo_tup,
											curcid,
											buffer,
											ctid,
											true);
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = true;
		else
			return UndoTupleSatisfiesUpdate(prev_urec_ptr,
											undo_tup,
											curcid,
											buffer,
											ctid,
											true);
	}
	else	/* undo tuple is the root tuple */
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapPageGetRawXid(trans_slot_id, opaque)))
		{
			if (ZHeapPageGetRawCommandId(trans_slot_id, opaque) >= curcid)
				result = false;	/* inserted after scan started */
			else
				result = true;	/* inserted before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = false;
		else if (TransactionIdDidCommit(ZHeapPageGetRawXid(trans_slot_id, opaque)))
			result = true;
		else
			result = false;
	}

	if (undo_tup)
		pfree(undo_tup);
	return result;
}

/*
 * ZHeapTupleSatisfiesMVCC
 *
 *	Returns the visible version of tuple if any, NULL otherwise. We need to
 *	traverse undo record chains to determine the visibility of tuple.  In
 *	this function we need to first the determine the visibility of modified
 *	tuple and if it is not visible, then we need to fetch the prior version
 *	of tuple from undo chain and decide based on its visibility.  The undo
 *	chain needs to be traversed till we reach root version of the tuple.
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

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleHeaderGetCid(tuple, buffer) >= snapshot->curcid)
			{
				/* deleted after scan started, get previous tuple from undo */
				return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
										zhtup,
										snapshot,
										buffer);
			}
			else
				return NULL;	/* deleted before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return NULL;	/* tuple is deleted */
		else	/* transaction is aborted */
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED)
	{
		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleHeaderGetCid(tuple, buffer) >= snapshot->curcid)
			{
				/* updated after scan started, get previous tuple from undo */
				return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
										zhtup,
										snapshot,
										buffer);
			}
			else
				return zhtup;	/* updated before scan started */
		}
		else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return zhtup;	/* tuple is updated */
		else	/* transaction is aborted */
			return GetTupleFromUndo(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
									zhtup,
									snapshot,
									buffer);
	}

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		if (ZHeapTupleHeaderGetCid(tuple, buffer) >= snapshot->curcid)
			return NULL;	/* inserted after scan started */
		else
			return zhtup;	/* inserted before scan started */
	}
	else if (XidInMVCCSnapshot(ZHeapTupleHeaderGetRawXid(tuple, opaque), snapshot))
		return NULL;
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return zhtup;
	else
		return NULL;

	return NULL;
}

/*
 * ZHeapTupleSatisfiesUpdate
 *
 *	The retrun values for this API are same as HeapTupleSatisfiesUpdate.
 *	However, there is a notable difference in the way to determine visibility
 *	of tuples.  We need to traverse undo record chains to determine the
 *	visibility of tuple.
 *
 *	ctid - returns the ctid of visible tuple if the tuple is either deleted or
 *	updated.  ctid needs to be retrieved from undo tuple.
 *	in_place_updated - returns whether the current version of tuple is updated
 *	in place.
 */
HTSU_Result
ZHeapTupleSatisfiesUpdate(ZHeapTuple zhtup, CommandId curcid,
						  Buffer buffer, ItemPointer ctid, bool free_zhtup,
						  bool *in_place_updated)
{
	ZHeapPageOpaque	opaque;
	ZHeapTupleHeader tuple = zhtup->t_data;
	bool	visible;

	opaque = (ZHeapPageOpaque) PageGetSpecialPointer(BufferGetPage(buffer));

	Assert(ItemPointerIsValid(&zhtup->t_self));
	Assert(zhtup->t_tableOid != InvalidOid);

	if (tuple->t_infomask & ZHEAP_DELETED)
	{
		*in_place_updated = false;
		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleHeaderGetCid(tuple, buffer) >= curcid)
			{
				/* deleted after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   free_zhtup);
				if (visible)
					return HeapTupleSelfUpdated;
				else
					return HeapTupleInvisible;
			}
			else
				return HeapTupleInvisible;	/* deleted before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup);

			if (visible)
				return HeapTupleBeingUpdated;
			else
				return HeapTupleInvisible;
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return HeapTupleUpdated;	/* tuple is deleted */
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - For aborted transactions, we should either wait for undo
			 * to be applied or apply undo by ourselves before modifying the
			 * the tuple.
			 */
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup);

			if (visible)
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleInvisible;
		}
	}
	else if (tuple->t_infomask & ZHEAP_INPLACE_UPDATED)
	{
		*in_place_updated = true;
		if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			if (ZHeapTupleHeaderGetCid(tuple, buffer) >= curcid)
			{
				/* updated after scan started, check previous tuple from undo */
				visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
												   zhtup,
												   curcid,
												   buffer,
												   ctid,
												   free_zhtup);
				if (visible)
					return HeapTupleSelfUpdated;
				else
					return HeapTupleInvisible;
			}
			else
				return HeapTupleMayBeUpdated;	/* updated before scan started */
		}
		else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		{
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup);

			if (visible)
				return HeapTupleBeingUpdated;
			else
				return HeapTupleInvisible;
		}
		else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
			return HeapTupleMayBeUpdated;	/* tuple is updated */
		else	/* transaction is aborted */
		{
			/*
			 * Fixme - For aborted transactions, we should either wait for undo
			 * to be applied or apply undo by ourselves before modifying the
			 * the tuple.
			 */
			visible = UndoTupleSatisfiesUpdate(ZHeapTupleHeaderGetRawUndoPtr(tuple, opaque),
											   zhtup,
											   curcid,
											   buffer,
											   ctid,
											   free_zhtup);

			if (visible)
				return HeapTupleMayBeUpdated;
			else
				return HeapTupleInvisible;
		}
	}

	if (TransactionIdIsCurrentTransactionId(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
	{
		if (ZHeapTupleHeaderGetCid(tuple, buffer) >= curcid)
			return HeapTupleInvisible;	/* inserted after scan started */
		else
			return HeapTupleMayBeUpdated;	/* inserted before scan started */
	}
	else if (TransactionIdIsInProgress(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return HeapTupleInvisible;
	else if (TransactionIdDidCommit(ZHeapTupleHeaderGetRawXid(tuple, opaque)))
		return HeapTupleMayBeUpdated;
	else
		return HeapTupleInvisible;

	return HeapTupleInvisible;
}
