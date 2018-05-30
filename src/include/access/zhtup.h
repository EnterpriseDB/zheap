/*-------------------------------------------------------------------------
 *
 * zhtup.h
 *	  POSTGRES zheap tuple header definitions.
 *
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zhtup.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZHTUP_H
#define ZHTUP_H

#include "access/genham.h"
#include "access/tupdesc.h"
#include "access/tupmacs.h"
#include "access/transam.h"
#include "access/undolog.h"
#include "access/undorecord.h"
#include "storage/bufpage.h"
#include "storage/buf.h"
#include "storage/itemptr.h"

/* valid values for transaction slot is between 0 and ZHEAP_PAGE_TRANS_SLOTS */
#define InvalidXactSlotId	(-1)
/* we use frozen slot to indicate that the tuple is all visible now */
#define	ZHTUP_SLOT_FROZEN	0x01F

typedef struct ZMultiLockMember
{
	TransactionId xid;
	int		trans_slot_id;
	LockTupleMode mode;
} ZMultiLockMember;

/*
 * Heap tuple header.  To avoid wasting space, the fields should be
 * laid out in such a way as to avoid structure padding.
 *
 * Following the fixed header fields, the nulls bitmap is stored (beginning
 * at t_bits).  The bitmap is *not* stored if t_infomask shows that there
 * are no nulls in the tuple.  If an OID field is present (as indicated by
 * t_infomask), then it is stored just before the user data, which begins at
 * the offset shown by t_hoff.  Note that t_hoff must be a multiple of
 * MAXALIGN.
 */

typedef struct ZHeapTupleHeaderData
{
	uint16		t_infomask2;	/* number of attributes + translot info + various flags */

	uint16		t_infomask;	/* various flag bits, see below */

	uint8		t_hoff;		/* sizeof header incl. bitmap, padding */

	/* ^ - 4 bytes - ^ */

	bits8		t_bits[FLEXIBLE_ARRAY_MEMBER];	/* bitmap of NULLs */

	/* MORE DATA FOLLOWS AT END OF STRUCT */
} ZHeapTupleHeaderData;

typedef ZHeapTupleHeaderData *ZHeapTupleHeader;

#define SizeofZHeapTupleHeader offsetof(ZHeapTupleHeaderData, t_bits)

typedef struct ZHeapTupleData
{
	uint32		t_len;			/* length of *t_data */
	ItemPointerData t_self;		/* SelfItemPointer */
	Oid			t_tableOid;		/* table the tuple came from */
	ZHeapTupleHeader t_data;		/* -> tuple header and data */
} ZHeapTupleData;

typedef ZHeapTupleData *ZHeapTuple;

#define ZHEAPTUPLESIZE	MAXALIGN(sizeof(ZHeapTupleData))

/*
 * information stored in t_infomask:
 */
#define ZHEAP_HASNULL			0x0001	/* has null attribute(s) */
#define ZHEAP_HASVARWIDTH		0x0002	/* has variable-width attribute(s) */
#define ZHEAP_HASEXTERNAL		0x0004	/* has external stored attribute(s) */
#define ZHEAP_HASOID			0x0008	/* has an object-id field */
#define	ZHEAP_DELETED			0x0010	/* tuple deleted */
#define	ZHEAP_INPLACE_UPDATED	0x0020	/* tuple is updated inplace */
#define	ZHEAP_UPDATED			0x0040	/* tuple is not updated inplace */
#define ZHEAP_XID_LOCK_ONLY		0x0080	/* xid, if valid, is only a locker */

#define ZHEAP_XID_KEYSHR_LOCK	0x0100	/* xid is a key-shared locker */
#define ZHEAP_XID_NOKEY_EXCL_LOCK	0x0200	/* xid is a nokey-exclusive locker */
 /* xid is a shared locker */
#define ZHEAP_XID_SHR_LOCK	(ZHEAP_XID_NOKEY_EXCL_LOCK | ZHEAP_XID_KEYSHR_LOCK)
#define ZHEAP_XID_EXCL_LOCK		0x0400	/* tuple was updated and key cols
										 * modified, or tuple deleted */
#define ZHEAP_MULTI_LOCKERS		0x0800	/* tuple was locked by multiple
										 * lockers */
#define ZHEAP_INVALID_XACT_SLOT	0x1000	/* transaction slot on tuple got reused */
#define ZHEAP_SPECULATIVE_INSERT	0x2000 /* tuple insertion is a speculative
											* insertion and can be taken back */

#define ZHEAP_LOCK_MASK		(ZHEAP_XID_KEYSHR_LOCK | ZHEAP_XID_NOKEY_EXCL_LOCK | \
							 ZHEAP_XID_SHR_LOCK | ZHEAP_XID_EXCL_LOCK)

#define ZHEAP_VIS_STATUS_MASK	0x1FF0	/* mask for visibility bits (5 ~ 13 bits) */

/*
 * Use these to test whether a particular lock is applied to a tuple
 */
#define ZHEAP_XID_IS_KEYSHR_LOCKED(infomask) \
	(((infomask) & ZHEAP_LOCK_MASK) == ZHEAP_XID_KEYSHR_LOCK)
#define ZHEAP_XID_IS_NOKEY_EXCL_LOCKED(infomask) \
	(((infomask) & ZHEAP_LOCK_MASK) == ZHEAP_XID_NOKEY_EXCL_LOCK)
#define ZHEAP_XID_IS_SHR_LOCKED(infomask) \
	(((infomask) & ZHEAP_LOCK_MASK) == ZHEAP_XID_SHR_LOCK)
#define ZHEAP_XID_IS_EXCL_LOCKED(infomask) \
	(((infomask) & ZHEAP_LOCK_MASK) == ZHEAP_XID_EXCL_LOCK)

/*
 * information stored in t_infomask2:
 */
#define ZHEAP_NATTS_MASK			0x07FF	/* 11 bits for number of attributes */
#define ZHEAP_XACT_SLOT				0xF800	/* 5 bits (12, 13, 14, 15 and 16) for transaction slot */
#define	ZHEAP_XACT_SLOT_MASK		0x000B	/* 11 - mask to retrieve transaction slot */


#define ZHEAP_XID_IS_LOCKED_ONLY(infomask) \
( \
	((infomask) & ZHEAP_XID_LOCK_ONLY) != 0 \
)

#define ZHeapTupleHasMultiLockers(infomask) \
( \
	((infomask) & ZHEAP_MULTI_LOCKERS) != 0 \
)

#define ZHeapTupleIsInPlaceUpdated(infomask) \
( \
  (infomask & ZHEAP_INPLACE_UPDATED) != 0 \
)

#define ZHeapTupleIsUpdated(infomask) \
( \
  (infomask & ZHEAP_UPDATED) != 0 \
)

#define ZHeapTupleHasInvalidXact(infomask) \
( \
	(infomask & ZHEAP_INVALID_XACT_SLOT) != 0 \
)

#define ZHeapTupleHeaderIsSpeculative(tup) \
( \
	(tup->t_infomask & ZHEAP_SPECULATIVE_INSERT) \
)

#define ZHeapTupleHeaderGetNatts(tup) \
( \
	((tup)->t_infomask2 & ZHEAP_NATTS_MASK) \
)

#define ZHeapTupleHeaderSetNatts(tup, natts) \
( \
	(tup)->t_infomask2 = ((tup)->t_infomask2 & ~ZHEAP_NATTS_MASK) | (natts) \
)

#define ZHeapTupleHeaderGetXactSlot(tup) \
( \
	(((tup)->t_infomask2 & ZHEAP_XACT_SLOT) >> ZHEAP_XACT_SLOT_MASK) \
)

#define ZHeapTupleHeaderSetXactSlot(tup, slotno) \
( \
	(tup)->t_infomask2 = ((tup)->t_infomask2 & ~ZHEAP_XACT_SLOT) | \
						 (slotno << ZHEAP_XACT_SLOT_MASK) \
)

#define ZHeapTupleHeaderGetOid(tup) \
( \
	((tup)->t_infomask & ZHEAP_HASOID) ? \
		*((Oid *) ((char *)(tup) + (tup)->t_hoff - sizeof(Oid))) \
	: \
		InvalidOid \
)

#define ZHeapTupleHeaderSetOid(tup, oid) \
do { \
	Assert((tup)->t_infomask & ZHEAP_HASOID); \
	*((Oid *) ((char *)(tup) + (tup)->t_hoff - sizeof(Oid))) = (oid); \
} while (0)

#define ZHeapTupleGetOid(tuple) \
		ZHeapTupleHeaderGetOid((tuple)->t_data)

#define ZHeapTupleSetOid(tuple, oid) \
		ZHeapTupleHeaderSetOid((tuple)->t_data, (oid))

/*
 * Accessor macros to be used with ZHeapTuple pointers.
 */

#define ZHeapTupleHasNulls(tuple) \
		(((tuple)->t_data->t_infomask & ZHEAP_HASNULL) != 0)

#define ZHeapTupleNoNulls(tuple) \
		(!((tuple)->t_data->t_infomask & ZHEAP_HASNULL))

#define ZHeapTupleHasVarWidth(tuple) \
		(((tuple)->t_data->t_infomask & ZHEAP_HASVARWIDTH) != 0)

#define ZHeapTupleDeleted(tup_data) \
		((tup_data->t_infomask & (ZHEAP_DELETED | ZHEAP_UPDATED)) != 0)



#define ZHeapTupleHeaderGetRawEpoch(tup, opaque) \
( \
	opaque->transinfo[ZHeapTupleHeaderGetXactSlot(tup)].xid_epoch \
)

#define ZHeapTupleHeaderGetRawXid(tup, opaque) \
( \
	opaque->transinfo[ZHeapTupleHeaderGetXactSlot(tup)].xid \
)

#define ZHeapTupleHeaderGetRawUndoPtr(tup, opaque) \
( \
	opaque->transinfo[ZHeapTupleHeaderGetXactSlot(tup)].urec_ptr \
)

#define ZHeapPageGetRawXid(slot, opaque) \
( \
	opaque->transinfo[slot].xid \
)

#define ZHeapPageGetRawEpoch(slot, opaque) \
( \
	opaque->transinfo[slot].xid_epoch \
)

#define ZHeapPageGetRawUndoPtr(slot, opaque) \
( \
	opaque->transinfo[slot].urec_ptr \
)

#define IsZHeapTupleModified(t_infomask) \
( \
	((t_infomask & ZHEAP_DELETED || \
	 t_infomask & ZHEAP_UPDATED || \
	 t_infomask & ZHEAP_INPLACE_UPDATED || \
	 t_infomask & ZHEAP_XID_LOCK_ONLY) != 0) \
)

#define ZHeapPageGetUndoPtr(slot, opaque) \
( \
	opaque->transinfo[slot].urec_ptr \
)

extern ZHeapTuple zheap_form_tuple(TupleDesc tupleDescriptor,
				Datum *values, bool *isnull);
extern void zheap_deform_tuple(ZHeapTuple tuple, TupleDesc tupleDesc,
				  Datum *values, bool *isnull);
extern void zheap_fill_tuple(TupleDesc tupleDesc,
				Datum *values, bool *isnull,
				char *data, Size data_size,
				uint16 *infomask, bits8 *bit);

extern void zheap_freetuple(ZHeapTuple zhtup);
extern Datum znocachegetattr(ZHeapTuple tup, int attnum,
				TupleDesc att);
extern Datum zheap_getsysattr(ZHeapTuple zhtup, Buffer buf, int attnum,
				 TupleDesc tupleDesc, bool *isnull);
extern bool zheap_attisnull(ZHeapTuple tup, int attnum, TupleDesc tupleDesc);

/* This is same as fastgetattr except that it takes ZHeapTuple as input. */
#define zfastgetattr(tup, attnum, tupleDesc, isnull)					\
(																	\
	AssertMacro((attnum) > 0),										\
	(*(isnull) = false),											\
	ZHeapTupleNoNulls(tup) ?											\
	(																\
		TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff >= 0 ?	\
		(															\
			fetchatt(TupleDescAttr((tupleDesc), (attnum)-1),		\
				(char *) (tup)->t_data + (tup)->t_data->t_hoff +	\
				TupleDescAttr((tupleDesc), (attnum)-1)->attcacheoff)\
		)															\
		:															\
			znocachegetattr((tup), (attnum), (tupleDesc))			\
	)																\
	:																\
	(																\
		att_isnull((attnum)-1, (tup)->t_data->t_bits) ?				\
		(															\
			(*(isnull) = true),										\
			(Datum)NULL												\
		)															\
		:															\
		(															\
			znocachegetattr((tup), (attnum), (tupleDesc))			\
		)															\
	)																\
)

/* This is same as heap_getattr except that it takes ZHeapTuple as input. */
#define zheap_getattr(tup, attnum, tupleDesc, isnull) \
	( \
		((attnum) > 0) ? \
		( \
			((attnum) > (int) ZHeapTupleHeaderGetNatts((tup)->t_data)) ? \
			( \
				(*(isnull) = true), \
				(Datum)NULL \
			) \
			: \
				zfastgetattr((tup), (attnum), (tupleDesc), (isnull)) \
		) \
		: \
			zheap_getsysattr((tup), (InvalidBuffer), (attnum), (tupleDesc), (isnull)) \
	)

/* Zheap transaction information related API's */
extern CommandId ZHeapTupleGetCid(ZHeapTuple zhtup, Buffer buf, UndoRecPtr urec_ptr);
extern CommandId ZHeapPageGetCid(int trans_slot, Buffer buf, OffsetNumber off);
extern void ZHeapTupleGetTransInfo(ZHeapTuple zhtup, Buffer buf,
						int *trans_slot, uint64 *epoch_xid_out,
						TransactionId *xid_out, CommandId *cid_out,
						UndoRecPtr *urec_ptr_out, bool nobuflock);
extern void ZHeapTupleGetCtid(ZHeapTuple zhtup, Buffer buf, ItemPointer ctid);
extern void ZHeapTupleGetSpecToken(ZHeapTuple zhtup, Buffer buf, uint32 *specToken);
extern void ZHeapPageGetCtid(int trans_slot, Buffer buf, ItemPointer ctid);

/* Page related API's. */

/*
 * MaxZHeapTupFixedSize - Fixed size for tuple, this is computed based
 * on data alignment.
 */
#define MaxZHeapTupFixedSize \
			(data_alignment_zheap == 0) ? \
				SizeofZHeapTupleHeader  + sizeof(ItemIdData) \
			: \
			( \
				(data_alignment_zheap == 4) ? \
					(INTALIGN(SizeofZHeapTupleHeader) + sizeof(ItemIdData)) \
				: \
				( \
					(MAXALIGN(SizeofZHeapTupleHeader) + sizeof(ItemIdData)) \
				) \
			)

#define MaxZHeapTupFixedSizeAlign0 \
			(SizeofZHeapTupleHeader  + sizeof(ItemIdData))


/* MaxZHeapPageFixedSpace - Maximum fixed size for page */
#define MaxZHeapPageFixedSpace \
	(BLCKSZ - SizeOfPageHeaderData - SizeOfZHeapPageOpaqueData)
/*
 * MaxZHeapTuplesPerPage is an upper bound on the number of tuples that can
 * fit on one zheap page.
 */
#define MaxZHeapTuplesPerPage	\
	((int) ((MaxZHeapPageFixedSpace) / \
			(MaxZHeapTupFixedSize)))

#define MaxZHeapTuplesPerPageAlign0 \
		((int) ((MaxZHeapPageFixedSpace) / \
				(MaxZHeapTupFixedSizeAlign0)))

#define MaxZHeapTupleSize  (BLCKSZ - MAXALIGN(SizeOfPageHeaderData + SizeOfZHeapPageOpaqueData + sizeof(ItemIdData)))
#define MinZHeapTupleSize  MAXALIGN(SizeofZHeapTupleHeader)

#define ZPageAddItem(page, item, size, offsetNumber, overwrite, is_heap) \
	ZPageAddItemExtended(page, item, size, offsetNumber, \
						 ((overwrite) ? PAI_OVERWRITE : 0) | \
						 ((is_heap) ? PAI_IS_HEAP : 0))

extern Size PageGetZHeapFreeSpace(Page page);
extern OffsetNumber ZPageAddItemExtended(Page page,
					 Item item, Size size, OffsetNumber offsetNumber,
					 int flags);

#endif   /* ZHTUP_H */
