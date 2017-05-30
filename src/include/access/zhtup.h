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
#include "storage/bufpage.h"
#include "storage/buf.h"
#include "storage/itemptr.h"

/* valid values for transaction slot is between 0 and MAX_PAGE_TRANS_INFO_SLOTS */
#define InvalidXactSlotId	(-1)

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

	uint8		t_infomask;	/* various flag bits, see below */

	uint8		t_hoff;		/* sizeof header incl. bitmap, padding */

	/* ^ - 3 bytes - ^ */

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
 * information stored in t_infomask2:
 */
#define ZHEAP_NATTS_MASK			0x07FF	/* 11 bits for number of attributes */
#define ZHEAP_XACT_SLOT				0x1800	/* 2 bits (12 and 13) for transaction slot */
#define	ZHEAP_XACT_SLOT_MASK		0x000B	/* 11 - mask to retrieve transaction slot */

#define ZHeapTupleHasNulls(tuple) \
		 (((tuple)->t_data->t_infomask & HEAP_HASNULL) != 0)

#define ZHeapTupleHeaderGetNatts(tup) \
( \
	((tup)->t_infomask2 & HEAP_NATTS_MASK) \
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

#define ZHeapTupleHeaderGetRawXid(tup, opaque) \
( \
	opaque->transinfo[ZHeapTupleHeaderGetXactSlot(tup)].xid \
)

#define ZHeapTupleHeaderGetRawCommandId(tup, opaque) \
( \
	opaque->transinfo[ZHeapTupleHeaderGetXactSlot(tup)].cid \
)

extern ZHeapTuple zheap_form_tuple(TupleDesc tupleDescriptor,
				Datum *values, bool *isnull);
extern void zheap_fill_tuple(TupleDesc tupleDesc,
				Datum *values, bool *isnull,
				char *data, Size data_size,
				uint8 *infomask, bits8 *bit);

extern void zheap_freetuple(ZHeapTuple zhtup);

/* Zheap transaction information related API's */
extern CommandId ZHeapTupleHeaderGetCid(ZHeapTupleHeader tup, Buffer buf);

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

/* MaxZHeapPageFixedSpace - Maximum fixed size for page */
#define MaxZHeapPageFixedSpace \
	(BLCKSZ - SizeOfPageHeaderData - sizeof(ZHeapPageOpaqueData))
/*
 * MaxZHeapTuplesPerPage is an upper bound on the number of tuples that can
 * fit on one zheap page.
 */
#define MaxZHeapTuplesPerPage	\
	((int) ((MaxZHeapPageFixedSpace) / \
			(MaxZHeapTupFixedSize)))

#define ZPageAddItem(page, item, size, offsetNumber, overwrite, is_heap) \
	ZPageAddItemExtended(page, item, size, offsetNumber, \
						 ((overwrite) ? PAI_OVERWRITE : 0) | \
						 ((is_heap) ? PAI_IS_HEAP : 0))

extern Size PageGetZHeapFreeSpace(Page page);
extern OffsetNumber ZPageAddItemExtended(Page page,
					 Item item, Size size, OffsetNumber offsetNumber,
					 int flags);

#endif   /* ZHTUP_H */
