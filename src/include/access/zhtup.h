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

/*
 * Fixme - We should not include heap related headers such as
 * heapam.h or htup.h.  Common things should be moved to some
 * common header.
 */
#include "access/heapam.h"
#include "access/htup.h"
#include "access/tupdesc.h"
#include "access/tupmacs.h"
#include "access/transam.h"
#include "storage/bufpage.h"
#include "utils/rel.h"

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
	uint8		t_numattrs;	/* number of attributes */

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

#define ZHeapTupleHeaderGetNatts(tup) \
( \
	(tup)->t_numattrs \
)

#define ZHeapTupleHeaderSetNatts(tup, natts) \
( \
	(tup)->t_numattrs = (natts) \
)

extern ZHeapTuple zheap_form_tuple(TupleDesc tupleDescriptor,
				Datum *values, bool *isnull);
extern void zheap_fill_tuple(TupleDesc tupleDesc,
				Datum *values, bool *isnull,
				char *data, Size data_size,
				uint8 *infomask, bits8 *bit);
extern Oid zheap_insert(Relation relation, ZHeapTuple tup, CommandId cid,
			 int options, BulkInsertState bistate);

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
