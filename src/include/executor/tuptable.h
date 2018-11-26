/*-------------------------------------------------------------------------
 *
 * tuptable.h
 *	  tuple table support stuff
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/executor/tuptable.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TUPTABLE_H
#define TUPTABLE_H

#include "access/htup.h"
#include "access/tupdesc.h"
#include "access/zhtup.h"
#include "storage/buf.h"

/*----------
 * The executor stores tuples in a "tuple table" which is a List of
 * independent TupleTableSlots.  There are several cases we need to handle:
 *		1. physical tuple in a disk buffer page
 *		2. physical tuple constructed in palloc'ed memory
 *		3. "minimal" physical tuple constructed in palloc'ed memory
 *		4. "virtual" tuple consisting of Datum/isnull arrays
 *
 * The first two cases are similar in that they both deal with "materialized"
 * tuples, but resource management is different.  For a tuple in a disk page
 * we need to hold a pin on the buffer until the TupleTableSlot's reference
 * to the tuple is dropped; while for a palloc'd tuple we usually want the
 * tuple pfree'd when the TupleTableSlot's reference is dropped.
 *
 * A "minimal" tuple is handled similarly to a palloc'd regular tuple.
 * At present, minimal tuples never are stored in buffers, so there is no
 * parallel to case 1.  Note that a minimal tuple has no "system columns".
 * (Actually, it could have an OID, but we have no need to access the OID.)
 *
 * A "virtual" tuple is an optimization used to minimize physical data
 * copying in a nest of plan nodes.  Any pass-by-reference Datums in the
 * tuple point to storage that is not directly associated with the
 * TupleTableSlot; generally they will point to part of a tuple stored in
 * a lower plan node's output TupleTableSlot, or to a function result
 * constructed in a plan node's per-tuple econtext.  It is the responsibility
 * of the generating plan node to be sure these resources are not released
 * for as long as the virtual tuple needs to be valid.  We only use virtual
 * tuples in the result slots of plan nodes --- tuples to be copied anywhere
 * else need to be "materialized" into physical tuples.  Note also that a
 * virtual tuple does not have any "system columns".
 *
 * It is also possible for a TupleTableSlot to hold both physical and minimal
 * copies of a tuple.  This is done when the slot is requested to provide
 * the format other than the one it currently holds.  (Originally we attempted
 * to handle such requests by replacing one format with the other, but that
 * had the fatal defect of invalidating any pass-by-reference Datums pointing
 * into the existing slot contents.)  Both copies must contain identical data
 * payloads when this is the case.
 *
 * The Datum/isnull arrays of a TupleTableSlot serve double duty.  When the
 * slot contains a virtual tuple, they are the authoritative data.  When the
 * slot contains a physical tuple, the arrays contain data extracted from
 * the tuple.  (In this state, any pass-by-reference Datums point into
 * the physical tuple.)  The extracted information is built "lazily",
 * ie, only as needed.  This serves to avoid repeated extraction of data
 * from the physical tuple.
 *
 * A TupleTableSlot can also be "empty", indicated by flag TTS_EMPTY set in
 * tts_flags, holding no valid data.  This is the only valid state for a
 * freshly-created slot that has not yet had a tuple descriptor assigned to it.
 * In this state, TTS_SHOULDFREE should not be set in tts_flag, tts_tuple must
 * be NULL, tts_buffer InvalidBuffer, and tts_nvalid zero.
 *
 * The tupleDescriptor is simply referenced, not copied, by the TupleTableSlot
 * code.  The caller of ExecSetSlotDescriptor() is responsible for providing
 * a descriptor that will live as long as the slot does.  (Typically, both
 * slots and descriptors are in per-query memory and are freed by memory
 * context deallocation at query end; so it's not worth providing any extra
 * mechanism to do more.  However, the slot will increment the tupdesc
 * reference count if a reference-counted tupdesc is supplied.)
 *
 * When TTS_SHOULDFREE is set in tts_flags, the physical tuple is "owned" by
 * the slot and should be freed when the slot's reference to the tuple is
 * dropped.
 *
 * If tts_buffer is not InvalidBuffer, then the slot is holding a pin
 * on the indicated buffer page; drop the pin when we release the
 * slot's reference to that buffer.  (tts_shouldFree should always be
 * false in such a case, since presumably tts_tuple is pointing at the
 * buffer page.)
 *
 * tts_nvalid indicates the number of valid columns in the tts_values/isnull
 * arrays.  When the slot is holding a "virtual" tuple this must be equal
 * to the descriptor's natts.  When the slot is holding a physical tuple
 * this is equal to the number of columns we have extracted (we always
 * extract columns from left to right, so there are no holes).
 *
 * tts_values/tts_isnull are allocated when a descriptor is assigned to the
 * slot; they are of length equal to the descriptor's natts.
 *
 * tts_mintuple must always be NULL if the slot does not hold a "minimal"
 * tuple.  When it does, tts_mintuple points to the actual MinimalTupleData
 * object (the thing to be pfree'd if tts_shouldFreeMin is true).  If the slot
 * has only a minimal and not also a regular physical tuple, then tts_tuple
 * points at tts_minhdr and the fields of that struct are set correctly
 * for access to the minimal tuple; in particular, tts_minhdr.t_data points
 * MINIMAL_TUPLE_OFFSET bytes before tts_mintuple.  This allows column
 * extraction to treat the case identically to regular physical tuples.
 *
 * TTS_SLOW flag in tts_flags and tts_off are saved state for
 * slot_deform_tuple, and should not be touched by any other code.
 *
 * For page mode scan of zheap table, locally stored per page tuples are
 * freed once we move to new page or at end of scan. The tts_shouldFreeZtup
 * will be set false for such tuples. The tts_shouldFreeZtup is set true
 * only for single tuple scan mode.
 *----------
 */

/* true = slot is empty */
#define			TTS_FLAG_EMPTY			(1 << 1)
#define TTS_EMPTY(slot)	(((slot)->tts_flags & TTS_FLAG_EMPTY) != 0)

/* should pfree tts_tuple? */
#define			TTS_FLAG_SHOULDFREE		(1 << 2)
#define TTS_SHOULDFREE(slot) (((slot)->tts_flags & TTS_FLAG_SHOULDFREE) != 0)

/* should pfree tts_ztuple? */
#define			TTS_FLAG_SHOULDZFREE	(1 << 3)
#define TTS_SHOULDZFREE(slot) (((slot)->tts_flags & TTS_FLAG_SHOULDZFREE) != 0)

/* should pfree tts_mintuple? */
#define			TTS_FLAG_SHOULDFREEMIN	(1 << 4)
#define TTS_SHOULDFREEMIN(slot) (((slot)->tts_flags & TTS_FLAG_SHOULDFREEMIN) != 0)

/* saved state for slot_deform_tuple */
#define			TTS_FLAG_SLOW		(1 << 5)
#define TTS_SLOW(slot) (((slot)->tts_flags & TTS_FLAG_SLOW) != 0)

/* fixed tuple descriptor */
#define			TTS_FLAG_FIXED		(1 << 6)
#define TTS_FIXED(slot) (((slot)->tts_flags & TTS_FLAG_FIXED) != 0)

typedef struct TupleTableSlot
{
	NodeTag		type;
#define FIELDNO_TUPLETABLESLOT_FLAGS 1
	uint16		tts_flags;		/* Boolean states */
#define FIELDNO_TUPLETABLESLOT_NVALID 2
	AttrNumber	tts_nvalid;		/* # of valid values in tts_values */
#define FIELDNO_TUPLETABLESLOT_TUPLE 3
	HeapTuple	tts_tuple;		/* physical tuple, or NULL if virtual */
	ZHeapTuple	tts_ztuple;
#define FIELDNO_TUPLETABLESLOT_TUPLEDESCRIPTOR 5
	TupleDesc	tts_tupleDescriptor;	/* slot's tuple descriptor */
	MemoryContext tts_mcxt;		/* slot itself is in this context */
	Buffer		tts_buffer;		/* tuple's buffer, or InvalidBuffer */
#define FIELDNO_TUPLETABLESLOT_OFF 8
	uint32		tts_off;		/* saved state for slot_deform_tuple */
#define FIELDNO_TUPLETABLESLOT_VALUES 9
	Datum	   *tts_values;		/* current per-attribute values */
#define FIELDNO_TUPLETABLESLOT_ISNULL 10
	bool	   *tts_isnull;		/* current per-attribute isnull flags */
	MinimalTuple tts_mintuple;	/* minimal tuple, or NULL if none */
	HeapTupleData tts_minhdr;	/* workspace for minimal-tuple-only case */
} TupleTableSlot;

#define TTS_HAS_PHYSICAL_TUPLE(slot)  \
	((slot)->tts_tuple != NULL && (slot)->tts_tuple != &((slot)->tts_minhdr))

/*
 * TupIsNull -- is a TupleTableSlot empty?
 */
#define TupIsNull(slot) \
	((slot) == NULL || TTS_EMPTY(slot))

/* in executor/execTuples.c */
extern TupleTableSlot *MakeTupleTableSlot(TupleDesc desc);
extern TupleTableSlot *ExecAllocTableSlot(List **tupleTable, TupleDesc desc);
extern void ExecResetTupleTable(List *tupleTable, bool shouldFree);
extern TupleTableSlot *MakeSingleTupleTableSlot(TupleDesc tupdesc);
extern void ExecDropSingleTupleTableSlot(TupleTableSlot *slot);
extern void ExecSetSlotDescriptor(TupleTableSlot *slot, TupleDesc tupdesc);

extern TupleTableSlot *ExecStoreHeapTuple(HeapTuple tuple,
				   TupleTableSlot *slot,
				   bool shouldFree);
extern TupleTableSlot *ExecStoreBufferHeapTuple(HeapTuple tuple,
						 TupleTableSlot *slot,
						 Buffer buffer);
extern TupleTableSlot *ExecStoreZTuple(ZHeapTuple tuple,
				TupleTableSlot *slot,
				Buffer buffer,
				bool shouldFree);
extern TupleTableSlot *ExecStoreMinimalTuple(MinimalTuple mtup,
					  TupleTableSlot *slot,
					  bool shouldFree);
extern TupleTableSlot *ExecClearTuple(TupleTableSlot *slot);
extern TupleTableSlot *ExecStoreVirtualTuple(TupleTableSlot *slot);
extern TupleTableSlot *ExecStoreAllNullTuple(TupleTableSlot *slot);
extern HeapTuple ExecCopySlotTuple(TupleTableSlot *slot);
extern ZHeapTuple ExecCopySlotZTuple(TupleTableSlot *slot);
extern MinimalTuple ExecCopySlotMinimalTuple(TupleTableSlot *slot);
extern HeapTuple ExecFetchSlotTuple(TupleTableSlot *slot);
extern MinimalTuple ExecFetchSlotMinimalTuple(TupleTableSlot *slot);
extern Datum ExecFetchSlotTupleDatum(TupleTableSlot *slot);
extern HeapTuple ExecMaterializeSlot(TupleTableSlot *slot);
extern ZHeapTuple ExecMaterializeZSlot(TupleTableSlot *slot);
extern TupleTableSlot *ExecCopySlot(TupleTableSlot *dstslot,
			 TupleTableSlot *srcslot);
extern void slot_getmissingattrs(TupleTableSlot *slot, int startAttNum,
					 int lastAttNum);
extern Datum slot_getattr(TupleTableSlot *slot, int attnum,
			 bool *isnull);
extern void slot_getsomeattrs(TupleTableSlot *slot, int attnum);

/* in access/common/heaptuple.c */
extern bool slot_attisnull(TupleTableSlot *slot, int attnum);
extern bool slot_getsysattr(TupleTableSlot *slot, int attnum,
				Datum *value, bool *isnull);
extern Datum getmissingattr(TupleDesc tupleDesc,
			   int attnum, bool *isnull);

extern bool slot_getsyszattr(TupleTableSlot *slot, int attnum,
				Datum *value, bool *isnull);
#ifndef FRONTEND

/*
 * slot_getallattrs
 *		This function forces all the entries of the slot's Datum/isnull
 *		arrays to be valid.  The caller may then extract data directly
 *		from those arrays instead of using slot_getattr.
 */
static inline void
slot_getallattrs(TupleTableSlot *slot)
{
	slot_getsomeattrs(slot, slot->tts_tupleDescriptor->natts);
}

#endif

#endif							/* TUPTABLE_H */
