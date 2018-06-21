/*-------------------------------------------------------------------------
 *
 * itemid.h
 *	  Standard POSTGRES buffer page item identifier definitions.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/itemid.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ITEMID_H
#define ITEMID_H

/*
 * An item pointer (also called line pointer) on a buffer page
 *
 * In some cases an item pointer is "in use" but does not have any associated
 * storage on the page.  By convention, lp_len == 0 in every item pointer
 * that does not have storage, independently of its lp_flags state.
 */
typedef struct ItemIdData
{
	unsigned	lp_off:15,		/* offset to tuple (from start of page) */
				lp_flags:2,		/* state of item pointer, see below */
				lp_len:15;		/* byte length of tuple */
} ItemIdData;

typedef ItemIdData *ItemId;

/*
 * lp_flags has these possible states.  An UNUSED line pointer is available
 * for immediate re-use, the other states are not.
 */
#define LP_UNUSED		0		/* unused (should always have lp_len=0) */
#define LP_NORMAL		1		/* used (should always have lp_len>0) */
#define LP_REDIRECT		2		/* HOT redirect (should have lp_len=0) */
#define LP_DEAD			3		/* dead, may or may not have storage */

/*
 * Flags used in zheap.  These flags are used in a line pointer of a deleted
 * item that has no actual storage.  These help in fetching the tuple from
 * undo when required.
 */
#define ITEMID_DELETED	0x0001	/* Item is deleted */
#define	ITEMID_XACT_INVALID	0x0002	/* transaction slot on tuple got reused */
#define	ITEMID_XACT_PENDING	0x0003	/* transaction that has marked item as
									 * unused is pending */
#define VISIBILTY_MASK	0x007F	/* 7 bits (1..7) for visibility mask */
#define XACT_SLOT		0x7F80	/* 8 bits (8..15) of offset for transaction slot */
#define XACT_SLOT_MASK	0x0007	/* 7 - mask to retrieve transaction slot */

/*
 * Item offsets and lengths are represented by these types when
 * they're not actually stored in an ItemIdData.
 */
typedef uint16 ItemOffset;
typedef uint16 ItemLength;


/* ----------------
 *		support macros
 * ----------------
 */

/*
 *		ItemIdGetLength
 */
#define ItemIdGetLength(itemId) \
   ((itemId)->lp_len)

/*
 *		ItemIdGetOffset
 */
#define ItemIdGetOffset(itemId) \
   ((itemId)->lp_off)

/*
 *		ItemIdGetFlags
 */
#define ItemIdGetFlags(itemId) \
   ((itemId)->lp_flags)

/*
 *		ItemIdGetRedirect
 * In a REDIRECT pointer, lp_off holds the link to the next item pointer
 */
#define ItemIdGetRedirect(itemId) \
   ((itemId)->lp_off)

/*
 * ItemIdIsValid
 *		True iff item identifier is valid.
 *		This is a pretty weak test, probably useful only in Asserts.
 */
#define ItemIdIsValid(itemId)	PointerIsValid(itemId)

/*
 * ItemIdIsUsed
 *		True iff item identifier is in use.
 */
#define ItemIdIsUsed(itemId) \
	((itemId)->lp_flags != LP_UNUSED)

/*
 * ItemIdIsNormal
 *		True iff item identifier is in state NORMAL.
 */
#define ItemIdIsNormal(itemId) \
	((itemId)->lp_flags == LP_NORMAL)

/*
 * ItemIdIsRedirected
 *		True iff item identifier is in state REDIRECT.
 */
#define ItemIdIsRedirected(itemId) \
	((itemId)->lp_flags == LP_REDIRECT)

/*
 * ItemIdIsDead
 *		True iff item identifier is in state DEAD.
 */
#define ItemIdIsDead(itemId) \
	((itemId)->lp_flags == LP_DEAD)

/*
 * ItemIdIsDeleted
 *		True iff item identifier is in state REDIRECT.
 */
#define ItemIdIsDeleted(itemId) \
	((itemId)->lp_flags == LP_REDIRECT)

/*
 * ItemIdHasStorage
 *		True iff item identifier has associated storage.
 */
#define ItemIdHasStorage(itemId) \
	((itemId)->lp_len != 0)

/*
 * ItemIdSetUnused
 *		Set the item identifier to be UNUSED, with no storage.
 *		Beware of multiple evaluations of itemId!
 */
#define ItemIdSetUnused(itemId) \
( \
	(itemId)->lp_flags = LP_UNUSED, \
	(itemId)->lp_off = 0, \
	(itemId)->lp_len = 0 \
)

/*
 * ItemIdSetNormal
 *		Set the item identifier to be NORMAL, with the specified storage.
 *		Beware of multiple evaluations of itemId!
 */
#define ItemIdSetNormal(itemId, off, len) \
( \
	(itemId)->lp_flags = LP_NORMAL, \
	(itemId)->lp_off = (off), \
	(itemId)->lp_len = (len) \
)

/*
 * ItemIdChangeLen
 *		Change the length of itemid.
 */
#define ItemIdChangeLen(itemId, len) \
	(itemId)->lp_len = (len)

/*
 * ItemIdChangeOff
 * 		Change the Offset of itemid.
 */
#define ItemIdChangeOff(itemId, off) \
	(itemId)->lp_off = (off)

/*
 * ItemIdSetRedirect
 *		Set the item identifier to be REDIRECT, with the specified link.
 *		Beware of multiple evaluations of itemId!
 */
#define ItemIdSetRedirect(itemId, link) \
( \
	(itemId)->lp_flags = LP_REDIRECT, \
	(itemId)->lp_off = (link), \
	(itemId)->lp_len = 0 \
)

/*
 * ItemIdSetUnusedExtended
 *		Set the item identifier to be UNUSED, with transaction slot
 *		information.  The most significant 8 bits in offset are used to store
 *		transaction slot information.  Such an item doesn't have any storage.
 *		We don't allow such an item to be reused till the transaction that has
 *		marked it as UNUSED is committed. Beware of multiple evaluations of
 *		itemId!
 */
static inline
void ItemIdSetUnusedExtended(ItemId itemId, int trans_slot)
{
	/*
	 * The slots that belongs to TPD entry always point to last slot on the
	 * page.
	 */
	if (trans_slot > ZHEAP_PAGE_TRANS_SLOTS)
		trans_slot = ZHEAP_PAGE_TRANS_SLOTS;
	itemId->lp_flags = LP_UNUSED;
	itemId->lp_off = (itemId->lp_off & ~VISIBILTY_MASK) | ITEMID_XACT_PENDING;
	itemId->lp_off = (itemId->lp_off & ~XACT_SLOT) | trans_slot << XACT_SLOT_MASK;
	itemId->lp_len = 0;
}

/*
 * ItemIdSetDeleted
 *		Set the item identifier to be Deleted, with the specified visibility
 *		info and transaction slot info.  The most significant 8 bits are used
 *		to store transaction slot information and the lower 7 bits are used to
 *		store visibility info.  Such an item has no storage.
 *		Beware of multiple evaluations of itemId!
 */
#define ItemIdSetDeleted(itemId, trans_slot, vis_info) \
( \
	(itemId)->lp_flags = LP_REDIRECT, \
	(itemId)->lp_off = ((itemId)->lp_off & ~VISIBILTY_MASK) | (vis_info), \
	(itemId)->lp_off = ((itemId)->lp_off & ~XACT_SLOT) | (trans_slot) << XACT_SLOT_MASK, \
	(itemId)->lp_len = 0 \
)

#define ItemIdSetInvalidXact(itemId) \
	((itemId)->lp_off = ((itemId)->lp_off & ~VISIBILTY_MASK) | ITEMID_XACT_INVALID)

#define ItemIdResetInvalidXact(itemId) \
	((itemId)->lp_off = ((itemId)->lp_off & ~VISIBILTY_MASK) & ~(ITEMID_XACT_INVALID))

/*
 * ItemIdGetTransactionSlot
 *	In a REDIRECT pointer, lp_off contains the transaction slot information in
 *	most significant 8 bits.
 */
#define ItemIdGetTransactionSlot(itemId) \
   (((itemId)->lp_off & XACT_SLOT) >> XACT_SLOT_MASK)

/*
 * ItemIdGetVisibilityInfo
 *	In a REDIRECT pointer, lp_off contains the visibility information in
 *	least significant 7 bits.
 */
#define ItemIdGetVisibilityInfo(itemId) \
   ((itemId)->lp_off & VISIBILTY_MASK)

#define ItemIdHasPendingXact(itemId) \
   (((itemId)->lp_off & VISIBILTY_MASK) & ITEMID_XACT_PENDING)

/*
 * ItemIdSetDead
 *		Set the item identifier to be DEAD, with no storage.
 *		Beware of multiple evaluations of itemId!
 */
#define ItemIdSetDead(itemId) \
( \
	(itemId)->lp_flags = LP_DEAD, \
	(itemId)->lp_off = 0, \
	(itemId)->lp_len = 0 \
)

/*
 * ItemIdMarkDead
 *		Set the item identifier to be DEAD, keeping its existing storage.
 *
 * Note: in indexes, this is used as if it were a hint-bit mechanism;
 * we trust that multiple processors can do this in parallel and get
 * the same result.
 */
#define ItemIdMarkDead(itemId) \
( \
	(itemId)->lp_flags = LP_DEAD \
)

#endif							/* ITEMID_H */
