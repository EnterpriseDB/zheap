/*-------------------------------------------------------------------------
 *
 * zhio.c
 *	  POSTGRES zheap access method input/output code.
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/zheap/zhio.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/tpd.h"
#include "access/visibilitymap.h"
#include "access/zheap.h"
#include "access/zhio.h"
#include "access/zhtup.h"
#include "storage/bufmgr.h"
#include "storage/freespace.h"
#include "storage/lmgr.h"
#include "storage/smgr.h"

/*
 * RelationGetBufferForZTuple
 *
 *	Returns pinned and exclusive-locked buffer of a page in given relation
 *	with free space >= given len.
 *
 *	This is quite similar to RelationGetBufferForTuple except for zheap
 *	specific handling.  If the last page where tuple needs to be inserted is a
 *	TPD page, we skip it and directly extend the relation.  We could instead
 *	check the previous page, but scanning relation backwards could be costly,
 *	so we avoid it for now.
 */
Buffer
RelationGetBufferForZTuple(Relation relation, Size len,
						   Buffer otherBuffer, int options,
						   BulkInsertState bistate,
						   Buffer *vmbuffer, Buffer *vmbuffer_other)
{
	bool		use_fsm = !(options & HEAP_INSERT_SKIP_FSM);
	Buffer		buffer = InvalidBuffer;
	Page		page;
	Size		pageFreeSpace = 0,
				saveFreeSpace = 0;
	BlockNumber targetBlock,
				otherBlock;
	bool		needLock = false;
	bool		recheck = true;
	bool		tpdPage = false;

	if (data_alignment_zheap == 0)
		;	/* no alignment */
	else if (data_alignment_zheap == 4)
		len = INTALIGN(len);	/* four byte alignment */
	else
		len = MAXALIGN(len);		/* be conservative */

	/* Bulk insert is not supported for updates, only inserts. */
	Assert(otherBuffer == InvalidBuffer || !bistate);

	/*
	 * If we're gonna fail for oversize tuple, do it right away
	 */
	if (len > MaxZHeapTupleSize)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("row is too big: size %zu, maximum size %zu",
						len, MaxZHeapTupleSize)));

	/* Compute desired extra freespace due to fillfactor option */
	saveFreeSpace = RelationGetTargetPageFreeSpace(relation,
												   HEAP_DEFAULT_FILLFACTOR);

	if (otherBuffer != InvalidBuffer)
		otherBlock = BufferGetBlockNumber(otherBuffer);
	else
		otherBlock = InvalidBlockNumber;	/* just to keep compiler quiet */

	/*
	 * We first try to put the tuple on the same page we last inserted a tuple
	 * on, as cached in the BulkInsertState or relcache entry.  If that
	 * doesn't work, we ask the Free Space Map to locate a suitable page.
	 * Since the FSM's info might be out of date, we have to be prepared to
	 * loop around and retry multiple times. (To insure this isn't an infinite
	 * loop, we must update the FSM with the correct amount of free space on
	 * each page that proves not to be suitable.)  If the FSM has no record of
	 * a page with enough free space, we give up and extend the relation.
	 *
	 * When use_fsm is false, we either put the tuple onto the existing target
	 * page or extend the relation.
	 */
	if (len + saveFreeSpace > MaxZHeapTupleSize)
	{
		/* can't fit, don't bother asking FSM */
		targetBlock = InvalidBlockNumber;
		use_fsm = false;
	}
	else if (bistate && bistate->current_buf != InvalidBuffer)
		targetBlock = BufferGetBlockNumber(bistate->current_buf);
	else
		targetBlock = RelationGetTargetBlock(relation);

	if (targetBlock == InvalidBlockNumber && use_fsm)
	{
		/*
		 * We have no cached target page, so ask the FSM for an initial
		 * target.
		 */
		targetBlock = GetPageWithFreeSpace(relation, len + saveFreeSpace);

		/*
		 * If the FSM knows nothing of the rel, try the last page before we
		 * give up and extend.  This avoids one-tuple-per-page syndrome during
		 * bootstrapping or in a recently-started system.
		 */
		if (targetBlock == InvalidBlockNumber)
		{
			BlockNumber nblocks = RelationGetNumberOfBlocks(relation);

			/*
			 * In zheap, first page is always a meta page, so we need to
			 * skip it for tuple insertions.
			 */
			if (nblocks > ZHEAP_METAPAGE + 1)
				targetBlock = nblocks - 1;
		}
	}

loop:
	while (targetBlock != InvalidBlockNumber)
	{
		/*
		 * Read and exclusive-lock the target block, as well as the other
		 * block if one was given, taking suitable care with lock ordering and
		 * the possibility they are the same block.
		 *
		 * If the page-level all-visible flag is set, caller will need to
		 * clear both that and the corresponding visibility map bit.  However,
		 * by the time we return, we'll have x-locked the buffer, and we don't
		 * want to do any I/O while in that state.  So we check the bit here
		 * before taking the lock, and pin the page if it appears necessary.
		 * Checking without the lock creates a risk of getting the wrong
		 * answer, so we'll have to recheck after acquiring the lock.
		 */
		if (otherBuffer == InvalidBuffer)
		{
			/* easy case */
			buffer = ReadBufferBI(relation, targetBlock, bistate);
			visibilitymap_pin(relation, targetBlock, vmbuffer);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		}
		else if (otherBlock == targetBlock)
		{
			/* also easy case */
			buffer = otherBuffer;
			visibilitymap_pin(relation, targetBlock, vmbuffer);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		}
		else if (otherBlock < targetBlock)
		{
			/* lock other buffer first */
			buffer = ReadBuffer(relation, targetBlock);
			visibilitymap_pin(relation, targetBlock, vmbuffer);
			LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		}
		else
		{
			/* lock target buffer first */
			buffer = ReadBuffer(relation, targetBlock);
			visibilitymap_pin(relation, targetBlock, vmbuffer);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
			LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);
		}

		if (PageGetSpecialSize(BufferGetPage(buffer)) == MAXALIGN(sizeof(TPDPageOpaqueData)))
			tpdPage = true;

		if (!tpdPage)
		{
			/*
			 * We now have the target page (and the other buffer, if any) pinned
			 * and locked.  However, since our initial PageIsAllVisible checks
			 * were performed before acquiring the lock, the results might now be
			 * out of date, either for the selected victim buffer, or for the
			 * other buffer passed by the caller.  In that case, we'll need to
			 * give up our locks, go get the pin(s) we failed to get earlier, and
			 * re-lock.  That's pretty painful, but hopefully shouldn't happen
			 * often.
			 *
			 * Note that there's a small possibility that we didn't pin the page
			 * above but still have the correct page pinned anyway, either because
			 * we've already made a previous pass through this loop, or because
			 * caller passed us the right page anyway.
			 *
			 * Note also that it's possible that by the time we get the pin and
			 * retake the buffer locks, the visibility map bit will have been
			 * cleared by some other backend anyway.  In that case, we'll have
			 * done a bit of extra work for no gain, but there's no real harm
			 * done.
			 */
			if (otherBuffer == InvalidBuffer || buffer <= otherBuffer)
				GetVisibilityMapPins(relation, buffer, otherBuffer,
									 targetBlock, otherBlock, vmbuffer,
									 vmbuffer_other);
			else
				GetVisibilityMapPins(relation, otherBuffer, buffer,
									 otherBlock, targetBlock, vmbuffer_other,
									 vmbuffer);

			/*
			 * Now we can check to see if there's enough free space here. If so,
			 * we're done.
			 */
			page = BufferGetPage(buffer);
			pageFreeSpace = PageGetZHeapFreeSpace(page);
			if (len + saveFreeSpace <= pageFreeSpace)
			{
				/* use this page as future insert target, too */
				RelationSetTargetBlock(relation, targetBlock);
				return buffer;
			}
		}

		/*
		 * Not enough space or a tpd page, so we must give up our page locks
		 * and pin (if any) and prepare to look elsewhere.  We don't care
		 * which order we unlock the two buffers in, so this can be slightly
		 * simpler than the code above.
		 */
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		if (otherBuffer == InvalidBuffer)
			ReleaseBuffer(buffer);
		else if (otherBlock != targetBlock)
		{
			LockBuffer(otherBuffer, BUFFER_LOCK_UNLOCK);
			ReleaseBuffer(buffer);
		}

		/*
		 * If this a tpd page or FSM doesn't need to be updated, always fall
		 * out of the loop and extend.
		 */
		if (!use_fsm || tpdPage)
			break;

		/*
		 * Update FSM as to condition of this page, and ask for another page
		 * to try.
		 */
		targetBlock = RecordAndGetPageWithFreeSpace(relation,
													targetBlock,
													pageFreeSpace,
													len + saveFreeSpace);
	}

	/*
	 * Have to extend the relation.
	 *
	 * We have to use a lock to ensure no one else is extending the rel at the
	 * same time, else we will both try to initialize the same new page.  We
	 * can skip locking for new or temp relations, however, since no one else
	 * could be accessing them.
	 */
	needLock = !RELATION_IS_LOCAL(relation);

recheck:
	/*
	 * If we need the lock but are not able to acquire it immediately, we'll
	 * consider extending the relation by multiple blocks at a time to manage
	 * contention on the relation extension lock.  However, this only makes
	 * sense if we're using the FSM; otherwise, there's no point.
	 */
	if (needLock)
	{
		if (!use_fsm)
			LockRelationForExtension(relation, ExclusiveLock);
		else if (!ConditionalLockRelationForExtension(relation, ExclusiveLock))
		{
			/* Couldn't get the lock immediately; wait for it. */
			LockRelationForExtension(relation, ExclusiveLock);

			/*
			 * Check if some other backend has extended a block for us while
			 * we were waiting on the lock.
			 */
			targetBlock = GetPageWithFreeSpace(relation, len + saveFreeSpace);

			/*
			 * If some other waiter has already extended the relation, we
			 * don't need to do so; just use the existing freespace.
			 */
			if (targetBlock != InvalidBlockNumber)
			{
				UnlockRelationForExtension(relation, ExclusiveLock);
				goto loop;
			}

			/* Time to bulk-extend. */
			RelationAddExtraBlocks(relation, bistate);
		}
	}

	/*
	 * In addition to whatever extension we performed above, we always add at
	 * least one block to satisfy our own request.
	 *
	 * XXX This does an lseek - rather expensive - but at the moment it is the
	 * only way to accurately determine how many blocks are in a relation.  Is
	 * it worth keeping an accurate file length in shared memory someplace,
	 * rather than relying on the kernel to do it for us?
	 */
	buffer = ReadBufferBI(relation, P_NEW, bistate);

	/*
	 * We can be certain that locking the otherBuffer first is OK, since it
	 * must have a lower page number.  We don't lock other buffer while holding
	 * extension lock.  See comments below.
	 */
	if (otherBuffer != InvalidBuffer && !needLock)
		LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);

	/*
	 * Now acquire lock on the new page.
	 */
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

	/*
	 * Release the file-extension lock; it's now OK for someone else to extend
	 * the relation some more.  Note that we cannot release this lock before
	 * we have buffer lock on the new page, or we risk a race condition
	 * against vacuumlazy.c --- see comments therein.
	 */
	if (needLock)
		UnlockRelationForExtension(relation, ExclusiveLock);

	/*
	 * We need to initialize the empty new page.  Double-check that it really
	 * is empty (this should never happen, but if it does we don't want to
	 * risk wiping out valid data).
	 */
	page = BufferGetPage(buffer);

	if (!PageIsNew(page))
		elog(ERROR, "page %u of relation \"%s\" should be empty but is not",
			 BufferGetBlockNumber(buffer),
			 RelationGetRelationName(relation));

	Assert(BufferGetBlockNumber(buffer) != ZHEAP_METAPAGE);
	ZheapInitPage(page, BufferGetPageSize(buffer));

	/*
	 * We don't acquire lock on otherBuffer while holding extension lock as it
	 * can create a deadlock against extending TPD entry where we take extension
	 * lock while holding the heap buffer lock.  See TPDAllocatePageAndAddEntry.
	 */
	if (needLock &&
		otherBuffer != InvalidBuffer &&
		BufferGetBlockNumber(buffer) > otherBlock)
	{
		LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
		LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);
		LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
		recheck = true;
	}	
	if (len > PageGetZHeapFreeSpace(page))
	{
		if (recheck)
			goto recheck;
		
		/* We should not get here given the test at the top */
		elog(PANIC, "tuple is too big: size %zu", len);
	}

	/*
	 * Remember the new page as our target for future insertions.
	 *
	 * XXX should we enter the new page into the free space map immediately,
	 * or just keep it for this backend's exclusive use in the short run
	 * (until VACUUM sees it)?	Seems to depend on whether you expect the
	 * current backend to make more insertions or not, which is probably a
	 * good bet most of the time.  So for now, don't add it to FSM yet.
	 */
	RelationSetTargetBlock(relation, BufferGetBlockNumber(buffer));

	return buffer;
}
