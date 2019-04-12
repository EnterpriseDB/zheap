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

static bool CheckBufferHasTPDPage(Buffer buffer);

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
 *	so we avoid it for now.  As we don't align tuples in zheap, use actual
 *	length to find the required buffer.
 */
Buffer
RelationGetBufferForZTuple(Relation relation, Size len,
						   Buffer otherBuffer, int options,
						   BulkInsertState bistate,
						   Buffer *vmbuffer, Buffer *vmbuffer_other)
{
	bool		use_fsm = !(options & TABLE_INSERT_SKIP_FSM);
	Buffer		buffer = InvalidBuffer;
	Page		page;
	Size		pageFreeSpace = 0,
				saveFreeSpace = 0;
	BlockNumber targetBlock,
				otherBlock;
	bool		needLock = false;

	/* Bulk insert is not supported for updates, only inserts. */
	Assert(otherBuffer == InvalidBuffer || !bistate);

	len = SHORTALIGN(len);

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
		targetBlock = GetPageWithFreeSpace(relation,
										   len + saveFreeSpace,
										   false);
	}

loop:
	while (targetBlock != InvalidBlockNumber)
	{
		bool		other_buffer_locked = false;

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
			buffer = ReadBufferBI(relation, targetBlock, RBM_NORMAL, bistate);
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

			other_buffer_locked = true;
		}
		else
		{
			/* lock target buffer first */
			buffer = ReadBuffer(relation, targetBlock);
			visibilitymap_pin(relation, targetBlock, vmbuffer);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * ZBORKED: This is my (Andres') adaption of the previously (in
			 * code) undocumented workaround around lock-ordering issue in tpd
			 * pages that was originally added in
			 * https://github.com/EnterpriseDB/zheap/commit/e4d3f718991b673ca3f6b02f5562366f7bc67b6d
			 *
			 * Whenever we need two buffers for updating a tuple
			 * (non-inplace), we use the rule "lock lower numbered buffer
			 * first" to avoid deadlocks. But, in zheap this is not the
			 * sufficient condition.  It's possible that the new buffer is a
			 * pruned TPD buffer and some other backend is trying to use it
			 * while holding lock on a zheap buffer with higher block number.
			 *
			 * To avoid deadlocking, we simply don't lock otherBuffer. We
			 * below update the FSM to remove TPD pages from the FSM -
			 * otherwise we'd potentially encounter this over-and-over.
			 */
			if (!CheckBufferHasTPDPage(buffer))
			{
				LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);
				other_buffer_locked = true;
			}
		}

		if (targetBlock == ZHEAP_METAPAGE || CheckBufferHasTPDPage(buffer))
		{
			/*
			 * ZBORKED: I (Andres) had to implement this because the previous
			 * code was plainly broken, and caused problems due to the newer
			 * fsm_local_map() logic.  We could handle the ZHEAP_METAPAGE case
			 * before locking (but be careful, it needs to be in the loop),
			 * but I'm doubtful it's worth it, because we still need to update
			 * the FSM etc.
			 */
			pageFreeSpace = 0;
		}
		else
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
			 *
			 * ZBORKED:
			 * Fixme: GetVisibilityMapPins use PageIsAllVisible which is not
			 * required for zheap, so either we need to rewrite that function or
			 * somehow avoid the usage of that call.
			 */
			if (otherBuffer == InvalidBuffer || targetBlock <= otherBlock)
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

			/*
			 * If necessary initialize page, it'll be used soon.  We could avoid
			 * dirtying the buffer here, and rely on the caller to do so whenever
			 * it puts a tuple onto the page, but there seems not much benefit in
			 * doing so.
			 */
			if (PageIsNew(page))
			{
				ZheapInitPage(page, BufferGetPageSize(buffer));
				MarkBufferDirty(buffer);
			}

			pageFreeSpace = PageGetZHeapFreeSpace(page);
			if (len + saveFreeSpace <= pageFreeSpace)
			{
				/* use this page as future insert target, too */
				RelationSetTargetBlock(relation, targetBlock);

				/*
				 * In case we used an in-memory map of available blocks, reset it
				 * for next use.
				 */
				FSMClearLocalMap();

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
			if (other_buffer_locked)
				LockBuffer(otherBuffer, BUFFER_LOCK_UNLOCK);
			ReleaseBuffer(buffer);
		}

		/* Without FSM, always fall out of the loop and extend */
		if (!use_fsm)
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
			targetBlock = GetPageWithFreeSpace(relation,
											   len + saveFreeSpace,
											   false);

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
	buffer = ReadBufferBI(relation, P_NEW, RBM_ZERO_AND_LOCK, bistate);

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
	MarkBufferDirty(buffer);

	/*
	 * Release the file-extension lock; it's now OK for someone else to extend
	 * the relation some more.
	 */
	if (needLock)
		UnlockRelationForExtension(relation, ExclusiveLock);

	/*
	 * Lock the other buffer. It's guaranteed to be of a lower page number
	 * than the new page. To conform with the deadlock prevent rules, we ought
	 * to lock otherBuffer first, but that would give other backends a chance
	 * to put tuples on our page. To reduce the likelihood of that, attempt to
	 * lock the other buffer conditionally, that's very likely to work.
	 * Otherwise we need to lock buffers in the correct order, and retry if
	 * the space has been used in the mean time.
	 *
	 * Alternatively, we could acquire the lock on otherBuffer before
	 * extending the relation, but that'd require holding the lock while
	 * performing IO, which seems worse than an unlikely retry.
	 */
	if (otherBuffer != InvalidBuffer)
	{
		Assert(otherBuffer != buffer);

		if (unlikely(!ConditionalLockBuffer(otherBuffer)))
		{
			LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
			LockBuffer(otherBuffer, BUFFER_LOCK_EXCLUSIVE);
			LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);

			/*
			 * Because the buffer was unlocked for a while, it's possible,
			 * although unlikely, that the page was filled. If so, just retry
			 * from start.
			 */
			if (len > PageGetHeapFreeSpace(page))
			{
				LockBuffer(otherBuffer, BUFFER_LOCK_UNLOCK);
				UnlockReleaseBuffer(buffer);

				goto loop;
			}
		}
	}

	if (len > PageGetHeapFreeSpace(page))
	{
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

	/* This should already be cleared by now, but make sure it is. */
	FSMClearLocalMap();

	return buffer;
}

/*
 * CheckBufferHasTPDPage - Check if buffer has TPD page.
 *
 * Returns true, if the buffer has a TPD page, otherwise, false.
 */
static bool
CheckBufferHasTPDPage(Buffer buffer)
{
	bool	tpdPage = false;
	Page	page = BufferGetPage(buffer);

	if (PageGetSpecialSize(page) == MAXALIGN(sizeof(TPDPageOpaqueData)))
	{
		tpdPage = true;

		/* Empty tpd page can be use as a zheap page. */
		if (PageIsEmpty(page))
		{
			ZheapInitPage(page, BufferGetPageSize(buffer));
			tpdPage = false;
		}
	}

	return tpdPage;
}
