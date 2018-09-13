/*-------------------------------------------------------------------------
 *
 * nodeSamplescan.c
 *	  Support routines for sample scans of relations (table sampling).
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/nodeSamplescan.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/hash.h"
#include "access/relscan.h"
#include "access/tsmapi.h"
#include "access/visibilitymap.h"
#include "executor/executor.h"
#include "executor/nodeSamplescan.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/predicate.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/tqual.h"
#include "utils/ztqual.h"

#define _beginscan_sampling(relation, ...) \
( \
	(RelationStorageIsZHeap(relation)) ? \
	zheap_beginscan_sampling(relation, __VA_ARGS__) \
	: \
	heap_beginscan_sampling(relation, __VA_ARGS__) \
)

#define _rescan_set_params(relation, ...) \
( \
	(RelationStorageIsZHeap(relation)) ? \
	zheap_rescan_set_params(__VA_ARGS__) \
	: \
	heap_rescan_set_params(__VA_ARGS__) \
)

#define tablesample_getnext(node) \
( \
	(RelationStorageIsZHeap(node->ss.ss_currentRelation)) ? \
	(void *)zheap_tablesample_getnext(node) \
	: \
	(void *)heap_tablesample_getnext(node) \
)

static TupleTableSlot *SampleNext(SampleScanState *node);
static void tablesample_init(SampleScanState *scanstate);
static HeapTuple heap_tablesample_getnext(SampleScanState *scanstate);
static bool SampleTupleVisible(HeapTuple tuple, OffsetNumber tupoffset,
				   HeapScanDesc scan);
static ZHeapTuple zheap_tablesample_getnext(SampleScanState *scanstate);

/* ----------------------------------------------------------------
 *						Scan Support
 * ----------------------------------------------------------------
 */

/* ----------------------------------------------------------------
 *		SampleNext
 *
 *		This is a workhorse for ExecSampleScan
 * ----------------------------------------------------------------
 */
static TupleTableSlot *
SampleNext(SampleScanState *node)
{
	void		*tuple = NULL;
	TupleTableSlot *slot;

	/*
	 * if this is first call within a scan, initialize
	 */
	if (!node->begun)
		tablesample_init(node);

	/*
	 * get the next tuple, and store it in our result slot
	 */
	tuple = tablesample_getnext(node);

	slot = node->ss.ss_ScanTupleSlot;

	if (tuple)
	{
		if (RelationStorageIsZHeap(node->ss.ss_currentRelation))
		{
			bool pagemode = node->ss.ss_currentScanDesc->rs_pageatatime;
			ExecStoreZTuple((ZHeapTuple)tuple,	/* tuple to store */
							slot,	/* slot to store in */
							node->ss.ss_currentScanDesc->rs_cbuf,	/* tuple's buffer */
							!pagemode);	/* don't free here for page at-a-time mode */
		}
		else
			ExecStoreBufferHeapTuple(tuple, /* tuple to store */
									 slot,	/* slot to store in */
									 node->ss.ss_currentScanDesc->rs_cbuf); /* tuple's buffer */
	}
	else
		ExecClearTuple(slot);

	return slot;
}

/*
 * SampleRecheck -- access method routine to recheck a tuple in EvalPlanQual
 */
static bool
SampleRecheck(SampleScanState *node, TupleTableSlot *slot)
{
	/*
	 * No need to recheck for SampleScan, since like SeqScan we don't pass any
	 * checkable keys to heap_beginscan.
	 */
	return true;
}

/* ----------------------------------------------------------------
 *		ExecSampleScan(node)
 *
 *		Scans the relation using the sampling method and returns
 *		the next qualifying tuple.
 *		We call the ExecScan() routine and pass it the appropriate
 *		access method functions.
 * ----------------------------------------------------------------
 */
static TupleTableSlot *
ExecSampleScan(PlanState *pstate)
{
	SampleScanState *node = castNode(SampleScanState, pstate);

	return ExecScan(&node->ss,
					(ExecScanAccessMtd) SampleNext,
					(ExecScanRecheckMtd) SampleRecheck);
}

/* ----------------------------------------------------------------
 *		ExecInitSampleScan
 * ----------------------------------------------------------------
 */
SampleScanState *
ExecInitSampleScan(SampleScan *node, EState *estate, int eflags)
{
	SampleScanState *scanstate;
	TableSampleClause *tsc = node->tablesample;
	TsmRoutine *tsm;

	Assert(outerPlan(node) == NULL);
	Assert(innerPlan(node) == NULL);

	/*
	 * create state structure
	 */
	scanstate = makeNode(SampleScanState);
	scanstate->ss.ps.plan = (Plan *) node;
	scanstate->ss.ps.state = estate;
	scanstate->ss.ps.ExecProcNode = ExecSampleScan;

	/*
	 * Miscellaneous initialization
	 *
	 * create expression context for node
	 */
	ExecAssignExprContext(estate, &scanstate->ss.ps);

	/*
	 * open the scan relation
	 */
	scanstate->ss.ss_currentRelation =
		ExecOpenScanRelation(estate,
							 node->scan.scanrelid,
							 eflags);

	/* we won't set up the HeapScanDesc till later */
	scanstate->ss.ss_currentScanDesc = NULL;

	/* and create slot with appropriate rowtype */
	ExecInitScanTupleSlot(estate, &scanstate->ss,
						  RelationGetDescr(scanstate->ss.ss_currentRelation));

	/*
	 * Initialize result type and projection.
	 */
	ExecInitResultTypeTL(&scanstate->ss.ps);
	ExecAssignScanProjectionInfo(&scanstate->ss);

	/*
	 * initialize child expressions
	 */
	scanstate->ss.ps.qual =
		ExecInitQual(node->scan.plan.qual, (PlanState *) scanstate);

	scanstate->args = ExecInitExprList(tsc->args, (PlanState *) scanstate);
	scanstate->repeatable =
		ExecInitExpr(tsc->repeatable, (PlanState *) scanstate);

	/*
	 * If we don't have a REPEATABLE clause, select a random seed.  We want to
	 * do this just once, since the seed shouldn't change over rescans.
	 */
	if (tsc->repeatable == NULL)
		scanstate->seed = random();

	/*
	 * Finally, initialize the TABLESAMPLE method handler.
	 */
	tsm = GetTsmRoutine(tsc->tsmhandler);
	scanstate->tsmroutine = tsm;
	scanstate->tsm_state = NULL;

	if (tsm->InitSampleScan)
		tsm->InitSampleScan(scanstate, eflags);

	/* We'll do BeginSampleScan later; we can't evaluate params yet */
	scanstate->begun = false;

	return scanstate;
}

/* ----------------------------------------------------------------
 *		ExecEndSampleScan
 *
 *		frees any storage allocated through C routines.
 * ----------------------------------------------------------------
 */
void
ExecEndSampleScan(SampleScanState *node)
{
	/*
	 * Tell sampling function that we finished the scan.
	 */
	if (node->tsmroutine->EndSampleScan)
		node->tsmroutine->EndSampleScan(node);

	/*
	 * Free the exprcontext
	 */
	ExecFreeExprContext(&node->ss.ps);

	/*
	 * clean out the tuple table
	 */
	if (node->ss.ps.ps_ResultTupleSlot)
		ExecClearTuple(node->ss.ps.ps_ResultTupleSlot);
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	/*
	 * close heap scan
	 */
	if (node->ss.ss_currentScanDesc)
	{
		/*
		 * In zheap if scan is in page at a time mode we do not free the locally
		 * stored rs_visztuples immediately after its access, I think it is time
		 * to free them now.
		 */
		if (RelationStorageIsZHeap(node->ss.ss_currentRelation)
						&& node->ss.ss_currentScanDesc->rs_pageatatime)
		{
			int i;
			for (i = 0; i < node->ss.ss_currentScanDesc->rs_ntuples; i++)
				zheap_freetuple(node->ss.ss_currentScanDesc->rs_visztuples[i]);
			node->ss.ss_currentScanDesc->rs_ntuples = 0;
		}
		heap_endscan(node->ss.ss_currentScanDesc);
	}
}

/* ----------------------------------------------------------------
 *		ExecReScanSampleScan
 *
 *		Rescans the relation.
 *
 * ----------------------------------------------------------------
 */
void
ExecReScanSampleScan(SampleScanState *node)
{
	/* Remember we need to do BeginSampleScan again (if we did it at all) */
	node->begun = false;

	ExecScanReScan(&node->ss);
}


/*
 * Initialize the TABLESAMPLE method: evaluate params and call BeginSampleScan.
 */
static void
tablesample_init(SampleScanState *scanstate)
{
	TsmRoutine *tsm = scanstate->tsmroutine;
	ExprContext *econtext = scanstate->ss.ps.ps_ExprContext;
	Datum	   *params;
	Datum		datum;
	bool		isnull;
	uint32		seed;
	bool		allow_sync;
	int			i;
	ListCell   *arg;

	params = (Datum *) palloc(list_length(scanstate->args) * sizeof(Datum));

	i = 0;
	foreach(arg, scanstate->args)
	{
		ExprState  *argstate = (ExprState *) lfirst(arg);

		params[i] = ExecEvalExprSwitchContext(argstate,
											  econtext,
											  &isnull);
		if (isnull)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TABLESAMPLE_ARGUMENT),
					 errmsg("TABLESAMPLE parameter cannot be null")));
		i++;
	}

	if (scanstate->repeatable)
	{
		datum = ExecEvalExprSwitchContext(scanstate->repeatable,
										  econtext,
										  &isnull);
		if (isnull)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TABLESAMPLE_REPEAT),
					 errmsg("TABLESAMPLE REPEATABLE parameter cannot be null")));

		/*
		 * The REPEATABLE parameter has been coerced to float8 by the parser.
		 * The reason for using float8 at the SQL level is that it will
		 * produce unsurprising results both for users used to databases that
		 * accept only integers in the REPEATABLE clause and for those who
		 * might expect that REPEATABLE works like setseed() (a float in the
		 * range from -1 to 1).
		 *
		 * We use hashfloat8() to convert the supplied value into a suitable
		 * seed.  For regression-testing purposes, that has the convenient
		 * property that REPEATABLE(0) gives a machine-independent result.
		 */
		seed = DatumGetUInt32(DirectFunctionCall1(hashfloat8, datum));
	}
	else
	{
		/* Use the seed selected by ExecInitSampleScan */
		seed = scanstate->seed;
	}

	/* Set default values for params that BeginSampleScan can adjust */
	scanstate->use_bulkread = true;
	scanstate->use_pagemode = true;

	/* Let tablesample method do its thing */
	tsm->BeginSampleScan(scanstate,
						 params,
						 list_length(scanstate->args),
						 seed);

	/* We'll use syncscan if there's no NextSampleBlock function */
	allow_sync = (tsm->NextSampleBlock == NULL);

	/* Now we can create or reset the HeapScanDesc */
	if (scanstate->ss.ss_currentScanDesc == NULL)
	{
		scanstate->ss.ss_currentScanDesc =
			_beginscan_sampling(scanstate->ss.ss_currentRelation,
									scanstate->ss.ps.state->es_snapshot,
									0, NULL,
									scanstate->use_bulkread,
									allow_sync,
									scanstate->use_pagemode);
	}
	else
	{
		_rescan_set_params(scanstate->ss.ss_currentRelation,
							   scanstate->ss.ss_currentScanDesc, NULL,
							   scanstate->use_bulkread,
							   allow_sync,
							   scanstate->use_pagemode);
	}

	pfree(params);

	/* And we're initialized. */
	scanstate->begun = true;
}

/*
 * Get next tuple from TABLESAMPLE method.
 *
 * Note: an awful lot of this is copied-and-pasted from heapam.c.  It would
 * perhaps be better to refactor to share more code.
 */
static HeapTuple
heap_tablesample_getnext(SampleScanState *scanstate)
{
	TsmRoutine *tsm = scanstate->tsmroutine;
	HeapScanDesc scan = scanstate->ss.ss_currentScanDesc;
	HeapTuple	tuple = &(scan->rs_ctup);
	Snapshot	snapshot = scan->rs_snapshot;
	bool		pagemode = scan->rs_pageatatime;
	BlockNumber blockno;
	Page		page;
	bool		all_visible;
	OffsetNumber maxoffset;

	if (!scan->rs_inited)
	{
		/*
		 * return null immediately if relation is empty
		 */
		if (scan->rs_nblocks == 0)
		{
			Assert(!BufferIsValid(scan->rs_cbuf));
			tuple->t_data = NULL;
			return NULL;
		}
		if (tsm->NextSampleBlock)
		{
			blockno = tsm->NextSampleBlock(scanstate);
			if (!BlockNumberIsValid(blockno))
			{
				tuple->t_data = NULL;
				return NULL;
			}
		}
		else
			blockno = scan->rs_startblock;
		Assert(blockno < scan->rs_nblocks);
		heapgetpage(scan, blockno);
		scan->rs_inited = true;
	}
	else
	{
		/* continue from previously returned page/tuple */
		blockno = scan->rs_cblock;	/* current page */
	}

	/*
	 * When not using pagemode, we must lock the buffer during tuple
	 * visibility checks.
	 */
	if (!pagemode)
		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

	page = (Page) BufferGetPage(scan->rs_cbuf);
	all_visible = PageIsAllVisible(page) && !snapshot->takenDuringRecovery;
	maxoffset = PageGetMaxOffsetNumber(page);

	for (;;)
	{
		OffsetNumber tupoffset;
		bool		finished;

		CHECK_FOR_INTERRUPTS();

		/* Ask the tablesample method which tuples to check on this page. */
		tupoffset = tsm->NextSampleTuple(scanstate,
										 blockno,
										 maxoffset);

		if (OffsetNumberIsValid(tupoffset))
		{
			ItemId		itemid;
			bool		visible;

			/* Skip invalid tuple pointers. */
			itemid = PageGetItemId(page, tupoffset);
			if (!ItemIdIsNormal(itemid))
				continue;

			tuple->t_data = (HeapTupleHeader) PageGetItem(page, itemid);
			tuple->t_len = ItemIdGetLength(itemid);
			ItemPointerSet(&(tuple->t_self), blockno, tupoffset);

			if (all_visible)
				visible = true;
			else
				visible = SampleTupleVisible(tuple, tupoffset, scan);

			/* in pagemode, heapgetpage did this for us */
			if (!pagemode)
				CheckForSerializableConflictOut(visible, scan->rs_rd, (void *) tuple,
												scan->rs_cbuf, snapshot);

			if (visible)
			{
				/* Found visible tuple, return it. */
				if (!pagemode)
					LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
				break;
			}
			else
			{
				/* Try next tuple from same page. */
				continue;
			}
		}

		/*
		 * if we get here, it means we've exhausted the items on this page and
		 * it's time to move to the next.
		 */
		if (!pagemode)
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);

		if (tsm->NextSampleBlock)
		{
			blockno = tsm->NextSampleBlock(scanstate);
			Assert(!scan->rs_syncscan);
			finished = !BlockNumberIsValid(blockno);
		}
		else
		{
			/* Without NextSampleBlock, just do a plain forward seqscan. */
			blockno++;
			if (blockno >= scan->rs_nblocks)
				blockno = 0;

			/*
			 * Report our new scan position for synchronization purposes.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_syncscan)
				ss_report_location(scan->rs_rd, blockno);

			finished = (blockno == scan->rs_startblock);
		}

		/*
		 * Reached end of scan?
		 */
		if (finished)
		{
			if (BufferIsValid(scan->rs_cbuf))
				ReleaseBuffer(scan->rs_cbuf);
			scan->rs_cbuf = InvalidBuffer;
			scan->rs_cblock = InvalidBlockNumber;
			tuple->t_data = NULL;
			scan->rs_inited = false;
			return NULL;
		}

		Assert(blockno < scan->rs_nblocks);
		heapgetpage(scan, blockno);

		/* Re-establish state for new page */
		if (!pagemode)
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);

		page = (Page) BufferGetPage(scan->rs_cbuf);
		all_visible = PageIsAllVisible(page) && !snapshot->takenDuringRecovery;
		maxoffset = PageGetMaxOffsetNumber(page);
	}

	/* Count successfully-fetched tuples as heap fetches */
	pgstat_count_heap_getnext(scan->rs_rd);

	return &(scan->rs_ctup);
}

/*
 * Check visibility of the tuple.
 */
static bool
SampleTupleVisible(HeapTuple tuple, OffsetNumber tupoffset, HeapScanDesc scan)
{
	if (scan->rs_pageatatime)
	{
		/*
		 * In pageatatime mode, heapgetpage() already did visibility checks,
		 * so just look at the info it left in rs_vistuples[].
		 *
		 * We use a binary search over the known-sorted array.  Note: we could
		 * save some effort if we insisted that NextSampleTuple select tuples
		 * in increasing order, but it's not clear that there would be enough
		 * gain to justify the restriction.
		 */
		int			start = 0,
					end = scan->rs_ntuples - 1;

		while (start <= end)
		{
			int			mid = (start + end) / 2;
			OffsetNumber curoffset = scan->rs_vistuples[mid];

			if (tupoffset == curoffset)
				return true;
			else if (tupoffset < curoffset)
				end = mid - 1;
			else
				start = mid + 1;
		}

		return false;
	}
	else
	{
		/* Otherwise, we have to check the tuple individually. */
		return HeapTupleSatisfiesVisibility(tuple,
											scan->rs_snapshot,
											scan->rs_cbuf);
	}
}

/*
 * Get next tuple from TABLESAMPLE method.
 *
 * Similar to heap_tablesample_getnext.
 */
static ZHeapTuple
zheap_tablesample_getnext(SampleScanState *scanstate)
{
	TsmRoutine *tsm = scanstate->tsmroutine;
	HeapScanDesc scan = scanstate->ss.ss_currentScanDesc;
	ZHeapTuple	tuple = scan->rs_cztup;
	Snapshot	snapshot = scan->rs_snapshot;
	BlockNumber blockno;
	OffsetNumber maxoffset;
	int			i;
	Page		page = NULL;
	bool		all_visible;
	bool		pagemode = scan->rs_pageatatime;
	bool		finished;
	bool		valid;

	if (!scan->rs_inited)
	{
		/*
		 * return null immediately if relation is empty
		 */
		if (scan->rs_nblocks == ZHEAP_METAPAGE + 1)
		{
			Assert(!BufferIsValid(scan->rs_cbuf));
			return NULL;
		}
		if (tsm->NextSampleBlock)
		{
			blockno = tsm->NextSampleBlock(scanstate);
			/* Skip metapage */
			if (blockno == ZHEAP_METAPAGE)
				blockno = tsm->NextSampleBlock(scanstate);
			if (!BlockNumberIsValid(blockno))
			{
				return NULL;
			}
		}
		else
			blockno = scan->rs_startblock;
		Assert(blockno < scan->rs_nblocks);
		valid = zheapgetpage(scan, blockno);
		if (!valid)
			goto get_next_page;
		scan->rs_inited = true;
	}
	else
	{
		/* continue from previously returned page/tuple */
		blockno = scan->rs_cblock;	/* current page */
	}

	/*
	 * When not using pagemode, we must lock the buffer during tuple
	 * visibility checks.
	 */
	if (!pagemode)
	{
		uint8		vmstatus;
		Buffer		vmbuffer = InvalidBuffer;

		LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
		page = (Page) BufferGetPage(scan->rs_cbuf);
		vmstatus = visibilitymap_get_status(scan->rs_rd,
										BufferGetBlockNumber(scan->rs_cbuf),
										&vmbuffer);

		all_visible = (vmstatus & VISIBILITYMAP_ALL_VISIBLE) &&
					  !snapshot->takenDuringRecovery;

		if (BufferIsValid(vmbuffer))
		{
			ReleaseBuffer(vmbuffer);
			vmbuffer = InvalidBuffer;
		}

		maxoffset = PageGetMaxOffsetNumber(page);
	}
	else
	{
		all_visible = false;
		maxoffset = scan->rs_ntuples;
	}

get_next_tuple:
	for (;;)
	{
		OffsetNumber tupoffset;

		CHECK_FOR_INTERRUPTS();

		/* Ask the tablesample method which tuples to check on this page. */
		tupoffset = tsm->NextSampleTuple(scanstate,
										 blockno,
										 maxoffset);

		if (OffsetNumberIsValid(tupoffset))
		{
			if (!pagemode)
			{
				ItemId		itemid;
				bool		visible;
				ZHeapTuple loctup = NULL;
				Size		loctup_len;
				ItemPointerData	tid;

				/* Skip invalid tuple pointers. */
				itemid = PageGetItemId(page, tupoffset);
				if (!ItemIdIsNormal(itemid))
					continue;

				tuple = NULL;
				ItemPointerSet(&tid, blockno, tupoffset);
				loctup_len = ItemIdGetLength(itemid);

				loctup = palloc(ZHEAPTUPLESIZE + loctup_len);
				loctup->t_data = (ZHeapTupleHeader) ((char *) loctup +
													 ZHEAPTUPLESIZE);

				loctup->t_tableOid = RelationGetRelid(scan->rs_rd);
				loctup->t_len = loctup_len;
				loctup->t_self = tid;

				/*
				 * We always need to make a copy of zheap tuple as once we release
				 * the buffer an in-place update can change the tuple.
				 */
				memcpy(loctup->t_data,
					   ((ZHeapTupleHeader) PageGetItem((Page) page, itemid)),
					   loctup->t_len);

				if (all_visible)
				{
					tuple = loctup;
					visible = true;
				}
				else
				{
					tuple = ZHeapTupleSatisfiesVisibility(loctup,
															scan->rs_snapshot,
															scan->rs_cbuf,
															NULL);

					visible = (tuple != NULL);
				}

				/*
				 * If any prior version is visible, we pass latest visible as
				 * true. The state of latest version of tuple is determined by
				 * the called function.
				 *
				 * Note that, it's possible that tuple is updated in-place and
				 * we're seeing some prior version of that. We handle that case
				 * in ZHeapTupleHasSerializableConflictOut.
				 */
				CheckForSerializableConflictOut(visible, scan->rs_rd, (void *) &tid,
												scan->rs_cbuf, snapshot);

				if (visible)
				{
					/* Found visible tuple, return it. */
					LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
					return tuple;
				}
				else
				{
					/* Try next tuple from same page. */
					continue;
				}
			}
			else
			{
				return scan->rs_visztuples[tupoffset - 1];
			}
		}

		/*
		 * if we get here, it means we've exhausted the items on this page and
		 * it's time to move to the next.
		 * For now we shall free all of the zheap tuples stored in rs_visztuples.
		 * Later a better memory management is required.
		 */
		if (pagemode)
		{
			for (i = 0; i < scan->rs_ntuples; i++)
				zheap_freetuple(scan->rs_visztuples[i]);
			scan->rs_ntuples = 0;
		}

		if (!pagemode)
			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_UNLOCK);
		break;
	}

get_next_page:
	for (;;)
	{
		if (tsm->NextSampleBlock)
		{
			blockno = tsm->NextSampleBlock(scanstate);
			/* Skip metapage */
			if (blockno == ZHEAP_METAPAGE)
				blockno = tsm->NextSampleBlock(scanstate);
			Assert(!scan->rs_syncscan);
			finished = !BlockNumberIsValid(blockno);
		}
		else
		{
			/* Without NextSampleBlock, just do a plain forward seqscan. */
			blockno++;
			if (blockno >= scan->rs_nblocks)
				blockno = ZHEAP_METAPAGE + 1;

			/*
			 * Report our new scan position for synchronization purposes.
			 *
			 * Note: we do this before checking for end of scan so that the
			 * final state of the position hint is back at the start of the
			 * rel.  That's not strictly necessary, but otherwise when you run
			 * the same query multiple times the starting position would shift
			 * a little bit backwards on every invocation, which is confusing.
			 * We don't guarantee any specific ordering in general, though.
			 */
			if (scan->rs_syncscan)
				ss_report_location(scan->rs_rd, blockno);

			finished = (blockno == scan->rs_startblock);
		}

		/*
		 * Reached end of scan?
		 */
		if (finished)
		{
			if (BufferIsValid(scan->rs_cbuf))
				ReleaseBuffer(scan->rs_cbuf);
			scan->rs_cbuf = InvalidBuffer;
			scan->rs_cblock = InvalidBlockNumber;
			scan->rs_inited = false;
			return NULL;
		}

		Assert(blockno < scan->rs_nblocks);
		valid = zheapgetpage(scan, blockno);
		if (!valid)
			continue;
		if (!scan->rs_inited)
			scan->rs_inited = true;

		/* Re-establish state for new page */
		if (!pagemode)
		{
			uint8		vmstatus;
			Buffer		vmbuffer = InvalidBuffer;

			LockBuffer(scan->rs_cbuf, BUFFER_LOCK_SHARE);
			vmstatus = visibilitymap_get_status(scan->rs_rd,
									BufferGetBlockNumber(scan->rs_cbuf),
									&vmbuffer);

			all_visible = (vmstatus & VISIBILITYMAP_ALL_VISIBLE) &&
						  !snapshot->takenDuringRecovery;

			if (BufferIsValid(vmbuffer))
			{
				ReleaseBuffer(vmbuffer);
				vmbuffer = InvalidBuffer;
			}

			page = (Page) BufferGetPage(scan->rs_cbuf);
			maxoffset = PageGetMaxOffsetNumber(page);
		}
		else
		{
			all_visible = false;
			maxoffset = scan->rs_ntuples;
		}

		goto get_next_tuple;
	}

	/* Count successfully-fetched tuples as heap fetches */
	pgstat_count_heap_getnext(scan->rs_rd);

	return scan->rs_cztup;
}
