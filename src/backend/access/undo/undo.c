/*-------------------------------------------------------------------------
 *
 * undo.c
 *	  common undo code
 *
 * The undo subsystem consists of several logically separate subsystems
 * that work together to achieve a common goal. The code in this file
 * provides a limited amount of common infrastructure that can be used
 * by all of those various subsystems, and helps coordinate activities
 * such as startup and shutdown across subsystems.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/undo/undo.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undo.h"
#include "access/undolog.h"
#include "access/undorecordset.h"
#include "access/xactundo.h"
#include "storage/ipc.h"
#include "storage/shmem.h"

static void AtProcExit_Undo(int code, Datum arg);

/*
 * UndoContext is a child of TopMemoryContext which is never reset. The only
 * reason for having a separate context is to make it easier to spot leaks or
 * excessive memory utilization.
 */
MemoryContext UndoContext = NULL;

/*
 * Figure out how much shared memory will be needed for undo.
 *
 * Each subsystem separately computes the space it requires, and we carefully
 * add up those values here.
 */
Size
UndoShmemSize(void)
{
	Size	size;

	size = UndoLogShmemSize();
	size = add_size(size, XactUndoShmemSize());

	return size;
}

/*
 * Initialize undo-related shared memory.
 *
 * Also, perform other initialization steps that need to be done very early.
 */
void
UndoShmemInit(void)
{
	/* First, make sure we can properly clean up on process exit. */
	on_shmem_exit(AtProcExit_Undo, 0);

	/* Initialize memory context. */
	Assert(UndoContext == NULL);
	UndoContext = AllocSetContextCreate(TopMemoryContext, "Undo",
										ALLOCSET_DEFAULT_SIZES);

	/* Now give various undo subsystems a chance to initialize. */
	UndoLogShmemInit();
	XactUndoShmemInit();
}

/*
 * Shutdown undo subsystems in the correct order.
 */
void
AtProcExit_Undo(int code, Datum arg)
{
	AtProcExit_XactUndo();
	AtProcExit_UndoRecordSet();
	AtProcExit_UndoLog();
}
