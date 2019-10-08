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

#include <unistd.h>

#include "access/undo.h"
#include "access/undolog.h"
#include "access/undorecordset.h"
#include "access/xactundo.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/shmem.h"

static void AtProcExit_Undo(int code, Datum arg);
static void CleanUpUndoCheckPointFiles(XLogRecPtr checkPointRedo);

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

void
StartupUndo(XLogRecPtr checkPointRedo)
{
	StartupUndoLogs(checkPointRedo);
}

void
CheckPointUndo(XLogRecPtr checkPointRedo, XLogRecPtr priorCheckPointRedo)
{
	CheckPointUndoLogs(checkPointRedo);
	CleanUpUndoCheckPointFiles(priorCheckPointRedo);
}

/*
 * Shut down undo subsystems in the correct order.
 *
 * Generally, higher-level stuff should be shut down first.
 */
static void
AtProcExit_Undo(int code, Datum arg)
{
	AtProcExit_XactUndo();
	AtProcExit_UndoRecordSet();
	AtProcExit_UndoLog();
}

/*
 * Delete unreachable files under pg_undo.  Any files corresponding to LSN
 * positions before the previous checkpoint are no longer needed.
 */
static void
CleanUpUndoCheckPointFiles(XLogRecPtr checkPointRedo)
{
	DIR	   *dir;
	struct dirent *de;
	char	path[MAXPGPATH];
	char	oldest_path[MAXPGPATH];

	/*
	 * If a base backup is in progress, we can't delete any checkpoint
	 * snapshot files because one of them corresponds to the backup label but
	 * there could be any number of checkpoints during the backup.
	 */
	if (BackupInProgress())
		return;

	/* Otherwise keep only those >= the previous checkpoint's redo point. */
	snprintf(oldest_path, MAXPGPATH, "%016" INT64_MODIFIER "X",
			 checkPointRedo);
	dir = AllocateDir("pg_undo");
	while ((de = ReadDir(dir, "pg_undo")) != NULL)
	{
		/*
		 * Assume that fixed width uppercase hex strings sort the same way as
		 * the values they represent, so we can use strcmp to identify undo
		 * log snapshot files corresponding to checkpoints that we don't need
		 * anymore.  This assumption holds for ASCII.
		 */
		if (!(strlen(de->d_name) == UNDO_CHECKPOINT_FILENAME_LENGTH))
			continue;

		if (UndoCheckPointFilenamePrecedes(de->d_name, oldest_path))
		{
			snprintf(path, MAXPGPATH, "pg_undo/%s", de->d_name);
			if (unlink(path) != 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not unlink file \"%s\": %m", path)));
			elog(DEBUG2, "unlinking unreachable pg_undo file \"%s\"", path);
		}
	}
	FreeDir(dir);
}
