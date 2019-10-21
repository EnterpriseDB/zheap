/*
 *	undo.c
 *
 *	Support for upgrading undo logs.\
 *	Copyright (c) 2019, PostgreSQL Global Development Group
 *	src/bin/pg_upgrade/undo.c
 */


#include "postgres_fe.h"

#include "access/undo.h"
#include "access/undolog.h"
#include "pg_upgrade.h"
#include "port/pg_crc32c.h"

/*
 * This is the same as the definition in backend/access/undo/undo.c, but we
 * can't use its routines because they report errors with ereport().
 * XXX Find a way to share struct + routines?
 */
struct UndoCheckpointContext
{
	char	path[MAXPGPATH];
	int		fd;
	pg_crc32c crc;
};

/*
 * The relevant parts of UndoLogMetaDataData, in a version-independent format.
 */
typedef struct
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	char		persistence;
	Oid			tablespace;
} UndoLogInfo;

static void
read_raw(UndoCheckpointContext *ctx, void *data, size_t size)
{
	int rc;

	rc = read(ctx->fd, data, size);
	if (rc < 0)
		pg_fatal("could not read file \"%s\": %m", ctx->path);
	if (rc < size)
		pg_fatal("could not read file \"%s\": read %d of %zu", ctx->path, rc,
				 size);
}

/*
 * Like ReadUndoCheckpointData(), but with error handling suitable for
 * pg_upgrade.
 */
static void
read_and_checksum(UndoCheckpointContext *ctx, void *data, size_t size)
{
	read_raw(ctx, data, size);
	COMP_CRC32C(ctx->crc, data, size);
}

static void
write_raw(UndoCheckpointContext *ctx, const void *data, size_t size)
{
	int rc;

	rc = write(ctx->fd, data, size);
	if (rc < 0)
		pg_fatal("could not write file \"%s\": %m", ctx->path);
	if (rc < size)
		pg_fatal("could not write file \"%s\": wrote %d of %zu", ctx->path, rc,
				 size);
}

/*
 * Like WriteUndoCheckpointData(), but with error handling suitable for
 * pg_upgrade.
 */
static void
write_and_checksum(UndoCheckpointContext *ctx, const void *data, size_t size)
{
	write_raw(ctx, data, size);
	COMP_CRC32C(ctx->crc, data, size);
}

/*
 * Read a single UndoLogMetaData object.  If the format changes in later
 * versions, this may need to change to be able to read different structs
 * depending on "cluster".
 */
static void
read_one_undo_log(UndoCheckpointContext *ctx,
				  ClusterInfo *cluster,
				  UndoLogInfo *info)
{
	UndoLogMetaData meta_data;

	read_and_checksum(ctx, &meta_data, sizeof(meta_data));

	info->logno = meta_data.logno;
	info->persistence = meta_data.persistence;
	info->tablespace = meta_data.tablespace;
	info->discard = meta_data.discard;
}

static void
merge_undo_log(UndoLogInfo *logs, UndoLogNumber *num_logs,
			   const UndoLogInfo *info)
{
	UndoLogNumber i;

	/* Do we already have an entry for this logno? */
	for (i = 0; i < *num_logs; ++i)
	{
		if (logs[i].logno == info->logno)
		{
			/*
			 * Take the highest discard offset, so that any pointers that
			 * originated in either cluster appear to be discarded.
			 */
			if (logs[i].discard < info->discard)
				logs[i].discard = info->discard;

			/* TODO: full! */

			/*
			 * Take the most persistent persistence level.  While we could
			 * just convert them all to permanent and it wouldn't hurt, it's
			 * probably a better idea to keep about the same number of each
			 * persistence level, so that a system that has stabilized with
			 * those numbers will continue to be stable after the upgrade (ie
			 * not suddenly need to create more undo logs of different
			 * levels).  The most permanent is the best choice, so that we
			 * have the option of rewinding TEMP undo logs to recycle their
			 * address space (not implemented yet).
			 */
			if (logs[i].persistence == 'p' || info->persistence == 'p')
				logs[i].persistence = 'p';
			else if (logs[i].persistence == 'u' || info->persistence == 'u')
				logs[i].persistence = 'u';
			else
				logs[i].persistence = 't';

			/*
			 * Take the highest tablespace OID.  The choice of 'highest' is
			 * arbitrary (we don't really expect the new cluster to have more
			 * than one log), but it seems useful to preserve the distribution
			 * of tablespaces from the old cluster for stability, as above.
			 */
			if (logs[i].tablespace < info->tablespace)
				logs[i].tablespace = info->tablespace;
			break;
		}
	}

	/* Otherwise create a new entry. */
	logs[*num_logs++] = *info;
}

/*
 * We need to merge the old undo logs and the new undo logs.  We know that
 * there is no live undo data (see check_for_live_undo_data()), but we need to
 * make sure that any undo record pointers that exist in the old OR new
 * cluster appear as discarded.  That is, any log numbers that are entirely
 * discarded in either cluster appear as entirely discarded, and we retain
 * the higher of the discard pointers in any log that is active.  This is
 * mostly a theoretical concern for now, but perhaps a future release will be
 * able to create higher undo record pointers during initdb than the old
 * cluster had, so let's use an algorithm that doesn't make any assumptions
 * about that.
 */
void
merge_undo_logs(void)
{
	UndoLogInfo *logs;
	UndoLogNumber num_logs;
	UndoLogNumber num_old_logs;
	UndoLogNumber old_next_logno;
	UndoLogNumber num_new_logs;
	UndoLogNumber new_next_logno;
	UndoLogNumber i;
	UndoCheckpointContext old_ctx;
	UndoCheckpointContext new_ctx;
	pg_crc32c	crc;
	size_t		size;

	/* If the old cluster has no undo logs, there is nothing to do */
	if (GET_MAJOR_VERSION(old_cluster.major_version) < 1300)
		return;

	INIT_CRC32C(old_ctx.crc);
	INIT_CRC32C(new_ctx.crc);

	/*
	 * Open the pg_undo files corresponding to the old and new redo locations.
	 * First, we'll reload pg_controldata output, so that we have up-to-date
	 * redo locations.
	 */
	get_control_data(&old_cluster, true);
	get_control_data(&new_cluster, true);
	snprintf(old_ctx.path,
			 sizeof(old_ctx.path),
			 "%s/pg_undo/%016" INT64_MODIFIER "X",
			 old_cluster.pgdata,
			 old_cluster.controldata.redo_location);
	snprintf(new_ctx.path,
			 sizeof(new_ctx.path),
			 "%s/pg_undo/%016" INT64_MODIFIER "X",
			 new_cluster.pgdata,
			 new_cluster.controldata.redo_location);
	old_ctx.fd = open(old_ctx.path, O_RDONLY, 0);
	if (old_ctx.fd < 0)
		pg_fatal("could not open file \"%s\": %m\n", old_ctx.path);
	new_ctx.fd = open(new_ctx.path, O_RDWR, 0);
	if (new_ctx.fd < 0)
		pg_fatal("could not open file \"%s\": %m\n", new_ctx.path);

	/*
	 * Read the part written by CheckPointUndoLogs().  This may require
	 * changes for different cluster major versions if the file format
	 * changes.
	 */
	read_and_checksum(&old_ctx, &old_next_logno, sizeof(old_next_logno));
	read_and_checksum(&old_ctx, &num_old_logs, sizeof(num_old_logs));
	read_and_checksum(&new_ctx, &new_next_logno, sizeof(new_next_logno));
	read_and_checksum(&new_ctx, &num_new_logs, sizeof(num_new_logs));

	/*
	 * Read the part written by CheckPointXactUndo().  We expect this to be
	 * empty.  For now we don't want undo data to have to be
	 * backward-compatible.
	 */
	read_and_checksum(&old_ctx, &size, sizeof(size));
	if (size != 0)
	{
		pg_fatal("cannot upgrade from a database cluster with outstanding undo requests");
		exit(1);
	}
	read_and_checksum(&new_ctx, &size, sizeof(size));
	if (size != 0)
	{
		pg_fatal("cannot upgrade to database cluster with outstanding undo requests");
		exit(1);
	}

	/* Read checksum and verify. */
	FIN_CRC32C(old_ctx.crc);
	FIN_CRC32C(new_ctx.crc);
	read_raw(&old_ctx, &crc, sizeof(crc));
	if (!EQ_CRC32C(old_ctx.crc, crc ))
		pg_fatal("undo checkpoint file \"%s\" contains incorrect checksum",
				 old_ctx.path);
	read_raw(&new_ctx, &crc, sizeof(crc));
	if (!EQ_CRC32C(new_ctx.crc, crc))
		pg_fatal("undo checkpoint file \"%s\" contains incorrect checksum",
				 new_ctx.path);

	/* We don't need the old file anymore. */
	close(old_ctx.fd);

	/* Allocate workspace that is sure to be enough for the merged set */
	logs = malloc(sizeof(*logs) * (num_old_logs + num_new_logs));
	if (logs == NULL)
	{
		pg_fatal("out of memory\n");
		exit(1);
	}
	num_logs = 0;

	/* The "next" log number to create should be the higher of the two. */
	new_next_logno = Max(old_next_logno, new_next_logno);

	/* Merge in the old logs */
	while (num_old_logs > 0)
	{
		UndoLogInfo	info;

		read_one_undo_log(&old_ctx, &old_cluster, &info);
		merge_undo_log(logs, &num_logs, &info);
		--num_old_logs;
	}

	/* Merge in the new logs */
	while (num_new_logs > 0)
	{
		UndoLogInfo	info;

		read_one_undo_log(&new_ctx, &old_cluster, &info);
		merge_undo_log(logs, &num_logs, &info);
		--num_new_logs;
	}

	/* Prepare to overwrite the new file. */
	if (ftruncate(new_ctx.fd, 0) < 0)
		pg_fatal("could not truncate file \"%s\": %m", new_ctx.path);
	if (lseek(new_ctx.fd, SEEK_SET, 0) < 0)
		pg_fatal("could not seek to start of file \"%s\": %m", new_ctx.path);

	INIT_CRC32C(new_ctx.crc);

	/* Write the part that CheckPointUndoLogs() normally writes. */
	write_and_checksum(&new_ctx, &new_next_logno, sizeof(new_next_logno));
	write_and_checksum(&new_ctx, &num_logs, sizeof(num_logs));
	for (i = 0; i < num_logs; ++i)
	{
		UndoLogMetaData	meta_data;
		UndoLogInfo	*info = &logs[i];

		memset(&meta_data, 0, sizeof(meta_data));
		meta_data.logno = info->logno;

		/*
		 * Round the insert and discard offsets up so that they point to the
		 * first byte in the next segment.  That means there is no logical
		 * data and no physical files are expected to exist.
		 */
		meta_data.insert = meta_data.discard =
			((meta_data.insert / UndoLogSegmentSize) + 1) *
			UndoLogSegmentSize;

		/* TODO handle full? */

		write_and_checksum(&new_ctx, &meta_data, sizeof(meta_data));
	}

	/* Write the part that CheckPointXactUndo() normally writes. */
	size = 0;
	write_and_checksum(&new_ctx, &size, sizeof(size));

	/* Write the checksum. */
	FIN_CRC32C(new_ctx.crc);
	write_raw(&new_ctx, &new_ctx.crc, sizeof(new_ctx.crc));

	close(new_ctx.fd);
	free(logs);
}
