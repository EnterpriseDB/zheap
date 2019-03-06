/*
 *	undo.c
 *
 *	Support for upgrading undo logs.\
 *	Copyright (c) 2019, PostgreSQL Global Development Group
 *	src/bin/pg_upgrade/undo.c
 */


#include "postgres_fe.h"
#include "pg_upgrade.h"
#include "access/undolog.h"

/*
 * The relevant parts of UndoLogMetaDataData, in a version-independent format.
 */
typedef struct
{
	UndoLogNumber logno;
	UndoLogOffset discard;
	UndoLogStatus status;
	UndoLogCategory category;
	Oid			tablespace;
} UndoLogInfo;

/*
 * Read the header of a pg_undo file and extract basic information.  If the
 * format of the header changes in later versions, this may need to change
 * depending on "cluster".
 */
static void
read_pg_undo_header(int fd, ClusterInfo *cluster, UndoLogNumber *low_logno,
					UndoLogNumber *next_logno, UndoLogNumber *num_logs)
{
	pg_crc32c crc;

	/* Read the header, much like StartupUndoLogs(). */
	if (read(fd, low_logno, sizeof(*low_logno)) != sizeof(*low_logno) ||
		read(fd, next_logno, sizeof(*next_logno)) != sizeof(*next_logno) ||
		read(fd, num_logs, sizeof(*num_logs)) != sizeof(*num_logs) ||
		read(fd, &crc, sizeof(crc)) != sizeof(crc))
		pg_fatal("pg_undo file is corrupted or cannot be read\n");
}

/*
 * Read a single UndoLogMetaData object.  If the format changes in later
 * versions, this may need to change to be able to read different structs
 * depending on "cluster".
 */
static void
read_one_undo_log(int fd, ClusterInfo *cluster, UndoLogInfo *info)
{
	UndoLogMetaData meta_data;
	int		rc;

	rc = read(fd, &meta_data, sizeof(meta_data));
	if (rc < 0)
		pg_fatal("could not read undo log meta-data: %m");
	else if (rc != sizeof(meta_data))
		pg_fatal("could not read undo log meta-data: expect %zu bytes but read only %d bytes",
				 sizeof(meta_data), rc);

	info->logno = meta_data.logno;
	info->category = meta_data.category;
	info->tablespace = meta_data.tablespace;
	info->discard = meta_data.discard;
	info->status = meta_data.status;
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

			/*
			 * Take the highest status so that entirely discarded logs trump
			 * active logs.
			 */
			StaticAssertStmt(UNDO_LOG_STATUS_ACTIVE < UNDO_LOG_STATUS_FULL,
							 "undo log status out of order");
			StaticAssertStmt(UNDO_LOG_STATUS_FULL < UNDO_LOG_STATUS_DISCARDED,
							 "undo log status out of order");
			if (logs[i].status < info->status)
				logs[i].status = info->status;

			/*
			 * Take the most persistent persistence level.  While we could
			 * just convert them all to permanent and it wouldn't hurt, it's
			 * probably a better idea to keep about the same number of each
			 * persistence level, so that a system that has stabilized with
			 * those numbers will continue to be stable after the upgrade (ie
			 * not suddenly need to create more undo logs of different
			 * levels).  The most permanent is the best choice, because TEMP
			 * undo logs might be rewound in future.
			 */
			StaticAssertStmt(UNDO_PERMANENT < UNDO_UNLOGGED,
							 "undo log persistent out of order");
			StaticAssertStmt(UNDO_UNLOGGED < UNDO_TEMP,
							 "undo log persistent out of order");
			if (logs[i].status > info->status)
				logs[i].status = info->status;

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
	char		old_pg_undo_path[MAXPGPATH];
	char		new_pg_undo_path[MAXPGPATH];
	UndoLogInfo *logs;
	UndoLogNumber num_logs;
	UndoLogNumber num_old_logs;
	UndoLogNumber old_low_logno;
	UndoLogNumber old_next_logno;
	UndoLogNumber num_new_logs;
	UndoLogNumber new_low_logno;
	UndoLogNumber new_next_logno;
	UndoLogNumber i;
	int			old_fd;
	int			new_fd;
	pg_crc32c	crc;

	/* If the old cluster has no undo logs, there is nothing to do */
	if (GET_MAJOR_VERSION(old_cluster.major_version) < 1300)
		return;

	/*
	 * Open the pg_undo files corresponding to the old and new redo locations.
	 * First, we'll reload pg_controldata output, so that we have up-to-date
	 * redo locations.
	 */
	get_control_data(&old_cluster, true);
	get_control_data(&new_cluster, true);
	snprintf(old_pg_undo_path,
			 sizeof(old_pg_undo_path),
			 "%s/pg_undo/%016" INT64_MODIFIER "X",
			 old_cluster.pgdata,
			 old_cluster.controldata.redo_location);
	snprintf(new_pg_undo_path,
			 sizeof(new_pg_undo_path),
			 "%s/pg_undo/%016" INT64_MODIFIER "X",
			 new_cluster.pgdata,
			 new_cluster.controldata.redo_location);
	old_fd = open(old_pg_undo_path, O_RDONLY, 0);
	if (old_fd < 0)
		pg_fatal("could not open file \"%s\": %m\n", old_pg_undo_path);
	new_fd = open(new_pg_undo_path, O_RDWR, 0);
	if (new_fd < 0)
		pg_fatal("could not open file \"%s\": %m\n", new_pg_undo_path);

	/* Read the headers */
	read_pg_undo_header(old_fd, &old_cluster, &old_low_logno, &old_next_logno, &num_old_logs);
	read_pg_undo_header(new_fd, &new_cluster, &new_low_logno, &new_next_logno, &num_new_logs);

	/* Allocate workspace that is sure to be enough for the merged set */
	logs = malloc(sizeof(*logs) * (num_old_logs + num_new_logs));
	if (logs == NULL)
	{
		pg_fatal("out of memory\n");
		exit(1);
	}
	num_logs = 0;

	/*
	 * Anything below the "low" logno has been entirely discarded, so we'll
	 * take the higher of the two values.  Likewise, the "next" log number to
	 * allocate should be the higher of the two.
	 */
	new_low_logno = Max(old_low_logno, new_low_logno);
	new_next_logno = Max(old_next_logno, new_next_logno);

	/* Merge in the old logs */
	while (num_old_logs > 0)
	{
		UndoLogInfo	info;

		read_one_undo_log(old_fd, &old_cluster, &info);
		merge_undo_log(logs, &num_logs, &info);
		--num_old_logs;
	}

	/* Merge in the new logs */
	while (num_new_logs > 0)
	{
		UndoLogInfo	info;

		read_one_undo_log(new_fd, &old_cluster, &info);
		merge_undo_log(logs, &num_logs, &info);
		--num_new_logs;
	}

	close(old_fd);

	/* Now write out the new file, much like CheckPointUndoLogs() */
	if (ftruncate(new_fd, 0) < 0)
		pg_fatal("could not truncate file \"%s\": %m", new_pg_undo_path);
	if (lseek(new_fd, SEEK_SET, 0) < 0)
		pg_fatal("could not seek to start of file \"%s\": %m", new_pg_undo_path);

	/* Compute header checksum */
	INIT_CRC32C(crc);
	COMP_CRC32C(crc, &new_low_logno, sizeof(new_low_logno));
	COMP_CRC32C(crc, &new_next_logno, sizeof(new_next_logno));
	COMP_CRC32C(crc, &num_logs, sizeof(num_logs));
	FIN_CRC32C(crc);

	/* Write out the header */
	if ((write(new_fd, &new_low_logno, sizeof(new_low_logno)) != sizeof(new_low_logno)) ||
		(write(new_fd, &new_next_logno, sizeof(new_next_logno)) != sizeof(new_next_logno)) ||
		(write(new_fd, &num_logs, sizeof(num_logs)) != sizeof(num_logs)) ||
		(write(new_fd, &crc, sizeof(crc)) != sizeof(crc)))
		pg_fatal("could not write to file \"%s\": %m", new_pg_undo_path);

	/* Write out the undo logs */
	INIT_CRC32C(crc);
	for (i = 0; i < num_logs; ++i)
	{
		UndoLogMetaData	meta_data;
		UndoLogInfo	*info = &logs[i];
		UndoLogOffset end;

		memset(&meta_data, 0, sizeof(meta_data));
		meta_data.logno = info->logno;

		/*
		 * Round the discard offset up so that it points to the first byte in
		 * a segment, and assign that to all three offsets.  That means there
		 * is no logical data, and there are no physical files.
		 */
		end = ((info->discard + UndoLogSegmentSize - 1) / UndoLogSegmentSize)
			* UndoLogSegmentSize;
		meta_data.unlogged.insert = meta_data.discard = meta_data.end = end;

		/*
		 * We have whatever was the highest status (though it probably
		 * wouldn't hurt if we set them all to ACTIVE).
		 */
		meta_data.status = info->status;


		if (write(new_fd, &meta_data, sizeof(meta_data)) != sizeof(meta_data))
			pg_fatal("could not write to file \"%s\": %m", new_pg_undo_path);

		COMP_CRC32C(crc, &meta_data, sizeof(meta_data));
	}
	FIN_CRC32C(crc);

	if (write(new_fd, &crc, sizeof(crc)) != sizeof(crc))
		pg_fatal("could not write to file \"%s\": %m", new_pg_undo_path);

	close(new_fd);
	free(logs);
}
