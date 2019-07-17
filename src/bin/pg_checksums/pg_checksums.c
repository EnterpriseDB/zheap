/*-------------------------------------------------------------------------
 *
 * pg_checksums.c
 *	  Checks, enables or disables page level checksums for an offline
 *	  cluster
 *
 * Copyright (c) 2010-2019, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/bin/pg_checksums/pg_checksums.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access/xlog_internal.h"
#include "common/controldata_utils.h"
#include "common/file_perm.h"
#include "common/file_utils.h"
#include "common/logging.h"
#include "getopt_long.h"
#include "pg_getopt.h"
#include "storage/bufpage.h"
#include "storage/checksum.h"
#include "storage/checksum_impl.h"


static int64 files = 0;
static int64 blocks = 0;
static int64 badblocks = 0;
static ControlFileData *ControlFile;

static char *only_filenode = NULL;
static bool do_sync = true;
static bool verbose = false;
static bool showprogress = false;

typedef enum
{
	PG_MODE_CHECK,
	PG_MODE_DISABLE,
	PG_MODE_ENABLE
} PgChecksumMode;

/*
 * Filename components.
 *
 * XXX: fd.h is not declared here as frontend side code is not able to
 * interact with the backend-side definitions for the various fsync
 * wrappers.
 */
#define PG_TEMP_FILES_DIR "pgsql_tmp"
#define PG_TEMP_FILE_PREFIX "pgsql_tmp"

static PgChecksumMode mode = PG_MODE_CHECK;

static const char *progname;

/*
 * Progress status information.
 */
int64		total_size = 0;
int64		current_size = 0;
static pg_time_t last_progress_report = 0;

static void
usage(void)
{
	printf(_("%s enables, disables, or verifies data checksums in a PostgreSQL database cluster.\n\n"), progname);
	printf(_("Usage:\n"));
	printf(_("  %s [OPTION]... [DATADIR]\n"), progname);
	printf(_("\nOptions:\n"));
	printf(_(" [-D, --pgdata=]DATADIR    data directory\n"));
	printf(_("  -c, --check              check data checksums (default)\n"));
	printf(_("  -d, --disable            disable data checksums\n"));
	printf(_("  -e, --enable             enable data checksums\n"));
	printf(_("  -f, --filenode=FILENODE  check only relation with specified filenode\n"));
	printf(_("  -N, --no-sync            do not wait for changes to be written safely to disk\n"));
	printf(_("  -P, --progress           show progress information\n"));
	printf(_("  -v, --verbose            output verbose messages\n"));
	printf(_("  -V, --version            output version information, then exit\n"));
	printf(_("  -?, --help               show this help, then exit\n"));
	printf(_("\nIf no data directory (DATADIR) is specified, "
			 "the environment variable PGDATA\nis used.\n\n"));
	printf(_("Report bugs to <pgsql-bugs@lists.postgresql.org>.\n"));
}

/*
 * List of files excluded from checksum validation.
 *
 * Note: this list should be kept in sync with what basebackup.c includes.
 */
static const char *const skip[] = {
	"pg_control",
	"pg_filenode.map",
	"pg_internal.init",
	"PG_VERSION",
#ifdef EXEC_BACKEND
	"config_exec_params",
	"config_exec_params.new",
#endif
	NULL,
};

/*
 * Report current progress status.  Parts borrowed from
 * src/bin/pg_basebackup/pg_basebackup.c.
 */
static void
progress_report(bool force)
{
	int			percent;
	char		total_size_str[32];
	char		current_size_str[32];
	pg_time_t	now;

	Assert(showprogress);

	now = time(NULL);
	if (now == last_progress_report && !force)
		return;					/* Max once per second */

	/* Save current time */
	last_progress_report = now;

	/* Adjust total size if current_size is larger */
	if (current_size > total_size)
		total_size = current_size;

	/* Calculate current percentage of size done */
	percent = total_size ? (int) ((current_size) * 100 / total_size) : 0;

	/*
	 * Separate step to keep platform-dependent format code out of
	 * translatable strings.  And we only test for INT64_FORMAT availability
	 * in snprintf, not fprintf.
	 */
	snprintf(total_size_str, sizeof(total_size_str), INT64_FORMAT,
			 total_size / (1024 * 1024));
	snprintf(current_size_str, sizeof(current_size_str), INT64_FORMAT,
			 current_size / (1024 * 1024));

	fprintf(stderr, _("%*s/%s MB (%d%%) computed"),
			(int) strlen(current_size_str), current_size_str, total_size_str,
			percent);

	/* Stay on the same line if reporting to a terminal */
	fprintf(stderr, isatty(fileno(stderr)) ? "\r" : "\n");
}

static bool
skipfile(const char *fn)
{
	const char *const *f;

	for (f = skip; *f; f++)
		if (strcmp(*f, fn) == 0)
			return true;

	return false;
}

static void
scan_file(const char *fn, BlockNumber first_blkno)
{
	PGAlignedBlock buf;
	PageHeader	header = (PageHeader) buf.data;
	int			f;
	BlockNumber blockno;
	int			flags;

	Assert(mode == PG_MODE_ENABLE ||
		   mode == PG_MODE_CHECK);

	flags = (mode == PG_MODE_ENABLE) ? O_RDWR : O_RDONLY;
	f = open(fn, PG_BINARY | flags, 0);

	if (f < 0)
	{
		pg_log_error("could not open file \"%s\": %m", fn);
		exit(1);
	}

	files++;

	for (blockno = 0;; blockno++)
	{
		uint16		csum;
		int			r = read(f, buf.data, BLCKSZ);

		if (r == 0)
			break;
		if (r != BLCKSZ)
		{
			pg_log_error("could not read block %u in file \"%s\": read %d of %d",
						 blockno, fn, r, BLCKSZ);
			exit(1);
		}
		blocks++;

		/* New pages have no checksum yet */
		if (PageIsNew(header))
			continue;

		csum = pg_checksum_page(buf.data, blockno + first_blkno);
		current_size += r;
		if (mode == PG_MODE_CHECK)
		{
			if (csum != header->pd_checksum)
			{
				if (ControlFile->data_checksum_version == PG_DATA_CHECKSUM_VERSION)
					pg_log_error("checksum verification failed in file \"%s\", block %u: calculated checksum %X but block contains %X",
								 fn, blockno, csum, header->pd_checksum);
				badblocks++;
			}
		}
		else if (mode == PG_MODE_ENABLE)
		{
			/* Set checksum in page header */
			header->pd_checksum = csum;

			/* Seek back to beginning of block */
			if (lseek(f, -BLCKSZ, SEEK_CUR) < 0)
			{
				pg_log_error("seek failed for block %u in file \"%s\": %m", blockno, fn);
				exit(1);
			}

			/* Write block with checksum */
			if (write(f, buf.data, BLCKSZ) != BLCKSZ)
			{
				pg_log_error("could not write block %u in file \"%s\": %m",
							 blockno, fn);
				exit(1);
			}
		}

		if (showprogress)
			progress_report(false);
	}

	if (verbose)
	{
		if (mode == PG_MODE_CHECK)
			pg_log_info("checksums verified in file \"%s\"", fn);
		if (mode == PG_MODE_ENABLE)
			pg_log_info("checksums enabled in file \"%s\"", fn);
	}

	close(f);
}

/*
 * Scan the given directory for items which can be checksummed and
 * operate on each one of them.  If "sizeonly" is true, the size of
 * all the items which have checksums is computed and returned back
 * to the caller without operating on the files.  This is used to compile
 * the total size of the data directory for progress reports.
 */
static int64
scan_directory(const char *basedir, const char *subdir, bool sizeonly)
{
	int64		dirsize = 0;
	char		path[MAXPGPATH];
	DIR		   *dir;
	struct dirent *de;

	snprintf(path, sizeof(path), "%s/%s", basedir, subdir);
	dir = opendir(path);
	if (!dir)
	{
		pg_log_error("could not open directory \"%s\": %m", path);
		exit(1);
	}
	while ((de = readdir(dir)) != NULL)
	{
		char		fn[MAXPGPATH];
		struct stat st;

		if (strcmp(de->d_name, ".") == 0 ||
			strcmp(de->d_name, "..") == 0)
			continue;

		/* Skip temporary files */
		if (strncmp(de->d_name,
					PG_TEMP_FILE_PREFIX,
					strlen(PG_TEMP_FILE_PREFIX)) == 0)
			continue;

		/* Skip temporary folders */
		if (strncmp(de->d_name,
					PG_TEMP_FILES_DIR,
					strlen(PG_TEMP_FILES_DIR)) == 0)
			continue;

		snprintf(fn, sizeof(fn), "%s/%s", path, de->d_name);
		if (lstat(fn, &st) < 0)
		{
			pg_log_error("could not stat file \"%s\": %m", fn);
			exit(1);
		}
		if (S_ISREG(st.st_mode))
		{
			char		fnonly[MAXPGPATH];
			char	   *forkpath,
					   *segmentpath;
			BlockNumber first_blkno;

			if (skipfile(de->d_name))
				continue;

			/*
			 * Cut off at the segment boundary (".") to get the segment number
			 * in order to mix it into the checksum. Then also cut off at the
			 * fork boundary, to get the filenode the file belongs to for
			 * filtering.
			 */
			strlcpy(fnonly, de->d_name, sizeof(fnonly));
			segmentpath = strchr(fnonly, '.');
			if (segmentpath != NULL)
			{
				char	   *end;

				*segmentpath++ = '\0';
				if (strstr(segmentpath, "undo"))
					first_blkno = strtol(segmentpath, &end, 16) / BLCKSZ;
				else
					first_blkno = strtol(segmentpath, &end, 10) * RELSEG_SIZE;
				if (*end != '\0')
				{
					pg_log_error("invalid segment number in file name \"%s\"",
								 fn);
					exit(1);
				}
			}
			else
				first_blkno = 0;

			forkpath = strchr(fnonly, '_');
			if (forkpath != NULL)
				*forkpath++ = '\0';

			if (only_filenode && strcmp(only_filenode, fnonly) != 0)
				/* filenode not to be included */
				continue;

			dirsize += st.st_size;

			/*
			 * No need to work on the file when calculating only the size of
			 * the items in the data folder.
			 */
			if (!sizeonly)
				scan_file(fn, first_blkno);
		}
#ifndef WIN32
		else if (S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
#else
		else if (S_ISDIR(st.st_mode) || pgwin32_is_junction(fn))
#endif
			dirsize += scan_directory(path, de->d_name, sizeonly);
	}
	closedir(dir);
	return dirsize;
}

int
main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"check", no_argument, NULL, 'c'},
		{"pgdata", required_argument, NULL, 'D'},
		{"disable", no_argument, NULL, 'd'},
		{"enable", no_argument, NULL, 'e'},
		{"filenode", required_argument, NULL, 'f'},
		{"no-sync", no_argument, NULL, 'N'},
		{"progress", no_argument, NULL, 'P'},
		{"verbose", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};

	char	   *DataDir = NULL;
	int			c;
	int			option_index;
	bool		crc_ok;

	pg_logging_init(argv[0]);
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("pg_checksums"));
	progname = get_progname(argv[0]);

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage();
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_checksums (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	while ((c = getopt_long(argc, argv, "cD:deNPf:v", long_options, &option_index)) != -1)
	{
		switch (c)
		{
			case 'c':
				mode = PG_MODE_CHECK;
				break;
			case 'd':
				mode = PG_MODE_DISABLE;
				break;
			case 'e':
				mode = PG_MODE_ENABLE;
				break;
			case 'f':
				if (atoi(optarg) == 0)
				{
					pg_log_error("invalid filenode specification, must be numeric: %s", optarg);
					exit(1);
				}
				only_filenode = pstrdup(optarg);
				break;
			case 'N':
				do_sync = false;
				break;
			case 'v':
				verbose = true;
				break;
			case 'D':
				DataDir = optarg;
				break;
			case 'P':
				showprogress = true;
				break;
			default:
				fprintf(stderr, _("Try \"%s --help\" for more information.\n"), progname);
				exit(1);
		}
	}

	if (DataDir == NULL)
	{
		if (optind < argc)
			DataDir = argv[optind++];
		else
			DataDir = getenv("PGDATA");

		/* If no DataDir was specified, and none could be found, error out */
		if (DataDir == NULL)
		{
			pg_log_error("no data directory specified");
			fprintf(stderr, _("Try \"%s --help\" for more information.\n"), progname);
			exit(1);
		}
	}

	/* Complain if any arguments remain */
	if (optind < argc)
	{
		pg_log_error("too many command-line arguments (first is \"%s\")",
					 argv[optind]);
		fprintf(stderr, _("Try \"%s --help\" for more information.\n"),
				progname);
		exit(1);
	}

	/* filenode checking only works in --check mode */
	if (mode != PG_MODE_CHECK && only_filenode)
	{
		pg_log_error("option -f/--filenode can only be used with --check");
		fprintf(stderr, _("Try \"%s --help\" for more information.\n"),
				progname);
		exit(1);
	}

	/* Read the control file and check compatibility */
	ControlFile = get_controlfile(DataDir, &crc_ok);
	if (!crc_ok)
	{
		pg_log_error("pg_control CRC value is incorrect");
		exit(1);
	}

	if (ControlFile->pg_control_version != PG_CONTROL_VERSION)
	{
		pg_log_error("cluster is not compatible with this version of pg_checksums");
		exit(1);
	}

	if (ControlFile->blcksz != BLCKSZ)
	{
		pg_log_error("database cluster is not compatible");
		fprintf(stderr, _("The database cluster was initialized with block size %u, but pg_checksums was compiled with block size %u.\n"),
				ControlFile->blcksz, BLCKSZ);
		exit(1);
	}

	/*
	 * Check if cluster is running.  A clean shutdown is required to avoid
	 * random checksum failures caused by torn pages.  Note that this doesn't
	 * guard against someone starting the cluster concurrently.
	 */
	if (ControlFile->state != DB_SHUTDOWNED &&
		ControlFile->state != DB_SHUTDOWNED_IN_RECOVERY)
	{
		pg_log_error("cluster must be shut down");
		exit(1);
	}

	if (ControlFile->data_checksum_version == 0 &&
		mode == PG_MODE_CHECK)
	{
		pg_log_error("data checksums are not enabled in cluster");
		exit(1);
	}

	if (ControlFile->data_checksum_version == 0 &&
		mode == PG_MODE_DISABLE)
	{
		pg_log_error("data checksums are already disabled in cluster");
		exit(1);
	}

	if (ControlFile->data_checksum_version > 0 &&
		mode == PG_MODE_ENABLE)
	{
		pg_log_error("data checksums are already enabled in cluster");
		exit(1);
	}

	/* Operate on all files if checking or enabling checksums */
	if (mode == PG_MODE_CHECK || mode == PG_MODE_ENABLE)
	{
		/*
		 * If progress status information is requested, we need to scan the
		 * directory tree twice: once to know how much total data needs to be
		 * processed and once to do the real work.
		 */
		if (showprogress)
		{
			total_size = scan_directory(DataDir, "global", true);
			total_size += scan_directory(DataDir, "base", true);
			total_size += scan_directory(DataDir, "pg_tblspc", true);
		}

		(void) scan_directory(DataDir, "global", false);
		(void) scan_directory(DataDir, "base", false);
		(void) scan_directory(DataDir, "pg_tblspc", false);

		if (showprogress)
		{
			progress_report(true);
			fprintf(stderr, "\n");	/* Need to move to next line */
		}

		printf(_("Checksum operation completed\n"));
		printf(_("Files scanned:  %s\n"), psprintf(INT64_FORMAT, files));
		printf(_("Blocks scanned: %s\n"), psprintf(INT64_FORMAT, blocks));
		if (mode == PG_MODE_CHECK)
		{
			printf(_("Bad checksums:  %s\n"), psprintf(INT64_FORMAT, badblocks));
			printf(_("Data checksum version: %d\n"), ControlFile->data_checksum_version);

			if (badblocks > 0)
				exit(1);
		}
	}

	/*
	 * Finally make the data durable on disk if enabling or disabling
	 * checksums.  Flush first the data directory for safety, and then update
	 * the control file to keep the switch consistent.
	 */
	if (mode == PG_MODE_ENABLE || mode == PG_MODE_DISABLE)
	{
		ControlFile->data_checksum_version =
			(mode == PG_MODE_ENABLE) ? PG_DATA_CHECKSUM_VERSION : 0;

		if (do_sync)
		{
			pg_log_info("syncing data directory");
			fsync_pgdata(DataDir, PG_VERSION_NUM);
		}

		pg_log_info("updating control file");
		update_controlfile(DataDir, ControlFile, do_sync);

		if (verbose)
			printf(_("Data checksum version: %d\n"), ControlFile->data_checksum_version);
		if (mode == PG_MODE_ENABLE)
			printf(_("Checksums enabled in cluster\n"));
		else
			printf(_("Checksums disabled in cluster\n"));
	}

	return 0;
}
