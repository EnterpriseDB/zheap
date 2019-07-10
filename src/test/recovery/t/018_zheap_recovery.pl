# Tests to verify replication and recovery in zheap
# Tests added are to verify tpdxlog.c,zheapamxlog.c,undoactionxlog.c,undoworker.c and undorequest.c
use strict;
use warnings;
use PostgresNode;
use TestLib;
use Test::More tests => 17;

# Initialize master node, doing archives
my $node_master = get_new_node('master');
$node_master->init(has_archiving => 1, allows_streaming => 1);

#append zheap related params
#modify rollback_overflow_size so that the tasks are pushed to undo workers
$node_master->append_conf('postgresql.conf', "wal_level = hot_standby \n");
$node_master->append_conf('postgresql.conf', "default_table_access_method = 'zheap'\n");
$node_master->append_conf('postgresql.conf', "rollback_overflow_size = 0\n");

# Start master
$node_master->start;

sub pgbench
{
	local $Test::Builder::Level = $Test::Builder::Level + 1;

	my ($opts, $stat, $out, $err, $name, $files, @args) = @_;
	my @cmd = ('pgbench', split /\s+/, $opts);
	my @filenames = ();
	if (defined $files)
	{
		for my $fn (sort keys %$files)
		{
			my $filename = $node_master->basedir . '/' . $fn;
			push @cmd, '-f', $filename;

			# cleanup file weight
			$filename =~ s/\@\d+$//;

			#push @filenames, $filename;
			# filenames are expected to be unique on a test
			if (-e $filename)
			{
				ok(0, "$filename must not already exists");
				unlink $filename or die "cannot unlink $filename: $!";
			}
			append_to_file($filename, $$files{$fn});
		}
	}

	push @cmd, @args;

	$node_master->command_checks_all(\@cmd, $stat, $out, $err, $name);

	# cleanup?
	#unlink @filenames or die "cannot unlink files (@filenames): $!";

	return;
}

# Take backup from which all operations will be run
$node_master->backup('my_backup');

# Initialize standby node from backup, fetching WAL from archives
my $node_standby = get_new_node('standby');
$node_standby->init_from_backup($node_master, 'my_backup',has_streaming => 1);
$node_standby->append_conf('postgresql.conf',"wal_retrieve_retry_interval = '100ms'");

#start standby
$node_standby->start;

# create history table,to log data.
$node_master->safe_psql('postgres','CREATE  TABLE pgbench_history (tid integer,bid integer,aid integer,delta integer,mtime timestamp without time zone,filler character(22))');

#Create data
pgbench (
	'-i -s 10 --foreign-keys',
	0,
	[qr{^$}i],
	[
		qr{dropping old tables},
		qr{creating tables},
		qr{vacuuming},
		qr{creating primary keys},
		qr{done\.}
	],
	'pgbench scale 10 initialization');

#Check that only READ-only queries can run on standbys
is($node_standby->psql('postgres', "INSERT INTO pgbench_accounts VALUES (1001,1001,1001,'aa');"),
	3, 'read-only queries on standby');

#start transactions on master,so that the WAL replay happens on standby
pgbench(
	"-M prepared -c8 -j8 -T 20 ",
	0,
	[
			qr{type: multiple scripts},
			qr{mode: prepared},
			qr{script 1: .*/custom_script_zheap_1},
			qr{weight: 5},
			qr{script 2: .*/custom_script_zheap_2},
			qr{weight: 5}
	],
	[qr{starting vacuum...end.}],
	'zheap pgbench custom scripts',
	{
		'custom_script_zheap_1@1' => q{-- custom_script
		\set aid random(1, 1000000)
		\set bid random(1, 10)
		\set tid random(1, 100)
		\set delta random(1, 5000)
		BEGIN;
		UPDATE pgbench_accounts SET abalance = abalance + :delta WHERE aid = :aid;
		SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
		UPDATE pgbench_tellers SET tbalance = tbalance + :delta WHERE tid = :tid;
		UPDATE pgbench_branches SET bbalance = bbalance + :delta WHERE bid = :bid;
		INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (:tid, :bid, :aid, :delta, CURRENT_TIMESTAMP);
		END;
},
		'custom_script_zheap_2@5' => q{-- custom_script_rb
		\set aid random(1, 1000000)
		\set bid random(1, 10)
		\set tid random(1, 100)
		\set delta random(1, 5000)
		BEGIN;
		UPDATE pgbench_accounts SET abalance = abalance + :delta WHERE aid = :aid;
		SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
		UPDATE pgbench_tellers SET tbalance = tbalance + :delta WHERE tid = :tid;
		UPDATE pgbench_branches SET bbalance = bbalance + :delta WHERE bid = :bid;
		rollback;
}
	});

#restart master,this will apply undoactions
$node_master->stop('immediate');
$node_master->start;


#check data on standby
my $result =$node_standby->safe_psql('postgres', "SELECT count(*) FROM pgbench_accounts");
 print "standby: $result\n";
is($result, qq(1000000), 'check streamed content on standby');

$node_master->stop;
$node_standby->stop;
done_testing();
