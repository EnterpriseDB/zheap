UNDO
====

* Travis, GCC, Ubuntu, runs `make check-world`: [![Build status](https://travis-ci.org/macdice/postgres.svg?branch=undo)](https://travis-ci.org/macdice/postgres)
* AppVeyor, MSVC, Windows, runs `make check`: [![Build status](https://ci.appveyor.com/api/projects/status/github/macdice/postgres?branch=undo&svg=true)](https://ci.appveyor.com/project/macdice/postgres)

Hello, this development branch is maintained by Thomas Munro, and aims for
inclusion in PostgreSQL 13 as part of the larger zHeap project.  It contains
the following:

* A way to put new kinds of data in the buffer pool.
* The undo log storage subsystem, accessed via the buffer pool. 
* The undo record API, allowing records to be stored and read back.
* The undo processing subsystem, allowing undo records to be executed during
  rollback (including after a crash).
* A patch to remove orphaned files using undo logs, so that PostgreSQL won't
  leak diskspace when it crashes before commiting, after creating (and filling
  up!) new tables.
* A module that allows undo logs to be inspected, for debugging/development
  purposes.

The orphaned file cleanup code is a simple way to demonstrate and test the undo
technology, while also solving a real problem that PostgreSQL suffers from.

The undo record API and processing layers are maintained by others at EDB, and I
periodically pull in new versions of those patches from other branches, and
feed fixups back to them.  The other code in this branch is maintained by me
and this is the primary development branch for it.

Later the [zHeap](https://github.com/EnterpriseDB/zheap/) project (led by
Amit Kapila with help from many others) and potentially other undo-aware table
access methods will use these facilities.  For now zHeap is using an older
version of the undo machinery; a big rebase is imminent.

A very quick tour
-----------------

A new system view allows us to see the undo logs that exist for the purpose
of storing undo records.  Initially there is one, but more might be created
as required to support concurrent activity with minimal contention.  We can
see it like so:

```
postgres=# select * from pg_stat_undo_logs;
 logno | category  | tablespace |     discard      |      insert      |       end        | xid | pid | status 
-------+-----------+------------+------------------+------------------+------------------+-----+-----+--------
     0 | permanent | pg_default | 0000000000003348 | 0000000000003348 | 0000000000100000 |     |     | ACTIVE
(1 row)
```

This tells us that there is no data currently (discard == insert).

To be able to see the contents of undo logs, first run
`make -C contrib/undoinspect install` so that you can install the
`undoinspect` extension:

```
postgres=# create extension undoinspect;
CREATE EXTENSION
```

Next, let's open a transaction and perform an action that creates an undo
record:

```
postgres=# begin;
BEGIN
postgres=# create table t1 ();
CREATE TABLE
```

We can see that our backend is now attached to the undo log by looking at the
`xid` and `pid` columns, and we can see that it contains some data (insert > discard):

```
postgres=# select * from pg_stat_undo_logs;
 logno | category  | tablespace |     discard      |      insert      |       end        | xid | pid  | status 
-------+-----------+------------+------------------+------------------+------------------+-----+------+--------
     0 | permanent | pg_default | 0000000000003348 | 0000000000003396 | 0000000000100000 | 490 | 2301 | ACTIVE
(1 row)
```

We can see that what it contains by using the `undoinspect()` function, which
defaults to showing the current backend's recently created undo records:

```
postgres=# select * from undoinspect();
     urecptr      |  rmgr   | flags | xid |                 description                 
------------------+---------+-------+-----+---------------------------------------------
 0000000000003348 | Storage | P,T   | 490 | CREATE dbid=12934, tsid=1663, relfile=24585
(1 row)
```

Still in the same transaction, we can create another undo record:

```
postgres=# create table t2 ();
CREATE TABLE
postgres=# select * from pg_stat_undo_logs;
 logno | category  | tablespace |     discard      |      insert      |       end        | xid | pid  | status 
-------+-----------+------------+------------------+------------------+------------------+-----+------+--------
     0 | permanent | pg_default | 0000000000003348 | 00000000000033C4 | 0000000000100000 | 490 | 2301 | ACTIVE
(1 row)

postgres=# select * from undoinspect();
     urecptr      |  rmgr   | flags | xid |                 description                 
------------------+---------+-------+-----+---------------------------------------------
 0000000000003396 | Storage | P     |     | CREATE dbid=12934, tsid=1663, relfile=24588
 0000000000003348 | Storage | P,T   | 490 | CREATE dbid=12934, tsid=1663, relfile=24585
(2 rows)
```

Finally, we can roll back the transaction.  The `CREATE` actions will be
undone, and the undo log will again be empty:

```
postgres=# abort;
ROLLBACK
postgres=# select * from pg_stat_undo_logs;
 logno | category  | tablespace |     discard      |      insert      |       end        | xid | pid  | status 
-------+-----------+------------+------------------+------------------+------------------+-----+------+--------
     0 | permanent | pg_default | 00000000000033C4 | 00000000000033C4 | 0000000000100000 | 490 | 2301 | ACTIVE
(1 row)

postgres=# select * from undoinspect();
 urecptr | rmgr | flags | xid | description 
---------+------+-------+-----+-------------
(0 rows)
```

Traditionally, PostgreSQL would remember to unlink new files on rollback using
an in-memory data-structure.  The difference here is that the information is
stored on disk, and will not be forgotten if we lose power, reboot, crash etc
and then restart.  Undo logs are stored using the same checkpointing and WAL
logging protocol as used for regular relation files, and here the WAL is
flushed before relation files are created so that the need to unlink on
rollback is durably stored before the file is even created.  Note that as in
traditional PostgreSQL, the actual `unlink` is still deferred until the next
checkpoint.

The contents of undo logs is stored in 1MB files that live under `base/undo`
by default:

```
$ ls -slap pgdata/base/undo/
total 2048
   0 drwx------  3 munro  staff       96 10 May 17:20 ./
   0 drwx------  6 munro  staff      192 10 May 17:20 ../
2048 -rw-------  1 munro  staff  1048576 11 May 15:25 000000.0000000000
```

These are named after the undo log address of their first byte.  If you create
a lot of undo data before committing or rolling back, you might finish up with
several of these files at the same time.  Using the orphaned file clean-up
patch, that is unlikely (you'd have to create a huge number of tables in one
transaction), but other users of the undo system are capable of creating
arbitrarily large amounts of data: for example, a transaction that updates
a lot of records using zHeap could produce large amounts of undo data.

Like relations, undo data can be stored in other tablespaces:

```
postgres=# create tablespace foo location '/tmp/foo';
CREATE TABLESPACE
postgres=# set undo_tablespaces = foo;
SET
postgres=# begin;
BEGIN
postgres=# create table blah ();
CREATE TABLE
postgres=# select * from pg_stat_undo_logs ;
 logno | category  | tablespace |     discard      |      insert      |       end        | xid | pid  | status 
-------+-----------+------------+------------------+------------------+------------------+-----+------+--------
     0 | permanent | pg_default | 00000000000033C4 | 00000000000033C4 | 0000000000100000 |     |      | ACTIVE
     1 | permanent | foo        | 0000010000000018 | 0000010000000066 | 0000010000100000 | 492 | 2301 | ACTIVE
(2 rows)
```

The backing files can be found inside the tablespace's directory:

```
$ ls -slap /tmp/foo/PG_12_201904281/undo/
total 2048
   0 drwx------  3 munro  wheel       96 11 May 17:22 ./
   0 drwx------  3 munro  wheel       96 11 May 17:22 ../
2048 -rw-------  1 munro  wheel  1048576 11 May 17:25 000001.0000000000
```

The tablespace can only be dropped after there is no live undo data in it.

Like relations, undo logs have a persistence level.  This isn't terribly
important for the orphaned file clean-up patch, but table AM implementation
like zHeap can arrange for the undo data relating to a given relation to be
stored in undo logs of the same persistence level.  This means it'll be
discarded at the same time (for unlogged tables, on crash restart; for
temporary tables, at startup and other times).

Undo page can be seen in the buffer cache using `pg_buffercache` extension,
which differentiates kinds of data using `smgrid` column.  0 is used for
regular relations, and 1 is used for undo data.

```
postgres=# create extension pg_buffercache;
CREATE EXTENSION
postgres=# select * from pg_buffercache where smgrid = 1;
 bufferid | smgrid | relfilenode | reltablespace | reldatabase | relforknumber | relblocknumber | isdirty | usagecount | pinning_backends 
----------+--------+-------------+---------------+-------------+---------------+----------------+---------+------------+------------------
        2 |      1 |           0 |          1663 |           0 |             0 |              1 | f       |          5 |                0
      277 |      1 |           1 |         24591 |           0 |             0 |              0 | f       |          5 |                0
(2 rows)
```

Background worker processes are used to 'discard' the undo data belonging to
committed transactions (that is, advance the discard pointer and potentially
recycle or unlink backing files when segment boundaries are crossed).  There
is much more to say about these processes, but their working are mostly
invisible to end users.

Undo records are executed when transactions roll back.  That is done either
by a backend that aborts directly, or by a background worker if the size of
undo work to be executed is greated than a GUC.

See the README files for more on all these topics.

Mailing list threads
--------------------

* [Orphaned file clean-up proposal](https://www.postgresql.org/message-id/flat/CAEepm%3D0ULqYgM2aFeOnrx6YrtBg3xUdxALoyCG%2BXpssKqmezug%40mail.gmail.com)
* The patch allowing more kinds of thinds in shared buffers is also posted
  [in a separate thread](https://www.postgresql.org/message-id/flat/CA%2BhUKG%2BOZqOiOuDm5tC5DyQZtJ3FH4%2BFSVMqtdC4P1atpJ%2Bqhg%40mail.gmail.com)
  because Shawn Debnath is proposing to use the same facility to put CLOG et al in shared buffers
