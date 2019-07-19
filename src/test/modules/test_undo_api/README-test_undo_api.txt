There are two sql callable functions written in this test undo api.

1. SELECT test_undo_api();

This test will insert the data in the undo using undo api and after that
it will fetch the data and verify that whether we have got the same data
back or not.

2. SELECT test_undo_insert(persistence level, block number, offset number);

This function can be used to insert an undorecord inside a transaction.  The
persistence level can be 'UNDO_PERMANENT' or 'UNDO_TEMP'. Once the undorecord
gets inserted, the user will get a NOTICE like following:

NOTICE:  Insert undo record: block: .....

If the transaction gets committed, the undo record will be discarded by the discard
worker.  If the transaction is rolled back, its undo action will be applied
which is noting but a NOTICE of the rollback record.

NOTICE:  Rollback undo record: block: ...

Once the rollback actions are applied, the same can be discarded as well.

To start with some basic testing, We have added a few test cases in
src/test/modules/test_undo_api/sql/test_undo_api.sql.

Goals
------------

1. We would like to have some test cases for the scenario where a transaction
inserts undo records across multiple undo logs. The default size of an undolog
is 1TB which is large.  But, we can make it a compile-time configurable
parameter and set a much lower value, for example, 1MB to test this scenario.
Another option is to force a log switch from a sql callable function.

2. As of now, all the test cases are based on printing some notice message.  It
will be good to have some basic mechanism so that we can actually apply the undo
actions.  For example, we can maintain an in-memory array where we can insert
an element and insert an undorecord.  If the transaction rolls back, we have to
remove the entry from that array.  This will also help us testing multi-client
scenarios.

3. If we set rollback_overflow_size to 0 in postgresql.conf, the undo actions
are pushed in queues and are performed by the undo workers later.  There are
different scenarios that should be verified for undo workers:
a. There are three different types of priority queues, viz. xid queue, size
queue and error queue.  We've to verify whether each of the queue works as
expected.
b. For error queues, we can store some probability and timestamp in the undo
payload.  If undo actions for the same record is performed before the timestamp,
the respective rmgr function (which performs the undo action) throws an error
using the user provided probability.
c. Use a large number of database with skewed rollback percentage.  The undo
launcher scheduling algorithm should be fair to each of the database.
d. Multiple extreme cases, for example, when the rollback hash table is full,
any of the queue is full.

4. We also need some tap-tests that will cover the recovery testing. Specially,
when the system restarts while performing a rollback.  We need to verify whether
the rollback gets completed after rollback.  Also, we need to check the progress
of a large rollback request as the system restarts multiple times in between.
