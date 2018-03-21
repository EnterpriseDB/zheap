The purpose of this document is to let users know how they can use zheap (a new
storage format for PostgreSQL) and the work that is still pending.  This new
storage format provides a better control over bloat, reduces the tuple size
and reduces the write amplification. The detail design of zheap is present in
zheap design document (src/backend/access/zheap/README).

How do I use zheap?
===================

We have provided a storage engine option which you can set when creating a table.
For example:

create table t_zheap(c1 int, c2 varchar) with (storage_engine='zheap');

Index creation for zheap tables doesn't need any special syntax.

You can also set the GUC parameter storage_engine.  The default value is
“heap", but you can set it to “zheap”.  If you do, all subsequently-created
tables will use zheap.

These interfaces will probably change once the storage format API work is
integrated into PostgreSQL.  We’ll adjust this code to use whatever interfaces
are agreed by the PostgreSQL community.

We have also provided a GUC called data_alignment, which sets the alignment
used for zheap tuples. 0 indicates no alignment, 4 uses a maximum of 4 byte
alignment, and any other value indicates align as per attalign.  This also
controls the padding between tuples. This parameter is just for some
experiments to see the impact of alignment on database size.  This parameter
will be removed later; we’ll align as described in the zheap design document.

Each zheap page has fixed set of transaction slots each of which contains the
transaction information (transaction id and epoch) and the latest undo record
pointer for that transaction.  By default, we have four transaction slots per
page, but this can be changed by setting --with-trans_slots_per_zheap_page=<value>
while configuring zheap.

What doesn’t work yet?
======================

Quite a bit.  Currently unsupported features include:

- Temporary and unlogged tables
- Logical decoding
- Serializable isolation
- CLUSTER
- VACUUM FULL
- TID scans
- Index-only scans
- Insert .. On Conflict
- Toast tables:  We would like to store toast table data in zheap, but this is
currently work in progress.  Currently, usage of toast tables will get error
that this feature is not supported.
- Tuple locking: This work is in progress.  Currently, Select .. For Update
works.  There is a partial implementation of Select .. For Share where only
one locker is allowed.  Any further usage of locking modes will result in an
error.
- Foreign keys: This work is dependent on tuple locking (Key Share Locks).
Currently, it will return Error.
- Vacuum/Autovacuum: We think that for delete-marked indexes we might not need
vacuum, but we still need it for indexes that doesn't support delete-marking.
Here, the idea is that by using undo technology we can change
three-pass-vacuum to two-pass-vacuum.  Currently any attempt to vacuum zheap
will return error.
- Insert .. On Conflict: The design is similar to current heap such that we
use the speculative token to detect conflicts and then take the action as
defined in command.  The implementation difference is that we store the
speculative token in undo instead of in the tuple header (CTID). This work is
in progress.  Currently we return Error if user tries to use this feature.
- Rollback prepared transactions: The main work required for this feature is
to store ‘from and to’ undo record locations to perform rollbacks.  The work
for this is in progress.  We have not blocked it, so the result will
unpredictable.

Tools
- pg_undo_dump similar to pg_wal_dump:  We would like to develop this utility
as it can be used to view undo record contents and can help us debug problems
related to undo chains.
- We also want to develop tools like pageinspect, pgstattuple, pgrowlocks that
allow us to inspect the contents of database pages at a low level.
- wal consistency checker: We would like to develop it for zheap.  This will
be used to check for bugs in the WAL redo routines.  This will be quite
similar to what we have in current heap, but we want to extend it to check the
consistency of undo pages similar to how it checks for data and index pages.

Open Issues
===========
- The work for Rollbacks is in progress and following features are not working
   - Rollback for a transaction that contains combination of DDL and DML
statements.
   - Rollback for concurrent DML operations.  For example, an Update is waiting
for other transaction to commit or rollback, now if the other transaction
rolled back, then the behavior is undefined.
- For extremely large transactions, we might fail while getting the tuple from
undo.  These are the cases where the size of a particular undo log exceeds 1TB.
- Undo logs are not yet crash-safe. Fsync and some recovery details are yet to
be implemented.

The other pending code related items are tracked on zheap wiki page:
https://wiki.postgresql.org/wiki/Zheap

You can find overall design of zheap in the README: src/backend/access/zheap/README
