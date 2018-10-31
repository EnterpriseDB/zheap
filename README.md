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
page, but this can be changed by setting --with-trans_slots_per_zheap_page=value
while configuring zheap.

What doesn’t work yet?
======================

- Logical decoding
- Snapshot too old - We might want to implement this after first version is
committed as this will work differently for zheap.

Tools
- pg_undo_dump similar to pg_wal_dump:  We would like to develop this utility
as it can be used to view undo record contents and can help us debug problems
related to undo chains.
- We also want to develop tools like pgstattuple, pgrowlocks that
allow us to inspect the contents of database pages at a low level.
- wal consistency checker: This will be used to check for bugs in the WAL redo
routines.  Currently, it is quite similar to what we have in current heap, but
we want to extend it to check the consistency of undo pages similar to how it
checks for data and index pages.

Open Issues
===========
- Currently, the TPD pages are not added to FSM even if they can be completely
reused.

The other pending code related items are tracked on zheap wiki page:
https://wiki.postgresql.org/wiki/Zheap

You can find overall design of zheap in the README: src/backend/access/zheap/README
