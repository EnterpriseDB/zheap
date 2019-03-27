The purpose of this document is to let users know how they can use zheap (a new
storage format for PostgreSQL) and the work that is still pending.  This new
storage format provides a better control over bloat, reduces the tuple size
and reduces the write amplification. The detail design of zheap is present in
zheap design document (src/backend/access/zheap/README).

How do I use zheap?
===================

We have provided a storage engine option which you can set when creating a table.
For example:

create table t_zheap(c1 int, c2 varchar) USING zheap;

Index creation for zheap tables doesn't need any special syntax.

You can also set the GUC parameter default_table_access_method.  The
default value is “heap", but you can set it to “zheap”.  If you do,
all subsequently-created tables will use zheap.

These interfaces will probably change once the storage format API work is
integrated into PostgreSQL.  We’ll adjust this code to use whatever interfaces
are agreed by the PostgreSQL community.

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
- Alter Table <table_name> Set Tablesapce <tbs_name> - For this feature to work
correctly in zheap, while copying pages, we need to ensure that pending aborts
gets applied before copying the page.

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
- Single user mode: This needs some investigation as to what exactly is required.
I think we need to ensure that undo gets applied without the need to invoke undo
worker.

The other pending code related items are tracked on zheap wiki page:
https://wiki.postgresql.org/wiki/Zheap

Test run before pushing code
============================
- make check-world
- make installcheck and isolation test (with default_table_access_method = 'zheap')
- make installcheck with hot standby (with wal_consistency_checking=all)

You can find overall design of zheap in the README: src/backend/access/zheap/README
