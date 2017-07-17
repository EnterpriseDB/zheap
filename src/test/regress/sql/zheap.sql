--
-- Test cases for ZHeap
--
set client_min_messages = warning;
--
-- 1. Test for storage engine
--

-- Normal heap
CREATE TABLE t1_heap
(
 a int
);
\d+ t1_heap;

-- Zheap heap
CREATE TABLE t1_zheap
(
 a int
) WITH (storage_engine = 'zheap');
\d+ t1_zheap;

-- Should throw error
CREATE TABLE t1_invalid
(
 a int
) WITH (storage_engine = 'invalid');

DROP TABLE t1_heap;
DROP TABLE t1_zheap;

--
-- 2. Test for Index Scan on zheap
--
set enable_seqscan to false;
set enable_indexonlyscan to false;
set enable_indexscan to true;
set enable_bitmapscan to false;

create table btree_zheap_tbl(id int4, t text) WITH (storage_engine='zheap', autovacuum_enabled=false);
create index btree_zheap_idx on btree_zheap_tbl (id);
insert into btree_zheap_tbl
  select g, g::text || '_' ||
            (select string_agg(md5(i::text), '_') from generate_series(1, 50) i)
			from generate_series(1, 100) g;

-- check the plan with index scan
explain (costs false) select * from btree_zheap_tbl where id=1;
select id from btree_zheap_tbl where id=1;

-- update a non-key column and delete a row
update btree_zheap_tbl set t='modified' where id=1;
select * from btree_zheap_tbl where id = 1;
delete from btree_zheap_tbl where id=2;
select * from btree_zheap_tbl where id = 2;

-- index creation on non-empty zheap relation. SHOULD FAIL!!
create index btree_zheap_idx1 on btree_zheap_tbl (id, t);
drop table btree_zheap_tbl;

set client_min_messages = notice;
