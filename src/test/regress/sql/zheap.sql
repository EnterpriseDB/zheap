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

-- Should throw error - not supported feature
ALTER TABLE t1_heap  set (storage_engine='zheap');
ALTER TABLE t1_heap  reset (storage_engine);
ALTER TABLE t1_zheap  set (storage_engine='heap');
ALTER TABLE t1_zheap  reset (storage_engine);

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
insert into btree_zheap_tbl
  select g, g::text || '_' ||
            (select string_agg(md5(i::text), '_') from generate_series(1, 50) i)
			from generate_series(1, 100) g;
create index btree_zheap_idx on btree_zheap_tbl (id);

-- check the plan with index scan
explain (costs false) select * from btree_zheap_tbl where id=1;
select id from btree_zheap_tbl where id=1;

-- update a non-key column and delete a row
update btree_zheap_tbl set t='modified' where id=1;
select * from btree_zheap_tbl where id = 1;
delete from btree_zheap_tbl where id=2;
select * from btree_zheap_tbl where id = 2;

drop table btree_zheap_tbl;


--
--3. Test for aggregate nodes
--
CREATE TABLE aggtest_zheap
(
 a int,
 b int
) WITH (storage_engine = 'zheap');
INSERT INTO aggtest_zheap SELECT g,g FROM generate_series(1,1000) g;

SELECT sum(a) AS sum_198 FROM aggtest_zheap;
SELECT max(aggtest_zheap.a) AS max_3 FROM aggtest_zheap;
SELECT stddev_pop(b) FROM aggtest_zheap;
SELECT stddev_samp(b) FROM aggtest_zheap;
SELECT var_pop(b) FROM aggtest_zheap;
SELECT var_samp(b) FROM aggtest_zheap;
SELECT stddev_pop(b::numeric) FROM aggtest_zheap;
SELECT stddev_samp(b::numeric) FROM aggtest_zheap;
SELECT var_pop(b::numeric) FROM aggtest_zheap;
SELECT var_samp(b::numeric) FROM aggtest_zheap;

DROP TABLE aggtest_zheap;
set client_min_messages = notice;

--
--4. Test for PRIMARY KEY on zheap tables.
--
CREATE TABLE pkey_test_zheap
(
 a int PRIMARY KEY,
 b int
) WITH (storage_engine = 'zheap');

-- should run suucessfully.
INSERT INTO pkey_test_zheap VALUES (10, 30);

-- should error out, primary key doesn't allow NULL value.
INSERT INTO pkey_test_zheap(b) VALUES (30);

-- should error out, primary key doesn't allow duplicate value.
INSERT INTO pkey_test_zheap VALUES (10, 30);

SELECT * FROM pkey_test_zheap;

DROP TABLE pkey_test_zheap;

--
-- 5.1. Test of non-inlace-update where new update goes to new page.
--
CREATE TABLE update_test_zheap(c1 int,c2 char(1000),c3 varchar(10));
INSERT INTO update_test_zheap VALUES(generate_series(1,7), 'aaa', 'aaa');
UPDATE update_test_zheap SET c3 = 'bbbb' WHERE c1=1;

-- verify the update
SELECT c3 FROM update_test_zheap WHERE c1=1;
DROP TABLE update_test_zheap;

--
-- 5.2. Test of non-inlace-update on same page and for index key updates.
--
set enable_indexonlyscan to false;
set enable_bitmapscan to false;
CREATE TABLE update_test_zheap(c1 int PRIMARY KEY, c2 int);
INSERT INTO update_test_zheap VALUES(generate_series(1,7), 1);
UPDATE update_test_zheap SET c2 = 100 WHERE c1 = 1;
UPDATE update_test_zheap SET c2 = 101 WHERE c1 = 2;

-- verify the update
SELECT c2 FROM update_test_zheap WHERE c1 IN (1,2);
DROP TABLE update_test_zheap;

--
-- 6. Test for bitmap heap scan - taken from bitmapops.sql
--

CREATE TABLE bmscantest (a int, b int, t text) WITH (storage_engine='zheap');

INSERT INTO bmscantest
  SELECT (r%53), (r%59), 'foooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
  FROM generate_series(1,70000) r;

CREATE INDEX i_bmtest_a ON bmscantest(a);
CREATE INDEX i_bmtest_b ON bmscantest(b);

-- We want to use bitmapscans. With default settings, the planner currently
-- chooses a bitmap scan for the queries below anyway, but let's make sure.
set enable_indexscan=false;
set enable_seqscan=false;

-- Lower work_mem to trigger use of lossy bitmaps
set work_mem = 64;


-- Test bitmap-and.
SELECT count(*) FROM bmscantest WHERE a = 1 AND b = 1;

-- Test bitmap-or.
SELECT count(*) FROM bmscantest WHERE a = 1 OR b = 1;


-- clean up
DROP TABLE bmscantest;
