CREATE EXTENSION pageinspect;

CREATE TABLE test_rel_forks (a int) USING heap;
-- Make sure there are enough blocks in the heap for the FSM to be created.
INSERT INTO test_rel_forks SELECT i from generate_series(1,2000) i;

-- set up FSM and VM
VACUUM test_rel_forks;

-- The page contents can vary, so just test that it can be read
-- successfully, but don't keep the output.

SELECT octet_length(get_raw_page('test_rel_forks', 'main', 0)) AS main_0;
SELECT octet_length(get_raw_page('test_rel_forks', 'main', 100)) AS main_100;

SELECT octet_length(get_raw_page('test_rel_forks', 'fsm', 0)) AS fsm_0;
SELECT octet_length(get_raw_page('test_rel_forks', 'fsm', 20)) AS fsm_20;

SELECT octet_length(get_raw_page('test_rel_forks', 'vm', 0)) AS vm_0;
SELECT octet_length(get_raw_page('test_rel_forks', 'vm', 1)) AS vm_1;

SELECT octet_length(get_raw_page('xxx', 'main', 0));
SELECT octet_length(get_raw_page('test_rel_forks', 'xxx', 0));

EXPLAIN (costs off, analyze on, timing off, summary off) SELECT * FROM
        fsm_page_contents(get_raw_page('test_rel_forks', 'fsm', 0));

SELECT get_raw_page('test_rel_forks', 0) = get_raw_page('test_rel_forks', 'main', 0);

DROP TABLE test_rel_forks;

CREATE TABLE test1 (a int, b int);
INSERT INTO test1 VALUES (16777217, 131584);

SELECT pagesize, version FROM page_header(get_raw_page('test1', 0));

SELECT page_checksum(get_raw_page('test1', 0), 0) IS NOT NULL AS silly_checksum_test;

SELECT tuple_data_split('test1'::regclass, t_data, t_infomask, t_infomask2, t_bits)
    FROM heap_page_items(get_raw_page('test1', 0));

DROP TABLE test1;

-- check that using any of these functions with a partitioned table or index
-- would fail
create table test_partitioned (a int) partition by range (a);
create index test_partitioned_index on test_partitioned (a);
select get_raw_page('test_partitioned', 0); -- error about partitioned table
select get_raw_page('test_partitioned_index', 0); -- error about partitioned index

-- a regular table which is a member of a partition set should work though
create table test_part1 partition of test_partitioned for values from ( 1 ) to (100);
select get_raw_page('test_part1', 0); -- get farther and error about empty table
drop table test_partitioned;

-- check null bitmap alignment for table whose number of attributes is multiple of 8
create table test8 (f1 int, f2 int, f3 int, f4 int, f5 int, f6 int, f7 int, f8 int);
insert into test8(f1, f8) values (x'7f00007f'::int, 0);
select t_bits, t_data from heap_page_items(get_raw_page('test8', 0));
select tuple_data_split('test8'::regclass, t_data, t_infomask, t_infomask2, t_bits)
    from heap_page_items(get_raw_page('test8', 0));
drop table test8;
