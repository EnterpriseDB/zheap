CREATE TABLE test_zheap (a int, b int) USING zheap;
INSERT INTO test_zheap VALUES (16777217, 131584);

-- The page contents can vary, so just test that it can be read
-- successfully, but don't keep the output.

SELECT pagesize, version FROM page_header(get_raw_page('test_zheap', 1));

SELECT page_checksum(get_raw_page('test_zheap', 1), 1) IS NOT NULL AS silly_checksum_test;

DROP TABLE test_zheap;

-- check that using any of these functions with a partitioned table would fail
create table test_partitioned (a int) partition by range (a);
select get_raw_page('test_partitioned', 1); -- error about partitioned table

-- a regular table which is a member of a partition set should work though
create table test_part1 partition of test_partitioned for values from ( 1 ) to (100) USING zheap;
select get_raw_page('test_part1', 1); -- get farther and error about empty table
drop table test_partitioned;

-- The tuple contents can vary, so we perform some basic testing of zheap_page_items.
-- We perform all the tuple modifications in a single transaction so that t_slot
-- doesn't change if we change trancsation slots in page during compile time.
-- Because of the same reason, we cannot check for all possibile output for
-- t_infomask_info (for example: slot-reused, multilock, l-nokey-ex etc).
create table test_zheap (a int, b text) USING zheap WITH (autovacuum_enabled=false);
begin;
insert into test_zheap (a) select generate_series(1,6);
update test_zheap set a=10 where a=2;
update test_zheap set b='abcd' where a=3;
delete from test_zheap where a=4;
select * from test_zheap where a=5 for share;
select * from test_zheap where a=6 for update;
commit;
select  lp,lp_flags,t_slot,t_infomask2,t_infomask,t_hoff,t_bits,
		t_infomask_info from zheap_page_items(get_raw_page('test_zheap', 1));
drop table test_zheap;
