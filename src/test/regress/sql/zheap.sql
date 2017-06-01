--
-- Test cases for ZHeap
--

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
