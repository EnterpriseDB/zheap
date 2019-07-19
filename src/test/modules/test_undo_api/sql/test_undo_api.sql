CREATE EXTENSION test_undo_api;

--
-- This test will insert the data in the undo using undo api and after that
-- it will fetch the data and verify that whether we have got the same data
-- back or not.
--
SELECT test_undo_api();

--
-- These tests are for testing different scenarios w.r.t transactions.
--

-- Normal transactions
-- Undo records are sorted by rmgr id, database id, block and offset before
-- performing rollbacks.
BEGIN;
SELECT test_undo_insert('UNDO_PERMANENT',2,2);
SELECT test_undo_insert('UNDO_PERMANENT',2,1);
SELECT test_undo_insert('UNDO_PERMANENT',1,2);
SELECT test_undo_insert('UNDO_PERMANENT',1,1);
ROLLBACK;

BEGIN;
SELECT test_undo_insert('UNDO_TEMP',1,1);
SELECT test_undo_insert('UNDO_TEMP',1,2);
ROLLBACK;

-- Sub-transactions --
BEGIN;
SELECT test_undo_insert('UNDO_PERMANENT',1,1);
SAVEPOINT a;
SELECT test_undo_insert('UNDO_PERMANENT',1,2);
ROLLBACK to a;
SELECT test_undo_insert('UNDO_PERMANENT',1,3);
ROLLBACK;

BEGIN;
SELECT test_undo_insert('UNDO_TEMP',1,1);
SAVEPOINT a;
SELECT test_undo_insert('UNDO_TEMP',1,2);
ROLLBACK to a;
SELECT test_undo_insert('UNDO_TEMP',1,3);
ROLLBACK;

-- Error inside transactions --
BEGIN;
SELECT test_undo_insert('UNDO_PERMANENT',1,1);
SELECT 1/0;
ROLLBACK;
