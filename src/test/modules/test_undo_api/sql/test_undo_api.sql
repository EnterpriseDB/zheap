CREATE EXTENSION test_undo_api;

--
-- This test will insert the data in the undo using undo api and after that
-- it will fetch the data and verify that whether we have got the same data
-- back or not.
--
SELECT test_undo_api('permanent');
