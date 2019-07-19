\echo Use "CREATE EXTENSION test_undo_api" to load this file. \quit

CREATE FUNCTION test_undo_api()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION test_undo_insert(persistence text, block_num int, off_num int)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;
