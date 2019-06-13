\echo Use "CREATE EXTENSION test_undo_api" to load this file. \quit

CREATE FUNCTION test_undo_api(persistence text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;
