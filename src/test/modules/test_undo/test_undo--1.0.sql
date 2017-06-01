\echo Use "CREATE EXTENSION test_undo" to load this file. \quit

CREATE FUNCTION undo_allocate(size int)
RETURNS bigint
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_advance(ptr bigint, size int)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_append(bytes bytea)
RETURNS bigint
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_read(undo_ptr bigint, size int)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_discard(undo_ptr bigint)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;


