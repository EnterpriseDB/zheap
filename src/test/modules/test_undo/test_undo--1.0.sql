\echo Use "CREATE EXTENSION test_undo" to load this file. \quit

CREATE FUNCTION undo_allocate(size int, persistence text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_advance(ptr text, size int, persistence text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_append(bytes bytea, persistence text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_append_transaction_header(xid xid, persistence text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_append_file(path text, persistence text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_extract_file(path text, undo_ptr text, size int, persistence text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_dump(undo_ptr text, size int, persistence text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_discard(undo_ptr text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_is_discarded(undo_ptr text)
RETURNS boolean
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_foreground_discard_test(loops int, size int, persistence text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION undo_detach_full()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;


