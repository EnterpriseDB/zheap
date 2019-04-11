CREATE FUNCTION test_undo_insert(tsid pg_catalog.int4,
		fork pg_catalog.int4, block pg_catalog.int4,
		payload pg_catalog.bytea, tuple pg_catalog.bytea,
		soffset pg_catalog.int4)
    RETURNS pg_catalog.bytea
	AS 'MODULE_PATHNAME' LANGUAGE C;
