/* src/test/modules/test_undo_request_manager/test_undo_request_manager--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION test_undo_request_manager" to load this file. \quit

CREATE FUNCTION urm_simple_test(capacity pg_catalog.int4,
								requests pg_catalog.int8[])
    RETURNS pg_catalog.int8[] STRICT
	AS 'MODULE_PATHNAME' LANGUAGE C;
