/* contrib/pageinspect/pageinspect--1.7--1.8.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pageinspect UPDATE TO '1.8'" to load this file. \quit

--
-- zheap functions
--

--
-- zheap_page_items()
--
CREATE FUNCTION zheap_page_items(IN page bytea,
    OUT lp smallint,
    OUT lp_off smallint,
    OUT lp_flags smallint,
    OUT lp_len smallint,
    OUT t_slot smallint,
    OUT t_infomask2 integer,
    OUT t_infomask integer,
    OUT t_hoff smallint,
    OUT t_bits text,
    OUT t_data bytea,
    OUT t_infomask_info text[])
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'zheap_page_items'
LANGUAGE C STRICT PARALLEL SAFE;

--
-- zheap_page_slots()
--
CREATE FUNCTION zheap_page_slots(IN page bytea,
    OUT slot_id smallint,
    OUT epoch int4,
    OUT xid int4,
    OUT undoptr int8)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'zheap_page_slots'
LANGUAGE C STRICT PARALLEL SAFE;
