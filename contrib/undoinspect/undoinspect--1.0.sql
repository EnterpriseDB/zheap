/* contrib/undoinspect/undoinspect--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION undoinspect" to load this file. \quit

--
-- The basic undoinspect function, that requires you to say which undo
-- log to look at and how much data to load.
--
CREATE FUNCTION undoinspect(
    IN i_logno oid,
    IN i_size int,
    OUT urecptr text,
    OUT rmgr text,
    OUT flags text,
    OUT xid xid,
    OUT description text)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'undoinspect'
LANGUAGE C STRICT PARALLEL SAFE;

--
-- A slightly more user-friendly wrapper to show the records for this
-- backend, defaulting to permanent records if you don't ask for a
-- different category.
--
CREATE FUNCTION undoinspect(
    IN i_category text DEFAULT 'permanent',
    IN i_size int DEFAULT 65535,
    OUT urecptr text,
    OUT rmgr text,
    OUT flags text,
    OUT xid xid,
    OUT description text)
RETURNS SETOF record AS
$$
SELECT *
  FROM undoinspect((SELECT logno
                      FROM pg_stat_undo_logs
                     WHERE pid = pg_backend_pid()
                       AND substr(category, 1, 1) = substr($1, 1, 1)), $2);
$$
LANGUAGE SQL STRICT STABLE PARALLEL SAFE;
