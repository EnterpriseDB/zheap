-- Notes:
--
-- - Obviously needs to show that UNDO is correctly being executed
-- - where applicable.
--
-- - it'd probably better to not use increasing numbers like I did
--   here, makes it harder to add new tests, and causes cascading
--   failures
--
-- - It'd be nice to find a way to test background undo
--

-- initialize
DROP TABLE IF EXISTS undoxacttest_perm;
CREATE TABLE undoxacttest_perm(data bytea not null);
ALTER TABLE undoxacttest_perm ALTER COLUMN data SET STORAGE plain;
SELECT undoxacttest_init_rel('undoxacttest_perm'::regclass);

-- want to show all undo in foreground, for testability
SET undo_force_foreground = true;

-- helper functions

CREATE OR REPLACE FUNCTION raise_error() RETURNS void VOLATILE LANGUAGE plpgsql AS
$p$
BEGIN
    RAISE 'you wanted me to fail';
END
$p$;

-- implicit xact: single undo generating statement, statement succeeds
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 1);
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- implicit xact: single undo generating  statement, statement fails
-- FIXME: this shows a WARNING indicating a bug
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 1) IS NOT NULL THEN raise_error() END;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: single undo generating statement, statement succeeds, followed by COMMIT
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 3);
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: single undo generating statement, statement succeeds, followed by ROLLBACK
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 4);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: single undo generating statement, statement fails, followed by COMMIT
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 5) IS NOT NULL THEN raise_error() END;
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: single undo generating statement, statement fails, followed by ROLLBACK
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 6) IS NOT NULL THEN raise_error() END;
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);


-- implicit xact: two undo generating statements, both succeed
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 7)\;SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 8);
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- implicit xact: two undo generating statements, both succeed, followed by erroring statement
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 9)\;SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 10);SELECT raise_error();
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- implicit xact: two undo generating statements, first succeeds, second fails
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 11)\;SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 12) IS NOT NULL THEN raise_error() END;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);


-- explicit xact: two undo generating statements, both succeed, followed by COMMIT
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 13);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 14);
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: two undo generating statements, both succeed, followed by ROLLBACK
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 13);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 14);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: two undo generating statements, both succeed, followed by errror, followed by COMMIT
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 15);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 16);
SELECT raise_error();
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: two undo generating statements, both succeed, followed by errror, followed by ROLLBACK
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 17);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 18);
SELECT raise_error();
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);


-- explicit xact: undo, savepoint, undo, rollback to savepoint, undo; commit;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 19);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 20);
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 21);
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, rollback to savepoint, undo; rollback;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 22);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 23);
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 24);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, error, rollback to savepoint, undo; commit;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 25);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 26);
SELECT raise_error();
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 27);
COMMIT;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, error, rollback to savepoint, undo; rollback;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 25);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 26);
SELECT raise_error();
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 27);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, commit;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 29);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 29);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 30);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, rollback;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 31);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 32);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 33);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo, savepoint, undo, rollback;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 31);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 32);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 33);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- implicit xact: create a fair bit of undo
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, g.i) FROM generate_series(1, 1000) g(i);
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: create a fair bit of undo, rollback
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, g.i) FROM generate_series(1, 1000) g(i);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

-- explicit xact: undo record set spanning logs, ROLLBACK
-- FIXME: test with commit, once hack below not needed
-- FIXME: this currently crashes
SELECT undoxacttest_read('undoxacttest_perm'::regclass);
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 35);

SELECT pg_force_truncate_undo_log(logno::int) FROM pg_stat_get_undo_logs() WHERE pid = pg_backend_pid();

SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 36);
ROLLBACK;
SELECT undoxacttest_read('undoxacttest_perm'::regclass);

DROP TABLE undoxacttest_perm;

-- a quick smoke test of a temporary undo log
DROP TABLE IF EXISTS undoxacttest_temp;
CREATE TEMPORARY TABLE undoxacttest_temp(data bytea not null);
ALTER TABLE undoxacttest_temp ALTER COLUMN data SET STORAGE plain;
SELECT undoxacttest_init_rel('undoxacttest_temp'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_temp'::regclass, 1);
DROP TABLE undoxacttest_temp;

-- a quick smoke test of an unlogged undo log
DROP TABLE IF EXISTS undoxacttest_unlogged;
CREATE UNLOGGED TABLE undoxacttest_unlogged(data bytea not null);
ALTER TABLE undoxacttest_unlogged ALTER COLUMN data SET STORAGE plain;
SELECT undoxacttest_init_rel('undoxacttest_unlogged'::regclass);
SELECT undoxacttest_fetch_and_inc('undoxacttest_unlogged'::regclass, 1);
DROP TABLE undoxacttest_unlogged;
