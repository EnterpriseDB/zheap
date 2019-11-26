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
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 1);

-- implicit xact: single undo generating  statement, statement fails
-- FIXME: this shows a WARNING indicating a bug
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 1) IS NOT NULL THEN raise_error() END;

-- explicit xact: single undo generating statement, statement succeeds, followed by COMMIT
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 3);
COMMIT;

-- explicit xact: single undo generating statement, statement succeeds, followed by ROLLBACK
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 4);
ROLLBACK;

-- explicit xact: single undo generating statement, statement fails, followed by COMMIT
BEGIN;
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 5) IS NOT NULL THEN raise_error() END;
COMMIT;

-- explicit xact: single undo generating statement, statement fails, followed by ROLLBACK
BEGIN;
SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 6) IS NOT NULL THEN raise_error() END;
COMMIT;


-- implicit xact: two undo generating statements, both succeed
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 7)\;SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 8);

-- implicit xact: two undo generating statements, both succeed, followed by erroring statement
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 9)\;SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 10);SELECT raise_error();

-- implicit xact: two undo generating statements, first succeeds, second fails
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 11)\;SELECT CASE WHEN undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 12) IS NOT NULL THEN raise_error() END;


-- explicit xact: two undo generating statements, both succeed, followed by COMMIT
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 13);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 14);
COMMIT;

-- explicit xact: two undo generating statements, both succeed, followed by ROLLBACK
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 13);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 14);
ROLLBACK;

-- explicit xact: two undo generating statements, both succeed, followed by errror, followed by COMMIT
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 15);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 16);
SELECT raise_error();
COMMIT;

-- explicit xact: two undo generating statements, both succeed, followed by errror, followed by ROLLBACK
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 17);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 18);
SELECT raise_error();
ROLLBACK;


-- explicit xact: undo, savepoint, undo, rollback to savepoint, undo; commit;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 19);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 20);
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 21);
COMMIT;

-- explicit xact: undo, savepoint, undo, rollback to savepoint, undo; rollback;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 22);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 23);
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 24);
ROLLBACK;

-- explicit xact: undo, savepoint, undo, error, rollback to savepoint, undo; commit;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 25);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 26);
SELECT raise_error();
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 27);
COMMIT;

-- explicit xact: undo, savepoint, undo, error, rollback to savepoint, undo; rollback;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 25);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 26);
SELECT raise_error();
ROLLBACK TO SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 27);
ROLLBACK;

-- explicit xact: undo, savepoint, undo, commit;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 29);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 29);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 30);
ROLLBACK;

-- explicit xact: undo, savepoint, undo, rollback;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 31);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 32);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 33);
ROLLBACK;

-- explicit xact: undo, savepoint, undo, rollback;
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 31);
SAVEPOINT foo;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 32);
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 33);
ROLLBACK;

-- implicit xact: create a fair bit of undo
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, g.i) FROM generate_series(1, 1000) g(i);

-- explicit xact: create a fair bit of undo, rollback
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, g.i) FROM generate_series(1, 1000) g(i);
ROLLBACK;

-- explicit xact: undo record set spanning logs, ROLLBACK
-- FIXME: test with commit, once hack below not needed
-- FIXME: this currently crashes
BEGIN;
SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 35);

SELECT pg_force_truncate_undo_log(logno::int) FROM pg_stat_get_undo_logs() WHERE pid = pg_backend_pid();

SELECT undoxacttest_fetch_and_inc('undoxacttest_perm'::regclass, 36);
ROLLBACK;

DROP TABLE undoxacttest_perm;
