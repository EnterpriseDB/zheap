# Scenarios that test sanity of zheap_get_latest_tid() function

setup
{
  CREATE TABLE tidscan (a int PRIMARY KEY, v varchar);
  INSERT INTO tidscan VALUES (1, NULL);
}

teardown
{
  DROP TABLE tidscan;
}

session "s1"
setup		{ BEGIN; }
step "s1u"	{ UPDATE tidscan SET a = a + 1; }
step "s1c"	{ COMMIT; }

session "s2"
setup		{ BEGIN; }
step "s2f"	{ DECLARE c CURSOR FOR SELECT a FROM tidscan; FETCH FIRST FROM c; }
step "s2u"	{ UPDATE tidscan SET a = a + 2, v = 'session2' WHERE CURRENT  OF c; }
step "s2c"	{ COMMIT; }
step "s2s"	{ SELECT * from tidscan ORDER BY a; }

permutation "s1u" "s2f" "s2u" "s1c" "s2c" "s2s"
