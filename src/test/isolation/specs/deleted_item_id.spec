#Test case to verify concurrently deleted itemId for update

setup
{
	CREATE TABLE a (i int);
	INSERT INTO a VALUES (1), (2);
}

teardown
{
	DROP TABLE a;
}

session "s1"
setup       { BEGIN; }
step "w1"   { UPDATE a SET i = 5 WHERE i = 1; }
step "c1"   { COMMIT; }

session "s2"
setup       { BEGIN; }
step "w2"   { UPDATE a SET i = 5 WHERE i >= 1; }
step "c2"   { COMMIT; }

session "s3"
step "t3"   { DELETE FROM a WHERE i = 2; }
step "v3"   { VACUUM; }

permutation "w1" "w2" "t3" "v3" "c1" "c2"
