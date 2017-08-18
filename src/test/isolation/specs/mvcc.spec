# Simple tests that show the behavior of snapshots working correctly.

setup
{
 CREATE TABLE animals (name text, counter int) WITH (storage_engine = 'zheap');
 INSERT INTO animals VALUES ('cat', 1), ('dog', 1), ('monkey', 1);
}

teardown
{
 DROP TABLE animals;
}

session "s1"
setup		{ BEGIN ISOLATION LEVEL REPEATABLE READ; }
step "r1"	{ SELECT * FROM animals; }
step "c1"	{ COMMIT; }

session "s2"
setup       { BEGIN; }
step "w2"	{ UPDATE animals SET counter = counter + 1 WHERE name = 'cat'; }
step "r2"	{ SELECT * FROM animals; }
step "d2"	{ DELETE FROM animals WHERE name = 'dog'; }
step "c2"	{ COMMIT; }

session "s3"
setup       { BEGIN; }
step "w3"	{ UPDATE animals SET counter = counter + 1 WHERE name = 'cat'; }
step "r3"	{ SELECT * FROM animals; }
step "i3"	{ INSERT INTO animals VALUES ('kangaroo', 1); }
step "c3"	{ COMMIT; }

# s1 sees previous version of "cat" tuple until the new version is committed
# but s2 sees its own uncommitted data
permutation "r1" "w2" "r2" "r1" "c2" "r1" "c1" "r1"  "c3"

# same thing, but with a two link update chain; again s2 and s3 see their
# own uncommitted data but s1 sees it only after commit
permutation "r1" "w2" "r2" "r1" "c2" "r1" "w3" "r3" "r1" "c3" "r1" "c1" "r1"

# s1 doesn't see a row as deleted until after commit, but s2 does
permutation "r1" "d2" "r2" "r1" "c2" "r1" "c1" "r1" "c3"

# same again, but this time it's an insert
permutation "r1" "i3" "r3" "r1" "c3" "r1" "c1" "r1" "c2"
