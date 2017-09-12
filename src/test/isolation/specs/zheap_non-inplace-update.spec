# Simple tests that show the behavior of snapshots working correctly
# for non-inplace-updates.

setup
{
 CREATE TABLE animals (name text, counter int) WITH (storage_engine = 'zheap');
 CREATE INDEX idx_animals_counter ON animals USING BTREE(counter);
 INSERT INTO animals VALUES ('cat', 1), ('dog', 1), ('monkey', 1);
}

teardown
{
 DROP TABLE animals;
}

session "s1"
setup		{ BEGIN; }
step "r1"	{ SELECT * FROM animals; }
step "c1"	{ COMMIT; }

# index key update
session "s2"
setup       { BEGIN; }
step "w2"	{ UPDATE animals SET counter = counter + 1 WHERE name = 'cat'; }
step "r2"	{ SELECT * FROM animals; }
step "c2"	{ COMMIT; }

# tuple size increase
session "s3"
setup       { BEGIN; }
step "w3"	{ UPDATE animals SET name = 'cat1' WHERE name = 'cat'; }
step "r3"	{ SELECT * FROM animals; }
step "c3"	{ COMMIT; }

# s1 sees previous version of "cat" tuple until the new version is committed
# but s2 sees its own uncommitted data
permutation "r1" "w2" "r2" "r1" "c2" "r1" "c1" "r1"  "c3"

# same thing, but for tuple size increase
permutation "r1" "w3" "r3" "r1" "c3" "r1" "c1" "r1"  "c2"
