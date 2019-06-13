# Simple tests that show the working of zheap correctly with TPD.
setup
{
 CREATE TABLE animals (name text, counter int) USING zheap;
 INSERT INTO animals VALUES ('cat', 1), ('dog', 10), ('monkey', 100);
}

teardown
{
 DROP TABLE animals;
}

session "s1"
setup		{ BEGIN; }
step "r1"	{ SELECT * FROM animals ORDER BY 1,2; }
step "i1"	{ INSERT INTO ANIMALS VALUES ('cow', 11); }
step "t1"	{ DELETE FROM ANIMALS WHERE name = 'dog'; }
step "c1"	{ COMMIT; }

# insert and index key update
session "s2"
setup       { BEGIN; }
step "w2"	{ UPDATE animals SET counter = counter + 2 WHERE name = 'cat'; }
step "i2"	{ INSERT INTO ANIMALS VALUES ('lion', 22); }
step "r2"	{ SELECT * FROM animals ORDER BY 1,2; }
step "t2"	{ DELETE FROM ANIMALS WHERE name = 'lion'; }
step "c2"	{ COMMIT; }
step "d2"	{ ROLLBACK; }

# tuple size increase
session "s3"
setup       { BEGIN; }
step "i3"	{ INSERT INTO ANIMALS VALUES ('panther', 33); }
step "w3"	{ UPDATE animals SET counter = counter + 3 WHERE name = 'cat'; }
step "t3"	{ DELETE FROM ANIMALS WHERE counter < 3; }
step "r3"	{ SELECT * FROM animals ORDER BY 1,2; }
step "c3"	{ COMMIT; }

# index key update
session "s4"
setup       { BEGIN; }
step "i4"	{ INSERT INTO ANIMALS VALUES ('giraffe', 44); }
step "w4"	{ UPDATE animals SET counter = counter + 4 WHERE name = 'cat'; }
step "r4"	{ SELECT * FROM animals ORDER BY 1,2; }
step "c4"	{ COMMIT; }

# insert and index key update
session "s5"
setup       { BEGIN; }
step "i5"	{ INSERT INTO ANIMALS VALUES('tiger', 55); }
step "w5"	{ UPDATE animals SET counter = counter + 5 WHERE name = 'cat'; }
step "r5"	{ SELECT * FROM animals; }
step "t5"	{ DELETE FROM ANIMALS WHERE name = 'dog'; }
step "c5"	{ COMMIT; }

# check if the insertions are handled with TPD pages
permutation "i1" "i2" "i3" "i4" "i5" "c5" "r5" "c4" "r4" "c2" "r2" "c3" "r3" "c1" "r1"

# check if the updates with rollback are handled are with TPD pages
permutation "i1" "i2" "i3" "i4" "i5" "w5" "c5" "r5" "w2" "d2" "r2" "w3" "c3" "r3" "c1" "c4"

# check for the correct handling of deletes with rollback with TPD pages
permutation "i1" "i2" "i3" "i4" "i5" "t5" "c5" "r5" "t2" "d2" "r2" "t3" "c3" "r3" "c1" "c4"
