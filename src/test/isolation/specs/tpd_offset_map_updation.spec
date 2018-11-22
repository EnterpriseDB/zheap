# If the previous transaction slot points to a TPD slot then we need to update
# the slot in the offset map of the TPD entry
#

setup
{
	CREATE TABLE t (a int, b int);
	INSERT INTO t SELECT g,g FROM generate_series(1,1000)g;
}

teardown
{
	DROP TABLE t;
}

session "s1"
step "s1a" { BEGIN; }
step "s1b" { INSERT INTO t VALUES (1001); }
step "s1c" { SELECT * FROM t WHERE a = 1; }
step "s1d" { END; }

session "s2"
step "s2a" { BEGIN; }
step "s2b" { UPDATE t SET b = b + 1 WHERE a = 1; }
step "s2c" { ROLLBACK; }

session "s3"
step "s3a" { BEGIN; }
step "s3b" { UPDATE t SET b = b + 1 WHERE a = 2; }
step "s3d" { END; }

session "s4"
step "s4a" { BEGIN; }
step "s4b" { UPDATE t SET b = b + 1 WHERE a = 3; }
step "s4c" { END; }

permutation "s1a" "s1b" "s2b"  "s2a" "s2b" "s3a" "s3b" "s4a" "s4b" "s2c" "s1c"
"s1d" "s3d" "s4c"
