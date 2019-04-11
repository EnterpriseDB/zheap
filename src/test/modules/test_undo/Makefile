# src/test/modules/test_undo/Makefile

MODULE_big = test_undo
OBJS = test_undo.o
PGFILEDESC = "test_undo - a test module for the undo log manager"

EXTENSION = test_undo
DATA = test_undo--1.0.sql

REGRESS = test_undo

check: tablespace-setup

.PHONY: tablespace-setup
tablespace-setup:
	rm -fr testtablespace1 testtablespace2
	mkdir testtablespace1 testtablespace2

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_undo
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
