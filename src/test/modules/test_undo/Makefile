# src/test/modules/test_undo/Makefile

MODULE_big = test_undo
OBJS = test_undo.o
PGFILEDESC = "test_undo - functions for debugging undo"

EXTENSION = test_undo
DATA = test_undo--1.0.sql

REGRESS = test_undo

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
