# src/test/modules/test_undo/Makefile

MODULE_big = test_undo_api
OBJS = test_undo_api.o
PGFILEDESC = "test_undo_api - a test module for the undo api layer"

EXTENSION = test_undo_api
DATA = test_undo_api--1.0.sql

REGRESS = test_undo_api

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_undo_api
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
