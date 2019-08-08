# src/test/modules/test_undo_request_manager/Makefile

MODULE_big = test_undo_request_manager
OBJS = test_undo_request_manager.o $(WIN32RES)
PGFILEDESC = "test_undo_request_manager - test undo request manager code"

EXTENSION = test_undo_request_manager
DATA = test_undo_request_manager--1.0.sql

REGRESS = test_undo_request_manager

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_undo_request_manager
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
