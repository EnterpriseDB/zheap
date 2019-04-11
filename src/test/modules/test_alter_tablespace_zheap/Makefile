# src/test/modules/test_alter_tablespace_zheap/Makefile

EXTRA_INSTALL=contrib/pageinspect

REGRESS = alter_tablespace_zheap
REGRESS_OPTS = --temp-config=$(top_srcdir)/src/test/modules/test_alter_tablespace_zheap/atz.conf

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_alter_tablespace_zheap
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

check: tablespace-setup temp-install

.PHONY: tablespace-setup
tablespace-setup:
	rm -fr ./testtablespace
	mkdir ./testtablespace
