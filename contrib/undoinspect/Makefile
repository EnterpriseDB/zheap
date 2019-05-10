# contrib/undoinspect/Makefile

MODULE_big	= undoinspect
OBJS		= undoinspect.o $(WIN32RES)

EXTENSION = undoinspect
DATA =  undoinspect--1.0.sql
PGFILEDESC = "undoinspect - functions to inspect contents of undo logs"

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/undoinspect
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
