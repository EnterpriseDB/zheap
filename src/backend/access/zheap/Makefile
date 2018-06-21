#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for access/zheap
#
# IDENTIFICATION
#    src/backend/access/zheap/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/access/zheap
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

OBJS = prunezheap.o tpd.o tpdxlog.o zheapam.o zheapamutils.o zheapamxlog.o \
	zhio.o zmultilocker.o

include $(top_srcdir)/src/backend/common.mk
