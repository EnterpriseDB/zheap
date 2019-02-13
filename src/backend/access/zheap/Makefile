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

OBJS = prunetpd.o prunezheap.o rewritezheap.o tpd.o tpdxlog.o zheapam.o \
	zheapam_handler.o zheapamutils.o zheapam_visibility.o zheapamxlog.o \
	zhio.o zmultilocker.o zvacuumlazy.o ztuptoaster.o

include $(top_srcdir)/src/backend/common.mk
