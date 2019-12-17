#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for access/undo
#
# IDENTIFICATION
#    src/backend/access/undo/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/access/undo
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

OBJS = \
	undo.o \
	undolog.o \
	undopage.o \
	undorecordset.o \
	undorecordset_xlog.o \
	undorequest.o \
	undoworker.o \
	xactundo.o

include $(top_srcdir)/src/backend/common.mk
