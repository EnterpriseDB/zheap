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

OBJS = discardworker.o undoaction.o undoactionxlog.o undodiscard.o undoinsert.o \
		undolog.o undorecord.o undorequest.o undoworker.o

include $(top_srcdir)/src/backend/common.mk
