/*-------------------------------------------------------------------------
 *
 * undorecordset.h
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorecordset.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORDSET_H
#define UNDORECORDSET_H

#include "access/undodefs.h"
#include "access/xlogreader.h"

typedef enum UndoRecordSetType
{
	URST_TRANSACTION,
	URST_FOO				/* THROWAWAY TEST VALUE */
} UndoRecordSetType;

/* The UndoRecordSet definition is private to undorecordset.c. */
struct UndoRecordSet;
typedef struct UndoRecordSet UndoRecordSet;

extern UndoRecordSet *UndoCreate(UndoRecordSetType type, char presistence,
								 int nestingLevel);
extern UndoRecordSet *UndoOpen(UndoRecordSetType type, UndoRecPtr start);
extern UndoRecordSet *UndoOpenAny(UndoRecPtr start_raw);
extern bool UndoPrepareToMarkClosed(UndoRecordSet *urs);
extern void UndoMarkClosed(UndoRecordSet *urs);
extern void UndoUpdateInRecovery(XLogReaderState *xlog_record);
extern UndoRecPtr UndoAllocate(UndoRecordSet *urs, size_t size);
extern void UndoInsert(UndoRecordSet *urs, uint8 first_block_id, void *data, size_t size);
extern UndoRecPtr UndoInsertInRecovery(XLogReaderState *xlog_record, void *data, size_t size);
extern void UndoPageSetLSN(UndoRecordSet *urs, XLogRecPtr lsn);
extern void UndoRelease(UndoRecordSet *urs);
extern void UndoDestroy(UndoRecordSet *urs);

/* transaction integration */
extern void UndoResetInsertion(void);
extern bool UndoPrepareToMarkClosedForXactLevel(int nestingLevel);
extern void UndoMarkClosedForXactLevel(int nestingLevel);
extern void UndoPageSetLSNForXactLevel(int nestingLevel, XLogRecPtr lsn);
extern void UndoDestroyForXactLevel(int nestingLevel);
extern void UndoCloseAndReleaseForXactLevel(int nestingLevel);

#endif
