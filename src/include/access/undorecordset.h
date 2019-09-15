/*-------------------------------------------------------------------------
 *
 * undorecordset.h
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undolog.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDORECORDSET_H
#define UNDORECORDSET_H

typedef enum UndoRecordSetType
{
	URST_TRANSACTION,
	URST_FOO				/* THROWAWAY TEST VALUE */
} UndoRecordSetType;

/* The UndoRecordSet definition is private to undorecordset.c. */
struct UndoRecordSet;
typedef struct UndoRecordSet UndoRecordSet;

extern UndoRecordSet *UndoCreate(UndoRecordSetType type, char presistence);
extern UndoRecordSet *UndoOpen(UndoRecordSetType type, UndoRecPtr start);
extern UndoRecordSet *UndoOpenAny(UndoRecPtr start_raw);
extern void UndoPrepareToMarkClosed(UndoRecordSet *urs);
extern void UndoMarkClosed(UndoRecordSet *urs);
extern void UndoUpdateInRecovery(XLogReaderState *xlog_record);
extern UndoRecPtr UndoAllocate(UndoRecordSet *urs, size_t size);
extern void UndoInsert(UndoRecordSet *urs, uint8 first_block_id, void *data, size_t size);
extern UndoRecPtr UndoInsertInRecovery(XLogReaderState *xlog_record, void *data, size_t size);
extern void UndoPageSetLSN(UndoRecordSet *urs, XLogRecPtr lsn);
extern void UndoRelease(UndoRecordSet *urs);

#endif
