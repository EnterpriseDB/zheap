/*-------------------------------------------------------------------------
 *
 * undorequest.h
 *		Undo request manager.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorequest.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOREQUEST_H
#define UNDOREQUEST_H

#include "access/transam.h"
#include "access/undodefs.h"
#include "datatype/timestamp.h"
#include "storage/lwlock.h"

struct UndoRequest;
struct UndoRequestManager;
typedef struct UndoRequest UndoRequest;
typedef struct UndoRequestManager UndoRequestManager;

/* GUCs */
extern bool undo_force_foreground;

/* Initialization functions. */
extern Size EstimateUndoRequestManagerSize(unsigned capacity);
extern void InitializeUndoRequestManager(UndoRequestManager *urm,
										 LWLock *lock, unsigned capacity,
										 unsigned soft_limit);

/* Call this before inserting undo records. */
extern UndoRequest *RegisterUndoRequest(UndoRequestManager *urm,
										FullTransactionId fxid,
										Oid dbid);

/* Remember undo size and end locations. */
extern void FinalizeUndoRequest(UndoRequestManager *urm,
								UndoRequest *req,
								Size size,
								UndoRecPtr start_location_logged,
								UndoRecPtr start_location_unlogged,
								UndoRecPtr end_location_logged,
								UndoRecPtr end_location_unlogged,
								bool mark_as_ready);

/* Forget about an UndoRequest we don't need any more. */
extern void UnregisterUndoRequest(UndoRequestManager *urm, UndoRequest *req);

/* Attempt to dispatch UndoRequest for background processing. */
extern bool PerformUndoInBackground(UndoRequestManager *urm, UndoRequest *req,
									bool force);

/* Check how long a worker would need to wait for an UndoRequest. */
extern long UndoRequestWaitTime(UndoRequestManager *urm, TimestampTz when);

/* Get work for background undo process. */
extern UndoRequest *GetNextUndoRequest(UndoRequestManager *urm, Oid dbid,
									   bool minimum_runtime_reached,
									   Oid *out_dbid, FullTransactionId *fxid,
									   UndoRecPtr *start_location_logged,
									   UndoRecPtr *end_location_logged,
									   UndoRecPtr *start_location_unlogged,
									   UndoRecPtr *end_location_unlogged);

/* Reschedule failed undo attempt. */
extern void RescheduleUndoRequest(UndoRequestManager *urm, UndoRequest *req);

/* Save and restore state. */
extern char *SerializeUndoRequestData(UndoRequestManager *urm, Size *nbytes);
extern void RestoreUndoRequestData(UndoRequestManager *urm, Size nbytes,
								   char *data);

/* Get oldest registered FXID. */
extern FullTransactionId UndoRequestManagerOldestFXID(UndoRequestManager *urm);

#endif
