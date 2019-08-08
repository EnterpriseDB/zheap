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
#include "access/undolog.h"
#include "datatype/timestamp.h"

struct UndoRequest;
struct UndoRequestManager;
typedef struct UndoRequest UndoRequest;
typedef struct UndoRequestManager UndoRequestManager;

/* Initialization functions. */
extern Size EstimateUndoRequestManagerSize(Size capacity);
extern void InitializeUndoRequestManager(UndoRequestManager *urm,
										 LWLock *lock, Size capacity,
										 Size soft_limit);

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
								UndoRecPtr end_location_unlogged);

/* Forget about an UndoRequest we don't need any more. */
extern void UnregisterUndoRequest(UndoRequestManager *urm, UndoRequest *req);

/* Attempt to dispatch UndoRequest for background processing. */
extern bool PerformUndoInBackground(UndoRequestManager *urm, UndoRequest *req,
									bool force);

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

/* Restore state after crash. */
extern bool RecreateUndoRequest(UndoRequestManager *urm,
								FullTransactionId fxid, Oid dbid,
								bool is_logged,
								UndoRecPtr start_location,
								UndoRecPtr end_location,
								Size size);
extern UndoRequest *SuspendPreparedUndoRequest(UndoRequestManager *urm,
											   FullTransactionId fxid);

/* Get oldest registered FXID. */
extern FullTransactionId UndoRequestManagerOldestFXID(UndoRequestManager *urm);

#endif
