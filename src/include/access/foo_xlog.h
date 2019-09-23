#ifndef FOO_XLOG_H
#define FOO_XLOG_H

#include "access/xlogreader.h"
#include "lib/stringinfo.h"

#define XLOG_FOO_STRING 0x10
#define XLOG_FOO_PING	0x20
#define XLOG_FOO_CREATEWRITECLOSE	0x40

extern void foo_redo(XLogReaderState *record);
extern void foo_desc(StringInfo buf,XLogReaderState *record);
extern const char *foo_identify(uint8 info);

#endif
