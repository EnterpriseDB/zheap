#include "postgres.h"

#include "access/foo_xlog.h"
#include "lib/stringinfo.h"

void
foo_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_FOO_STRING)
	{
		appendStringInfo(buf, "\"%s\"", rec);
	}
	else if (info == XLOG_FOO_CREATEWRITECLOSE)
	{
		appendStringInfo(buf, "\"%s\"", rec);
	}
}

const char *
foo_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_FOO_STRING:
			id = "STRING";
			break;
		case XLOG_FOO_PING:
			id = "PING";
			break;
		case XLOG_FOO_CREATEWRITECLOSE:
			id = "CREATEWRITECLOSE";
			break;
	}

	return id;
}
