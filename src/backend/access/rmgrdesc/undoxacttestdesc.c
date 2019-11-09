#include "postgres.h"

#include "access/undoxacttest.h"
#include "lib/stringinfo.h"

void
undoxacttest_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_UNDOXACTTEST_MOD:
			{
				xl_undoxacttest_mod *xlrec = (xl_undoxacttest_mod *) rec;

				appendStringInfo(buf, "newval: "INT64_FORMAT" debug_mod: "INT64_FORMAT" debug_oldval: "INT64_FORMAT,
								 xlrec->newval, xlrec->debug_mod, xlrec->debug_oldval);
			}
			break;
		default:
			appendStringInfo(buf, "unknown action");
	}
}

const char *
undoxacttest_identify(uint8 info)
{
	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_UNDOXACTTEST_MOD:
			return "mod";
		default:
			return NULL;
	}
}
