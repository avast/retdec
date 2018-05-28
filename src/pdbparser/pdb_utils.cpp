/**
 * @file src/pdbparser/pdb_utils.cpp
 * @brief Utils
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdio>
#include <cstdlib>

#include "retdec/pdbparser/pdb_info.h"
#include "retdec/pdbparser/pdb_utils.h"

namespace retdec {
namespace pdbparser {

PDB_PBYTE RecordValue(PDB_PBYTE pbData, PDB_PDWORD pdValue)
{
	PDB_WORD wValue;
	PDB_DWORD dValue = -1;
	PDB_PBYTE pbText = nullptr;

	if (pbData != nullptr)
	{
		if ((wValue = *reinterpret_cast<PDB_PWORD>(pbData)) < LF_NUMERIC)
		{
			dValue = wValue;
			pbText = pbData + WORD_;
		}
		else
		{
			switch (wValue)
			{
				case LF_CHAR:
				{
					dValue = static_cast<PDB_LONG>(*reinterpret_cast<PDB_PCHAR>(pbData + WORD_));
					pbText = pbData + WORD_ + CHAR_;
					break;
				}
				case LF_SHORT:
				{
					dValue = static_cast<PDB_LONG>(*reinterpret_cast<PDB_PSHORT>(pbData + WORD_));
					pbText = pbData + WORD_ + SHORT_;
					break;
				}
				case LF_USHORT:
				{
					dValue = static_cast<PDB_LONG>(*reinterpret_cast<PDB_PUSHORT>(pbData + WORD_));
					pbText = pbData + WORD_ + USHORT_;
					break;
				}
				case LF_LONG:
				{
					dValue = *reinterpret_cast<PDB_PLONG>(pbData + WORD_);
					pbText = pbData + WORD_ + LONG_;
					break;
				}
				case LF_ULONG:
				{
					dValue = static_cast<PDB_LONG>(*reinterpret_cast<PDB_PULONG>(pbData + WORD_));
					pbText = pbData + WORD_ + ULONG_;
					break;
				}
				default:
				{
					// nothing ...
					break;
				}
			}
		}
	}
	if (pdValue != nullptr)
		*pdValue = dValue;
	return pbText;
}

// -----------------------------------------------------------------

void print_dwords(PDB_DWORD *data, int len)
{
	int cnt = (len - 2) / 4;
	for (int i = 0; i < cnt; i++)
	{
		printf("%08x ", data[i]);
	}
}

void print_bytes(PDB_BYTE *data, int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%02x", data[i]);
	}
}

} // namespace pdbparser
} // namespace retdec
