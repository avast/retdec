/**
 * @file src/serdes/architecture.cpp
 * @brief Architecture (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/architecture.h"
#include "retdec/serdes/architecture.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_name    = "name";
const std::string JSON_endian  = "endian";
const std::string JSON_bitSize = "bitSize";

const std::string JSON_val_little = "little";
const std::string JSON_val_big    = "big";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Architecture& a)
{
	Json::Value arch;

	arch[JSON_name] = a.getName();
	arch[JSON_bitSize] = a.getBitSize();
	if (a.isEndianLittle())
		arch[JSON_endian] = JSON_val_little;
	else if (a.isEndianBig())
		arch[JSON_endian] = JSON_val_big;

	return arch;
}

void deserialize(const Json::Value& val, common::Architecture& a)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	a.setName(safeGetString(val, JSON_name));
	a.setBitSize(safeGetUint(val, JSON_bitSize));

	std::string e = safeGetString(val, JSON_endian);
	if (e == JSON_val_big)
	{
		a.setIsEndianBig();
	}
	else if (e == JSON_val_little)
	{
		a.setIsEndianLittle();
	}
	else
	{
		a.setIsEndianUnknown();
	}
}

} // namespace serdes
} // namespace retdec
