/**
 * @file src/serdes/type.cpp
 * @brief Data type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/type.h"
#include "retdec/serdes/type.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_llvmIr     = "llvmIr";
const std::string JSON_wideString = "isWideString";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Type& t)
{
	Json::Value type;

	if (t.isDefined())
	{
		type[JSON_llvmIr] = t.getLlvmIr();
	}
	if (t.isDefined() && t.isWideString())
	{
		type[JSON_wideString] = t.isWideString();
	}

	return type;
}

void deserialize(const Json::Value& val, common::Type& t)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	t.setLlvmIr(safeGetString(val, JSON_llvmIr));
	t.setIsWideString(safeGetBool(val, JSON_wideString));
}

} // namespace serdes
} // namespace retdec
