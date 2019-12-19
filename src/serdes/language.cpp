/**
 * @file src/serdes/language.cpp
 * @brief Language (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/language.h"
#include "retdec/serdes/language.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_name        = "name";
const std::string JSON_moduleCount = "moduleCount";
const std::string JSON_bytecode    = "bytecode";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Language& l)
{
	Json::Value lang;

	lang[JSON_name] = l.getName();
	if (l.isModuleCountSet())
	{
		lang[JSON_moduleCount] = l.getModuleCount();
	}
	lang[JSON_bytecode] = l.isBytecode();

	return lang;
}

void deserialize(const Json::Value& val, common::Language& l)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	l.setName(safeGetString(val, JSON_name));

	int c = safeGetInt(val, JSON_moduleCount, -1);
	if (c >= 0)
	{
		l.setModuleCount(c);
	}
	l.setIsBytecode(safeGetBool(val, JSON_bytecode));
}

} // namespace serdes
} // namespace retdec
