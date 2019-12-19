/**
 * @file src/serdes/storage.cpp
 * @brief Storage (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <vector>

#include "retdec/common/storage.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/storage.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_type      = "type";
const std::string JSON_value     = "value";
const std::string JSON_regNum    = "registerNumber";

const std::vector<std::string> typeStrings =
{
	"undefined",
	"global",
	"register",
	"stack"
};

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Storage& s)
{
	Json::Value obj;

	if (s.isMemory())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(
				common::Storage::eType::GLOBAL) ];
		obj[JSON_value] = serdes::serialize(s.getAddress());
	}
	else if (s.isRegister())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(
				common::Storage::eType::REGISTER) ];
		obj[JSON_value] = s.getRegisterName();
	}
	else if (s.isStack())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(
				common::Storage::eType::STACK) ];
		obj[JSON_value] = s.getStackOffset();
	}
	else
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(
				common::Storage::eType::UNDEFINED) ];
	}

	auto registerNumber = s.getRegisterNumber();
	if (registerNumber.has_value())
	{
		obj[JSON_regNum] = registerNumber.value();
	}

	return obj;
}

void deserialize(const Json::Value& val, common::Storage& s)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Storage::eType type = common::Storage::eType::UNDEFINED;
	std::string enumStr = safeGetString(val, JSON_type);
	auto it = std::find(typeStrings.begin(), typeStrings.end(), enumStr);
	if (it != typeStrings.end())
	{
		type = static_cast<common::Storage::eType>(
				std::distance(typeStrings.begin(), it));
	}

	if (type == common::Storage::eType::GLOBAL)
	{
		common::Address a;
		serdes::deserialize(val[JSON_value], a);
		s = common::Storage::inMemory(a);
	}
	else if (type == common::Storage::eType::REGISTER)
	{
		s = common::Storage::inRegister(safeGetString(val, JSON_value));
	}
	else if (type == common::Storage::eType::STACK)
	{
		s = common::Storage::onStack(safeGetInt(val, JSON_value));
	}
	else
	{
		assert(type == common::Storage::eType::UNDEFINED);
	}

	if (val.isMember(JSON_regNum))
	{
		s.setRegisterNumber(safeGetUint(val, JSON_regNum));
	}
}

} // namespace serdes
} // namespace retdec
