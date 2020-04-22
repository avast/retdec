/**
 * @file src/serdes/storage.cpp
 * @brief Storage (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/storage.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/storage.h"
#include "retdec/serdes/std.h"

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

template <typename Writer>
void serialize(Writer& writer, const common::Storage& s)
{
	writer.StartObject();

	if (s.isMemory())
	{
		serializeString(writer, JSON_type, typeStrings[ static_cast<size_t>(
				common::Storage::eType::GLOBAL) ]);
		serialize(writer, JSON_value, s.getAddress());
	}
	else if (s.isRegister())
	{
		serializeString(writer, JSON_type, typeStrings[ static_cast<size_t>(
				common::Storage::eType::REGISTER) ]);
		serializeString(writer, JSON_value, s.getRegisterName());
	}
	else if (s.isStack())
	{
		serializeString(writer, JSON_type, typeStrings[ static_cast<size_t>(
				common::Storage::eType::STACK) ]);
		serializeInt64(writer, JSON_value, s.getStackOffset());
	}
	else
	{
		serializeString(writer, JSON_type, typeStrings[ static_cast<size_t>(
				common::Storage::eType::UNDEFINED) ]);
	}

	auto regnum = s.getRegisterNumber();
	if (regnum.has_value())
	{
		serializeUint64(writer, JSON_regNum, regnum.value());
	}

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Storage)

void deserialize(const rapidjson::Value& val, common::Storage& s)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Storage::eType type = common::Storage::eType::UNDEFINED;
	std::string enumStr = deserializeString(val, JSON_type);
	auto it = std::find(typeStrings.begin(), typeStrings.end(), enumStr);
	if (it != typeStrings.end())
	{
		type = static_cast<common::Storage::eType>(
				std::distance(typeStrings.begin(), it));
	}

	if (type == common::Storage::eType::GLOBAL)
	{
		common::Address a;
		deserialize(val, JSON_value, a);
		s = common::Storage::inMemory(a);
	}
	else if (type == common::Storage::eType::REGISTER)
	{
		s = common::Storage::inRegister(deserializeString(val, JSON_value));
	}
	else if (type == common::Storage::eType::STACK)
	{
		s = common::Storage::onStack(deserializeInt64(val, JSON_value));
	}
	else
	{
		assert(type == common::Storage::eType::UNDEFINED);
	}

	if (val.HasMember(JSON_regNum))
	{
		s.setRegisterNumber(deserializeUint64(val, JSON_regNum));
	}
}

} // namespace serdes
} // namespace retdec
