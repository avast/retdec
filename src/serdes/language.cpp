/**
 * @file src/serdes/language.cpp
 * @brief Language (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/language.h"
#include "retdec/serdes/language.h"

#include "retdec/serdes/std.h"

namespace {

const std::string JSON_name        = "name";
const std::string JSON_moduleCount = "moduleCount";
const std::string JSON_bytecode    = "bytecode";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Language& l)
{
	writer.StartObject();

	serializeString(writer, JSON_name, l.getName());
	serializeUint64(writer, JSON_moduleCount, l.getModuleCount(), l.isModuleCountSet());
	serializeBool(writer, JSON_bytecode, l.isBytecode());

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Language)

void deserialize(const rapidjson::Value& val, common::Language& l)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	l.setName(deserializeString(val, JSON_name));

	int c = deserializeUint64(val, JSON_moduleCount, -1);
	if (c >= 0)
	{
		l.setModuleCount(c);
	}
	l.setIsBytecode(deserializeBool(val, JSON_bytecode));
}

} // namespace serdes
} // namespace retdec
