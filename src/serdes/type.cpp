/**
 * @file src/serdes/type.cpp
 * @brief Data type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/type.h"
#include "retdec/serdes/type.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_llvmIr     = "llvmIr";
const std::string JSON_wideString = "isWideString";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Type& t)
{
	writer.StartObject();

	serializeString(writer, JSON_llvmIr, t.getLlvmIr(), t.isDefined());
	serializeBool(writer, JSON_wideString, t.isWideString(), t.isDefined() && t.isWideString());

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Type)

void deserialize(const rapidjson::Value& val, common::Type& t)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	t.setLlvmIr(deserializeString(val, JSON_llvmIr));
	t.setIsWideString(deserializeBool(val, JSON_wideString));
}

} // namespace serdes
} // namespace retdec
