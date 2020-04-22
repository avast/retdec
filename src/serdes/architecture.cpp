/**
 * @file src/serdes/architecture.cpp
 * @brief Architecture (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/architecture.h"
#include "retdec/serdes/architecture.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_name    = "name";
const std::string JSON_endian  = "endian";
const std::string JSON_bitSize = "bitSize";

const std::string JSON_val_little = "little";
const std::string JSON_val_big    = "big";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Architecture& a)
{
	writer.StartObject();

	serializeString(writer, JSON_name, a.getName());
	serializeUint64(writer, JSON_bitSize, a.getBitSize());

	if (a.isEndianLittle())
	{
		serializeString(writer, JSON_endian, JSON_val_little);
	}
	else if (a.isEndianBig())
	{
		serializeString(writer, JSON_endian, JSON_val_big);
	}

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Architecture)

void deserialize(const rapidjson::Value& val, common::Architecture& a)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	a.setName(deserializeString(val, JSON_name));
	a.setBitSize(deserializeUint64(val, JSON_bitSize));

	std::string e = deserializeString(val, JSON_endian);
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
