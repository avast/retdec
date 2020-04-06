/**
 * @file src/serdes/address.cpp
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/serdes/address.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_start  = "start";
const std::string JSON_end    = "end";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Address& a)
{
	writer.String(a.isDefined() ? a.toHexPrefixString() : std::string());
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Address)

void deserialize(const rapidjson::Value& val, common::Address& a)
{
	if (val.IsNull() || !val.IsString())
	{
		return;
	}

	a = common::Address(val.GetString());
}

template <typename Writer>
void serialize(Writer& writer, const common::AddressRange& r)
{
	writer.StartObject();
	if (r.getStart().isDefined() && r.getEnd().isDefined())
	{
		serialize(writer, JSON_start, r.getStart());
		serialize(writer, JSON_end, r.getEnd());
	}
	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::AddressRange)

void deserialize(const rapidjson::Value& val, common::AddressRange& r)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Address s, e;
	deserialize(val, JSON_start, s);
	deserialize(val, JSON_end, e);
	r.setStartEnd(s, e);
}

} // namespace serdes
} // namespace retdec
