/**
 * @file src/serdes/tool_info.cpp
 * @brief Tool information (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/tool_info.h"
#include "retdec/serdes/tool_info.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_type             = "type";
const std::string JSON_name             = "name";
const std::string JSON_version          = "version";
const std::string JSON_additional       = "additional";
const std::string JSON_percentage       = "percentage";
const std::string JSON_idSignNibbles    = "identicalSignificantNibbles";
const std::string JSON_totalSignNibbles = "totalSignificantNibbles";
const std::string JSON_heuristics       = "heuristics";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::ToolInfo& ti)
{
	writer.StartObject();

	serializeString(writer, JSON_type, ti.getType());
	serializeString(writer, JSON_name, ti.getName());
	serializeDouble(writer, JSON_percentage, ti.getPercentage());
	serializeUint64(writer, JSON_idSignNibbles, ti.getIdenticalSignificantNibbles());
	serializeUint64(writer, JSON_totalSignNibbles, ti.getTotalSignificantNibbles());
	serializeBool(writer, JSON_heuristics, ti.isFromHeuristics());
	serializeString(writer, JSON_version, ti.getVersion());
	serializeString(writer, JSON_additional, ti.getAdditionalInfo());

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::ToolInfo)

void deserialize(const rapidjson::Value& val, common::ToolInfo& ti)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	ti.setVersion( deserializeString(val, JSON_version) );
	ti.setType( deserializeString(val, JSON_type) );
	ti.setName( deserializeString(val, JSON_name) );
	ti.setAdditionalInfo( deserializeString(val, JSON_additional) );
	ti.setPercentage( deserializeDouble(val, JSON_percentage) );
	ti.setIdenticalSignificantNibbles( deserializeUint64(val, JSON_idSignNibbles) );
	ti.setTotalSignificantNibbles( deserializeUint64(val, JSON_totalSignNibbles) );
	ti.setIsFromHeuristics( deserializeBool(val, JSON_heuristics) );
}

} // namespace serdes
} // namespace retdec
