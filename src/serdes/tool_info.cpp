/**
 * @file src/serdes/tool_info.cpp
 * @brief Tool information (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/tool_info.h"
#include "retdec/serdes/tool_info.h"

#include "serdes/utils.h"

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

Json::Value serialize(const common::ToolInfo& ti)
{
	Json::Value comp;

	comp[JSON_type] = ti.getType();
	comp[JSON_name] = ti.getName();
	comp[JSON_percentage] = ti.getPercentage();
	comp[JSON_idSignNibbles] = ti.getIdenticalSignificantNibbles();
	comp[JSON_totalSignNibbles] = ti.getTotalSignificantNibbles();
	comp[JSON_heuristics] = ti.isFromHeuristics();

	if (!ti.getVersion().empty())
	{
		comp[JSON_version] = ti.getVersion();
	}
	if (!ti.getAdditionalInfo().empty())
	{
		comp[JSON_additional] = ti.getAdditionalInfo();
	}

	return comp;
}

void deserialize(const Json::Value& val, common::ToolInfo& ti)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	ti.setVersion( safeGetString(val, JSON_version) );
	ti.setType( safeGetString(val, JSON_type) );
	ti.setName( safeGetString(val, JSON_name) );
	ti.setAdditionalInfo( safeGetString(val, JSON_additional) );
	ti.setPercentage( safeGetDouble(val, JSON_percentage) );
	ti.setIdenticalSignificantNibbles( safeGetUint(val, JSON_idSignNibbles) );
	ti.setTotalSignificantNibbles( safeGetUint(val, JSON_totalSignNibbles) );
	ti.setIsFromHeuristics( safeGetBool(val, JSON_heuristics) );
}

} // namespace serdes
} // namespace retdec
