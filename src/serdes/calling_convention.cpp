/**
 * @file src/serdes/calling_convention.cpp
 * @brief Calling convention (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/calling_convention.h"
#include "retdec/serdes/calling_convention.h"
#include "retdec/serdes/std.h"

namespace {

const std::vector<std::string> ccStrings =
{
	"unknown",
	"voidarg",
	"cdecl",
	"ellipsis",
	"stdcall",
	"pascal",
	"fastcall",
	"thiscall",
	"manual",
	"spoiled",
	"speciale",
	"specialp",
	"special",
	"watcom",
	"x64_os_default",
	"arm_default",
	"arm64_default",
	"mips_default",
	"mips64_default",
	"powerpc_default",
	"powerpc64_default",
	"pic32_default"
};

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::CallingConvention& cc)
{
	if (ccStrings.size() > static_cast<uint64_t>(cc.getID()))
	{
		writer.String(ccStrings[static_cast<uint64_t>(cc.getID())]);
	}
	else
	{
		writer.String(ccStrings[static_cast<uint64_t>(
				common::CallingConvention::eCC::CC_UNKNOWN)]);
	}
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::CallingConvention)

void deserialize(const rapidjson::Value& val, common::CallingConvention& cc)
{
	if (val.IsNull() || !val.IsString())
	{
		return;
	}

	std::string enumStr = val.GetString();
	auto it = std::find(ccStrings.begin(), ccStrings.end(), enumStr);
	if (it == ccStrings.end())
	{
		cc.setIsUnknown();
	}
	else
	{
		cc.set(static_cast<common::CallingConvention::eCC>(
				std::distance(ccStrings.begin(), it)));
	}
}

} // namespace serdes
} // namespace retdec
