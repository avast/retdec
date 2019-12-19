/**
 * @file src/serdes/calling_convention.cpp
 * @brief Calling convention (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/common/calling_convention.h"
#include "retdec/serdes/calling_convention.h"

#include "serdes/utils.h"

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

Json::Value serialize(const common::CallingConvention& cc)
{
	if (ccStrings.size() > static_cast<size_t>(cc.getID()))
	{
		return ccStrings[static_cast<size_t>(cc.getID())];
	}
	else
	{
		return ccStrings[static_cast<size_t>(
				common::CallingConvention::eCC::CC_UNKNOWN)];
	}
}

void deserialize(const Json::Value& val, common::CallingConvention& cc)
{
	if (val.isNull())
	{
		return;
	}

	std::string enumStr = safeGetString(val);
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
