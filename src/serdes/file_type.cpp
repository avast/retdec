/**
 * @file src/serdes/file_type.cpp
 * @brief File type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/file_type.h"
#include "retdec/serdes/file_type.h"

#include "serdes/utils.h"

namespace {

const std::vector<std::string> ftStrings =
{
	"unknown",
	"shared",
	"archive",
	"object",
	"executable"
};

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::FileType& ft)
{
	if (ftStrings.size() > static_cast<size_t>(ft.getID()))
	{
		return ftStrings[static_cast<size_t>(ft.getID())];
	}
	else
	{
		return ftStrings[static_cast<size_t>(
			common::FileType::eFileType::FT_UNKNOWN)];
	}
}

void deserialize(const Json::Value& val, common::FileType& ft)
{
	if (val.isNull())
	{
		return;
	}

	std::string enumStr = safeGetString(val);
	auto it = std::find(ftStrings.begin(), ftStrings.end(), enumStr);
	if (it == ftStrings.end())
	{
		ft.set(common::FileType::eFileType::FT_UNKNOWN);
	}
	else
	{
		ft.set(static_cast<common::FileType::eFileType>(
			std::distance(ftStrings.begin(), it)));
	}
}

} // namespace serdes
} // namespace retdec
