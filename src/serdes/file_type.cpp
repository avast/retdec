/**
 * @file src/serdes/file_type.cpp
 * @brief File type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/file_type.h"
#include "retdec/serdes/file_type.h"

#include "retdec/serdes/std.h"

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

template <typename Writer>
void serialize(Writer& writer, const common::FileType& ft)
{
	if (ftStrings.size() > static_cast<size_t>(ft.getID()))
	{
		writer.String(ftStrings[static_cast<size_t>(ft.getID())]);
	}
	else
	{
		writer.String(ftStrings[static_cast<size_t>(
			common::FileType::eFileType::FT_UNKNOWN)]);
	}
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::FileType)

void deserialize(const rapidjson::Value& val, common::FileType& ft)
{
	if (val.IsNull() || !val.IsString())
	{
		return;
	}

	std::string enumStr = val.GetString();
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
