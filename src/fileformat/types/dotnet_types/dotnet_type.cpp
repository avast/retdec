/**
 * @file src/fileformat/types/dotnet_types/dotnet_type.cpp
 * @brief Class for .NET type.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <unordered_map>

#include "retdec/utils/container.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type.h"

namespace retdec {
namespace fileformat {

namespace
{

const std::unordered_map<DotnetTypeVisibility, std::string, retdec::utils::EnumClassKeyHash> visibilityStrings =
{
	{ DotnetTypeVisibility::Public,    "public"    },
	{ DotnetTypeVisibility::Protected, "protected" },
	{ DotnetTypeVisibility::Private,   "private"   }
};

}

const std::string& DotnetType::getVisibilityString() const
{
	return visibilityStrings.at(visibility);
}

} // namespace fileformat
} // namespace retdec
