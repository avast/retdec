/**
 * @file src/fileformat/types/dotnet_types/dotnet_type.cpp
 * @brief Class for .NET type.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <unordered_map>

#include "tl-cpputils/container.h"
#include "fileformat/types/dotnet_types/dotnet_type.h"

namespace fileformat {

namespace
{

const std::unordered_map<DotnetTypeVisibility, std::string, tl_cpputils::EnumClassKeyHash> visibilityStrings =
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
