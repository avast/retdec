/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_type.h
 * @brief Class for .NET type.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_TYPE_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_TYPE_H

#include <cstdint>
#include <string>

namespace retdec {
namespace fileformat {

/**
 * .NET type visibility
 */
enum class DotnetTypeVisibility
{
	Public,
	Protected,
	Private
};

/**
 * .NET Type
 */
class DotnetType
{
	protected:
		std::string name;
		std::string nameSpace;
		DotnetTypeVisibility visibility;
	public:
		virtual ~DotnetType() = default;

		/// @name Getters
		/// @{
		std::string getName() const { return name; }
		const std::string& getNameSpace() const { return nameSpace; }
		DotnetTypeVisibility getVisibility() const { return visibility; }
		std::string getFullyQualifiedName() const { return nameSpace.empty() ? name : nameSpace + '.' + name; }
		const std::string& getVisibilityString() const;
		/// @}

		/// @name Setters
		/// @{
		void setName(const std::string& typeName) { name = typeName; }
		void setNameSpace(const std::string& typeNameSpace) { nameSpace = typeNameSpace; }
		void setVisibility(DotnetTypeVisibility typeVisibility) { visibility = typeVisibility; }
		/// @}

		/// @name Detection
		/// @{
		bool isPublic() const { return visibility == DotnetTypeVisibility::Public; }
		bool isProtected() const { return visibility == DotnetTypeVisibility::Protected; }
		bool isPrivate() const { return visibility == DotnetTypeVisibility::Private; }
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
