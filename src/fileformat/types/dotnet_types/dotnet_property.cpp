/**
 * @file src/fileformat/types/dotnet_types/dotnet_property.cpp
 * @brief Class for .NET property.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_types/dotnet_data_types.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_property.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the data type of the property.
 * @return Data type of the property.
 */
const DotnetDataTypeBase* DotnetProperty::getDataType() const
{
	return dataType.get();
}

/**
 * Sets the data type of the property.
 * @param propertyDataType Data type of the property.
 */
void DotnetProperty::setDataType(std::unique_ptr<DotnetDataTypeBase>&& propertyDataType)
{
	dataType = std::move(propertyDataType);
}

/**
 * Sets whether the property is static.
 * @param set @c true for static, otherwise @c false.
 */
void DotnetProperty::setIsStatic(bool set)
{
	propertyIsStatic = set;
}

/**
 * Returns whether the property is static.
 * @return @c true if static, otherwise @c false.
 */
bool DotnetProperty::isStatic() const
{
	return propertyIsStatic;
}

} // namespace fileformat
} // namespace retdec
