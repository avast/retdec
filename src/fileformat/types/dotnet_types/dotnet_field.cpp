/**
 * @file src/fileformat/types/dotnet_types/dotnet_field.cpp
 * @brief Class for .NET field.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_types/dotnet_field.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the data type of the field.
 * @return Data type of the field.
 */
const DotnetDataTypeBase* DotnetField::getDataType() const
{
	return dataType.get();
}

/**
 * Sets the data type of the field.
 * @param fieldDataType Data type of the field.
 */
void DotnetField::setDataType(std::unique_ptr<DotnetDataTypeBase>&& fieldDataType)
{
	dataType = std::move(fieldDataType);
}

/**
 * Sets whether the field is static.
 * @param set @c true for static, otherwise @c false.
 */
void DotnetField::setIsStatic(bool set)
{
	fieldIsStatic = set;
}

/**
 * Returns whether the field is static.
 * @return @c true if static, otherwise @c false.
 */
bool DotnetField::isStatic() const
{
	return fieldIsStatic;
}

} // namespace fileformat
} // namespace retdec
