/**
 * @file src/fileformat/types/dotnet_types/dotnet_parameter.cpp
 * @brief Class for .NET method parameter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_types/dotnet_parameter.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the data type of the parameter.
 * @return Data type of the parameter.
 */
const DotnetDataTypeBase* DotnetParameter::getDataType() const
{
	return dataType.get();
}

/**
 * Sets the data type of the parameter.
 * @param paramDataType Data type of the parameter.
 */
void DotnetParameter::setDataType(std::unique_ptr<DotnetDataTypeBase>&& paramDataType)
{
	dataType = std::move(paramDataType);
}

} // namespace fileformat
} // namespace retdec
