/**
 * @file include/fileformat/types/dotnet_types/dotnet_parameter.h
 * @brief Class for .NET method parameter.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_PARAMETER_H
#define FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_PARAMETER_H

#include <memory>

#include "fileformat/types/dotnet_types/dotnet_data_types.h"
#include "fileformat/types/dotnet_types/dotnet_type.h"

namespace fileformat {

/**
 * .NET method parameter
 */
class DotnetParameter : public DotnetType
{
	private:
		std::unique_ptr<DotnetDataTypeBase> dataType;
	public:
		/// @name Getters
		/// @{
		const DotnetDataTypeBase* getDataType() const;
		/// @}

		/// @name Setters
		/// @{
		void setDataType(std::unique_ptr<DotnetDataTypeBase>&& paramDataType);
		/// @}
};

} // namespace fileformat

#endif
