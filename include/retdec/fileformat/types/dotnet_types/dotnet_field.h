/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_field.h
 * @brief Class for .NET field.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_FIELD_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_FIELD_H

#include <memory>

#include "retdec/fileformat/types/dotnet_types/dotnet_data_types.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type.h"

namespace retdec {
namespace fileformat {

/**
 * .NET field
 */
class DotnetField : public DotnetType
{
	private:
		std::unique_ptr<DotnetDataTypeBase> dataType;
		bool fieldIsStatic;
	public:
		/// @name Getters
		/// @{
		const DotnetDataTypeBase* getDataType() const;
		/// @}

		/// @name Setters
		/// @{
		void setDataType(std::unique_ptr<DotnetDataTypeBase>&& fieldDataType);
		void setIsStatic(bool set);
		/// @}

		/// @name Detection
		/// @{
		bool isStatic() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
