/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_method.h
 * @brief Class for .NET method.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_METHOD_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_METHOD_H

#include <memory>

#include "retdec/fileformat/types/dotnet_types/dotnet_data_types.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_parameter.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type.h"

namespace retdec {
namespace fileformat {

/**
 * .NET method
 */
class DotnetMethod : public DotnetType
{
	private:
		const MethodDef* rawRecord;
		std::unique_ptr<DotnetDataTypeBase> returnType;
		std::vector<std::unique_ptr<DotnetParameter>> parameters;
		std::vector<std::string> genericParameters;
		bool methodIsStatic;
		bool methodIsVirtual;
		bool methodIsAbstract;
		bool methodIsFinal;
		bool methodIsConstructor;
		std::size_t declaredParamsCount;
	public:
		/// @name Getters
		/// @{
		const MethodDef* getRawRecord() const;
		std::string getNameWithGenericParameters() const;
		const DotnetDataTypeBase* getReturnType() const;
		const std::vector<std::unique_ptr<DotnetParameter>>& getParameters() const;
		const std::vector<std::string>& getGenericParameters() const;
		std::size_t getDeclaredParametersCount() const;
		/// @}

		/// @name Setters
		/// @{
		void setRawRecord(const MethodDef* record);
		void setReturnType(std::unique_ptr<DotnetDataTypeBase>&& methodReturnType);
		void setIsStatic(bool set);
		void setIsVirtual(bool set);
		void setIsAbstract(bool set);
		void setIsFinal(bool set);
		void setIsConstructor(bool set);
		void setDeclaredParametersCount(std::size_t paramsCount);
		/// @}

		/// @name Detection
		/// @{
		bool isStatic() const;
		bool isVirtual() const;
		bool isAbstract() const;
		bool isFinal() const;
		bool isConstructor() const;
		/// @}

		/// @name Parameter
		void addParameter(std::unique_ptr<DotnetParameter>&& param);
		void addGenericParameter(std::string&& genericParam);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
