/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_class.h
 * @brief Class for .NET class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_CLASS_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_CLASS_H

#include <memory>
#include <vector>

#include "retdec/fileformat/types/dotnet_types/dotnet_field.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_method.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_property.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type.h"

namespace retdec {
namespace fileformat {

/**
 * .NET class
 */
class DotnetClass : public DotnetType
{
	private:
		const TypeDef* rawRecord;
		std::size_t declaredFieldsCount;
		std::size_t declaredMethodsCount;
		std::size_t declaredGenericParametersCount;
		std::vector<std::unique_ptr<DotnetField>> fields;
		std::vector<std::unique_ptr<DotnetProperty>> properties;
		std::vector<std::unique_ptr<DotnetMethod>> methods;
		std::vector<std::string> genericParameters;
		std::vector<std::unique_ptr<DotnetDataTypeBase>> baseTypes;
		bool classOrInterface;
		bool abstract;
		bool sealed;

		std::string getGenericParametersString() const;
	public:
		/// @name Getters
		/// @{
		const TypeDef* getRawRecord() const;
		std::string getNameWithGenericParameters() const;
		std::string getFullyQualifiedNameWithGenericParameters() const;
		std::size_t getDeclaredFieldsCount() const;
		std::size_t getDeclaredMethodsCount() const;
		std::size_t getDeclaredGenericParametersCount() const;
		const std::vector<std::unique_ptr<DotnetField>>& getFields() const;
		const std::vector<std::unique_ptr<DotnetProperty>>& getProperties() const;
		const std::vector<std::unique_ptr<DotnetMethod>>& getMethods() const;
		const std::vector<std::string>& getGenericParameters() const;
		const std::vector<std::unique_ptr<DotnetDataTypeBase>>& getBaseTypes() const;
		std::size_t getFieldsCount() const;
		std::size_t getPropertiesCount() const;
		std::size_t getMethodsCount() const;
		std::size_t getGenericParametersCount() const;
		std::string getTypeString() const;
		/// @}

		/// @name Setters
		/// @{
		void setRawRecord(const TypeDef* classTypeDef);
		void setDeclaredFieldsCount(std::size_t classFieldsCount);
		void setDeclaredMethodsCount(std::size_t classMethodsCount);
		void setDeclaredGenericParametersCount(std::size_t classGenericParamsCount);
		void setIsInterface(bool set);
		void setIsAbstract(bool set);
		void setIsSealed(bool set);
		/// @}

		/// @name Detection
		/// @{
		bool isClass() const;
		bool isInterface() const;
		bool isAbstract() const;
		bool isSealed() const;
		/// @}

		/// @name Additions
		/// @{
		void addField(std::unique_ptr<DotnetField>&& field);
		void addProperty(std::unique_ptr<DotnetProperty>&& property);
		void addMethod(std::unique_ptr<DotnetMethod>&& method);
		void addGenericParameter(std::string&& genericParam);
		void addBaseType(std::unique_ptr<DotnetDataTypeBase>&& baseType);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
