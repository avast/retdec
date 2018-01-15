/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_type_reconstructor.h
 * @brief Class for .NET reconstructor.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_TYPE_RECONSTRUCTOR_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_TYPE_RECONSTRUCTOR_H

#include "retdec/fileformat/types/dotnet_headers/blob_stream.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_stream.h"
#include "retdec/fileformat/types/dotnet_headers/string_stream.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"

namespace retdec {
namespace fileformat {

class DotnetTypeReconstructor
{
	public:
		using ClassList = std::vector<std::shared_ptr<DotnetClass>>;
		using ClassTable = std::map<std::size_t, std::shared_ptr<DotnetClass>>;
		using ClassToMethodTable = std::unordered_map<const DotnetClass*, std::vector<std::unique_ptr<DotnetMethod>>>;
		using MethodTable = std::map<std::size_t, DotnetMethod*>;
		using SignatureTable = std::map<const DotnetMethod*, std::vector<std::uint8_t>>;

		DotnetTypeReconstructor(const MetadataStream* metadata, const StringStream* strings, const BlobStream* blob);

		bool reconstruct();

		ClassList getDefinedClasses() const;
		ClassList getReferencedClasses() const;

	private:
		bool reconstructClasses();
		bool reconstructMethods();
		bool reconstructGenericParameters();
		bool reconstructMethodParameters();
		bool reconstructFields();
		bool reconstructProperties();
		bool reconstructNestedClasses();
		bool reconstructBaseTypes();

		std::unique_ptr<DotnetClass> createClassDefinition(const TypeDef* typeDef, std::size_t fieldsCount, std::size_t methodsCount);
		std::unique_ptr<DotnetClass> createClassReference(const TypeRef* typeRef);
		std::unique_ptr<DotnetField> createField(const Field* field, const DotnetClass* ownerClass);
		std::unique_ptr<DotnetProperty> createProperty(const Property* property, const DotnetClass* ownerClass);
		std::unique_ptr<DotnetMethod> createMethod(const MethodDef* methodDef, const DotnetClass* ownerClass);
		std::unique_ptr<DotnetParameter> createMethodParameter(const Param* param, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod, std::vector<std::uint8_t>& signature);

		template <typename T> std::unique_ptr<T> createDataTypeFollowedByReference(std::vector<std::uint8_t>& data);
		template <typename T> std::unique_ptr<T> createDataTypeFollowedByType(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);
		template <typename T, typename U> std::unique_ptr<T> createGenericReference(std::vector<std::uint8_t>& data, const U* owner);
		std::unique_ptr<DotnetDataTypeGenericInst> createGenericInstantiation(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);
		std::unique_ptr<DotnetDataTypeArray> createArray(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);
		template <typename T> std::unique_ptr<T> createModifier(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);
		std::unique_ptr<DotnetDataTypeFnPtr> createFnPtr(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);

		std::unique_ptr<DotnetDataTypeBase> dataTypeFromSignature(std::vector<std::uint8_t>& signature, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod);

		const DotnetClass* selectClass(const TypeDefOrRef& typeDefOrRef) const;

		const MetadataStream* metadataStream;
		const StringStream* stringStream;
		const BlobStream* blobStream;
		ClassTable defClassTable;
		ClassTable refClassTable;
		MethodTable methodTable;
		ClassToMethodTable classToMethodTable;
		SignatureTable methodReturnTypeAndParamTypeTable;
};

} // namespace fileformat
} // namespace retdec

#endif
