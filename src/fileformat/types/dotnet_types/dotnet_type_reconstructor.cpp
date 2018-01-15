/**
 * @file src/fileformat/types/dotnet_types/dotnet_type_reconstructor.cpp
 * @brief Class for .NET reconstructor.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_data_types.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_field.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_type_reconstructor.h"

namespace retdec {
namespace fileformat {

namespace
{

/**
 * Signature constants.
 */
const std::uint8_t FieldSignature    = 0x06; ///< Field signature.
const std::uint8_t PropertySignature = 0x08; ///< Property signature.
const std::uint8_t HasThis           = 0x20; ///< Flag indicating whether the method/property is static or not (has this).
const std::uint8_t Generic           = 0x10; ///< Flag indicating whether the method is generic or not.

/**
 * Decodes unsigned integer out of the signature.
 * @param data Signature data.
 * @param [out] bytesRead Amount of bytes read out of signature.
 * @return Decoded unsigned integer.
 */
std::uint64_t decodeUnsigned(const std::vector<std::uint8_t>& data, std::uint64_t& bytesRead)
{
	std::uint64_t result = 0;
	bytesRead = 0;

	// If highest bit not set, it is 1-byte number
	if ((data[0] & 0x80) == 0)
	{
		if (data.size() < 1)
			return result;

		result = data[0];
		bytesRead = 1;
	}
	// If highest bit set and second highest not set, it is 2-byte number
	else if ((data[0] & 0xC0) == 0x80)
	{
		if (data.size() < 2)
			return result;

		result = ((static_cast<std::uint64_t>(data[0]) & 0x3F) << 8)
			| data[1];
		bytesRead = 2;
	}
	// If highest bit and second highest are set and third bit is not set, it is 4-byte number
	else if ((data[0] & 0xE0) == 0xC0)
	{
		if (data.size() < 4)
			return result;

		result = ((static_cast<std::uint64_t>(data[0]) & 0x1F) << 24)
			| (static_cast<std::uint64_t>(data[1]) << 16)
			| (static_cast<std::uint64_t>(data[2]) << 8)
			| data[3];
		bytesRead = 4;
	}

	return result;
}

/**
 * Decodes signed integer out of the signature.
 * @param data Signature data.
 * @param [out] bytesRead Amount of bytes read out of signature.
 * @return Decoded signed integer.
 */
std::int64_t decodeSigned(const std::vector<std::uint8_t>& data, std::uint64_t& bytesRead)
{
	std::int64_t result = 0;
	bytesRead = 0;

	// If highest bit not set, it is 1-byte number
	if ((data[0] & 0x80) == 0)
	{
		if (data.size() < 1)
			return result;

		std::int8_t result8 = (data[0] & 0x01 ? 0x80 : 0x00)
			| static_cast<std::uint64_t>(data[0]);
		result = result8 >> 1;
		bytesRead = 1;
	}
	// If highest bit set and second highest not set, it is 2-byte number
	else if ((data[0] & 0xC0) == 0x80)
	{
		if (data.size() < 2)
			return result;

		std::int16_t result16 = (data[1] & 0x01 ? 0xC000 : 0x0000)
			| ((static_cast<std::uint64_t>(data[0]) & 0x1F) << 8)
			| static_cast<std::uint64_t>(data[1]);
		result = result16 >> 1;
		bytesRead = 2;
	}
	// If highest bit and second highest are set and third bit is not set, it is 4-byte number
	else if ((data[0] & 0xE0) == 0xC0)
	{
		if (data.size() < 4)
			return result;

		std::int32_t result32 = (data[3] & 0x01 ? 0xE0000000 : 0x00000000)
			| ((static_cast<std::uint64_t>(data[0]) & 0x0F) << 24)
			| (static_cast<std::uint64_t>(data[1]) << 16)
			| (static_cast<std::uint64_t>(data[2]) << 8)
			| static_cast<std::uint64_t>(data[3]);
		result = result32 >> 1;
		bytesRead = 4;
	}

	return result;
}

/**
 * Extracts the classes from the class table.
 * @param classTable Class table.
 * @return Classes in form of list.
 */
auto classesFromTable(const DotnetTypeReconstructor::ClassTable& classTable)
{
	DotnetTypeReconstructor::ClassList classes;
	classes.reserve(classTable.size());

	for (auto& kv : classTable)
		classes.push_back(kv.second);

	return classes;
}

/**
 * Extracts the generic parameter count out of class name that is stored in metadata tables.
 * Class names encode this information in form of "ClassName`N" where N is number of generic parameters.
 * @param className Class name.
 * @return Number of generic parameters.
 */
std::uint64_t extractGenericParamsCountAndFixClassName(std::string& className)
{
	// Generic types end with `N where N is number of generic parameters
	std::uint64_t genericParamsCount = 0;
	auto isGenericPos = className.find('`');
	if (isGenericPos != std::string::npos)
	{
		// Obtain number of generic parameters
		retdec::utils::strToNum(className.substr(isGenericPos + 1), genericParamsCount);

		// Remove `N part
		className.erase(isGenericPos);
	}

	return genericParamsCount;
}

/**
 * Transforms metadata table record to visibility.
 * @param source Metadata table record.
 * @return Visibility.
 */
template <typename T>
DotnetTypeVisibility toTypeVisibility(const T* source)
{
	if (source->isPublic())
		return DotnetTypeVisibility::Public;
	else if (source->isProtected())
		return DotnetTypeVisibility::Protected;
	else if (source->isPrivate())
		return DotnetTypeVisibility::Private;
	else
		return DotnetTypeVisibility::Private;
}

template <>
DotnetTypeVisibility toTypeVisibility<TypeDef>(const TypeDef* source)
{
	if (source->isPublic() || source->isNestedPublic())
		return DotnetTypeVisibility::Public;
	else if (source->isNestedProtected())
		return DotnetTypeVisibility::Protected;
	else if (source->isNonPublic() || source->isNestedPrivate())
		return DotnetTypeVisibility::Private;
	else
		return DotnetTypeVisibility::Private;
}

}

/**
 * Constructor.
 * @param metadata Metadata stream.
 * @param strings String stream.
 * @param blob Blob stream.
 */
DotnetTypeReconstructor::DotnetTypeReconstructor(const MetadataStream* metadata, const StringStream* strings, const BlobStream* blob)
	: metadataStream(metadata), stringStream(strings), blobStream(blob), defClassTable(), refClassTable(), methodTable(),
	classToMethodTable(), methodReturnTypeAndParamTypeTable()
{
}

/**
 * Reconstructs classes, methods, fields, properties and class hierarchy.
 * @return @c true if reconstruction was successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstruct()
{
	if (!metadataStream || !stringStream || !blobStream)
		return false;

	// Order matters here, because some stages of reconstruction need to have information from previous stages
	// Required conditions are:
	// - Reconstruction of generic parameters needs to known which classes and methods are defined
	// - Reconstruction of method parameters needs to known which generic parameters exist
	// - Reconstruction of fields and properties needs to know which classes are defined and which generic parameters they contain
	// - Reconstruction of nested classes and base types needs to know all the classes that are defined
	return reconstructClasses()
		&& reconstructMethods()
		&& reconstructGenericParameters()
		&& reconstructMethodParameters()
		&& reconstructFields()
		&& reconstructProperties()
		&& reconstructNestedClasses()
		&& reconstructBaseTypes();
}

/**
 * Returns the defined classes.
 * @return Defined classes.
 */
DotnetTypeReconstructor::ClassList DotnetTypeReconstructor::getDefinedClasses() const
{
	return classesFromTable(defClassTable);
}

/**
 * Returns the referenced (imported) classes.
 * @return Referenced (imported) classes.
 */
DotnetTypeReconstructor::ClassList DotnetTypeReconstructor::getReferencedClasses() const
{
	return classesFromTable(refClassTable);
}

/**
 * Reconstructs defined and referenced (imported) classes and interfaces.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructClasses()
{
	auto typeDefTable = static_cast<const MetadataTable<TypeDef>*>(metadataStream->getMetadataTable(MetadataTableType::TypeDef));
	auto typeRefTable = static_cast<const MetadataTable<TypeRef>*>(metadataStream->getMetadataTable(MetadataTableType::TypeRef));
	auto fieldTable = static_cast<const MetadataTable<Field>*>(metadataStream->getMetadataTable(MetadataTableType::Field));
	auto methodDefTable = static_cast<const MetadataTable<MethodDef>*>(metadataStream->getMetadataTable(MetadataTableType::MethodDef));
	if (typeDefTable == nullptr || typeRefTable == nullptr)
		return false;

	// Reconstruct defined classes from TypeDef table
	for (std::size_t i = 1; i <= typeDefTable->getNumberOfRows(); ++i)
	{
		auto typeDef = typeDefTable->getRow(i);

		std::size_t fieldsCount = 0;
		std::size_t methodsCount = 0;

		// Field & method count needs to be determined based on index the following record in the table stores
		// We use size of the referenced table for the last record
		auto nextTypeDef = typeDefTable->getRow(i + 1);

		// Obtain number of fields if there are any
		if (fieldTable && typeDef->fieldList.getIndex() <= fieldTable->getSize())
		{
			fieldsCount = nextTypeDef
				? nextTypeDef->fieldList.getIndex() - typeDef->fieldList.getIndex()
				: fieldTable->getSize() - typeDef->fieldList.getIndex() + 1;
		}

		// Obtain number of methods if there are any
		if (methodDefTable && typeDef->methodList.getIndex() <= methodDefTable->getSize())
		{
			methodsCount = nextTypeDef
				? nextTypeDef->methodList.getIndex() - typeDef->methodList.getIndex()
				: methodDefTable->getSize() - typeDef->methodList.getIndex() + 1;
		}

		auto newClass = createClassDefinition(typeDef, fieldsCount, methodsCount);
		if (newClass == nullptr)
			continue;

		defClassTable.emplace(i, std::move(newClass));
	}

	// Reconstruct referenced classes from TypeRef table
	for (std::size_t i = 1; i <= typeRefTable->getNumberOfRows(); ++i)
	{
		auto typeRef = typeRefTable->getRow(i);

		auto newClass = createClassReference(typeRef);
		if (newClass == nullptr)
			continue;

		refClassTable.emplace(i, std::move(newClass));
	}

	return true;
}

/**
 * Reconstructs methods in the classes and interfaces. Method parameters are not reconstructed here.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructMethods()
{
	auto methodDefTable = static_cast<const MetadataTable<MethodDef>*>(metadataStream->getMetadataTable(MetadataTableType::MethodDef));
	if (methodDefTable == nullptr)
		return true;

	for (const auto& kv : defClassTable)
	{
		// Obtain TypeDef from the class
		const auto& classType = kv.second;
		auto typeDef = classType->getRawRecord();

		auto methodStartIndex = typeDef->methodList.getIndex();
		for (auto i = methodStartIndex; i < methodStartIndex + classType->getDeclaredMethodsCount(); ++i)
		{
			auto methodDef = methodDefTable->getRow(i);
			if (methodDef == nullptr)
				break;

			auto newMethod = createMethod(methodDef, classType.get());
			if (newMethod == nullptr)
				continue;

			// Place method into method table so we can later associate its table index with DotnetMethod object
			methodTable.emplace(i, newMethod.get());

			// Do not add method to the class yet, because we don't know if return type and parameter are OK
			classToMethodTable[classType.get()].push_back(std::move(newMethod));
		}
	}

	return true;
}

/**
 * Reconstructs generic parameters of classes and methods.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructGenericParameters()
{
	auto genericParamTable = static_cast<const MetadataTable<GenericParam>*>(metadataStream->getMetadataTable(MetadataTableType::GenericParam));
	if (genericParamTable == nullptr)
		return true;

	for (const auto& genericParam : *genericParamTable)
	{
		// Obtain generic parameter name
		std::string genericParamName;
		if (!stringStream->getString(genericParam.name.getIndex(), genericParamName))
			continue;
		genericParamName = retdec::utils::replaceNonprintableChars(genericParamName);

		// Generic parameter points either to TypeDef or MethodDef table depending on what it belongs to
		MetadataTableType classOrMethod;
		if (!genericParam.owner.getTable(classOrMethod))
			continue;

		if (classOrMethod == MetadataTableType::TypeDef)
		{
			auto itr = defClassTable.find(genericParam.owner.getIndex());
			if (itr == defClassTable.end())
				continue;

			itr->second->addGenericParameter(std::move(genericParamName));
		}
		else if (classOrMethod == MetadataTableType::MethodDef)
		{
			auto itr = methodTable.find(genericParam.owner.getIndex());
			if (itr == methodTable.end())
				continue;

			itr->second->addGenericParameter(std::move(genericParamName));
		}
	}

	return true;
}

/**
 * Reconstructs parameters of methods.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructMethodParameters()
{
	auto paramTable = static_cast<const MetadataTable<Param>*>(metadataStream->getMetadataTable(MetadataTableType::Param));
	if (paramTable == nullptr)
		return true;

	// We need to iterate over classes because we need to know the owner of every single method
	for (const auto& kv : defClassTable)
	{
		const auto& classType = kv.second;

		// Now iterate over all methods
		for (auto&& method : classToMethodTable[classType.get()])
		{
			// Obtain postponed signature
			// We now know all the information required for method parameters reconstruction
			auto methodDef = method->getRawRecord();
			auto signature = methodReturnTypeAndParamTypeTable[method.get()];

			// Reconstruct return type
			auto returnType = dataTypeFromSignature(signature, classType.get(), method.get());
			if (returnType == nullptr)
				continue;
			method->setReturnType(std::move(returnType));

			// Reconstruct parameters
			bool methodOk = true;
			auto startIndex = methodDef->paramList.getIndex();
			for (auto i = startIndex; i < startIndex + method->getDeclaredParametersCount(); ++i)
			{
				auto param = paramTable->getRow(i);
				if (param == nullptr)
					break;

				auto newParam = createMethodParameter(param, classType.get(), method.get(), signature);
				if (newParam == nullptr)
				{
					methodOk = false;
					break;
				}

				method->addParameter(std::move(newParam));
			}

			// Now we can add method to class
			if (methodOk)
				classType->addMethod(std::move(method));
		}
	}

	return true;
}

/**
 * Reconstructs fields of classes.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructFields()
{
	auto fieldTable = static_cast<const MetadataTable<Field>*>(metadataStream->getMetadataTable(MetadataTableType::Field));
	if (fieldTable == nullptr)
		return true;

	for (const auto& kv : defClassTable)
	{
		const auto& classType = kv.second;
		auto typeDef = classType->getRawRecord();

		auto fieldStartIndex = typeDef->fieldList.getIndex();
		for (auto i = fieldStartIndex; i < fieldStartIndex + classType->getDeclaredFieldsCount(); ++i)
		{
			auto field = fieldTable->getRow(i);
			if (field == nullptr)
				break;

			auto newField = createField(field, classType.get());
			if (newField == nullptr)
				continue;

			classType->addField(std::move(newField));
		}
	}

	return true;
}

/**
 * Reconstructs fields of classes.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructProperties()
{
	// Properties does not have very nice structure and cannot be easily reconstructed
	// Their reconstruction needs to be done using two tables Property and PropertyMap
	// Property table contains information about every single property, however it does not contain the reference to the class it belongs to
	// PropertyMap table actually contains mapping of properties to classes
	auto propertyTable = static_cast<const MetadataTable<Property>*>(metadataStream->getMetadataTable(MetadataTableType::Property));
	auto propertyMapTable = static_cast<const MetadataTable<PropertyMap>*>(metadataStream->getMetadataTable(MetadataTableType::PropertyMap));
	if (propertyTable == nullptr || propertyMapTable == nullptr)
		return true;

	for (std::size_t i = 1; i <= propertyMapTable->getNumberOfRows(); ++i)
	{
		auto propertyMap = propertyMapTable->getRow(i);

		// First obtain owning class
		auto ownerIndex = propertyMap->parent.getIndex();
		auto itr = defClassTable.find(ownerIndex);
		if (itr == defClassTable.end())
		{
			continue;
		}
		const auto& ownerClass = itr->second;

		// Property count needs to be determined based on index the following record in the table stores
		// We use size of the table for the last record
		auto nextPropertyMap = propertyMapTable->getRow(i + 1);
		auto propertyCount = nextPropertyMap
			? nextPropertyMap->propertyList.getIndex() - propertyMap->propertyList.getIndex()
			: propertyTable->getSize() - propertyMap->propertyList.getIndex() + 1;

		auto startIndex = propertyMap->propertyList.getIndex();
		for (std::size_t propertyIndex = startIndex; propertyIndex < startIndex + propertyCount; ++propertyIndex)
		{
			auto property = propertyTable->getRow(propertyIndex);
			if (property == nullptr)
				break;

			auto newProperty = createProperty(property, ownerClass.get());
			if (newProperty == nullptr)
				continue;

			ownerClass->addProperty(std::move(newProperty));
		}
	}

	return true;
}

/**
 * Reconstructs namespaces of nested classes.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructNestedClasses()
{
	// Nested classes does not have proper namespaces set so we need to fix them
	auto nestedClassTable = static_cast<const MetadataTable<NestedClass>*>(metadataStream->getMetadataTable(MetadataTableType::NestedClass));
	if (nestedClassTable == nullptr)
		return true;

	for (std::size_t i = 1; i <= nestedClassTable->getNumberOfRows(); ++i)
	{
		auto nestedClass = nestedClassTable->getRow(i);

		auto nestedItr = defClassTable.find(nestedClass->nestedClass.getIndex());
		if (nestedItr == defClassTable.end())
			continue;

		auto enclosingItr = defClassTable.find(nestedClass->enclosingClass.getIndex());
		if (enclosingItr == defClassTable.end())
			continue;

		nestedItr->second->setNameSpace(enclosingItr->second->getFullyQualifiedName());
	}

	return true;
}

/**
 * Reconstructs base types of classes.
 * @return @c true if reconstruction successful, otherwise @c false.
 */
bool DotnetTypeReconstructor::reconstructBaseTypes()
{
	// Even though CLI does not support multiple inheritance, any class can still implement more than one interface
	auto typeSpecTable = static_cast<const MetadataTable<TypeSpec>*>(metadataStream->getMetadataTable(MetadataTableType::TypeSpec));

	// First reconstruct classic inheritance
	for (const auto& kv : defClassTable)
	{
		const auto& classType = kv.second;

		std::unique_ptr<DotnetDataTypeBase> baseType;

		auto typeDef = classType->getRawRecord();

		MetadataTableType extendsTable;
		if (!typeDef->extends.getTable(extendsTable))
			continue;

		if (extendsTable == MetadataTableType::TypeDef)
		{
			auto itr = defClassTable.find(typeDef->extends.getIndex());
			if (itr == defClassTable.end())
				continue;

			baseType = std::make_unique<DotnetDataTypeClass>(itr->second.get());
		}
		else if (extendsTable == MetadataTableType::TypeRef)
		{
			auto itr = refClassTable.find(typeDef->extends.getIndex());
			if (itr == refClassTable.end())
				continue;

			baseType = std::make_unique<DotnetDataTypeClass>(itr->second.get());
		}
		else if (typeSpecTable && extendsTable == MetadataTableType::TypeSpec)
		{
			// TypeSpec table is used when class inherits from some generic type like Class<T>, Class<int> or similar
			auto typeSpec = typeSpecTable->getRow(typeDef->extends.getIndex());
			if (typeSpec == nullptr)
				continue;

			auto signature = blobStream->getElement(typeSpec->signature.getIndex());
			baseType = dataTypeFromSignature(signature, classType.get(), nullptr);
			if (baseType == nullptr)
				continue;
		}
		else
			continue;

		classType->addBaseType(std::move(baseType));
	}

	// Reconstruct interface implementations from InterfaceImpl table
	auto interfaceImplTable = static_cast<const MetadataTable<InterfaceImpl>*>(metadataStream->getMetadataTable(MetadataTableType::InterfaceImpl));
	if (interfaceImplTable == nullptr)
		return true;

	for (std::size_t i = 1; i <= interfaceImplTable->getSize(); ++i)
	{
		auto interfaceImpl = interfaceImplTable->getRow(i);
		if (interfaceImpl == nullptr)
			continue;

		std::unique_ptr<DotnetDataTypeBase> baseType;

		auto itr = defClassTable.find(interfaceImpl->classType.getIndex());
		if (itr == defClassTable.end())
			continue;

		MetadataTableType interfaceTable;
		if (!interfaceImpl->interfaceType.getTable(interfaceTable))
			continue;

		if (interfaceTable == MetadataTableType::TypeDef)
		{
			auto itr = defClassTable.find(interfaceImpl->interfaceType.getIndex());
			if (itr == defClassTable.end())
				continue;

			baseType =  std::make_unique<DotnetDataTypeClass>(itr->second.get());
		}
		else if (interfaceTable == MetadataTableType::TypeRef)
		{
			auto itr = refClassTable.find(interfaceImpl->interfaceType.getIndex());
			if (itr == refClassTable.end())
				continue;

			baseType = std::make_unique<DotnetDataTypeClass>(itr->second.get());
		}
		else if (typeSpecTable && interfaceTable == MetadataTableType::TypeSpec)
		{
			// TypeSpec table is used when class implements some generic interface like Interface<T>, Interface<int> or similar
			auto typeSpec = typeSpecTable->getRow(interfaceImpl->interfaceType.getIndex());
			if (typeSpec == nullptr)
				continue;

			auto signature = blobStream->getElement(typeSpec->signature.getIndex());
			baseType = dataTypeFromSignature(signature, itr->second.get(), nullptr);
			if (baseType == nullptr)
				continue;
		}
		else
			continue;

		itr->second->addBaseType(std::move(baseType));
	}

	return true;
}

/**
 * Creates new class definition from TypeDef table record.
 * @param typeDef TypeDef table record.
 * @param fieldsCount Declared number of fields.
 * @param methodsCount Declared number of methods.
 * @return New class definition or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetClass> DotnetTypeReconstructor::createClassDefinition(const TypeDef* typeDef, std::size_t fieldsCount, std::size_t methodsCount)
{
	std::string className, classNameSpace;
	if (!stringStream->getString(typeDef->typeName.getIndex(), className) || !stringStream->getString(typeDef->typeNamespace.getIndex(), classNameSpace))
		return nullptr;

	className = retdec::utils::replaceNonprintableChars(className);
	classNameSpace = retdec::utils::replaceNonprintableChars(classNameSpace);
	auto genericParamsCount = extractGenericParamsCountAndFixClassName(className);

	// Skip this special type, it seems to be used in C# binaries
	if (className.empty() || className == "<Module>")
		return nullptr;

	auto newClass = std::make_unique<DotnetClass>();
	newClass->setRawRecord(typeDef);
	newClass->setName(className);
	newClass->setNameSpace(classNameSpace);
	newClass->setVisibility(toTypeVisibility(typeDef));
	newClass->setIsInterface(typeDef->isInterface());
	newClass->setIsAbstract(typeDef->isAbstract());
	newClass->setIsSealed(typeDef->isSealed());
	newClass->setDeclaredFieldsCount(fieldsCount);
	newClass->setDeclaredMethodsCount(methodsCount);
	newClass->setDeclaredGenericParametersCount(genericParamsCount);

	return newClass;
}

/**
 * Creates new class reference from TypeRef table record.
 * @param typeRef TypeRef table record.
 * @return New class reference or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetClass> DotnetTypeReconstructor::createClassReference(const TypeRef* typeRef)
{
	std::string className, classNameSpace;
	if (!stringStream->getString(typeRef->typeName.getIndex(), className) || !stringStream->getString(typeRef->typeNamespace.getIndex(), classNameSpace))
		return nullptr;

	className = retdec::utils::replaceNonprintableChars(className);
	classNameSpace = retdec::utils::replaceNonprintableChars(classNameSpace);
	auto genericParamsCount = extractGenericParamsCountAndFixClassName(className);

	if (className.empty())
		return nullptr;

	auto newClass = std::make_unique<DotnetClass>();
	newClass->setName(className);
	newClass->setNameSpace(classNameSpace);
	newClass->setDeclaredGenericParametersCount(genericParamsCount);

	return newClass;
}

/**
 * Creates new field from Field table record.
 * @param field Field table record.
 * @param ownerClass Owning class.
 * @return New field or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetField> DotnetTypeReconstructor::createField(const Field* field, const DotnetClass* ownerClass)
{
	std::string fieldName;
	if (!stringStream->getString(field->name.getIndex(), fieldName))
		return nullptr;

	fieldName = retdec::utils::replaceNonprintableChars(fieldName);
	auto signature = blobStream->getElement(field->signature.getIndex());

	if (signature.empty() || signature[0] != FieldSignature)
		return nullptr;
	signature.erase(signature.begin(), signature.begin() + 1);

	auto type = dataTypeFromSignature(signature, ownerClass, nullptr);
	if (type == nullptr)
		return nullptr;

	auto newField = std::make_unique<DotnetField>();
	newField->setName(fieldName);
	newField->setNameSpace(ownerClass->getFullyQualifiedName());
	newField->setVisibility(toTypeVisibility(field));
	newField->setDataType(std::move(type));
	newField->setIsStatic(field->isStatic());

	return newField;
}

/**
 * Creates new property from Property table record.
 * @param property Property table record.
 * @param ownerClass Owning class.
 * @return New property or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetProperty> DotnetTypeReconstructor::createProperty(const Property* property, const DotnetClass* ownerClass)
{
	std::string propertyName;
	if (!stringStream->getString(property->name.getIndex(), propertyName))
		return nullptr;

	propertyName = retdec::utils::replaceNonprintableChars(propertyName);
	auto signature = blobStream->getElement(property->type.getIndex());

	if (signature.size() < 2 || (signature[0] & ~HasThis) != PropertySignature)
		return nullptr;
	bool hasThis = signature[0] & HasThis;
	// Delete two bytes because the first is 0x08 (or 0x28 if HASTHIS is set) and the other one is number of parameters
	// This seems like a weird thing, because I don't think that C# allows any parameters in getters/setters and therefore this will always be 0
	signature.erase(signature.begin(), signature.begin() + 2);

	auto type = dataTypeFromSignature(signature, ownerClass, nullptr);
	if (type == nullptr)
		return nullptr;

	auto newProperty = std::make_unique<DotnetProperty>();
	newProperty->setName(propertyName);
	newProperty->setNameSpace(ownerClass->getFullyQualifiedName());
	newProperty->setIsStatic(!hasThis);
	newProperty->setDataType(std::move(type));

	return newProperty;
}

/**
 * Creates new method from MethodDef table record.
 * @param methodDef MethodDef table record.
 * @param ownerClass Owning class.
 * @return New method or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetMethod> DotnetTypeReconstructor::createMethod(const MethodDef* methodDef, const DotnetClass* ownerClass)
{
	std::string methodName;
	if (!stringStream->getString(methodDef->name.getIndex(), methodName))
		return nullptr;

	methodName = retdec::utils::replaceNonprintableChars(methodName);
	auto signature = blobStream->getElement(methodDef->signature.getIndex());

	if (methodName.empty() || signature.empty())
		return nullptr;

	// If method contains generic paramters, we need to read the number of these generic paramters
	if (signature[0] & Generic)
	{
		signature.erase(signature.begin(), signature.begin() + 1);

		// We ignore this value just because we have this information already from the class name in format 'ClassName`N'
		std::uint64_t bytesRead = 0;
		decodeUnsigned(signature, bytesRead);
		if (bytesRead == 0)
			return nullptr;

		signature.erase(signature.begin(), signature.begin() + bytesRead);
	}
	else
	{
		signature.erase(signature.begin(), signature.begin() + 1);
	}

	// It is followed by number of parameters
	std::uint64_t bytesRead = 0;
	std::uint64_t paramsCount = decodeUnsigned(signature, bytesRead);
	if (bytesRead == 0)
		return nullptr;
	signature.erase(signature.begin(), signature.begin() + bytesRead);

	auto newMethod = std::make_unique<DotnetMethod>();
	newMethod->setRawRecord(methodDef);
	newMethod->setName(methodName);
	newMethod->setNameSpace(ownerClass->getFullyQualifiedName());
	newMethod->setVisibility(toTypeVisibility(methodDef));
	newMethod->setIsStatic(methodDef->isStatic());
	newMethod->setIsVirtual(methodDef->isVirtual());
	newMethod->setIsAbstract(methodDef->isAbstract());
	newMethod->setIsFinal(methodDef->isFinal());
	newMethod->setIsConstructor(methodName == ".ctor" || methodName == ".cctor");
	newMethod->setDeclaredParametersCount(paramsCount);

	// We need to postpone loading of return type and parameters because first we need to known all generic types
	// However, we can't reconstruct generic types until we know all classes and methods, so we first create method just with its name, properties and parameter count
	methodReturnTypeAndParamTypeTable.emplace(newMethod.get(), signature);

	return newMethod;
}

/**
 * Creates new method parameter from Param table record.
 * @param param Param table record.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @param signature Signature with data types. Is destroyed in the meantime.
 * @return New method parameter or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetParameter> DotnetTypeReconstructor::createMethodParameter(const Param* param, const DotnetClass* ownerClass,
		const DotnetMethod* ownerMethod, std::vector<std::uint8_t>& signature)
{
	std::string paramName;
	if (!stringStream->getString(param->name.getIndex(), paramName))
		return nullptr;

	paramName = retdec::utils::replaceNonprintableChars(paramName);
	auto type = dataTypeFromSignature(signature, ownerClass, ownerMethod);
	if (type == nullptr)
		return nullptr;

	auto newParam = std::make_unique<DotnetParameter>();
	newParam->setName(paramName);
	newParam->setNameSpace(ownerMethod->getFullyQualifiedName());
	newParam->setDataType(std::move(type));

	return newParam;
}

/**
 * Creates data type from signature that references defined or imported class.
 * @param data Signature data.
 * @return New data type or @c nullptr in case of failure.
 */
template <typename T>
std::unique_ptr<T> DotnetTypeReconstructor::createDataTypeFollowedByReference(std::vector<std::uint8_t>& data)
{
	std::uint64_t bytesRead;
	TypeDefOrRef typeRef;
	typeRef.setIndex(decodeUnsigned(data, bytesRead));
	if (bytesRead == 0)
		return nullptr;

	auto classRef = selectClass(typeRef);
	if (classRef == nullptr)
		return nullptr;

	data.erase(data.begin(), data.begin() + bytesRead);
	return std::make_unique<T>(classRef);
}

/**
 * Creates data type from signature that refers to another data type.
 * @param data Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
template <typename T>
std::unique_ptr<T> DotnetTypeReconstructor::createDataTypeFollowedByType(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	auto type = dataTypeFromSignature(data, ownerClass, ownerMethod);
	if (type == nullptr)
		return nullptr;

	return std::make_unique<T>(std::move(type));
}

/**
 * Creates data type from signature that references generic parameter.
 * @param data Signature data.
 * @param owner Owning class or method.
 * @return New data type or @c nullptr in case of failure.
 */
template <typename T, typename U>
std::unique_ptr<T> DotnetTypeReconstructor::createGenericReference(std::vector<std::uint8_t>& data, const U* owner)
{
	if (owner == nullptr)
		return nullptr;

	// Index of generic parameter
	std::uint64_t bytesRead = 0;
	std::uint64_t index = decodeUnsigned(data, bytesRead);
	if (bytesRead == 0)
		return nullptr;

	const auto& genericParams = owner->getGenericParameters();
	if (index >= genericParams.size())
		return nullptr;

	data.erase(data.begin(), data.begin() + bytesRead);
	return std::make_unique<T>(&genericParams[index]);
}

/**
 * Creates data type from signature that instantiates generic data type.
 * @param data Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetDataTypeGenericInst> DotnetTypeReconstructor::createGenericInstantiation(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	if (data.empty())
		return nullptr;

	// Instantiated type
	auto type = dataTypeFromSignature(data, ownerClass, ownerMethod);
	if (type == nullptr)
		return nullptr;

	if (data.empty())
		return nullptr;

	// Number of instantiated generic parameters
	auto genericCount = data[0];
	data.erase(data.begin(), data.begin() + 1);

	// Generic parameters used for instantiation
	std::vector<std::unique_ptr<DotnetDataTypeBase>> genericTypes;
	for (std::size_t i = 0; i < genericCount; ++i)
	{
		auto genericType = dataTypeFromSignature(data, ownerClass, ownerMethod);
		if (genericType == nullptr)
			return nullptr;

		genericTypes.push_back(std::move(genericType));
	}

	return std::make_unique<DotnetDataTypeGenericInst>(std::move(type), std::move(genericTypes));
}

/**
 * Creates data type from signature that represent array.
 * @param data Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetDataTypeArray> DotnetTypeReconstructor::createArray(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	// First comes data type representing elements in array
	auto type = dataTypeFromSignature(data, ownerClass, ownerMethod);
	if (type == nullptr)
		return nullptr;

	// Rank of an array comes then, this means how many dimensions our array has
	std::uint64_t bytesRead = 0;
	std::uint64_t rank = decodeUnsigned(data, bytesRead);
	if (bytesRead == 0)
		return nullptr;
	data.erase(data.begin(), data.begin() + bytesRead);

	// Rank must be non-zero number
	if (rank == 0)
		return nullptr;
	std::vector<std::pair<std::int64_t, std::int64_t>> dimensions(rank);

	// Some dimensions can have limited size by declaration
	// Size 0 means not specified
	std::uint64_t numOfSizes = decodeUnsigned(data, bytesRead);
	if (bytesRead == 0)
		return nullptr;
	data.erase(data.begin(), data.begin() + bytesRead);

	// Now get all those sizes
	for (std::uint64_t i = 0; i < numOfSizes; ++i)
	{
		dimensions[i].second = decodeSigned(data, bytesRead);
		if (bytesRead == 0)
			return nullptr;
		data.erase(data.begin(), data.begin() + bytesRead);
	}

	// And some dimensions can also be limited by special lower bound
	std::size_t numOfLowBounds = decodeUnsigned(data, bytesRead);
	if (bytesRead == 0)
		return nullptr;
	data.erase(data.begin(), data.begin() + bytesRead);

	// Make sure we don't get out of bounds with dimensions
	numOfLowBounds = std::min(dimensions.size(), numOfLowBounds);
	for (std::uint64_t i = 0; i < numOfLowBounds; ++i)
	{
		dimensions[i].first = decodeSigned(data, bytesRead);
		if (bytesRead == 0)
			return nullptr;
		data.erase(data.begin(), data.begin() + bytesRead);

		// Adjust higher bound according to lower bound
		dimensions[i].second += dimensions[i].first;
	}

	return std::make_unique<DotnetDataTypeArray>(std::move(type), std::move(dimensions));
}

/**
 * Creates data type from signature that represent type modifier.
 * @param data Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
template <typename T>
std::unique_ptr<T> DotnetTypeReconstructor::createModifier(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	// These modifiers are used to somehow specify data type using some data type
	// The only usage we know about right know is 'volatile' keyword

	// First read reference to type used for modifier
	std::uint64_t bytesRead;
	TypeDefOrRef typeRef;
	typeRef.setIndex(decodeUnsigned(data, bytesRead));
	if (bytesRead == 0)
		return nullptr;

	auto modifier = selectClass(typeRef);
	if (modifier == nullptr)
		return nullptr;
	data.erase(data.begin(), data.begin() + bytesRead);

	// Go further in signature because we only have modifier, we need to obtain type that is modified
	auto type = dataTypeFromSignature(data, ownerClass, ownerMethod);
	if (type == nullptr)
		return nullptr;

	return std::make_unique<T>(modifier, std::move(type));
}

/**
 * Creates data type from signature that represents function pointer.
 * @param data Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetDataTypeFnPtr> DotnetTypeReconstructor::createFnPtr(std::vector<std::uint8_t>& data, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	if (data.empty())
		return nullptr;

	// Delete first byte, what does it even mean?
	data.erase(data.begin(), data.begin() + 1);

	// Read number of parameters
	std::uint64_t bytesRead = 0;
	std::uint64_t paramsCount = decodeUnsigned(data, bytesRead);
	if (bytesRead == 0)
		return nullptr;
	data.erase(data.begin(), data.begin() + bytesRead);

	auto returnType = dataTypeFromSignature(data, ownerClass, ownerMethod);
	if (returnType == nullptr)
		return nullptr;

	std::vector<std::unique_ptr<DotnetDataTypeBase>> paramTypes;
	for (std::size_t i = 0; i < paramsCount; ++i)
	{
		auto paramType = dataTypeFromSignature(data, ownerClass, ownerMethod);
		if (paramType == nullptr)
			return nullptr;

		paramTypes.push_back(std::move(paramType));
	}

	return std::make_unique<DotnetDataTypeFnPtr>(std::move(returnType), std::move(paramTypes));
}

/**
 * Creates data type from signature. Signature is destroyed in the meantime.
 * @param signature Signature data.
 * @param ownerClass Owning class.
 * @param ownerMethod Owning method.
 * @return New data type or @c nullptr in case of failure.
 */
std::unique_ptr<DotnetDataTypeBase> DotnetTypeReconstructor::dataTypeFromSignature(std::vector<std::uint8_t>& signature, const DotnetClass* ownerClass, const DotnetMethod* ownerMethod)
{
	if (signature.empty())
		return nullptr;

	std::unique_ptr<DotnetDataTypeBase> result;
	auto type = static_cast<ElementType>(signature[0]);
	signature.erase(signature.begin(), signature.begin() + 1);

	switch (type)
	{
		case ElementType::Void:
			result = std::make_unique<DotnetDataTypeVoid>();
			break;
		case ElementType::Boolean:
			result = std::make_unique<DotnetDataTypeBoolean>();
			break;
		case ElementType::Char:
			result = std::make_unique<DotnetDataTypeChar>();
			break;
		case ElementType::Int8:
			result = std::make_unique<DotnetDataTypeInt8>();
			break;
		case ElementType::UInt8:
			result = std::make_unique<DotnetDataTypeUInt8>();
			break;
		case ElementType::Int16:
			result = std::make_unique<DotnetDataTypeInt16>();
			break;
		case ElementType::UInt16:
			result = std::make_unique<DotnetDataTypeUInt16>();
			break;
		case ElementType::Int32:
			result = std::make_unique<DotnetDataTypeInt32>();
			break;
		case ElementType::UInt32:
			result = std::make_unique<DotnetDataTypeUInt32>();
			break;
		case ElementType::Int64:
			result = std::make_unique<DotnetDataTypeInt64>();
			break;
		case ElementType::UInt64:
			result = std::make_unique<DotnetDataTypeUInt64>();
			break;
		case ElementType::Float32:
			result = std::make_unique<DotnetDataTypeFloat32>();
			break;
		case ElementType::Float64:
			result = std::make_unique<DotnetDataTypeFloat64>();
			break;
		case ElementType::String:
			result = std::make_unique<DotnetDataTypeString>();
			break;
		case ElementType::Ptr:
			result = createDataTypeFollowedByType<DotnetDataTypePtr>(signature, ownerClass, ownerMethod);
			break;
		case ElementType::ByRef:
			result = createDataTypeFollowedByType<DotnetDataTypeByRef>(signature, ownerClass, ownerMethod);
			break;
		case ElementType::ValueType:
			result = createDataTypeFollowedByReference<DotnetDataTypeValueType>(signature);
			break;
		case ElementType::Class:
			result = createDataTypeFollowedByReference<DotnetDataTypeClass>(signature);
			break;
		case ElementType::GenericVar:
			result = createGenericReference<DotnetDataTypeGenericVar>(signature, ownerClass);
			break;
		case ElementType::Array:
			result = createArray(signature, ownerClass, ownerMethod);
			break;
		case ElementType::GenericInst:
			result = createGenericInstantiation(signature, ownerClass, ownerMethod);
			break;
		case ElementType::TypedByRef:
			result = std::make_unique<DotnetDataTypeTypedByRef>();
			break;
		case ElementType::IntPtr:
			result = std::make_unique<DotnetDataTypeIntPtr>();
			break;
		case ElementType::UIntPtr:
			result = std::make_unique<DotnetDataTypeUIntPtr>();
			break;
		case ElementType::FnPtr:
			result = createFnPtr(signature, ownerClass, ownerMethod);
			break;
		case ElementType::Object:
			result = std::make_unique<DotnetDataTypeObject>();
			break;
		case ElementType::SzArray:
			result = createDataTypeFollowedByType<DotnetDataTypeSzArray>(signature, ownerClass, ownerMethod);
			break;
		case ElementType::GenericMVar:
			result = createGenericReference<DotnetDataTypeGenericMVar>(signature, ownerMethod);
			break;
		case ElementType::CModOptional:
			result = createModifier<DotnetDataTypeCModOptional>(signature, ownerClass, ownerMethod);
			break;
		case ElementType::CModRequired:
			result = createModifier<DotnetDataTypeCModRequired>(signature, ownerClass, ownerMethod);
			break;
		case ElementType::Internal:
			return nullptr;
		case ElementType::Modifier:
			return nullptr;
		case ElementType::Sentinel:
			return nullptr;
		case ElementType::Pinned:
			return nullptr;
		case ElementType::MetaType:
			return nullptr;
		case ElementType::BoxedObject:
			return nullptr;
		case ElementType::CustomField:
			return nullptr;
		case ElementType::CustomProperty:
			return nullptr;
		case ElementType::CustomEnum:
			return nullptr;
		default:
			break;
	}

	return result;
}

/**
 * Selects a class from defined or referenced class table based on provided @c TypeDefOrRef index.
 * @param typeDefOrRef Index.
 * @return Class if any exists, otherwise @c nullptr.
 */
const DotnetClass* DotnetTypeReconstructor::selectClass(const TypeDefOrRef& typeDefOrRef) const
{
	MetadataTableType refTable;
	if (!typeDefOrRef.getTable(refTable))
		return nullptr;

	const DotnetClass* result = nullptr;
	if (refTable == MetadataTableType::TypeDef)
	{
		auto itr = defClassTable.find(typeDefOrRef.getIndex());
		if (itr == defClassTable.end())
			return nullptr;

		result = itr->second.get();
	}
	else if (refTable == MetadataTableType::TypeRef)
	{
		auto itr = refClassTable.find(typeDefOrRef.getIndex());
		if (itr == refClassTable.end())
			return nullptr;

		result = itr->second.get();
	}

	return result;
}

} // namespace fileformat
} // namespace retdec
