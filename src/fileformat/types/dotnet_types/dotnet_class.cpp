/**
 * @file src/fileformat/types/dotnet_types/dotnet_class.cpp
 * @brief Class for .NET class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
DotnetClass::DotnetClass(MetadataTableType rType, std::size_t idx) : rawRecord{static_cast<const TypeDef *>(nullptr)},
							parent(nullptr), index(idx), declaredFieldsCount(0), declaredMethodsCount(0),
							declaredGenericParametersCount(0), classOrInterface(false), abstract(false),
							sealed(false), recordType(rType)
{

}

/**
 * Returns string containing all the generic pamaters. Returned string is in the format <Param1,Param2,...,ParamN>
 * @return Generic parameter string.
 */
std::string DotnetClass::getGenericParametersString() const
{
	std::string repr;
	if (!genericParameters.empty())
		repr += '<' + retdec::utils::joinStrings(genericParameters, ",") + '>';

	return repr;
}

/**
 * Returns the raw metadata table record for this class.
 * @return Raw typeDef record.
 */
const TypeDef* DotnetClass::getRawTypeDef() const
{
	if (recordType != MetadataTableType::TypeDef)
	{
		return nullptr;
	}

	return mpark::get<const TypeDef*>(rawRecord);
}

/**
 * Returns the raw metadata table record for this class.
 * @return Raw typeRef record.
 */
const TypeRef* DotnetClass::getRawTypeRef() const
{
	if (recordType != MetadataTableType::TypeRef)
	{
		return nullptr;
	}

	return mpark::get<const TypeRef*>(rawRecord);
}

/**
 * Returns this classes parent.
 * @return Parent.
 */
const DotnetClass* DotnetClass::getParent() const
{
	return parent;
}

/**
 * Returns the name of the class appended with generic paramters.
 * @return Name with generic parameters.
 */
std::string DotnetClass::getNameWithGenericParameters() const
{
	return getName() + getGenericParametersString();
}

/**
 * Returns fully qualified name of the classes appended with generic parameters.
 * @return Fully qualified name with generic parameters.
 */
std::string DotnetClass::getFullyQualifiedNameWithGenericParameters() const
{
	return getFullyQualifiedName() + getGenericParametersString();
}

/**
 * Returns the name of the class appended with parent class presentation index.
 * @return Name with parent class presentation index.
 */
std::string DotnetClass::getNameWithParentClassIndex() const
{
	if (name.empty() || !parent)
	{
		return name;
	}

	return name + "." + numToStr(parent->getIndex() - 1);
}

/**
 * Returns the nested name of the class.
 * @return Nested name.
 */
std::string DotnetClass::getNestedName() const
{
	auto nestedName = name;

	if (nestedName.empty())
	{
		return "";
	}

	for (auto p = parent; p; p = p->getParent())
	{
		nestedName += "." + p->getName();
	}

	return nestedName;
}

/**
 * Returns library name of the referencing class
 * @return Library name of the referencing class.
 */
const std::string& DotnetClass::getLibName() const
{
	if (recordType == MetadataTableType::AssemblyRef)
	{
		return libName;
	}
	if (parent)
	{
		return parent->getLibName();
	}
	
	return libName;
}

/**
 * Returns the top level namespace of the class.
 * @return Top level namespace.
 */
const std::string& DotnetClass::getTopLevelNameSpace() const
{
	auto dnClass = this;

	while (dnClass->parent)
	{
		dnClass = dnClass->parent;
	}

	return dnClass->getNameSpace();
}

/**
 * Returns index of the class
 * @return Index of the class
 */
std::size_t DotnetClass::getIndex() const
{
	return index;
}

/**
 * Returns the declared number of fields according to metadata tables.
 * @return Declared number of fields.
 */
std::size_t DotnetClass::getDeclaredFieldsCount() const
{
	return declaredFieldsCount;
}

/**
 * Returns the declared number of methods according to metadata tables.
 * @return Declared number of methods.
 */
std::size_t DotnetClass::getDeclaredMethodsCount() const
{
	return declaredMethodsCount;
}

/**
 * Returns the declared number of generic parameters according to metadata tables.
 * @return Declared number of generic parameters.
 */
std::size_t DotnetClass::getDeclaredGenericParametersCount() const
{
	return declaredGenericParametersCount;
}

/**
 * Returns the fields of the class.
 * @return Fields.
 */
const std::vector<std::unique_ptr<DotnetField>>& DotnetClass::getFields() const
{
	return fields;
}

/**
 * Returns the properties of the class.
 * @return Properties.
 */
const std::vector<std::unique_ptr<DotnetProperty>>& DotnetClass::getProperties() const
{
	return properties;
}

/**
 * Returns the methods of the class.
 * @return Methods.
 */
const std::vector<std::unique_ptr<DotnetMethod>>& DotnetClass::getMethods() const
{
	return methods;
}

/**
 * Returns the generic parameters of the class.
 * @return Generic parameters.
 */
const std::vector<std::string>& DotnetClass::getGenericParameters() const
{
	return genericParameters;
}

/**
 * Returns the base types of the class.
 * @return Base types.
 */
const std::vector<std::unique_ptr<DotnetDataTypeBase>>& DotnetClass::getBaseTypes() const
{
	return baseTypes;
}

/**
 * Returns the number of fields.
 * @return Number of fields.
 */
std::size_t DotnetClass::getFieldsCount() const
{
	return fields.size();
}

/**
 * Returns the number of properties.
 * @return Number of properties.
 */
std::size_t DotnetClass::getPropertiesCount() const
{
	return properties.size();
}

/**
 * Returns the number of methods.
 * @return Number of methods.
 */
std::size_t DotnetClass::getMethodsCount() const
{
	return methods.size();
}

/**
 * Returns the number of generic parameters.
 * @return Number of generic parameters.
 */
std::size_t DotnetClass::getGenericParametersCount() const
{
	return genericParameters.size();
}

/**
 * Returns the type of the class in the string representation. Type means whether it is actual class or interface.
 * @return @c class in case of class, otherwise @c interface.
 */
std::string DotnetClass::getTypeString() const
{
	return isClass() ? "class" : "interface";
}

/**
 * Returns the record type of the class
 * @return Record type of the class
 */
MetadataTableType DotnetClass::getRecordType() const
{
	return recordType;
}

/**
 * Sets the raw metadata table record for this class.
 * @param rRecord Raw metadata table record.
 */
void DotnetClass::setRawRecord(mpark::variant<const TypeDef*, const TypeRef*> rRecord)
{
	rawRecord = rRecord;
}

/**
 * Sets this classes parent.
 * @param par Parent.
 */
void DotnetClass::setParent(const DotnetClass* par)
{
	parent = par;
}

/**
 * Sets the declared number of fields.
 * @param classFieldsCount Declared number of fields.
 */
void DotnetClass::setDeclaredFieldsCount(std::size_t classFieldsCount)
{
	declaredFieldsCount = classFieldsCount;
}

/**
 * Sets the declared number of methods.
 * @param classMethodsCount Declared number of methods.
 */
void DotnetClass::setDeclaredMethodsCount(std::size_t classMethodsCount)
{
	declaredMethodsCount = classMethodsCount;
}

/**
 * Sets the declared number of generic parameters.
 * @param classGenericParamsCount Declared number of generic parameters.
 */
void DotnetClass::setDeclaredGenericParametersCount(std::size_t classGenericParamsCount)
{
	declaredGenericParametersCount = classGenericParamsCount;
}

/**
 * Sets the library name of referencing class.
 * @param lName Library name.
 */
void DotnetClass::setLibName(const std::string &lName)
{
	libName = lName;
}

/**
 * Sets whether the class is actual class or interface.
 * @param set @c true for interface, otherwise class.
 */
void DotnetClass::setIsInterface(bool set)
{
	classOrInterface = set;
}

/**
 * Sets whether the class is abstract.
 * @param set @c true for abstract, otherwise not abstract.
 */
void DotnetClass::setIsAbstract(bool set)
{
	abstract = set;
}

/**
 * Sets whether the class is sealed.
 * @param set @c true for sealed, otherwise not sealed.
 */
void DotnetClass::setIsSealed(bool set)
{
	sealed = set;
}

/**
 * Returns whether the class is actual class.
 * @return @c true if class, otherwise @c false.
 */
bool DotnetClass::isClass() const
{
	return !classOrInterface;
}

/**
 * Returns whether the class is interface.
 * @return @c true if interface, otherwise @c false.
 */
bool DotnetClass::isInterface() const
{
	return classOrInterface;
}

/**
 * Returns whether the class is abstract.
 * @return @c true if abstract, otherwise @c false.
 */
bool DotnetClass::isAbstract() const
{
	return abstract;
}

/**
 * Returns whether the class is sealed.
 * @return @c true if sealed, otherwise @c false.
 */
bool DotnetClass::isSealed() const
{
	return sealed;
}

/**
 * Adds the field to the class.
 * @param field Field to add.
 */
void DotnetClass::addField(std::unique_ptr<DotnetField>&& field)
{
	fields.push_back(std::move(field));
}

/**
 * Adds the property to the class.
 * @param property Property to add.
 */
void DotnetClass::addProperty(std::unique_ptr<DotnetProperty>&& property)
{
	properties.push_back(std::move(property));
}

/**
 * Adds the method to the class.
 * @param method Method to add.
 */
void DotnetClass::addMethod(std::unique_ptr<DotnetMethod>&& method)
{
	methods.push_back(std::move(method));
}

/**
 * Adds the generic parameter to the class.
 * @param genericParam Generic parameter to add.
 */
void DotnetClass::addGenericParameter(std::string&& genericParam)
{
	genericParameters.push_back(std::move(genericParam));
}

/**
 * Adds the base type to the class.
 * @param baseType Base type to add.
 */
void DotnetClass::addBaseType(std::unique_ptr<DotnetDataTypeBase>&& baseType)
{
	baseTypes.push_back(std::move(baseType));
}

} // namespace fileformat
} // namespace retdec
