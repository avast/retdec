/**
 * @file src/fileformat/types/dotnet_types/dotnet_method.cpp
 * @brief Class for .NET method.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_method.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the raw metadata table record for this method.
 * @return Raw type record.
 */
const MethodDef* DotnetMethod::getRawRecord() const
{
	return rawRecord;
}

/**
 * Returns the name of the method appended with generic paramters.
 * @return Name with generic parameters.
 */
std::string DotnetMethod::getNameWithGenericParameters() const
{
	std::string repr = getName();
	if (!genericParameters.empty())
		repr += '<' + retdec::utils::joinStrings(genericParameters, ",") + '>';

	return repr;
}

/**
 * Returns the return type of the method.
 * @return Return type.
 */
const DotnetDataTypeBase* DotnetMethod::getReturnType() const
{
	return returnType.get();
}

/**
 * Returns the parameters of the method.
 * @return The method parameters.
 */
const std::vector<std::unique_ptr<DotnetParameter>>& DotnetMethod::getParameters() const
{
	return parameters;
}

/**
 * Returns the generic parameters of the method.
 * @return The method generic parameters.
 */
const std::vector<std::string>& DotnetMethod::getGenericParameters() const
{
	return genericParameters;
}

/**
 * Returns the declared number of parameters according to metadata tables.
 * @return The declared number of parameters.
 */
std::size_t DotnetMethod::getDeclaredParametersCount() const
{
	return declaredParamsCount;
}

/**
 * Sets the raw metadata table record for this method.
 * @param record Raw metadata table record.
 */
void DotnetMethod::setRawRecord(const MethodDef* record)
{
	rawRecord = record;
}

/**
 * Sets the return type of this method.
 * @param methodReturnType The return type.
 */
void DotnetMethod::setReturnType(std::unique_ptr<DotnetDataTypeBase>&& methodReturnType)
{
	returnType = std::move(methodReturnType);
}

/**
 * Sets whether the method is static.
 * @param set @c true for static, otherwise not static.
 */
void DotnetMethod::setIsStatic(bool set)
{
	methodIsStatic = set;
}

/**
 * Sets whether the method is virtual.
 * @param set @c true for virtual, otherwise not virtual.
 */
void DotnetMethod::setIsVirtual(bool set)
{
	methodIsVirtual = set;
}

/**
 * Sets whether the method is abstract.
 * @param set @c true for abstract, otherwise not abstract.
 */
void DotnetMethod::setIsAbstract(bool set)
{
	methodIsAbstract = set;
}

/**
 * Sets whether the method is final.
 * @param set @c true for final, otherwise not final.
 */
void DotnetMethod::setIsFinal(bool set)
{
	methodIsFinal = set;
}

/**
 * Sets whether the method is constructor.
 * @param set @c true for constructor, otherwise not constructor.
 */
void DotnetMethod::setIsConstructor(bool set)
{
	methodIsConstructor = set;
}

/**
 * Sets the declared number of parameters.
 * @param paramsCount Declared number of parameters.
 */
void DotnetMethod::setDeclaredParametersCount(std::size_t paramsCount)
{
	declaredParamsCount = paramsCount;
}

/**
 * Returns whether the method is static.
 * @return @c true if static, otherwise @c false.
 */
bool DotnetMethod::isStatic() const
{
	return methodIsStatic;
}

/**
 * Returns whether the method is virtual.
 * @return @c true if virtual, otherwise @c false.
 */
bool DotnetMethod::isVirtual() const
{
	return methodIsVirtual;
}

/**
 * Returns whether the method is abstract.
 * @return @c true if abstract, otherwise @c false.
 */
bool DotnetMethod::isAbstract() const
{
	return methodIsAbstract;
}

/**
 * Returns whether the method is final.
 * @return @c true if final, otherwise @c false.
 */
bool DotnetMethod::isFinal() const
{
	return methodIsFinal;
}

/**
 * Returns whether the method is constructor.
 * @return @c true if constructor, otherwise @c false.
 */
bool DotnetMethod::isConstructor() const
{
	return methodIsConstructor;
}

/**
 * Adds the parameter to the method.
 * @param param Parameter to add.
 */
void DotnetMethod::addParameter(std::unique_ptr<DotnetParameter>&& param)
{
	parameters.push_back(std::move(param));
}

/**
 * Adds the generic parameter to the method.
 * @param genericParam Generic parameter to add.
 */
void DotnetMethod::addGenericParameter(std::string&& genericParam)
{
	genericParameters.push_back(std::move(genericParam));
}

} // namespace fileformat
} // namespace retdec
