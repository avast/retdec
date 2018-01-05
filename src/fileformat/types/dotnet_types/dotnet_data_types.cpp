/**
 * @file src/fileformat/types/dotnet_types/dotnet_data_types.cpp
 * @brief Classes for .NET data types.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <unordered_map>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_data_types.h"

namespace retdec {
namespace fileformat {

std::string DotnetDataTypePtr::getText() const
{
	return "Ptr<" + pointed->getText() + '>';
}

std::string DotnetDataTypeByRef::getText() const
{
	return "ref " + referred->getText();
}

std::string DotnetDataTypeValueType::getText() const
{
	return type->getFullyQualifiedName();
}

std::string DotnetDataTypeClass::getText() const
{
	return type->getFullyQualifiedName();
}

std::string DotnetDataTypeGenericVar::getText() const
{
	return *genericVar;
}

std::string DotnetDataTypeArray::getText() const
{
	std::string repr;
	for (auto itr = dimensions.begin(), end = dimensions.end(); itr != end; ++itr)
	{
		std::string dimStr;
		if (itr->first != 0 || itr->second != 0)
		{
			if (itr->first != 0)
				dimStr += retdec::utils::numToStr(itr->first) + "...";
			dimStr += retdec::utils::numToStr(itr->second);
		}

		repr += dimStr;
		if (itr + 1 != end)
			repr += ',';
	}

	return underlyingType->getText() + '[' + repr + ']';
}

std::string DotnetDataTypeGenericInst::getText() const
{
	std::string genericStr;
	for (const auto& genericType : genericTypes)
	{
		if (!genericStr.empty())
			genericStr += ',';
		genericStr += genericType->getText();
	}

	return type->getText() + '<' + genericStr + '>';
}

std::string DotnetDataTypeFnPtr::getText() const
{
	std::string repr;
	for (const auto& paramType : paramTypes)
	{
		if (!repr.empty())
			repr += ", ";

		repr += paramType->getText();
	}

	return "FnPtr<" + returnType->getText() + '(' + repr + ")>";
}

std::string DotnetDataTypeSzArray::getText() const
{
	return underlyingType->getText() + "[]";
}

std::string DotnetDataTypeGenericMVar::getText() const
{
	return *genericVar;
}

std::string DotnetDataTypeCModRequired::getText() const
{
	if (modifier->getFullyQualifiedName() == "System.Runtime.CompilerServices.IsVolatile")
		return "volatile " + type->getText();

	return type->getText();
}

std::string DotnetDataTypeCModOptional::getText() const
{
	return type->getText();
}

} // namespace fileformat
} // namespace retdec
