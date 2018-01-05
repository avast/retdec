/**
 * @file src/config/types.cpp
 * @brief Decompilation configuration manipulation: objects.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/config/types.h"

namespace {

const std::string JSON_llvmIr     = "llvmIr";
const std::string JSON_wideString = "isWideString";

} // anonymous namespace

namespace retdec {
namespace config {

/**
 * Default type is i32.
 */
Type::Type()
{
}

Type::Type(const std::string& llvmIrRepre) :
		_llvmIr(llvmIrRepre)
{
}

/**
 * Reads JSON object (associative array) holding type information.
 * @param val JSON object.
 */
Type Type::fromJsonValue(const Json::Value& val)
{
	Type ret;
	ret.readJsonValue(val);
	return ret;
}

/**
 * Returns JSON object (associative array) holding type information.
 * @return JSON object.
 */
Json::Value Type::getJsonValue() const
{
	Json::Value type;

	if (isDefined()) type[JSON_llvmIr] = getLlvmIr();
	if (isDefined() && isWideString()) type[JSON_wideString] = isWideString();

	return type;
}

/**
 * Reads JSON object (associative array) holding type information.
 * @param val JSON object.
 */
void Type::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() || !val.isObject() )
	{
		return;
	}

	setLlvmIr( safeGetString(val, JSON_llvmIr) );
	setIsWideString( safeGetBool(val, JSON_wideString) );
}

/**
 * @return Type is defined if @c llvmIr member is not empty.
 */
bool Type::isDefined() const
{
	return !_llvmIr.empty();
}

/**
 * Wide strings are in LLVM IR represented as int arrays.
 * This flag can be use to distinguish them from ordinary int arrays.
 */
bool Type::isWideString() const
{
	return _wideString;
}

void Type::setIsWideString(bool b)
{
	_wideString = b;
}

void Type::setLlvmIr(const std::string& t)
{
	_llvmIr = t;
}

/**
 * @return Type's ID is its LLVM IR representation.
 */
std::string Type::getId() const
{
	return getLlvmIr();
}

/**
 * @return LLVM IR string representation (unique ID).
 */
std::string Type::getLlvmIr() const
{
	assert(isDefined());
	return _llvmIr;
}

/**
 * Less-than comparison of this instance with the provided one.
 * Default string comparison of @c llvmIr members is used.
 * @param val Other type to compare with.
 * @return True if @c this instance is considered to be less-than @c val.
 */
bool Type::operator<(const Type& val) const
{
	assert(isDefined());
	return getLlvmIr() < val.getLlvmIr();
}

/**
 * Types are equal if their llvm ir representations are equal.
 */
bool Type::operator==(const Type& val) const
{
	assert(isDefined());
	return getLlvmIr() == val.getLlvmIr();
}

} // namespace config
} // namespace retdec
