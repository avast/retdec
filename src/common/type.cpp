/**
 * @file src/common/type.cpp
 * @brief Common data type representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/common/type.h"

namespace retdec {
namespace common {

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

} // namespace common
} // namespace retdec
