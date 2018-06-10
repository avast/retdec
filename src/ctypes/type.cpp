/**
* @file src/ctypes/type.cpp
* @brief Implementation of Type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new type.
*/
Type::Type(const std::string &name, unsigned bitWidth):
	name(name), bitWidth(bitWidth) {}

const std::string &Type::getName() const
{
	return name;
}

unsigned Type::getBitWidth() const
{
	return bitWidth;
}

bool Type::isArray() const
{
	return false;
}

bool Type::isEnum() const
{
	return false;
}

bool Type::isFloatingPoint() const
{
	return false;
}

bool Type::isFunction() const
{
	return false;
}

bool Type::isIntegral() const
{
	return false;
}

bool Type::isPointer() const
{
	return false;
}

bool Type::isStruct() const
{
	return false;
}

bool Type::isTypedef() const
{
	return false;
}

bool Type::isUnion() const
{
	return false;
}

bool Type::isUnknown() const
{
	return false;
}

bool Type::isVoid() const
{
	return false;
}

} // namespace ctypes
} // namespace retdec
