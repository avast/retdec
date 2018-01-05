/**
* @file src/ctypes/member.cpp
* @brief Implementation of Member.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/member.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new member.
*/
Member::Member(const std::string &name, const std::shared_ptr<Type> &type):
	name(name), type(type) {}

/**
* @brief Returns member's name.
*/
const std::string &Member::getName() const
{
	return name;
}

/**
* @brief Returns member's type.
*/
std::shared_ptr<Type> Member::getType() const
{
	return type;
}

bool Member::operator==(const Member &other) const
{
	return name == other.name && type == other.type;
}

bool Member::operator!=(const Member &other) const
{
	return !(*this == other);
}

} // namespace ctypes
} // namespace retdec
