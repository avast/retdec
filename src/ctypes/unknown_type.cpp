/**
* @file src/ctypes/unknown_type.cpp
* @brief Implementation of unknown type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "ctypes/unknown_type.h"
#include "ctypes/visitor.h"

namespace ctypes {

/**
* @brief Constructs a new unknown type.
*
* See @c create() for more information.
*/
UnknownType::UnknownType() :
	Type() {}

/**
* @brief Creates unknown type.
*
* Function always returns the same instance.
*/
std::shared_ptr<UnknownType> UnknownType::create()
{
	static std::shared_ptr<UnknownType> createdType(new UnknownType());
	return createdType;
}

/**
* Returns @c true when Type is unknown, @c false otherwise.
*/
bool UnknownType::isUnknown() const
{
	return true;
}

void UnknownType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<UnknownType>(shared_from_this()));
}

} // namespace ctypes
