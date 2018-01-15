/**
* @file src/ctypes/void_type.cpp
* @brief Implementation of void type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/visitor.h"
#include "retdec/ctypes/void_type.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new void type.
*
* See @c create() for more information.
*/
VoidType::VoidType() :
	Type() {}

/**
* @brief Creates VoidType.
*
* Function always returns the same instance.
*/
std::shared_ptr<VoidType> VoidType::create()
{
	static std::shared_ptr<VoidType> createdType(new VoidType());
	return createdType;
}

/**
* Returns @c true when Type is void, @c false otherwise.
*/
bool VoidType::isVoid() const
{
	return true;
}

void VoidType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<VoidType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
