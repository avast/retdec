/**
* @file src/ctypes/floating_point_type.cpp
* @brief Implementation of FloatingPointType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new floating point type.
*
* See @c create() for more information.
*/
FloatingPointType::FloatingPointType(const std::string &name, unsigned bitWidth):
	Type(name, bitWidth) {}

/**
* @brief Creates floating point type.
*
* @param context Storage for already created functions, types.
* @param name Name of new type.
* @param bitWidth Number of bits used by this type.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new floating point type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<FloatingPointType>FloatingPointType::create(
	const std::shared_ptr<Context> &context, const std::string &name, unsigned bitWidth)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isFloatingPoint())
	{
		return std::static_pointer_cast<FloatingPointType>(type);
	}

	std::shared_ptr<FloatingPointType> newType(new FloatingPointType(name, bitWidth));
	context->addNamedType(newType);
	return newType;
}

/**
* Returns @c true when Type is floating point, @c false otherwise.
*/
bool FloatingPointType::isFloatingPoint() const
{
	return true;
}

void FloatingPointType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<FloatingPointType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
