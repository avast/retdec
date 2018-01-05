/**
* @file src/ctypes/pointer_type.cpp
* @brief Implementation of PointerType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new pointer type.
*/
PointerType::PointerType(const std::shared_ptr<Type> &pointedType, unsigned bitWidth):
	Type("", bitWidth), pointedType(pointedType) {}

/**
* @brief Creates pointer type.
*
* @param context Storage for already created functions, types.
* @param pointedType Type that this pointer points to.
* @param bitWidth Number of bits used by this type.
*
* @par Preconditions
*  - @a context is not null
*  - @a pointedType is not null
*
* Does not create new pointer type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<PointerType> PointerType::create(
	const std::shared_ptr<Context> &context,
	const std::shared_ptr<Type> &pointedType,
	unsigned bitWidth)
{
	assert(context && "violated precondition - context cannot be null");
	assert(pointedType && "violated precondition - pointedType cannot be null");

	auto type = context->getPointerType(pointedType);
	if (type)
	{
		return type;
	}

	std::shared_ptr<PointerType> newType(new PointerType(pointedType, bitWidth));
	context->addPointerType(newType);
	return newType;
}

/**
* @brief Returns pointed type.
*/
std::shared_ptr<Type> PointerType::getPointedType() const
{
	return pointedType;
}
/**
* Returns @c true when Type is pointer, @c false otherwise.
*/
bool PointerType::isPointer() const
{
	return true;
}

void PointerType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<PointerType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
