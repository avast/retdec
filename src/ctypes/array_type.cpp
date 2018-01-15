/**
* @file src/ctypes/array_type.cpp
* @brief Implementation of ArrayType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/// Sets unknown dimension's value.
const ArrayType::DimensionType ArrayType::UNKNOWN_DIMENSION = 0;

/**
* @brief Constructs a new array type.
*/
ArrayType::ArrayType(const std::shared_ptr<Type> &elementType,
	const Dimensions &dimensions):
	elementType(elementType), dimensions(dimensions) {}

/**
* @brief Creates array type.
*
* @param context Storage for already created functions, types.
* @param elementType Type that this array contains.
* @param dimensions Array's dimensions.
*
* @par Preconditions
*  - @a context is not null
*  - @a elementType is not null
*
* Does not create new array type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<ArrayType> ArrayType::create(const std::shared_ptr<Context> &context,
	const std::shared_ptr<Type> &elementType, const Dimensions &dimensions)
{
	assert(context && "violated precondition - context cannot be null");
	assert(elementType && "violated precondition - elementType cannot be null");

	auto type = context->getArrayType(elementType, dimensions);
	if (type)
	{
		return type;
	}

	std::shared_ptr<ArrayType> newType(new ArrayType(elementType, dimensions));
	context->addArrayType(newType);
	return newType;
}

/**
* @brief Returns element type.
*/
std::shared_ptr<Type> ArrayType::getElementType() const
{
	return elementType;
}

/**
* @brief Returns array's dimensions.
*/
const ArrayType::Dimensions &ArrayType::getDimensions() const
{
	return dimensions;
}

/**
* @brief Returns array's dimensions count.
*/
ArrayType::Dimensions::size_type ArrayType::getDimensionCount() const
{
	return dimensions.size();
}

/**
* @brief Returns @c true when Type is array, @c false otherwise.
*/
bool ArrayType::isArray() const
{
	return true;
}

void ArrayType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<ArrayType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
