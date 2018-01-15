/**
* @file src/llvmir2hll/ir/array_type.cpp
* @brief Implementation of ArrayType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new array type.
*
* See create() for more information.
*/
ArrayType::ArrayType(ShPtr<Type> elemType, const Dimensions &dims):
	Type(), elemType(elemType), dims(dims) {}

/**
* @brief Destructs the type.
*/
ArrayType::~ArrayType() {}

ShPtr<Value> ArrayType::clone() {
	return ArrayType::create(elemType, dims);
}

bool ArrayType::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and numbers of dimensions have to be equal.
	if (ShPtr<ArrayType> otherArrayType = cast<ArrayType>(otherValue)) {
		if ((elemType == otherArrayType->elemType) &&
				(dims == otherArrayType->dims)) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns the type of elements of the array.
*/
ShPtr<Type> ArrayType::getContainedType() const {
	return elemType;
}

/**
* @brief Returns the dimensions of the array.
*/
ArrayType::Dimensions ArrayType::getDimensions() const {
	return dims;
}

/**
* @brief Are the dimensions empty?
*/
bool ArrayType::hasEmptyDimensions() const {
	return dims.empty();
}

/**
* @brief Creates a new array type.
*
* @param[in] elemType Type of elements of the array.
* @param[in] dims Array dimensions.
*/
ShPtr<ArrayType> ArrayType::create(ShPtr<Type> elemType, const Dimensions &dims) {
	// There is no special initialization needed.
	return ShPtr<ArrayType>(new ArrayType(elemType, dims));
}

void ArrayType::accept(Visitor *v) {
	v->visit(ucast<ArrayType>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
