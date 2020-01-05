/**
* @file src/llvmir2hll/ir/pointer_type.cpp
* @brief Implementation of PointerType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new pointer type.
*
* See create() for more information.
*/
PointerType::PointerType(Type* containedType):
	Type(), containedType(containedType) {}

Value* PointerType::clone() {
	return PointerType::create(ucast<Type>(containedType->clone()));
}

bool PointerType::isEqualTo(Value* otherValue) const {
	// Both types and contained types have to be equal.
	if (PointerType* otherPointerType = cast<PointerType>(otherValue)) {
		return containedType->isEqualTo(otherPointerType->containedType);
	}
	return false;
}

/**
* @brief Sets a new contained type.
*
* @par Preconditions
*  - @a newContainedType is non-null
*/
void PointerType::setContainedType(Type* newContainedType) {
	PRECONDITION_NON_NULL(newContainedType);

	containedType = newContainedType;
}

/**
* @brief Returns the contained type.
*/
Type* PointerType::getContainedType() const {
	return containedType;
}

/**
* @brief Creates a new pointer type.
*
* @param[in] containedType Contained type.
*
* @par Preconditions
*  - @a containedType is non-null
*/
PointerType* PointerType::create(Type* containedType) {
	PRECONDITION_NON_NULL(containedType);

	// There is no special initialization.
	return new PointerType(containedType);
}

void PointerType::accept(Visitor *v) {
	v->visit(ucast<PointerType>(this));
}

} // namespace llvmir2hll
} // namespace retdec
