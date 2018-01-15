/**
* @file src/llvmir2hll/ir/const_null_pointer.cpp
* @brief Implementation of ConstNullPointer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a null pointer constant of the given type.
*
* See create() for more information.
*/
ConstNullPointer::ConstNullPointer(ShPtr<PointerType> type):
	Constant(), type(type) {}

/**
* @brief Destructs the constant.
*/
ConstNullPointer::~ConstNullPointer() {}

ShPtr<Value> ConstNullPointer::clone() {
	ShPtr<ConstNullPointer> constPointer(ConstNullPointer::create(type));
	constPointer->setMetadata(getMetadata());
	return constPointer;
}

bool ConstNullPointer::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types have to be equal.
	if (ShPtr<ConstNullPointer> otherConstPointer = cast<ConstNullPointer>(otherValue)) {
		return type->isEqualTo(otherConstPointer->type);
	}
	return false;
}

ShPtr<Type> ConstNullPointer::getType() const {
	return type;
}

void ConstNullPointer::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Creates a null pointer constant of the given type.
*
* @param[in] type Type of the pointer.
*/
ShPtr<ConstNullPointer> ConstNullPointer::create(ShPtr<PointerType> type) {
	return ShPtr<ConstNullPointer>(new ConstNullPointer(type));
}

void ConstNullPointer::accept(Visitor *v) {
	v->visit(ucast<ConstNullPointer>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
