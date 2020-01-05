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
ConstNullPointer::ConstNullPointer(PointerType* type):
	Constant(), type(type) {}

Value* ConstNullPointer::clone() {
	ConstNullPointer* constPointer(ConstNullPointer::create(type));
	constPointer->setMetadata(getMetadata());
	return constPointer;
}

bool ConstNullPointer::isEqualTo(Value* otherValue) const {
	// Both types have to be equal.
	if (ConstNullPointer* otherConstPointer = cast<ConstNullPointer>(otherValue)) {
		return type->isEqualTo(otherConstPointer->type);
	}
	return false;
}

Type* ConstNullPointer::getType() const {
	return type;
}

void ConstNullPointer::replace(Expression* oldExpr, Expression* newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Creates a null pointer constant of the given type.
*
* @param[in] type Type of the pointer.
*/
ConstNullPointer* ConstNullPointer::create(PointerType* type) {
	return new ConstNullPointer(type);
}

void ConstNullPointer::accept(Visitor *v) {
	v->visit(ucast<ConstNullPointer>(this));
}

} // namespace llvmir2hll
} // namespace retdec
