/**
* @file src/llvmir2hll/ir/struct_index_op_expr.cpp
* @brief Implementation of StructIndexOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a struct index operator.
*
* See create() for more information.
*/
StructIndexOpExpr::StructIndexOpExpr(ShPtr<Expression> base,
	ShPtr<ConstInt> fieldNumber):
		BinaryOpExpr(base, fieldNumber) {}

/**
* @brief Destructs the operator.
*/
StructIndexOpExpr::~StructIndexOpExpr() {
	// Observers are deleted in the superclass.
}

ShPtr<Type> StructIndexOpExpr::getType() const {
	ShPtr<Type> op1Type(op1->getType());

	// StructIndexOpExpr works on both values and pointers, so if op1Type is a
	// pointer, use the underlying type.
	if (ShPtr<PointerType> op1PointerType = cast<PointerType>(op1Type)) {
		op1Type = op1PointerType->getContainedType();
	}

	if (ShPtr<StructType> op1StructType = cast<StructType>(op1Type)) {
		return op1StructType->getTypeOfElement(ucast<ConstInt>(op2));
	}

	// The type cannot be computed.
	return UnknownType::create();
}

bool StructIndexOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<StructIndexOpExpr> otherValueStructIndexOpExpr =
			cast<StructIndexOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueStructIndexOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueStructIndexOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> StructIndexOpExpr::clone() {
	ShPtr<StructIndexOpExpr> structIndexOpExpr(StructIndexOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<ConstInt>(op2->clone())));
	structIndexOpExpr->setMetadata(getMetadata());
	return structIndexOpExpr;
}

/**
* @brief Creates a new struct index operator.
*
* @param[in] base Base part of the operator (op1).
* @param[in] fieldNumber Index part of the operator (op2).
*
* An equivalent in C is @c base.fieldNumber (however, notice that contrary to
* C, there are no field names, just numbers).
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<StructIndexOpExpr> StructIndexOpExpr::create(ShPtr<Expression> base,
		ShPtr<ConstInt> fieldNumber) {
	PRECONDITION_NON_NULL(base);
	PRECONDITION_NON_NULL(fieldNumber);

	ShPtr<StructIndexOpExpr> expr(new StructIndexOpExpr(base, fieldNumber));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	base->addObserver(expr);
	fieldNumber->addObserver(expr);

	return expr;
}

void StructIndexOpExpr::accept(Visitor *v) {
	v->visit(ucast<StructIndexOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
