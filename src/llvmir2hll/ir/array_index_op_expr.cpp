/**
* @file src/llvmir2hll/ir/array_index_op_expr.cpp
* @brief Implementation of ArrayIndexOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an array subscript operator.
*
* See create() for more information.
*/
ArrayIndexOpExpr::ArrayIndexOpExpr(Expression* base, Expression* index):
	BinaryOpExpr(base, index) {}

Type* ArrayIndexOpExpr::getType() const {
	Type* op1Type(op1->getType());

	if (ArrayType* op1ArrayType = cast<ArrayType>(op1Type)) {
		return op1ArrayType->getContainedType();
	}

	if (PointerType* op1PointerType = cast<PointerType>(op1Type)) {
		return op1PointerType->getContainedType();
	}

	// The type cannot be computed.
	return UnknownType::create();
}

bool ArrayIndexOpExpr::isEqualTo(Value* otherValue) const {
	if (ArrayIndexOpExpr* otherValueArrayIndexOpExpr =
			cast<ArrayIndexOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueArrayIndexOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueArrayIndexOpExpr->getSecondOperand());
	}
	return false;
}

Value* ArrayIndexOpExpr::clone() {
	ArrayIndexOpExpr* arrayIndexOpExpr(ArrayIndexOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	arrayIndexOpExpr->setMetadata(getMetadata());
	return arrayIndexOpExpr;
}

/**
* @brief Returns the base (i.e. the first operand).
*/
Expression* ArrayIndexOpExpr::getBase() const {
	return getFirstOperand();
}

/**
* @brief Returns the index (i.e. the second operand).
*/
Expression* ArrayIndexOpExpr::getIndex() const {
	return getSecondOperand();
}

/**
* @brief Creates a new array subscript operator.
*
* @param[in] base Base part of the operator (op1).
* @param[in] index Index part of the operator (op2).
*
* An equivalent in C is @c base[index].
*
* @par Preconditions
*  - both operands are non-null
*/
ArrayIndexOpExpr* ArrayIndexOpExpr::create(Expression* base,
		Expression* index) {
	PRECONDITION_NON_NULL(base);
	PRECONDITION_NON_NULL(index);

	ArrayIndexOpExpr* expr(new ArrayIndexOpExpr(base, index));

	// Initialization (recall that this cannot be called in a
	// constructor).
	base->addObserver(expr);
	index->addObserver(expr);

	return expr;
}

void ArrayIndexOpExpr::accept(Visitor *v) {
	v->visit(ucast<ArrayIndexOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
