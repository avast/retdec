/**
* @file src/llvmir2hll/ir/bit_or_op_expr.cpp
* @brief Implementation of BitOrOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bit-or operator.
*
* See create() for more information.
*/
BitOrOpExpr::BitOrOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
BitOrOpExpr::~BitOrOpExpr() {
	// Observers are removed in the superclass.
}

bool BitOrOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<BitOrOpExpr> otherValueBitOrOpExpr = cast<BitOrOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitOrOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitOrOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> BitOrOpExpr::clone() {
	ShPtr<BitOrOpExpr> bitOrOpExpr(BitOrOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	bitOrOpExpr->setMetadata(getMetadata());
	return bitOrOpExpr;
}

/**
* @brief Creates a new bit-or operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<BitOrOpExpr> BitOrOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<BitOrOpExpr> expr(new BitOrOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitOrOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitOrOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
