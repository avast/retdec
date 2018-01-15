/**
* @file src/llvmir2hll/ir/bit_and_op_expr.cpp
* @brief Implementation of BitAndOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bit-and operator.
*
* See create() for more information.
*/
BitAndOpExpr::BitAndOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
BitAndOpExpr::~BitAndOpExpr() {
	// Observers are removed in the superclass.
}

bool BitAndOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<BitAndOpExpr> otherValueBitAndOpExpr = cast<BitAndOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitAndOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitAndOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> BitAndOpExpr::clone() {
	ShPtr<BitAndOpExpr> bitAndOpExpr(BitAndOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	bitAndOpExpr->setMetadata(getMetadata());
	return bitAndOpExpr;
}

/**
* @brief Creates a new bit-and operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<BitAndOpExpr> BitAndOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<BitAndOpExpr> expr(new BitAndOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitAndOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitAndOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
