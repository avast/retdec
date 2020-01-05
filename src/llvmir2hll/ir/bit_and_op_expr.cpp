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
BitAndOpExpr::BitAndOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(op1, op2) {}

bool BitAndOpExpr::isEqualTo(Value* otherValue) const {
	if (BitAndOpExpr* otherValueBitAndOpExpr = cast<BitAndOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitAndOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitAndOpExpr->getSecondOperand());
	}
	return false;
}

Value* BitAndOpExpr::clone() {
	BitAndOpExpr* bitAndOpExpr(BitAndOpExpr::create(
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
BitAndOpExpr* BitAndOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	BitAndOpExpr* expr(new BitAndOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitAndOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitAndOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
