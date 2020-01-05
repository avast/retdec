/**
* @file src/llvmir2hll/ir/bit_shl_op_expr.cpp
* @brief Implementation of BitShlOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bit left shift operator.
*
* See create() for more information.
*/
BitShlOpExpr::BitShlOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(op1, op2) {}

bool BitShlOpExpr::isEqualTo(Value* otherValue) const {
	if (BitShlOpExpr* otherValueBitShlOpExpr = cast<BitShlOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitShlOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitShlOpExpr->getSecondOperand());
	}
	return false;
}

Value* BitShlOpExpr::clone() {
	BitShlOpExpr* bitShlOpExpr(BitShlOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	bitShlOpExpr->setMetadata(getMetadata());
	return bitShlOpExpr;
}

/**
* @brief Creates a new bit left shift operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
BitShlOpExpr* BitShlOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	BitShlOpExpr* expr(new BitShlOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitShlOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitShlOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
