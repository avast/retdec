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
BitShlOpExpr::BitShlOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
BitShlOpExpr::~BitShlOpExpr() {
	// Observers are removed in the superclass.
}

bool BitShlOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<BitShlOpExpr> otherValueBitShlOpExpr = cast<BitShlOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitShlOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitShlOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> BitShlOpExpr::clone() {
	ShPtr<BitShlOpExpr> bitShlOpExpr(BitShlOpExpr::create(
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
ShPtr<BitShlOpExpr> BitShlOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<BitShlOpExpr> expr(new BitShlOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitShlOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitShlOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
