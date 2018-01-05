/**
* @file src/llvmir2hll/ir/bit_xor_op_expr.cpp
* @brief Implementation of BitXorOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bit-xor operator.
*
* See create() for more information.
*/
BitXorOpExpr::BitXorOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
BitXorOpExpr::~BitXorOpExpr() {
	// Observers are removed in the superclass.
}

bool BitXorOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<BitXorOpExpr> otherValueBitXorOpExpr = cast<BitXorOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueBitXorOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitXorOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> BitXorOpExpr::clone() {
	ShPtr<BitXorOpExpr> bitXorOpExpr(BitXorOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	bitXorOpExpr->setMetadata(getMetadata());
	return bitXorOpExpr;
}

/**
* @brief Creates a new bit-xor operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<BitXorOpExpr> BitXorOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<BitXorOpExpr> expr(new BitXorOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitXorOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitXorOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
