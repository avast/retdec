/**
* @file src/llvmir2hll/ir/bit_shr_op_expr.cpp
* @brief Implementation of BitShrOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a bit right shift operator.
*
* See create() for more information.
*/
BitShrOpExpr::BitShrOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(Value::ValueKind::BitShrOpExpr, op1, op2), variant(variant) {}

bool BitShrOpExpr::isEqualTo(Value* otherValue) const {
	if (BitShrOpExpr* otherValueBitShrOpExpr = cast<BitShrOpExpr>(otherValue)) {
		return variant == otherValueBitShrOpExpr->variant &&
			op1->isEqualTo(otherValueBitShrOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueBitShrOpExpr->getSecondOperand());
	}
	return false;
}

Value* BitShrOpExpr::clone() {
	BitShrOpExpr* bitShrOpExpr(BitShrOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone()), variant));
	bitShrOpExpr->setMetadata(getMetadata());
	return bitShrOpExpr;
}

/**
* @brief Returns the variant of the operator.
*/
BitShrOpExpr::Variant BitShrOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Returns @c true if the shift is logical, @c false otherwise.
*/
bool BitShrOpExpr::isLogical() const {
	return variant == Variant::Logical;
}

/**
* @brief Returns @c true if the shift is logical, @c false otherwise.
*/
bool BitShrOpExpr::isArithmetical() const {
	return variant == Variant::Arithmetical;
}

/**
* @brief Creates a new bit right shift operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operator
*
* @par Preconditions
*  - @a op1 and @a op2 are non-null
*/
BitShrOpExpr* BitShrOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	BitShrOpExpr* expr(new BitShrOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void BitShrOpExpr::accept(Visitor *v) {
	v->visit(ucast<BitShrOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
