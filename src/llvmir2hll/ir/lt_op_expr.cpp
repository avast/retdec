/**
* @file src/llvmir2hll/ir/lt_op_expr.cpp
* @brief Implementation of LtOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a less-than operator.
*
* See create() for more information.
*/
LtOpExpr::LtOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(op1, op2), variant(variant) {}

bool LtOpExpr::isEqualTo(Value* otherValue) const {
	if (LtOpExpr* otherValueLtOpExpr = cast<LtOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueLtOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueLtOpExpr->getSecondOperand());
	}
	return false;
}

Value* LtOpExpr::clone() {
	LtOpExpr* ltOpExpr(LtOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	ltOpExpr->setMetadata(getMetadata());
	return ltOpExpr;
}

Type* LtOpExpr::getType() const {
	// The type of `x < y` should be bool.
	return IntType::create(1);
}

/**
* @brief Returns variant of operation.
*/
LtOpExpr::Variant LtOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new less-than operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operator.
*
* @par Preconditions
*  - both operands are non-null
*/
LtOpExpr* LtOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	LtOpExpr* expr(new LtOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void LtOpExpr::accept(Visitor *v) {
	v->visit(ucast<LtOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
