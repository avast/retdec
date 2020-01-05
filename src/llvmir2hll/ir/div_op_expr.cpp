/**
* @file src/llvmir2hll/ir/div_op_expr.cpp
* @brief Implementation of DivOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a division operator.
*
* See create() for more information.
*/
DivOpExpr::DivOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(Value::ValueKind::DivOpExpr, op1, op2), variant(variant) {}

bool DivOpExpr::isEqualTo(Value* otherValue) const {
	if (DivOpExpr* otherValueDivOpExpr = cast<DivOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueDivOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueDivOpExpr->getSecondOperand());
	}
	return false;
}

Value* DivOpExpr::clone() {
	DivOpExpr* divOpExpr(DivOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	divOpExpr->setMetadata(getMetadata());
	return divOpExpr;
}

/**
* @brief Returns variant of operation.
*/
DivOpExpr::Variant DivOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new division operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operation.
*
* @par Preconditions
*  - both operands are non-null
*/
DivOpExpr* DivOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	DivOpExpr* expr(new DivOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void DivOpExpr::accept(Visitor *v) {
	v->visit(ucast<DivOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
