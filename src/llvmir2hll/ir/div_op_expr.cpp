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
DivOpExpr::DivOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant):
	BinaryOpExpr(op1, op2), variant(variant) {}

/**
* @brief Destructs the operator.
*/
DivOpExpr::~DivOpExpr() {
	// Observers are removed in the superclass.
}

bool DivOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<DivOpExpr> otherValueDivOpExpr = cast<DivOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueDivOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueDivOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> DivOpExpr::clone() {
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(
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
ShPtr<DivOpExpr> DivOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<DivOpExpr> expr(new DivOpExpr(op1, op2, variant));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void DivOpExpr::accept(Visitor *v) {
	v->visit(ucast<DivOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
