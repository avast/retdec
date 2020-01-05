/**
* @file src/llvmir2hll/ir/gt_eq_op_expr.cpp
* @brief Implementation of GtEqOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a greater-than-or-equal operator.
*
* See create() for more information.
*/
GtEqOpExpr::GtEqOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(op1, op2), variant(variant) {}

bool GtEqOpExpr::isEqualTo(Value* otherValue) const {
	if (GtEqOpExpr* otherValueGtEqOpExpr = cast<GtEqOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueGtEqOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueGtEqOpExpr->getSecondOperand());
	}
	return false;
}

Value* GtEqOpExpr::clone() {
	GtEqOpExpr* gtEqOpExpr(GtEqOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	gtEqOpExpr->setMetadata(getMetadata());
	return gtEqOpExpr;
}

Type* GtEqOpExpr::getType() const {
	// The type of `x >= y` should be bool.
	return IntType::create(1);
}

/**
* @brief Returns variant of operation.
*/
GtEqOpExpr::Variant GtEqOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new greater-than-or-equal operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operator (signed or unsigned).
*
* @par Preconditions
*  - both operands are non-null
*/
GtEqOpExpr* GtEqOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	GtEqOpExpr* expr(new GtEqOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void GtEqOpExpr::accept(Visitor *v) {
	v->visit(ucast<GtEqOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
