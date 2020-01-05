/**
* @file src/llvmir2hll/ir/mod_op_expr.cpp
* @brief Implementation of ModOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a modulo operator.
*
* See create() for more information.
*/
ModOpExpr::ModOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(op1, op2), variant(variant) {}

bool ModOpExpr::isEqualTo(Value* otherValue) const {
	if (ModOpExpr* otherValueModOpExpr = cast<ModOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueModOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueModOpExpr->getSecondOperand());
	}
	return false;
}

Value* ModOpExpr::clone() {
	ModOpExpr* modOpExpr(ModOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	modOpExpr->setMetadata(getMetadata());
	return modOpExpr;
}

/**
* @brief Returns variant of operation.
*/
ModOpExpr::Variant ModOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new modulo operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operation.
*
* @par Preconditions
*  - both operands are non-null
*/
ModOpExpr* ModOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ModOpExpr* expr(new ModOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void ModOpExpr::accept(Visitor *v) {
	v->visit(ucast<ModOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
