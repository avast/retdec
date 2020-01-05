/**
* @file src/llvmir2hll/ir/lt_eq_op_expr.cpp
* @brief Implementation of LtEqOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a less-than-or-equal operator.
*
* See create() for more information.
*/
LtEqOpExpr::LtEqOpExpr(Expression* op1, Expression* op2,
		Variant variant):
	BinaryOpExpr(Value::ValueKind::LtEqOpExpr, op1, op2), variant(variant) {}

bool LtEqOpExpr::isEqualTo(Value* otherValue) const {
	if (LtEqOpExpr* otherValueLtEqOpExpr = cast<LtEqOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueLtEqOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueLtEqOpExpr->getSecondOperand());
	}
	return false;
}

Value* LtEqOpExpr::clone() {
	LtEqOpExpr* ltEqOpExpr(LtEqOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	ltEqOpExpr->setMetadata(getMetadata());
	return ltEqOpExpr;
}

Type* LtEqOpExpr::getType() const {
	// The type of `x <= y` should be bool.
	return IntType::create(1);
}

/**
* @brief Returns variant of operation.
*/
LtEqOpExpr::Variant LtEqOpExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new less-than-or-equal operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
* @param[in] variant Variant of the operator (signed or unsigned).
*
* @par Preconditions
*  - both operands are non-null
*/
LtEqOpExpr* LtEqOpExpr::create(Expression* op1, Expression* op2,
		Variant variant) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	LtEqOpExpr* expr(new LtEqOpExpr(op1, op2, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void LtEqOpExpr::accept(Visitor *v) {
	v->visit(ucast<LtEqOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
