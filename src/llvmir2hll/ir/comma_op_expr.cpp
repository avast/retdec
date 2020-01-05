/**
* @file src/llvmir2hll/ir/comma_op_expr.cpp
* @brief Implementation of CommaOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an comma operator.
*
* See create() for more information.
*/
CommaOpExpr::CommaOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(Value::ValueKind::CommaOpExpr, op1, op2) {}

bool CommaOpExpr::isEqualTo(Value* otherValue) const {
	if (auto otherExpr = cast<CommaOpExpr>(otherValue)) {
		return op1->isEqualTo(otherExpr->getFirstOperand()) &&
			op2->isEqualTo(otherExpr->getSecondOperand());
	}
	return false;
}

Value* CommaOpExpr::clone() {
	auto expr = CommaOpExpr::create(
		ucast<Expression>(op1->clone()),
		ucast<Expression>(op2->clone())
	);
	expr->setMetadata(getMetadata());
	return expr;
}

/**
* @brief Creates a new comma operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
CommaOpExpr* CommaOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	CommaOpExpr* expr(new CommaOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void CommaOpExpr::accept(Visitor *v) {
	v->visit(ucast<CommaOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
