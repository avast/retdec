/**
* @file src/llvmir2hll/ir/assign_op_expr.cpp
* @brief Implementation of AssignOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an assignment operator.
*
* See create() for more information.
*/
AssignOpExpr::AssignOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(op1, op2) {}

bool AssignOpExpr::isEqualTo(Value* otherValue) const {
	if (auto otherExpr = cast<AssignOpExpr>(otherValue)) {
		return op1->isEqualTo(otherExpr->getFirstOperand()) &&
			op2->isEqualTo(otherExpr->getSecondOperand());
	}
	return false;
}

Value* AssignOpExpr::clone() {
	auto expr = AssignOpExpr::create(
		ucast<Expression>(op1->clone()),
		ucast<Expression>(op2->clone())
	);
	expr->setMetadata(getMetadata());
	return expr;
}

/**
* @brief Creates a new assignment operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
AssignOpExpr* AssignOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	AssignOpExpr* expr(new AssignOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void AssignOpExpr::accept(Visitor *v) {
	v->visit(ucast<AssignOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
