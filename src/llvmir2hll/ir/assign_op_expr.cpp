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
AssignOpExpr::AssignOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
AssignOpExpr::~AssignOpExpr() {
	// Observers are removed in the superclass.
}

bool AssignOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (auto otherExpr = cast<AssignOpExpr>(otherValue)) {
		return op1->isEqualTo(otherExpr->getFirstOperand()) &&
			op2->isEqualTo(otherExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> AssignOpExpr::clone() {
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
ShPtr<AssignOpExpr> AssignOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<AssignOpExpr> expr(new AssignOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void AssignOpExpr::accept(Visitor *v) {
	v->visit(ucast<AssignOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
