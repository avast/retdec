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
CommaOpExpr::CommaOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
CommaOpExpr::~CommaOpExpr() {
	// Observers are removed in the superclass.
}

bool CommaOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (auto otherExpr = cast<CommaOpExpr>(otherValue)) {
		return op1->isEqualTo(otherExpr->getFirstOperand()) &&
			op2->isEqualTo(otherExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> CommaOpExpr::clone() {
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
ShPtr<CommaOpExpr> CommaOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<CommaOpExpr> expr(new CommaOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void CommaOpExpr::accept(Visitor *v) {
	v->visit(ucast<CommaOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
