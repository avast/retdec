/**
* @file src/llvmir2hll/ir/sub_op_expr.cpp
* @brief Implementation of SubOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a subtraction operator.
*
* See create() for more information.
*/
SubOpExpr::SubOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
SubOpExpr::~SubOpExpr() {
	// Observers are deleted in the superclass.
}

bool SubOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<SubOpExpr> otherValueSubOpExpr = cast<SubOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueSubOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueSubOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> SubOpExpr::clone() {
	ShPtr<SubOpExpr> subOpExpr(SubOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	subOpExpr->setMetadata(getMetadata());
	return subOpExpr;
}

/**
* @brief Creates a new subtraction operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<SubOpExpr> SubOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<SubOpExpr> expr(new SubOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void SubOpExpr::accept(Visitor *v) {
	v->visit(ucast<SubOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
