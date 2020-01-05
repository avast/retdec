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
SubOpExpr::SubOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(Value::ValueKind::SubOpExpr, op1, op2) {}

bool SubOpExpr::isEqualTo(Value* otherValue) const {
	if (SubOpExpr* otherValueSubOpExpr = cast<SubOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueSubOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueSubOpExpr->getSecondOperand());
	}
	return false;
}

Value* SubOpExpr::clone() {
	SubOpExpr* subOpExpr(SubOpExpr::create(
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
SubOpExpr* SubOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	SubOpExpr* expr(new SubOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void SubOpExpr::accept(Visitor *v) {
	v->visit(ucast<SubOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
