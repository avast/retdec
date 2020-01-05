/**
* @file src/llvmir2hll/ir/add_op_expr.cpp
* @brief Implementation of AddOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs an addition operator.
*
* See create() for more information.
*/
AddOpExpr::AddOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(op1, op2) {}

bool AddOpExpr::isEqualTo(Value* otherValue) const {
	if (AddOpExpr* otherValueAddOpExpr = cast<AddOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueAddOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueAddOpExpr->getSecondOperand());
	}
	return false;
}

Value* AddOpExpr::clone() {
	AddOpExpr* addOpExpr(AddOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	addOpExpr->setMetadata(getMetadata());
	return addOpExpr;
}

/**
* @brief Creates a new addition operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
AddOpExpr* AddOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	AddOpExpr* expr(new AddOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void AddOpExpr::accept(Visitor *v) {
	v->visit(ucast<AddOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
