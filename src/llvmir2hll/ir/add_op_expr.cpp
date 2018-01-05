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
AddOpExpr::AddOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
AddOpExpr::~AddOpExpr() {
	// Observers are removed in the superclass.
}

bool AddOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<AddOpExpr> otherValueAddOpExpr = cast<AddOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueAddOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueAddOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> AddOpExpr::clone() {
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(
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
ShPtr<AddOpExpr> AddOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<AddOpExpr> expr(new AddOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void AddOpExpr::accept(Visitor *v) {
	v->visit(ucast<AddOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
