/**
* @file src/llvmir2hll/ir/or_op_expr.cpp
* @brief Implementation of OrOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a logical "or" operator.
*
* See create() for more information.
*/
OrOpExpr::OrOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
OrOpExpr::~OrOpExpr() {
	// Observers are removed in the superclass.
}

bool OrOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<OrOpExpr> otherValueOrOpExpr = cast<OrOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueOrOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueOrOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> OrOpExpr::clone() {
	ShPtr<OrOpExpr> orOpExpr(OrOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	orOpExpr->setMetadata(getMetadata());
	return orOpExpr;
}

ShPtr<Type> OrOpExpr::getType() const {
	// The type of `x || y` should be bool.
	return IntType::create(1);
}

/**
* @brief Creates a new logical "or" operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<OrOpExpr> OrOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<OrOpExpr> expr(new OrOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void OrOpExpr::accept(Visitor *v) {
	v->visit(ucast<OrOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
