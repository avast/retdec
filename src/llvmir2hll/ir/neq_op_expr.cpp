/**
* @file src/llvmir2hll/ir/neq_op_expr.cpp
* @brief Implementation of NeqOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a non-equality operator.
*
* See create() for more information.
*/
NeqOpExpr::NeqOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
NeqOpExpr::~NeqOpExpr() {
	// Observers are removed in the superclass.
}

bool NeqOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<NeqOpExpr> otherValueNeqOpExpr = cast<NeqOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueNeqOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueNeqOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> NeqOpExpr::clone() {
	ShPtr<NeqOpExpr> neqOpExpr(NeqOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	neqOpExpr->setMetadata(getMetadata());
	return neqOpExpr;
}

ShPtr<Type> NeqOpExpr::getType() const {
	// The type of `x != y` should be bool.
	return IntType::create(1);
}

/**
* @brief Creates a new non-equality operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<NeqOpExpr> NeqOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<NeqOpExpr> expr(new NeqOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void NeqOpExpr::accept(Visitor *v) {
	v->visit(ucast<NeqOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
