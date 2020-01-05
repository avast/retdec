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
NeqOpExpr::NeqOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(op1, op2) {}

bool NeqOpExpr::isEqualTo(Value* otherValue) const {
	if (NeqOpExpr* otherValueNeqOpExpr = cast<NeqOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueNeqOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueNeqOpExpr->getSecondOperand());
	}
	return false;
}

Value* NeqOpExpr::clone() {
	NeqOpExpr* neqOpExpr(NeqOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	neqOpExpr->setMetadata(getMetadata());
	return neqOpExpr;
}

Type* NeqOpExpr::getType() const {
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
NeqOpExpr* NeqOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	NeqOpExpr* expr(new NeqOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void NeqOpExpr::accept(Visitor *v) {
	v->visit(ucast<NeqOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
