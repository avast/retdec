/**
* @file src/llvmir2hll/ir/mul_op_expr.cpp
* @brief Implementation of MulOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a multiplication operator.
*
* See create() for more information.
*/
MulOpExpr::MulOpExpr(Expression* op1, Expression* op2):
	BinaryOpExpr(Value::ValueKind::MulOpExpr, op1, op2) {}

bool MulOpExpr::isEqualTo(Value* otherValue) const {
	if (MulOpExpr* otherValueMulOpExpr = cast<MulOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueMulOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueMulOpExpr->getSecondOperand());
	}
	return false;
}

Value* MulOpExpr::clone() {
	MulOpExpr* mulOpExpr(MulOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	mulOpExpr->setMetadata(getMetadata());
	return mulOpExpr;
}

/**
* @brief Creates a new multiplication operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
MulOpExpr* MulOpExpr::create(Expression* op1, Expression* op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	MulOpExpr* expr(new MulOpExpr(op1, op2));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void MulOpExpr::accept(Visitor *v) {
	v->visit(ucast<MulOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
