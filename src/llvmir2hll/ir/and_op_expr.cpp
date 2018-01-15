/**
* @file src/llvmir2hll/ir/and_op_expr.cpp
* @brief Implementation of AndOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a logical "and" operator.
*
* See create() for more information.
*/
AndOpExpr::AndOpExpr(ShPtr<Expression> op1, ShPtr<Expression> op2):
	BinaryOpExpr(op1, op2) {}

/**
* @brief Destructs the operator.
*/
AndOpExpr::~AndOpExpr() {
	// Observers are removed in the superclass.
}

bool AndOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<AndOpExpr> otherValueAndOpExpr = cast<AndOpExpr>(otherValue)) {
		return op1->isEqualTo(otherValueAndOpExpr->getFirstOperand()) &&
			op2->isEqualTo(otherValueAndOpExpr->getSecondOperand());
	}
	return false;
}

ShPtr<Value> AndOpExpr::clone() {
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(
		ucast<Expression>(op1->clone()), ucast<Expression>(op2->clone())));
	andOpExpr->setMetadata(getMetadata());
	return andOpExpr;
}

ShPtr<Type> AndOpExpr::getType() const {
	// The type of `x && y` should be bool.
	return IntType::create(1);
}

/**
* @brief Creates a new logical "and" operator.
*
* @param[in] op1 First operand.
* @param[in] op2 Second operand.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<AndOpExpr> AndOpExpr::create(ShPtr<Expression> op1, ShPtr<Expression> op2) {
	PRECONDITION_NON_NULL(op1);
	PRECONDITION_NON_NULL(op2);

	ShPtr<AndOpExpr> expr(new AndOpExpr(op1, op2));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op1->addObserver(expr);
	op2->addObserver(expr);

	return expr;
}

void AndOpExpr::accept(Visitor *v) {
	v->visit(ucast<AndOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
