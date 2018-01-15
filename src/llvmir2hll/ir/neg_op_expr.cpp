/**
* @file src/llvmir2hll/ir/neg_op_expr.cpp
* @brief Implementation of NegOpExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a negation operator.
*
* See create() for more information.
*/
NegOpExpr::NegOpExpr(ShPtr<Expression> op):
	UnaryOpExpr(op) {}

/**
* @brief Destructs the operator.
*/
NegOpExpr::~NegOpExpr() {
	// Observers are removed in the superclass.
}

bool NegOpExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (ShPtr<NegOpExpr> otherValueNegOpExpr = cast<NegOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueNegOpExpr->getOperand());
	}
	return false;
}

ShPtr<Value> NegOpExpr::clone() {
	ShPtr<NegOpExpr> negOpExpr(NegOpExpr::create(ucast<Expression>(op->clone())));
	negOpExpr->setMetadata(getMetadata());
	return negOpExpr;
}

/**
* @brief Creates a new negation operator.
*
* @param[in] op Operand.
*
* @par Preconditions
*  - @a op is non-null
*/
ShPtr<NegOpExpr> NegOpExpr::create(ShPtr<Expression> op) {
	PRECONDITION_NON_NULL(op);

	ShPtr<NegOpExpr> expr(new NegOpExpr(op));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void NegOpExpr::accept(Visitor *v) {
	v->visit(ucast<NegOpExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
