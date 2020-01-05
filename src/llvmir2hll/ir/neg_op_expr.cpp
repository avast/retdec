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
NegOpExpr::NegOpExpr(Expression* op):
	UnaryOpExpr(Value::ValueKind::NegOpExpr, op) {}

bool NegOpExpr::isEqualTo(Value* otherValue) const {
	if (NegOpExpr* otherValueNegOpExpr = cast<NegOpExpr>(otherValue)) {
		return op->isEqualTo(otherValueNegOpExpr->getOperand());
	}
	return false;
}

Value* NegOpExpr::clone() {
	NegOpExpr* negOpExpr(NegOpExpr::create(ucast<Expression>(op->clone())));
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
NegOpExpr* NegOpExpr::create(Expression* op) {
	PRECONDITION_NON_NULL(op);

	NegOpExpr* expr(new NegOpExpr(op));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void NegOpExpr::accept(Visitor *v) {
	v->visit(ucast<NegOpExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
