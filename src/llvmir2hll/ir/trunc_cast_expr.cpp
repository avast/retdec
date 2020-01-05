/**
* @file src/llvmir2hll/ir/trunc_cast_expr.cpp
* @brief Implementation of TruncCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instructions FPTrunc/Trunc.
*
* See create() for more information.
*/
TruncCastExpr::TruncCastExpr(Expression* op, Type* dstType):
	CastExpr(Value::ValueKind::TruncCastExpr, op, dstType) {}

bool TruncCastExpr::isEqualTo(Value* otherValue) const {
	// Both types and values of all operands have to be equal.
	if (TruncCastExpr* otherCastExpr = cast<TruncCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
Value* TruncCastExpr::clone() {
	TruncCastExpr* castExpr(TruncCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Creates a new cast operator of LLVM instructions FPTrunc/Trunc.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
*
* @par Preconditions
*  - operand is non-null
*/
TruncCastExpr* TruncCastExpr::create(Expression* op, Type* dstType) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	TruncCastExpr* expr(new TruncCastExpr(op, dstType));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void TruncCastExpr::accept(Visitor *v) {
	v->visit(ucast<TruncCastExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
