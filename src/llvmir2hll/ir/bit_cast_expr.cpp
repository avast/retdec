/**
* @file src/llvmir2hll/ir/bit_cast_expr.cpp
* @brief Implementation of BitCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instruction BitCast.
*
* See create() for more information.
*/
BitCastExpr::BitCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType):
	CastExpr(op, dstType) {}

/**
* @brief Destructs the operator.
*/
BitCastExpr::~BitCastExpr() {
	// Observers are removed in the superclass.
}

bool BitCastExpr::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values of all operands have to be equal.
	if (ShPtr<BitCastExpr> otherCastExpr = cast<BitCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
ShPtr<Value> BitCastExpr::clone() {
	ShPtr<BitCastExpr> BitCastExpr(BitCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	BitCastExpr->setMetadata(getMetadata());
	return BitCastExpr;
}

/**
* @brief Creates a new cast operator of LLVM instruction BitCast.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
*
* @par Preconditions
*  - both operands are non-null
*/
ShPtr<BitCastExpr> BitCastExpr::create(ShPtr<Expression> op,
		ShPtr<Type> dstType) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	ShPtr<BitCastExpr> expr(new BitCastExpr(op, dstType));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void BitCastExpr::accept(Visitor *v) {
	v->visit(ucast<BitCastExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
