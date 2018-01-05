/**
* @file src/llvmir2hll/ir/fp_to_int_cast_expr.cpp
* @brief Implementation of FPToIntCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instructions FPtoSI/FPtoUI.
*
* See create() for more information.
*/
FPToIntCastExpr::FPToIntCastExpr(ShPtr<Expression> op, ShPtr<Type> dstType):
	CastExpr(op, dstType) {}

/**
* @brief Destructs the operator.
*/
FPToIntCastExpr::~FPToIntCastExpr() {
	// Observers are removed in the superclass.
}

bool FPToIntCastExpr::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values of all operands have to be equal.
	if (ShPtr<FPToIntCastExpr> otherCastExpr = cast<FPToIntCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
ShPtr<Value> FPToIntCastExpr::clone() {
	ShPtr<FPToIntCastExpr> castExpr(FPToIntCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Creates a new cast operator of of LLVM instructions FPtoSI/FPtoUI.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
*
* @par Preconditions
*  - operand is non-null
*/
ShPtr<FPToIntCastExpr> FPToIntCastExpr::create(ShPtr<Expression> op,
		ShPtr<Type> dstType) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	ShPtr<FPToIntCastExpr> expr(new FPToIntCastExpr(op, dstType));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void FPToIntCastExpr::accept(Visitor *v) {
	v->visit(ucast<FPToIntCastExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
