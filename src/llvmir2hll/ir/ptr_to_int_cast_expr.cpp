/**
* @file src/llvmir2hll/ir/ptr_to_int_cast_expr.cpp
* @brief Implementation of PtrToIntCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instruction PtrToInt.
*
* See create() for more information.
*/
PtrToIntCastExpr::PtrToIntCastExpr(Expression* op, Type* dstType):
	CastExpr(op, dstType) {}

bool PtrToIntCastExpr::isEqualTo(Value* otherValue) const {
	// Both types and values of all operands have to be equal.
	if (PtrToIntCastExpr* otherCastExpr = cast<PtrToIntCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
Value* PtrToIntCastExpr::clone() {
	PtrToIntCastExpr* castExpr(PtrToIntCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Creates a new cast operator of LLVM instruction PtrToInt.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
*
* @par Preconditions
*  - operand is non-null
*/
PtrToIntCastExpr* PtrToIntCastExpr::create(Expression* op,
		Type* dstType) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	PtrToIntCastExpr* expr(new PtrToIntCastExpr(op, dstType));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void PtrToIntCastExpr::accept(Visitor *v) {
	v->visit(ucast<PtrToIntCastExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
