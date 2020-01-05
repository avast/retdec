/**
* @file src/llvmir2hll/ir/int_to_ptr_cast_expr.cpp
* @brief Implementation of IntToPtrCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instruction IntToPtr.
*
* See create() for more information.
*/
IntToPtrCastExpr::IntToPtrCastExpr(Expression* op, Type* dstType):
	CastExpr(op, dstType) {}

bool IntToPtrCastExpr::isEqualTo(Value* otherValue) const {
	// Both types and values of all operands have to be equal.
	if (IntToPtrCastExpr* otherCastExpr = cast<IntToPtrCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
Value* IntToPtrCastExpr::clone() {
	IntToPtrCastExpr* castExpr(IntToPtrCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Creates a new cast operator of LLVM instruction IntToPtr.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
*
* @par Preconditions
*  - operand is non-null
*/
IntToPtrCastExpr* IntToPtrCastExpr::create(Expression* op,
		Type* dstType) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	IntToPtrCastExpr* expr(new IntToPtrCastExpr(op, dstType));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void IntToPtrCastExpr::accept(Visitor *v) {
	v->visit(ucast<IntToPtrCastExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
