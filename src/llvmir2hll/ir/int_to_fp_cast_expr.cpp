/**
* @file src/llvmir2hll/ir/int_to_fp_cast_expr.cpp
* @brief Implementation of IntToFPCastExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a cast operator of LLVM instructions SItoFP/UItoFP.
*
* See create() for more information.
*/
IntToFPCastExpr::IntToFPCastExpr(Expression* op, Type* dstType,
		Variant variant):
	CastExpr(Value::ValueKind::IntToFPCastExpr, op, dstType), variant(variant) {}

bool IntToFPCastExpr::isEqualTo(Value* otherValue) const {
	// Both types and values of all operands have to be equal.
	if (IntToFPCastExpr* otherCastExpr = cast<IntToFPCastExpr>(otherValue)) {
		return dstType->isEqualTo(otherCastExpr->getType()) &&
			op->isEqualTo(otherCastExpr->getOperand());
	}
	return false;
}

/**
* @brief Clones the cast operator.
*/
Value* IntToFPCastExpr::clone() {
	IntToFPCastExpr* castExpr(IntToFPCastExpr::create(
		ucast<Expression>(op->clone()), dstType));
	castExpr->setMetadata(getMetadata());
	return castExpr;
}

/**
* @brief Returns variant of the integer to floating point cast.
*/
IntToFPCastExpr::Variant IntToFPCastExpr::getVariant() const {
	return variant;
}

/**
* @brief Creates a new cast operator of LLVM instructions SItoFP/UItoFP.
*
* @param[in] op Operand.
* @param[in] dstType Destination type.
* @param[in] variant Variant of the cast.
*
* @par Preconditions
*  - @a op is non-null
*/
IntToFPCastExpr* IntToFPCastExpr::create(Expression* op,
		Type* dstType, Variant variant) {
	PRECONDITION_NON_NULL(op);
	PRECONDITION_NON_NULL(dstType);

	IntToFPCastExpr* expr(new IntToFPCastExpr(op, dstType, variant));

	// Initialization (recall that this cannot be called in a
	// constructor).
	op->addObserver(expr);

	return expr;
}

void IntToFPCastExpr::accept(Visitor *v) {
	v->visit(ucast<IntToFPCastExpr>(this));
}

} // namespace llvmir2hll
} // namespace retdec
