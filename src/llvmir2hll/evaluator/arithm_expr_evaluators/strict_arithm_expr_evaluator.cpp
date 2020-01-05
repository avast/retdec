/**
* @file src/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.cpp
* @brief Implementation of StrictArithmExprEvaluator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <optional>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator_factory.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("strict", STRICT_ARITHM_EXPR_EVALUATOR_ID,
	ArithmExprEvaluatorFactory, StrictArithmExprEvaluator::create);

/**
* @brief Creates a new StrictArithmExprEvaluator.
*/
ArithmExprEvaluator* StrictArithmExprEvaluator::create() {
	return new StrictArithmExprEvaluator();
}

std::string StrictArithmExprEvaluator::getId() const {
	return STRICT_ARITHM_EXPR_EVALUATOR_ID;
}

/**
* @brief Resolve types of operands in binary operations.
*
* @param[in, out] constPair Pair of constants on which is resolved types.
*/
void StrictArithmExprEvaluator::resolveTypesBinaryOp(ConstPair &constPair) {
	if (!constPair.first->getType()->isEqualTo(constPair.second->getType())) {
		// Both of operands must have same type.
		canBeEvaluated = false;
	}

	if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(constPair)) {
		APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
		if (apsIntPair.first.getBitWidth() !=
				apsIntPair.second.getBitWidth()) {
			// Both of operands must have to same bitWidth.
			canBeEvaluated = false;
		}
	}
}

void StrictArithmExprEvaluator::resolveOpSpecifications(DivOpExpr* expr,
		ConstPair &constPair) {
	if (!canBeEvaluated) {
		return;
	}

	if (isConstantZero(constPair.second)) {
		// Division with zero is not supported.
		canBeEvaluated = false;
		return;
	}

	// Supported only division without remainder.
	if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(constPair)) {
		APSIntPair apsIntPair = getAPSIntsFromConstants(constIntPair);
		ConstInt* remConstInt(ConstInt::create(apsIntPair.first.srem(
			apsIntPair.second)));
		if (!remConstInt->isZero()) {
			canBeEvaluated = false;
		}
	}
}

void StrictArithmExprEvaluator::resolveOpSpecifications(ModOpExpr* expr,
		ConstPair &constPair) {
	// Remaindering with zero not supported.
	canBeEvaluated &= !isConstantZero(constPair.second);
}

void StrictArithmExprEvaluator::resolveOpSpecifications(NegOpExpr* expr,
		Constant* &constant) {
	ConstInt* opConstInt(cast<ConstInt>(constant));
	ConstFloat* opConstFloat(cast<ConstFloat>(constant));
	if (opConstInt && opConstInt->isSigned() && opConstInt->isMinSigned()) {
		// Don't evaluate -128 on 8 bits to 128. Overflow.
		canBeEvaluated = false;
	}
	if (!opConstInt && !opConstFloat) {
		// Don't evaluate -True.
		canBeEvaluated = false;
	}
}

void StrictArithmExprEvaluator::resolveCast(BitCastExpr* expr,
		Constant* &constant) {
	canBeEvaluated = false;
}

void StrictArithmExprEvaluator::resolveCast(ExtCastExpr* expr,
		Constant* &constant) {
	canBeEvaluated = false;
}

void StrictArithmExprEvaluator::resolveCast(FPToIntCastExpr* expr,
		Constant* &constant) {
	canBeEvaluated = false;
}

void StrictArithmExprEvaluator::resolveCast(IntToFPCastExpr* expr,
		Constant* &constant) {
	canBeEvaluated = false;
}

void StrictArithmExprEvaluator::resolveCast(TruncCastExpr* expr,
		Constant* &constant) {
	canBeEvaluated = false;
}

/**
* @brief Stop evaluation if overflow occurred.
*
* @param[in] overflow Overflow.
*/
void StrictArithmExprEvaluator::resolveOverflowForAPInt(bool overflow) {
	canBeEvaluated &= !overflow;
}

/**
* @brief Stop evaluation if overflow occurred.
*
* @param[in] opStatus Status.
*/
void StrictArithmExprEvaluator::resolveOverflowForAPFloat(
		llvm::APFloat::opStatus opStatus) {
	canBeEvaluated &= opStatus == llvm::APFloat::opOK;
}

} // namespace llvmir2hll
} // namespace retdec
