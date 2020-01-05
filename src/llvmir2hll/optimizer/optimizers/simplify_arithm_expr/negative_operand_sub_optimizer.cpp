/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negative_operand_sub_optimizer.cpp
* @brief Implementation of NegativeOperandSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negative_operand_sub_optimizer.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("NegativeOperand", NEGATIVE_OPERAND_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, NegativeOperandSubOptimizer::create);

/**
* @brief Constructs the NegativeOperandSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
NegativeOperandSubOptimizer::NegativeOperandSubOptimizer(
		ArithmExprEvaluator* arithmExprEvaluator):
			SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Creates a new NegativeOperandSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
SubOptimizer* NegativeOperandSubOptimizer::create(
		ArithmExprEvaluator* arithmExprEvaluator) {
	return new NegativeOperandSubOptimizer(
		arithmExprEvaluator);
}

std::string NegativeOperandSubOptimizer::getId() const {
	return NEGATIVE_OPERAND_SUB_OPTIMIZER_ID;
}

void NegativeOperandSubOptimizer::visit(AddOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	// -------
	// First negative operand optimization.
	//
	ConstInt* firstOpNegConstInt(
		ifNegativeConstIntReturnIt(expr->getFirstOperand()));
	ConstFloat* firstOpNegConstFloat(
		ifNegativeConstFloatReturnIt(expr->getFirstOperand()));
	NegOpExpr* firstOpNegOpExpr(cast<NegOpExpr>(expr->getFirstOperand()));

	// Optimization like "-3 + a" -> optimized to "a - 3".
	if (firstOpNegConstInt && !firstOpNegConstInt->isMinSigned()) {
		// We can't optimize expressions like -128 + a when -128 is only
		// on 8 bits because in this case, .abs() does not invert this
		// number to positive.
		firstOpNegConstInt->flipSign();
		SubOpExpr* sub(SubOpExpr::create(expr->getSecondOperand(),
			firstOpNegConstInt));
		optimizeExpr(expr, sub);
		return;
	}

	// Optimization like "-3.0 + a" -> optimized to "a - 3.0".
	if (firstOpNegConstFloat) {
		firstOpNegConstFloat->flipSign();
		SubOpExpr* sub(SubOpExpr::create(expr->getSecondOperand(),
			firstOpNegConstFloat));
		optimizeExpr(expr, sub);
		return;
	}

	// Optimization like "(NegOpExpr)a + 3" -> optimized to "3 - a".
	if (firstOpNegOpExpr) {
		SubOpExpr* sub(SubOpExpr::create(expr->getSecondOperand(),
			firstOpNegOpExpr->getOperand()));
		optimizeExpr(expr, sub);
		return;
	}
	//
	// -------

	// -------
	// Second negative operand optimization.
	//
	ConstInt* secOpNegConstInt(
		ifNegativeConstIntReturnIt(expr->getSecondOperand()));
	ConstFloat* secOpNegConstFloat(
		ifNegativeConstFloatReturnIt(expr->getSecondOperand()));
	NegOpExpr* secOpNegOpExpr(cast<NegOpExpr>(expr->getSecondOperand()));

	// Optimization like "a + -2" -> optimized to "a - 2".
	if (secOpNegConstInt && !secOpNegConstInt->isMinSigned()) {
		secOpNegConstInt->flipSign();
		// We can't optimize expressions like a + -128 when -128 is only
		// on 8 bits because in this case, .abs() does not invert this
		// number to positive.
		SubOpExpr* sub(SubOpExpr::create(expr->getFirstOperand(),
			secOpNegConstInt));
		optimizeExpr(expr, sub);
		return;
	}

	// Optimization like "a + -2.0" -> optimized to "a - 2.0".
	if (secOpNegConstFloat) {
		secOpNegConstFloat->flipSign();
		SubOpExpr* sub(SubOpExpr::create(expr->getFirstOperand(),
			secOpNegConstFloat));
		optimizeExpr(expr, sub);
		return;
	}

	// Optimization like "2 + (NegOpExpr)a" -> optimized to "2 - a".
	if (secOpNegOpExpr) {
		SubOpExpr* sub(SubOpExpr::create(expr->getFirstOperand(),
			secOpNegOpExpr->getOperand()));
		optimizeExpr(expr, sub);
		return;
	}
	//
	// -------
}

void NegativeOperandSubOptimizer::visit(SubOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	// -------
	// Second negative operand optimization.
	//
	ConstInt* secOpNegConstInt(
		ifNegativeConstIntReturnIt(expr->getSecondOperand()));
	ConstFloat* secOpNegConstFloat(
		ifNegativeConstFloatReturnIt(expr->getSecondOperand()));
	NegOpExpr* secOpNegOpExpr(cast<NegOpExpr>(expr->getSecondOperand()));

	// Optimization like "a - -2" -> optimized to "a + 2".
	if (secOpNegConstInt && !secOpNegConstInt->isMinSigned()) {
		// We can't optimize expressions like a - -128 when -128 is only
		// on 8 bits because in this case, .abs() does not invert this
		// number to positive.
		secOpNegConstInt->flipSign();
		AddOpExpr* add(AddOpExpr::create(expr->getFirstOperand(),
			secOpNegConstInt));
		optimizeExpr(expr, add);
		return;
	}

	// Optimization like "a - -2.0" -> optimized to "a + 2.0".
	if (secOpNegConstFloat) {
		secOpNegConstFloat->flipSign();
		AddOpExpr* add(AddOpExpr::create(expr->getFirstOperand(),
			secOpNegConstFloat));
		optimizeExpr(expr, add);
		return;
	}

	// Optimization like "2 - (NegOpExpr)a" -> optimized to "2 + a".
	if (secOpNegOpExpr) {
		AddOpExpr* add(AddOpExpr::create(expr->getFirstOperand(),
			secOpNegOpExpr->getOperand()));
		optimizeExpr(expr, add);
		return;
	}
	//
	// -------
}

/**
* @brief If @a expr is negative @c ConstInt, return it.
*
* @param[in] expr An expression to check.
*
* @return @c ConstInt if @a expr is negative @c ConstInt, otherwise the null
*         pointer.
*/
ConstInt* NegativeOperandSubOptimizer::ifNegativeConstIntReturnIt(
		Expression* expr) const {
	ConstInt* constInt(cast<ConstInt>(expr));
	if (constInt && constInt->isNegative()) {
		return constInt;
	} else {
		return nullptr;
	}
}

/**
* @brief If @a expr is negative @c ConstFloat, return it.
*
* @param[in] expr An expression to check.
*
* @return @c ConstFloat if @a expr is negative @c ConstFloat, otherwise the
*         null pointer.
*/
ConstFloat* NegativeOperandSubOptimizer::ifNegativeConstFloatReturnIt(
		Expression* expr) const {
	ConstFloat* constFloat(cast<ConstFloat>(expr));
	if (constFloat && constFloat->isNegative()) {
		return constFloat;
	} else {
		return nullptr;
	}
}

} // namespace llvmir2hll
} // namespace retdec
