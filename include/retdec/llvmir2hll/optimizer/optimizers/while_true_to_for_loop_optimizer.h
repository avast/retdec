/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer.h
* @brief Optimizes while loops into for loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_FOR_LOOP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_FOR_LOOP_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;
class BinaryOpExpr;
class ValueAnalysis;

/**
* @brief Optimizes while loops into for loops.
*
* For example, the following loop
* @code
* i = 0
* while True:
*     printf("test")
*     if i >= g:
*         break
*     i = i + 1
* @endcode
* can be optimized into
* @code
* for i in range(0, g + 1):
*     printf("test")
* @endcode
*
* Prerequisities:
*  - This optimization requires that LoopLastContinueOptimizer has run.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class WhileTrueToForLoopOptimizer final: public FuncOptimizer {
public:
	WhileTrueToForLoopOptimizer(Module* module, ValueAnalysis* va,
		ArithmExprEvaluator* arithmExprEvaluator);

	virtual std::string getId() const override { return "WhileTrueToForLoop"; }

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(WhileLoopStmt* stmt) override;
	/// @}

	Expression* computeStartValueOfForLoop(
		IndVarInfo* indVarInfo) const;
	Expression* computeStepOfForLoop(
		IndVarInfo* indVarInfo) const;
	Expression* computeEndCondOfForLoop(
		IndVarInfo* indVarInfo,
		Expression* startValue, Expression* step) const;
	ConstInt* evaluate(Expression* expr) const;

	static BinaryOpExpr* exchangeCompOpAndOperands(
		BinaryOpExpr* expr);
	static bool isNonNegative(Expression* expr);
	static bool isPositive(Expression* expr);

private:
	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// Evaluator of expressions.
	ArithmExprEvaluator* arithmExprEvaluator = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
