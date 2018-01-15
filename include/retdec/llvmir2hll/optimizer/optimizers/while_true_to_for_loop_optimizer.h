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
	WhileTrueToForLoopOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator);

	virtual ~WhileTrueToForLoopOptimizer() override;

	virtual std::string getId() const override { return "WhileTrueToForLoop"; }

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

	ShPtr<Expression> computeStartValueOfForLoop(
		ShPtr<IndVarInfo> indVarInfo) const;
	ShPtr<Expression> computeStepOfForLoop(
		ShPtr<IndVarInfo> indVarInfo) const;
	ShPtr<Expression> computeEndCondOfForLoop(
		ShPtr<IndVarInfo> indVarInfo,
		ShPtr<Expression> startValue, ShPtr<Expression> step) const;
	ShPtr<ConstInt> evaluate(ShPtr<Expression> expr) const;

	static ShPtr<BinaryOpExpr> exchangeCompOpAndOperands(
		ShPtr<BinaryOpExpr> expr);
	static bool isNonNegative(ShPtr<Expression> expr);
	static bool isPositive(ShPtr<Expression> expr);

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Evaluator of expressions.
	ShPtr<ArithmExprEvaluator> arithmExprEvaluator;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
