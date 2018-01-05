/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer.h
* @brief Optimizes the bodies of @c while @c True loops to simplify
*        other optimizations of these loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_PRE_WHILE_TRUE_LOOP_CONV_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_PRE_WHILE_TRUE_LOOP_CONV_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;
class VarUsesVisitor;

/**
* @brief Optimizes the bodies of @c while @c True loops to simplify
*        other optimizations of these loops.
*
* This optimization searches for the following patterns in the code (of course,
* the operations or the break conditions may differ).
*
* Optimization (1):
* @code
* while True:
*     ...
*     tmp = i + 1
*     if tmp >= 1:
*         break
*     i = tmp
* @endcode
* is optimized to
* @code
* while True:
*     ...
*     if i + 1 >= 1:
*         break
*     i = i + 1
* @endcode
*
* Optimization (2):
* @code
* while True:
*     ...
*     tmp = i;
*     i = tmp + 1;
*     if (tmp == 100):
*         break
* @endcode
* is optimized to
* @code
* while True:
*     ...
*     if i == 100:
*         break
*     i = i + 1
* @endcode
*
* Optimization (3):
* @code
* i = 0;
* if (i >= x):
*     return
* while True:
*     ...
* @endcode
* is optimized to
* @code
* if (0 >= x):
*     return
* i = 0;
* while True:
*     ...
* @endcode
*
* Optimization (4):
* @code
* while True:
*     ...
*     tmp = rand()
*     if (i >= tmp):
*         break
* @endcode
* is optimized to
* @code
* while True:
*     ...
*     if (i >= rand()):
*         break
* @endcode
*
* Optimization (5):
* @code
* while True:
*     ...
*     i = i + 1
*     if (i > 5):
*         break
* @endcode
* is optimized to
* @code
* while True:
*     ...
*     if (i + 1 > 5):
*         break
*     i = i + 1
* @endcode
*
* The reason for this optimization is that after it runs, it makes other loop
* optimizations more simple since they do not have to handle cases like these.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class PreWhileTrueLoopConvOptimizer final: public FuncOptimizer {
public:
	PreWhileTrueLoopConvOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~PreWhileTrueLoopConvOptimizer() override;

	virtual std::string getId() const override { return "PreWhileTrueLoopConv"; }

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

	bool tryOptimizationCase1(ShPtr<WhileLoopStmt> stmt);
	bool tryOptimizationCase2(ShPtr<WhileLoopStmt> stmt);
	bool tryOptimizationCase3(ShPtr<WhileLoopStmt> stmt);
	bool tryOptimizationCase4(ShPtr<WhileLoopStmt> stmt);
	bool tryOptimizationCase5(ShPtr<WhileLoopStmt> stmt);

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Visitor for obtaining uses of variables.
	ShPtr<VarUsesVisitor> vuv;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
