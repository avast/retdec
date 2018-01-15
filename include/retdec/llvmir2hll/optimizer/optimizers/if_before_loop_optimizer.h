/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer.h
* @brief Optimizes if statements before loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_BEFORE_LOOP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_BEFORE_LOOP_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;

/**
* @brief Optimizes if statements before loops.
*
* This optimization optimizes if statements before loops.
*
* Optimization (1):
* @code
* if x > 1:
*     for i in range(0, (x - 2) + 1):
*         printf("test")
* return 0
* @endcode
* can be optimized into
* @code
* for i in range(0, (x - 2) + 1):
*     printf("test")
* return 0
* @endcode
*
* Optimization (2):
* @code
* if x < 1:
*     return
* for i in range(0, (x - 2) + 1):
*     printf("test")
* @endcode
* can be optimized into
* @code
* for i in range(0, (x - 2) + 1):
*     printf("test")
* @endcode
*
* The reason for this optimization is that the if statement is introduced by
* LLVM even on places where it is not necessary. Indeed, LLVM produces only
* "while True" loops, so when we use a different type of a loop, we may
* optimize the if statement.
*
* Prerequisities:
*  - For the sake of effectiveness, this optimizer should be ran after the
*    WhileTrueToForLoopOptimizer and WhileTrueToWhileCondOptimizer optimizations.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class IfBeforeLoopOptimizer final: public FuncOptimizer {
public:
	IfBeforeLoopOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~IfBeforeLoopOptimizer() override;

	virtual std::string getId() const override { return "IfBeforeLoop"; }

private:
	virtual void doOptimization() override;

	bool tryOptimizationCase1(ShPtr<IfStmt> stmt);
	bool tryOptimizationCase2(ShPtr<IfStmt> stmt);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	/// @}

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
