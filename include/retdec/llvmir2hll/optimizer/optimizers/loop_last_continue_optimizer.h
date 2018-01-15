/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer.h
* @brief Optimizes redundant continue statements in loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_LOOP_LAST_CONTINUE_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_LOOP_LAST_CONTINUE_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes redundant continue statements in loops.
*
* This optimizer removes redundant continue statements in loops. More
* specifically, it removes continue statements at the end of loops. For
* example,
* @code
* while True:
*     printf("test")
*     if i + 2 >= g:
*         break
*     i = i + 1
*     continue
* @endcode
* can be optimized into
* @code
* while True:
*     printf("test")
*     if i + 2 >= g:
*         break
*     i = i + 1
* @endcode
*
* If a continue statement has some attached metadata, this optimizer replaces
* the continue statement with an empty statement to preserve the metadata.
*
* Prerequisities:
*  - This optimization should be run after all optimizations changing the
*    structure of the code, such as IfStructureOptimizer.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class LoopLastContinueOptimizer final: public FuncOptimizer {
public:
	LoopLastContinueOptimizer(ShPtr<Module> module);

	virtual ~LoopLastContinueOptimizer() override;

	virtual std::string getId() const override { return "LoopLastContinue"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

	void tryToOptimize(ShPtr<Statement> stmt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
