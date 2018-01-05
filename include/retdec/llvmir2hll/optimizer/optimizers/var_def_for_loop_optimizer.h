/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/var_def_for_loop_optimizer.h
* @brief Optimizes VarDefStmts for induction variables of for loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_VAR_DEF_FOR_LOOP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_VAR_DEF_FOR_LOOP_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes VarDefStmts for induction variables of for loops.
*
* This optimizer removes variable defining statements at the beginning of a
* function which correspond to induction variables of for loops. For example,
* @code
* void func(void) {
*     int i;
*     // ...
*     for (int i = 0; i < 10, ++i) {
*         // ...
*     }
*     // ...
* }
* @endcode
* is optimized into
* @code
* void func(void) {
*     // ...
*     for (int i = 0; i < 10, ++i) {
*         // ...
*     }
*     // ...
* }
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class VarDefForLoopOptimizer final: public FuncOptimizer {
public:
	VarDefForLoopOptimizer(ShPtr<Module> module);

	virtual ~VarDefForLoopOptimizer() override;

	virtual std::string getId() const override { return "VarDefForLoop"; }

private:
	virtual void runOnFunction(ShPtr<Function> func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	/// @}

private:
	/// Set of induction variables of for loops in each function.
	VarSet indVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
