/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/dead_local_assign_optimizer.h
* @brief Elimination of dead assignments to local variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_LOCAL_ASSIGN_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_LOCAL_ASSIGN_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class ValueAnalysis;
class VarUses;
class VarUsesVisitor;

/**
* @brief Elimination of dead assignments to local variables.
*
* This optimization eliminates dead variables by removing dead assignments or
* variable definitions. These are assignments which assign a value into a
* variable which is then never used.
*
* For example, the following code
* @code
* a = 1
* return x
* @endcode
* can be replaced with
* @code
* return x
* @endcode
* provided that @c a is non-global.
*
* Instances of this class have reference object semantics. This is a concrete
* optimizer which should not be subclassed.
*/
class DeadLocalAssignOptimizer final: public FuncOptimizer {
public:
	DeadLocalAssignOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);
	virtual ~DeadLocalAssignOptimizer() override;

	virtual std::string getId() const override { return "DeadLocalAssign"; }

private:
	virtual void doOptimization() override;
	virtual void runOnFunction(ShPtr<Function> func) override;

	bool canBeOptimized(ShPtr<Variable> var, ShPtr<VarUses> varUses);
	bool tryToOptimize(ShPtr<Function> func);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	/// @}

private:
	/// Analysis of used values.
	ShPtr<ValueAnalysis> va;

	/// Visitor for obtaining uses of variables.
	ShPtr<VarUsesVisitor> vuv;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
