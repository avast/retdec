/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/dead_global_assign_optimizer.h
* @brief Elimination of dead assignments to global variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_GLOBAL_ASSIGN_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_GLOBAL_ASSIGN_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class CFGBuilder;
class CallInfoObtainer;
class Module;
class ValueAnalysis;

/**
* @brief Elimination of dead assignments to global variables.
*
* This optimization eliminates dead assignments to global variables. For
* example, the following code
* @code
* g = 1
* g = func();
* @endcode
* can be replaced with
* @code
* g = func();
* @endcode
* provided that @c g is a global variables which is not used in @c func().
*
* Instances of this class have reference object semantics. This is a concrete
* optimizer which should not be subclassed.
*/
class DeadGlobalAssignOptimizer final: public FuncOptimizer {
public:
	DeadGlobalAssignOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);
	virtual ~DeadGlobalAssignOptimizer() override;

	virtual std::string getId() const override { return "DeadGlobalAssign"; }

private:
	virtual void doOptimization() override;
	virtual void runOnFunction(ShPtr<Function> func) override;

	bool canBeOptimized(ShPtr<AssignStmt> stmt);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	/// @}

private:
	/// Analysis of used values.
	ShPtr<ValueAnalysis> va;

	/// Obtainer of information about function calls.
	ShPtr<CallInfoObtainer> cio;

	/// CFG of the current function.
	ShPtr<CFG> currCFG;

	/// The used builder of CFGs.
	ShPtr<CFGBuilder> cfgBuilder;

	/// All global variables in the module.
	VarSet globalVars;

	/// Has the code changed?
	bool codeChanged;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
