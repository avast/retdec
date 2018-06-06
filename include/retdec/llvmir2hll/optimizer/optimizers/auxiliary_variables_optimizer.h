/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/auxiliary_variables_optimizer.h
* @brief Elimination of auxiliary variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AUXILIARY_VARIABLES_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AUXILIARY_VARIABLES_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class Module;
class ValueAnalysis;

/**
* @brief Elimination of auxiliary variables.
*
* An auxiliary variable @c b is a variable which stores another variable @c a,
* and after storing this variable, @c a is never modified while @c b is
* modified. For example, in the following code,
* @code
* v1 = rand()
* lime = v1
* return lime + 7
* @endcode
* @c lime is an auxiliary variable and @c v1 is the original value for @c v1.
* Usually, @c v1 is a variable with an assigned name from debug information.
*
* This optimization should be run after CopyPropagationOptimizer.
*
* Instances of this class have reference object semantics. This is a concrete
* optimizer which should not be subclassed.
*/
class AuxiliaryVariablesOptimizer final: public FuncOptimizer {
public:
	AuxiliaryVariablesOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

	virtual ~AuxiliaryVariablesOptimizer() override;

	virtual std::string getId() const override { return "AuxiliaryVariables"; }

private:
	virtual void doOptimization() override;
	virtual void runOnFunction(ShPtr<Function> func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	void visit(ShPtr<AssignStmt> stmt) override;
	void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}

private:
	/// Obtainer of information about function calls.
	ShPtr<CallInfoObtainer> cio;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Auxiliary variables for the current function.
	VarSet auxVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
