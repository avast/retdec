/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/global_to_local_optimizer.h
* @brief Converts global variables to local variables wherever possible.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_GLOBAL_TO_LOCAL_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_GLOBAL_TO_LOCAL_OPTIMIZER_H

#include <map>

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CG;
class CallInfoObtainer;
class ValueAnalysis;
class VarUsesVisitor;

/**
* @brief Converts global variables to local variables wherever possible.
*
* By converting global variables to local ones, the copy propagation
* optimization can be more effective. This optimization also removes global
* variables that are never used.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class GlobalToLocalOptimizer final: public Optimizer {
public:
	GlobalToLocalOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

	virtual ~GlobalToLocalOptimizer() override;

	virtual std::string getId() const override { return "GlobalToLocal"; }

private:
	/// Mapping of a function into a set of variables.
	using FuncVarsMap = std::map<ShPtr<Function>, VarSet>;

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	/// @}

	void removeUnusedGlobalVars();
	void convertUselessGlobalVars();
	void convertUnneededGlobalVars();
	void convertOtherGlobalVars();

	void computeGlobalVars();
	void computeGlobalVarsUsedInGlobalVarDef();
	void computeUsedGlobalVars();
	VarSet computeUsedGlobalVarsForFunc(ShPtr<Function> func) const;
	bool isUsedInFunc(ShPtr<Variable> var, ShPtr<Function> func);
	void computeUsefulAndUselessGlobalVars();
	bool isUsefulInFunc(ShPtr<Variable> var, ShPtr<Function> func) const;
	bool globalVarMayBeRemovedAsUnused(ShPtr<Variable> var);
	bool globalVarMayBeConverted(ShPtr<Variable> var, ShPtr<Function> func);
	void convertGlobalVar(ShPtr<Variable> var, ShPtr<Function> func);
	bool isStatementImplyingUsefulness(ShPtr<Statement> stmt) const;
	void convertUnneededGlobalVarsForFunc(ShPtr<Function> func);

private:
	/// Call graph of the current module.
	ShPtr<CG> cg;

	/// Analysis of used values.
	ShPtr<ValueAnalysis> va;

	/// Obtainer of information about function calls.
	ShPtr<CallInfoObtainer> cio;

	/// Visitor for obtaining uses of variables.
	ShPtr<VarUsesVisitor> vuv;

	/// Global variables in @c module. This is here to speedup the optimization.
	/// By using this set, we do not have to ask @c module every time we need
	/// such information.
	VarSet globalVars;

	/// Global variables that are used in the definition of other global
	/// variables.
	VarSet globalVarsUsedInGlobalVarDef;

	/// Global variables that are ``useful'' (see the description of
	/// computeUsefulAndUselessGlobalVars()).
	VarSet usefulGlobalVars;

	/// Global variables that are ``useless'' (see the description of
	/// computeUsefulAndUselessGlobalVars()).
	VarSet uselessGlobalVars;

	/// Mapping of a function into the set of global variables used in the
	/// function.
	FuncVarsMap funcUsedGlobalVarsMap;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
