/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/auxiliary_variables_cfg_traversal.h
* @brief A CFG traversal for computing auxiliary variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* @see AuxiliaryVariablesOptimizer
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_AUXILIARY_VARIABLES_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_AUXILIARY_VARIABLES_CFG_TRAVERSAL_H

#include <map>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CG;
class CallInfoObtainer;
class Function;
class Module;
class Statement;
class ValueAnalysis;
class Variable;

/**
* @brief A CFG traversal for computing auxiliary variables.
*
* For the definition of an auxiliary variable, see AuxiliaryVariablesOptimizer
* (this class is meant to be used in this optimizer).
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class AuxiliaryVariablesCFGTraversal final: public CFGTraversal {
public:
	~AuxiliaryVariablesCFGTraversal();

	static VarSet getAuxiliaryVariables(ShPtr<Module> module,
		ShPtr<CallInfoObtainer> cio, ShPtr<ValueAnalysis> va,
		ShPtr<CFG> cfg);

private:
	/// Mapping of a variable into another variable.
	using VarToVarMap = std::map<ShPtr<Variable>, ShPtr<Variable>>;

private:
	/// Module which contains the function specified by its CFG.
	ShPtr<Module> module;

	/// Global variables in @c module. This is here to speedup the traversal. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;

	/// Variables corresponding to functions in @c module. This is here to
	/// speedup the traversal. By using this set, we do not have to ask @c
	/// module every time we need such information.
	VarSet varsForFuncs;

	/// Call graph of the module.
	ShPtr<CG> cg;

	/// Used call info obtainer.
	ShPtr<CallInfoObtainer> cio;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// CFG that is being traversed.
	ShPtr<CFG> cfg;

	/// Function whose CFG is being traversed.
	ShPtr<Function> func;

	/// Variables that cannot be auxiliary.
	VarSet notAuxVars;

	/// Mapping of an auxiliary (or, to be more precise, potentially auxiliary)
	/// variable into its original variable.
	/// For example, in the following code,
	/// @code
	/// a = ...
	/// b = a
	/// // a is not used in the rest of the function
	/// @endcode
	/// @c b is an auxiliary variable mapped to @c a.
	VarToVarMap auxVarToVarMap;

private:
	AuxiliaryVariablesCFGTraversal(ShPtr<Module> module,
		ShPtr<CallInfoObtainer> cio, ShPtr<ValueAnalysis> va,
		ShPtr<CFG> cfg);

	VarSet performComputation();
	bool checkIfStmtIsAuxVarDef(ShPtr<Statement> stmt);
	void checkIfPotentialAuxVarsAreAuxVars(ShPtr<Statement> stmt);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
