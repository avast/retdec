/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/unneeded_global_vars_cfg_traversal.h
* @brief A CFG traversal that obtains so-called ``unneeded'' global variables
*        from functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_UNNEEDED_GLOBAL_VARS_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_UNNEEDED_GLOBAL_VARS_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class Function;
class Module;
class Statement;
class ValueAnalysis;
class Variable;

/**
* @brief A CFG traversal that obtains the set of ``unneeded'' global variables in
*        a function.
*
* This class is meant to be used in GlobalToLocalOptimizer. For more
* information, mainly for the definition of a ``unneeded'' global variable, see
* GlobalToLocalOptimizer::convertUnneededGlobalVars().
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class UnneededGlobalVarsCFGTraversal final: public CFGTraversal {
public:
	/**
	* @brief Information about unneeded global variables in a function.
	*/
	class UnneededGlobalVars {
	public:
		UnneededGlobalVars(ShPtr<Function> func, VarSet vars,
			StmtSet stmts): func(func), vars(vars), stmts(stmts) {}

	public:
		/// Function for which the info has been computed.
		ShPtr<Function> func;

		/// Unneeded global variables in the given function.
		VarSet vars;

		/// Set of statements that can be removed from the function when all
		/// unneeded global variables are converted into local variables.
		StmtSet stmts;
	};

public:
	~UnneededGlobalVarsCFGTraversal();

	static ShPtr<UnneededGlobalVars> getUnneededGlobalVars(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio, ShPtr<CFG> cfg);

private:
	/// A mapping of a variable into another variable.
	using VarToVarMap = std::map<ShPtr<Variable>, ShPtr<Variable>>;

private:
	/// Module in which the function specified by its CFG is.
	ShPtr<Module> module;

	/// Global variables in @c module. This is here to speedup the traversal. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// The used call info obtainer.
	ShPtr<CallInfoObtainer> cio;

	/// The CFG that is being traversed.
	ShPtr<CFG> cfg;

	/// The function whose CFG is being traversed.
	ShPtr<Function> traversedFunc;

	/// Global variables that (1) are read into local variables at the
	/// beginning of the function's body and (2) the local variables are just
	/// read, not assigned.
	VarToVarMap storedGlobalVars;

	/// Set of statements that can be removed from the function when all
	/// unneeded global variables are converted into local variables.
	StmtSet unneededStmts;

private:
	UnneededGlobalVarsCFGTraversal(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio,
		ShPtr<CFG> cfg);

	ShPtr<UnneededGlobalVars> performUnneededGlobalVarsComputation();
	void updateUnneededGlobalVarsInfo(ShPtr<Statement> stmt);
	bool checkExitNodesPredecessor(ShPtr<CFG::Node> node);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
