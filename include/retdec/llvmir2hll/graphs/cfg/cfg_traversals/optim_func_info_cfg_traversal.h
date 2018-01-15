/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/optim_func_info_cfg_traversal.h
* @brief A CFG traversal for computing OptimFuncInfos.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* @see OptimCallInfoObtainer::OptimFuncInfo
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_OPTIM_FUNC_INFO_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_OPTIM_FUNC_INFO_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CG;
class Function;
class Module;
class Statement;
class Variable;

/**
* @brief A CFG traversal for computing OptimFuncInfos.
*
* This class is meant to be used in OptimCallInfoObtainer.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class OptimFuncInfoCFGTraversal final: public CFGTraversal {
public:
	~OptimFuncInfoCFGTraversal();

	static ShPtr<OptimFuncInfo> getOptimFuncInfo(ShPtr<Module> module,
		ShPtr<OptimCallInfoObtainer> cio, ShPtr<ValueAnalysis> va,
		ShPtr<CFG> cfg);

private:
	/// A mapping of a variable into another variable.
	using VarToVarMap = std::map<ShPtr<Variable>, ShPtr<Variable>>;

private:
	/// Module which contains the function specified by its CFG.
	ShPtr<Module> module;

	/// Global variables in @c module. This is here to speedup the traversal. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;

	/// Call graph of the module.
	ShPtr<CG> cg;

	/// The used call info obtainer.
	ShPtr<OptimCallInfoObtainer> cio;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// The CFG that is being traversed.
	ShPtr<CFG> cfg;

	/// The function whose CFG is being traversed.
	ShPtr<Function> traversedFunc;

	/// Called functions from @c traversedFunc.
	ShPtr<CG::CalledFuncs> calledFuncs;

	/// The currently computed FuncInfo.
	ShPtr<OptimFuncInfo> funcInfo;

	/// Global variables that (1) are read into local variables at the
	/// beginning of the function's body and (2) the local variables are just
	/// read, not modified.
	VarToVarMap storedGlobalVars;

private:
	OptimFuncInfoCFGTraversal(ShPtr<Module> module,
		ShPtr<OptimCallInfoObtainer> cio, ShPtr<ValueAnalysis> va,
		ShPtr<CFG> cfg);

	ShPtr<OptimFuncInfo> performComputation();
	void precomputeAlwaysModifiedVarsBeforeRead();
	void updateFuncInfo(ShPtr<Statement> stmt);
	bool checkExitNodesPredecessor(ShPtr<CFG::Node> node);
	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
