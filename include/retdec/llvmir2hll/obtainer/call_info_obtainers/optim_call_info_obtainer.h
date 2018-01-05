/**
* @file include/retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h
* @brief Obtainer of information about functions and function calls that
*        assumes it has access to complete information about the module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINERS_OPTIM_CALL_INFO_OBTAINER_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINERS_OPTIM_CALL_INFO_OBTAINER_H

#include <map>
#include <string>

#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimistic information about a function call.
*
* Use OptimCallInfoObtainer to create instances.
*
* Instances of this class have reference object semantics.
*/
class OptimCallInfo: public CallInfo {
	friend class OptimCallInfoObtainer;
	friend class OptimFuncInfoCFGTraversal;

public:
	explicit OptimCallInfo(ShPtr<CallExpr> call);

	void debugPrint();

	virtual bool isNeverRead(ShPtr<Variable> var) const override;
	virtual bool mayBeRead(ShPtr<Variable> var) const override;
	virtual bool isAlwaysRead(ShPtr<Variable> var) const override;

	virtual bool isNeverModified(ShPtr<Variable> var) const override;
	virtual bool mayBeModified(ShPtr<Variable> var) const override;
	virtual bool isAlwaysModified(ShPtr<Variable> var) const override;

	virtual bool valueIsNeverChanged(ShPtr<Variable> var) const override;
	virtual bool isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const override;

private:
	/// Variables that are never read in this function call.
	VarSet neverReadVars;

	/// Variables that may be read in this function call.
	VarSet mayBeReadVars;

	/// Variables that are always read in this function call.
	VarSet alwaysReadVars;

	/// Variables that are never modified in this function call.
	VarSet neverModifiedVars;

	/// Variables that may be modified in this function call.
	VarSet mayBeModifiedVars;

	/// Variables that are always modified in this function call.
	VarSet alwaysModifiedVars;

	/// Variables whose value is never changed in this function call.
	VarSet varsWithNeverChangedValue;

	/// Variables which are always modified before read in this function call.
	VarSet varsAlwaysModifiedBeforeRead;
};

/**
* @brief Optimistic information about a function.
*
* Use OptimCallInfoObtainer to create instances.
*
* Instances of this class have reference object semantics.
*/
class OptimFuncInfo: public FuncInfo {
	friend class OptimCallInfoObtainer;
	friend class OptimFuncInfoCFGTraversal;

public:
	explicit OptimFuncInfo(ShPtr<Function> func);

	void debugPrint();

	virtual bool isNeverRead(ShPtr<Variable> var) const override;
	virtual bool mayBeRead(ShPtr<Variable> var) const override;
	virtual bool isAlwaysRead(ShPtr<Variable> var) const override;

	virtual bool isNeverModified(ShPtr<Variable> var) const override;
	virtual bool mayBeModified(ShPtr<Variable> var) const override;
	virtual bool isAlwaysModified(ShPtr<Variable> var) const override;

	virtual bool valueIsNeverChanged(ShPtr<Variable> var) const override;
	virtual bool isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const override;

private:
	/// Variables that are never read in this function.
	VarSet neverReadVars;

	/// Variables that may be read in this function.
	VarSet mayBeReadVars;

	/// Variables that are always read in this function.
	VarSet alwaysReadVars;

	/// Variables that are never modified in this function.
	VarSet neverModifiedVars;

	/// Variables that may be modified in this function.
	VarSet mayBeModifiedVars;

	/// Variables that are always modified in this function.
	VarSet alwaysModifiedVars;

	/// Variables whose value is never changed in this function.
	VarSet varsWithNeverChangedValue;

	/// Variables which are always modified before read in this function.
	VarSet varsAlwaysModifiedBeforeRead;
};

/**
* @brief Obtainer of information about functions and function calls that
*        assumes it has access to complete information about the module.
*
* Currently, this obtainer utilizes the following assumptions:
*  - functions that are not defined (just declared) do not read or modify any
*    global variable
*  - function calls with no arguments don't modify any local variable from the
*    caller
*
* Compare with PessimCallInfoObtainer.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class OptimCallInfoObtainer: public CallInfoObtainer {
	friend class OptimFuncInfoCFGTraversal;

public:
	static ShPtr<CallInfoObtainer> create();

	virtual void init(ShPtr<CG> cg, ShPtr<ValueAnalysis> va) override;
	virtual std::string getId() const override;
	virtual ShPtr<CallInfo> getCallInfo(ShPtr<CallExpr> call,
		ShPtr<Function> caller) override;
	virtual ShPtr<FuncInfo> getFuncInfo(ShPtr<Function> func) override;

private:
	/// Mapping of a function into its info.
	using FuncInfoMap = std::map<ShPtr<Function>, ShPtr<OptimFuncInfo>>;

	/// Mapping of a function call into its info.
	using CallInfoMap = std::map<ShPtr<CallExpr>, ShPtr<OptimCallInfo>>;

private:
	OptimCallInfoObtainer();

	void computeAllFuncInfos();
	void computeFuncInfo(ShPtr<Function> func);
	void computeFuncInfos(const FuncSet &funcs);
	VarSet skipLocalVars(const VarSet &vars);
	ShPtr<OptimFuncInfo> computeFuncInfoDeclaration(ShPtr<Function> func);
	ShPtr<OptimFuncInfo> computeFuncInfoDefinition(ShPtr<Function> func);
	ShPtr<OptimCallInfo> computeCallInfo(ShPtr<CallExpr> call,
		ShPtr<Function> caller);

	static bool areDifferent(ShPtr<OptimFuncInfo> fi1,
		ShPtr<OptimFuncInfo> fi2);
	static bool hasChanged(const FuncInfoMap &oldInfo,
		const FuncInfoMap &newInfo);

private:
	/// Mapping of a function into its info.
	FuncInfoMap funcInfoMap;

	/// Mapping of a call into its info.
	CallInfoMap callInfoMap;

	/// Global variables in the module, including functions.
	VarSet globalVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
