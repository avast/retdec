/**
* @file src/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.cpp
* @brief Implementation of OptimCallInfoObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversals/optim_func_info_cfg_traversal.h"
#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer_factory.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;
using retdec::utils::setIntersection;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("optim", OPTIM_CALL_INFO_OBTAINER_ID, CallInfoObtainerFactory,
	OptimCallInfoObtainer::create);

/**
* @brief Constructs a new optimistic piece of information about the given
*        function call.
*/
OptimCallInfo::OptimCallInfo(CallExpr* call): CallInfo(call) {}

/**
* @brief Emits the info to standard error.
*
* Only for debugging purposes.
*/
void OptimCallInfo::debugPrint() {
	llvm::errs() << "[OptimCallInfo] Debug info for '" << call << "':\n";

	llvm::errs() << "  neverReadVars:      ";
	dump(neverReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  mayBeReadVars:      ";
	dump(mayBeReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  alwaysReadVars:     ";
	dump(alwaysReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  neverModifiedVars:  ";
	dump(neverModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  mayBeModifiedVars:  ";
	dump(mayBeModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  alwaysModifiedVars: ";
	dump(alwaysModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  varsWithNeverChangedValue: ";
	dump(varsWithNeverChangedValue, dumpFuncGetName<Variable*>);

	llvm::errs() << "  varsAlwaysModifiedBeforeRead: ";
	dump(varsAlwaysModifiedBeforeRead, dumpFuncGetName<Variable*>);

	llvm::errs() << "\n";
}

bool OptimCallInfo::isNeverRead(Variable* var) const {
	return hasItem(neverReadVars, var);
}

bool OptimCallInfo::mayBeRead(Variable* var) const {
	return hasItem(mayBeReadVars, var);
}

bool OptimCallInfo::isAlwaysRead(Variable* var) const {
	return hasItem(alwaysReadVars, var);
}

bool OptimCallInfo::isNeverModified(Variable* var) const {
	return hasItem(neverModifiedVars, var);
}

bool OptimCallInfo::mayBeModified(Variable* var) const {
	return hasItem(mayBeModifiedVars, var);
}

bool OptimCallInfo::isAlwaysModified(Variable* var) const {
	return hasItem(alwaysModifiedVars, var);
}

bool OptimCallInfo::valueIsNeverChanged(Variable* var) const {
	return hasItem(varsWithNeverChangedValue, var);
}

bool OptimCallInfo::isAlwaysModifiedBeforeRead(Variable* var) const {
	return hasItem(varsAlwaysModifiedBeforeRead, var);
}

/**
* @brief Constructs a new optimistic piece of information about the given
*        function.
*/
OptimFuncInfo::OptimFuncInfo(Function* func): FuncInfo(func) {}

/**
* @brief Emits the info to standard error.
*
* Only for debugging purposes.
*/
void OptimFuncInfo::debugPrint() {
	llvm::errs() << "[OptimFuncInfo] Debug info for function '" << func->getName() << "':\n";

	llvm::errs() << "  neverReadVars:      ";
	dump(neverReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  mayBeReadVars:      ";
	dump(mayBeReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  alwaysReadVars:     ";
	dump(alwaysReadVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  neverModifiedVars:  ";
	dump(neverModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  mayBeModifiedVars:  ";
	dump(mayBeModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  alwaysModifiedVars: ";
	dump(alwaysModifiedVars, dumpFuncGetName<Variable*>);

	llvm::errs() << "  varsWithNeverChangedValue: ";
	dump(varsWithNeverChangedValue, dumpFuncGetName<Variable*>);

	llvm::errs() << "  varsAlwaysModifiedBeforeRead: ";
	dump(varsAlwaysModifiedBeforeRead, dumpFuncGetName<Variable*>);

	llvm::errs() << "\n";
}

bool OptimFuncInfo::isNeverRead(Variable* var) const {
	return hasItem(neverReadVars, var);
}

bool OptimFuncInfo::mayBeRead(Variable* var) const {
	return hasItem(mayBeReadVars, var);
}

bool OptimFuncInfo::isAlwaysRead(Variable* var) const {
	return hasItem(alwaysReadVars, var);
}

bool OptimFuncInfo::isNeverModified(Variable* var) const {
	return hasItem(neverModifiedVars, var);
}

bool OptimFuncInfo::mayBeModified(Variable* var) const {
	return hasItem(mayBeModifiedVars, var);
}

bool OptimFuncInfo::isAlwaysModified(Variable* var) const {
	return hasItem(alwaysModifiedVars, var);
}

bool OptimFuncInfo::valueIsNeverChanged(Variable* var) const {
	return hasItem(varsWithNeverChangedValue, var);
}

bool OptimFuncInfo::isAlwaysModifiedBeforeRead(Variable* var) const {
	return hasItem(varsAlwaysModifiedBeforeRead, var);
}

/**
* @brief Constructs a new obtainer.
*
* See create() for the description of parameters.
*/
OptimCallInfoObtainer::OptimCallInfoObtainer(): CallInfoObtainer() {}

/**
* @brief Computes @c funcInfoMap for each function in the module.
*
* Declarations are also considered.
*/
void OptimCallInfoObtainer::computeAllFuncInfos() {
	// Obtain the order in which function information should be computed.
	FuncInfoCompOrder* fico(getFuncInfoCompOrder(cg));

	// Compute the information from the obtained order.
	for (const auto &func : fico->order) {
		// Based on the description of CallInfoObtainer::FuncInfoOrder, we
		// first compute the info for the current function, and then for the
		// SCC that contains it.
		computeFuncInfo(func);

		// For each SCC in the order...
		for (const auto &scc : fico->sccs) {
			if (hasItem(scc, func)) {
				computeFuncInfos(scc);
			}
		}
	}
}

/**
* @brief Computes @c funcInfoMap[func] for @a func from the currently known
*        information.
*/
void OptimCallInfoObtainer::computeFuncInfo(Function* func) {
	OptimFuncInfo* funcInfo = func->isDeclaration() ?
		computeFuncInfoDeclaration(func) : computeFuncInfoDefinition(func);
	funcInfoMap[func] = funcInfo;
}

/**
* @brief Computes @c funcInfoMap[f] for every function @c f from @a funcs using the
*        currently known information.
*
* The computation is iterative. The function keeps computing @c funcInfoMap[f]
* for every function @c f from @a funcs until there is no change (i.e. it
* performs a fixed-point computation).
*/
void OptimCallInfoObtainer::computeFuncInfos(const FuncSet &funcs) {
	FuncInfoMap oldFuncInfoMap;
	do {
		// Store the current FuncInfo for each function from funcs so we can
		// check whether it has changed after the iteration.
		for (const auto &func : funcs) {
			oldFuncInfoMap[func] = funcInfoMap[func];
		}

		// Compute a new FuncInfo for every function in funcs.
		for (const auto &func : funcs) {
			computeFuncInfo(func);
		}
	} while (hasChanged(oldFuncInfoMap, funcInfoMap));
}

/**
* @brief Returns the set of variables that are in both @a vars and @c
*        globalVars.
*/
VarSet OptimCallInfoObtainer::skipLocalVars(const VarSet &vars) {
	return setIntersection(globalVars, vars);
}

/**
* @brief Computes and returns a function info for the given function
*        declaration.
*
* @par Preconditions
*  - @a func is a declaration
*/
OptimFuncInfo* OptimCallInfoObtainer::computeFuncInfoDeclaration(
		Function* func) {
	OptimFuncInfo* funcInfo(new OptimFuncInfo(func));

	// Use our assumption of global variables (see the class description).
	funcInfo->neverReadVars = globalVars;
	funcInfo->neverModifiedVars = globalVars;
	funcInfo->varsWithNeverChangedValue = globalVars;
	funcInfo->varsAlwaysModifiedBeforeRead = globalVars;

	return funcInfo;
}

/**
* @brief Computes and returns a function info for the given function
*        definition.
*
* @par Preconditions
*  - @a func is a definition
*/
OptimFuncInfo* OptimCallInfoObtainer::computeFuncInfoDefinition(
		Function* func) {
	return OptimFuncInfoCFGTraversal::getOptimFuncInfo(module,
		ucast<OptimCallInfoObtainer>(this), va, funcCFGMap[func]);
}

/**
* @brief Computes and returns information about the given function call
*        which occurs in @a caller.
*
* See the description of getCallInfo() for more information on the
* preconditions.
*/
OptimCallInfo* OptimCallInfoObtainer::computeCallInfo(CallExpr* call,
		Function* caller) {
	OptimCallInfo* callInfo(new OptimCallInfo(call));

	Variable* calledVar(cast<Variable>(call->getCalledExpr()));
	Function* calledFunc;
	if (calledVar) {
		calledFunc = module->getFuncByName(calledVar->getName());
	}

	// Handle indirect calls.
	if (!calledFunc) {
		// An indirect call may read/change every global variable.
		// TODO Improve the info by browsing through all defined functions
		//      and checking which variables they read/modify?
		callInfo->mayBeReadVars = globalVars;
		callInfo->mayBeModifiedVars = globalVars;

		// TODO How to improve the callInfo even more?

		return callInfo;
	}

	//
	// It is a call to a defined/declared function.
	//

	// Copy the information from the calledFunc's FuncInfo. However, remove
	// local variables from the info because they cause problems when a
	// function recursively calls itself (even indirectly). Indeed, consider
	// the following piece of code:
	//
	// def func(i):
	//    if i == 0:
	//        return 1
	//    a = func(i - 1)
	//    return a
	//
	// Then, if we included local variables, we would have that the variable a
	// is modified in the call func(i - 1), which is not true.
	OptimFuncInfo* calledFuncInfo(funcInfoMap[calledFunc]);
	callInfo->neverReadVars = skipLocalVars(calledFuncInfo->neverReadVars);
	callInfo->mayBeReadVars = skipLocalVars(calledFuncInfo->mayBeReadVars);
	callInfo->alwaysReadVars = skipLocalVars(calledFuncInfo->alwaysReadVars);
	callInfo->neverModifiedVars = skipLocalVars(calledFuncInfo->neverModifiedVars);
	callInfo->mayBeModifiedVars = skipLocalVars(calledFuncInfo->mayBeModifiedVars);
	callInfo->alwaysModifiedVars = skipLocalVars(calledFuncInfo->alwaysModifiedVars);
	callInfo->varsWithNeverChangedValue = skipLocalVars(
		calledFuncInfo->varsWithNeverChangedValue);
	callInfo->varsAlwaysModifiedBeforeRead = skipLocalVars(
		calledFuncInfo->varsAlwaysModifiedBeforeRead);

	// We assume that function calls with no arguments don't modify any local
	// variable from the caller.
	const ExprVector &args(call->getArgs());
	if (args.size() == 0) {
		VarSet callerLocalVars(caller->getLocalVars(true));
		addToSet(callerLocalVars, callInfo->neverModifiedVars);
	}

	// TODO How to improve the callInfo even more? What about the call's
	//      arguments?

	return callInfo;
}

/**
* @brief Creates a new obtainer.
*/
CallInfoObtainer* OptimCallInfoObtainer::create() {
	return new OptimCallInfoObtainer();
}

void OptimCallInfoObtainer::init(CG* cg, ValueAnalysis* va) {
	CallInfoObtainer::init(cg, va);
	funcInfoMap.clear();
	callInfoMap.clear();

	// Initialize the set of global variables.
	globalVars = module->getGlobalVars();
	// We also add functions to it (they may be considered as global
	// constants).
	// For each function in the module...
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		globalVars.insert((*i)->getAsVar());
	}

	// When, for example, computing a FuncInfo for function A which calls
	// function B, it may happen that FuncInfo for B has not yet been computed
	// (take recursive calls as an example). To this end, we initialize all
	// FuncInfos here before any computation.
	// For each function in the module...
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		funcInfoMap[*i] = new OptimFuncInfo(*i);
	}

	computeAllFuncInfos();
}

std::string OptimCallInfoObtainer::getId() const {
	return OPTIM_CALL_INFO_OBTAINER_ID;
}

CallInfo* OptimCallInfoObtainer::getCallInfo(CallExpr* call,
		Function* caller) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(caller),
		"function `" << caller->getName() << "` does not exist");

	// Have we already computed the info?
	auto callInfoIter = callInfoMap.find(call);
	if (callInfoIter != callInfoMap.end()) {
		return callInfoIter->second;
	}

	// We haven't, so compute it.
	OptimCallInfo* callInfo(computeCallInfo(call, caller));
	callInfoMap[call] = callInfo;
	return callInfo;
}

FuncInfo* OptimCallInfoObtainer::getFuncInfo(Function* func) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(func),
		"function `" << func->getName() << "` does not exist");

	return funcInfoMap[func];
}

/**
* @brief Returns @c true if @a fi1 differs from @a fi2, @c false otherwise.
*/
bool OptimCallInfoObtainer::areDifferent(OptimFuncInfo* fi1,
		OptimFuncInfo* fi2) {
	return fi1->getFunc() != fi2->getFunc() ||
		fi1->neverReadVars != fi2->neverReadVars ||
		fi1->mayBeReadVars != fi2->mayBeReadVars ||
		fi1->alwaysReadVars != fi2->alwaysReadVars ||
		fi1->neverModifiedVars != fi2->neverModifiedVars ||
		fi1->mayBeModifiedVars != fi2->mayBeModifiedVars ||
		fi1->alwaysModifiedVars != fi2->alwaysModifiedVars ||
		fi1->varsWithNeverChangedValue != fi2->varsWithNeverChangedValue ||
		fi1->varsAlwaysModifiedBeforeRead != fi2->varsAlwaysModifiedBeforeRead;
}

/**
* @brief Returns @c true if the FuncInfos in @a newInfo for functions that are
*        also in @a oldInfo have changed, @c false otherwise.
*/
bool OptimCallInfoObtainer::hasChanged(const FuncInfoMap &oldInfo,
		const FuncInfoMap &newInfo) {
	// For every FuncInfo in oldInfo... (It may contain a less number of
	// functions that newInfo.)
	for (const auto &p : oldInfo) {
		auto i = newInfo.find(p.first);
		ASSERT_MSG(i != newInfo.end(), "oldInfo contains info for a function `" <<
			p.first->getName() << "`that is not in newInfo");
		if (areDifferent(p.second, i->second)) {
			return true;
		}
	}
	return false;
}

} // namespace llvmir2hll
} // namespace retdec
