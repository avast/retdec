/**
* @file src/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.cpp
* @brief Implementation of UnreachableFuncs optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <string>

#include <llvm/ADT/Statistic.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/reachable_funcs_analysis.h"
#include "retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h"
#include "retdec/bin2llvmir/utils/instruction.h"

#define OPTIMIZATION_NAME "unreachable-funcs"
#define DEBUG_TYPE OPTIMIZATION_NAME

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/// Name of main.
const std::string NAME_OF_MAIN = "main";

/**
* @brief Removes function from current module.
*
* @param[in] funcToRemove Function to remove.
* @param[in] callGraph Call graph of module.
*/
void removeFuncFromModule(Function &funcToRemove, CallGraph &callGraph) {
	CallGraphNode *funcToRemoveNode(callGraph[&funcToRemove]);
	for (auto &item : callGraph) {
		item.second->removeAnyCallEdgeTo(funcToRemoveNode);
	}
	funcToRemove.replaceAllUsesWith(UndefValue::get(funcToRemove.getType()));
	funcToRemoveNode->removeAllCalledFunctions();
	funcToRemove.deleteBody();

	callGraph.removeFunctionFromModule(funcToRemoveNode);
}

bool userCannotBeOptimized(User* user, const FuncSet &funcs)
{
	if (auto* inst = dyn_cast<Instruction>(user)) {
		auto* pf = inst->getFunction();
		if (pf == nullptr || hasItem(funcs, pf)) {
			return true;
		}
	}
	else if (auto* ce = dyn_cast<ConstantExpr>(user))
	{
		for (auto* u : ce->users()) {
			if (userCannotBeOptimized(u, funcs)) {
				return true;
			}
		}
	}
	else {
		return true;
	}

	return false;
}

/**
* @brief Returns @c true if @a func can't be optimized, otherwise @c false.
*
* For more details what can't be optimized @see getFuncsThatCannotBeOptimized().
*/
bool cannotBeOptimized(Function &func, const FuncSet &funcs) {
	for (auto* u : func.users()) {
		if (userCannotBeOptimized(u, funcs)) {
			return true;
		}
	}

	return false;
}

} // anonymous namespace

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char UnreachableFuncs::ID = 0;

const char *UnreachableFuncs::NAME = OPTIMIZATION_NAME;

RegisterPass<UnreachableFuncs> UnreachableFuncsRegistered(UnreachableFuncs::
	getName(), "Unreachable functions optimization", false, false);

STATISTIC(NumFuncsRemoved, "Number of removed functions definitions");

/**
* @brief Created a new unreachable functions optimizer.
*/
UnreachableFuncs::UnreachableFuncs(): ModulePass(ID), mainFunc(nullptr) {}

void UnreachableFuncs::getAnalysisUsage(AnalysisUsage &au) const {
	au.addRequired<CallGraphWrapperPass>();
}

bool UnreachableFuncs::runOnModule(Module &module) {
	config = ConfigProvider::getConfig(&module);
	if (config)
	{
		config->getConfig().parameters.completedFrontendPasses.insert(getName());
	}

	initializeMainFunc(module);
	if (!optimizationCanRun()) {
		return false;
	}

	CallGraph &callGraph(getAnalysis<CallGraphWrapperPass>().getCallGraph());
	FuncSet funcsThatCannotBeOptimized(ReachableFuncsAnalysis::
		getReachableDefinedFuncsFor(*mainFunc, module, callGraph));
	addToSet(ReachableFuncsAnalysis::getGloballyReachableFuncsFor(module), funcsThatCannotBeOptimized);
	addToSet(getFuncsThatCannotBeOptimized(funcsThatCannotBeOptimized, module),
		funcsThatCannotBeOptimized);

	removeFuncsThatCanBeOptimized(funcsThatCannotBeOptimized, module);

	return NumFuncsRemoved > 0;
}

/**
* @brief Initializes @c mainFunc.
*/
void UnreachableFuncs::initializeMainFunc(Module &module) {
	mainFunc = module.getFunction(NAME_OF_MAIN);
}

/**
* @brief Can the optimization run?
*/
bool UnreachableFuncs::optimizationCanRun() const {
	if (config &&
			(config->getConfig().fileType.isShared()
			|| config->getConfig().fileType.isObject())) {
		return false;
	}

	// We need the main function as the starting point.
	if (!mainFunc) {
		return false;
	}

	// The main function has to be a definition, not just a declaration. This
	// is needed when decompiling shared libraries containing an import of main.
	if (mainFunc->isDeclaration()) {
		return false;
	}

	return true;
}

/**
* @brief Returns functions that can't be optimized.
*
* - We don't want optimize functions, that has use in reachable functions. It is
*   needed because address of these functions can be taken and then used.
* - We don't want optimize functions which address is taken and stored into
*   global variables.
* - We don't want to optimize functions, which are used in statistics.
*
* @param[in] reachableFuncs Reachable functions.
* @param[in] module Current module.
*/
FuncSet UnreachableFuncs::getFuncsThatCannotBeOptimized(
		const FuncSet &reachableFuncs, Module &module) const {
	FuncSet result;
	for (Function &func : module) {
		if (cannotBeOptimized(func, reachableFuncs)) {
			result.insert(&func);
		}
	}

	return result;
}

/**
* @brief Returns functions that can be optimized in a module.
*
* @param[in] funcsThatCannotBeOptimized Functions that can't be optimized.
* @param[in] module We want optimize functions in this module.
*
* @return Functions to optimize.
*/
FuncSet UnreachableFuncs::getFuncsThatCanBeOptimized(
		const FuncSet funcsThatCannotBeOptimized, Module &module) const {
	FuncSet toBeOptimized;
	for (Function &func : module) {
		if (func.isDeclaration()) {
			// We don't want to optimize functions only with declaration.
			continue;
		}

		if (hasItem(funcsThatCannotBeOptimized, &func)) {
			continue;
		}

		if (&func == mainFunc) {
			// We don't want to remove main function.
			continue;
		}

		toBeOptimized.insert(&func);
	}

	return toBeOptimized;
}

/**
* @brief Removes unreachable functions from main.
*
* @param[in] funcsThatCannotBeOptimized Functions that can't be optimized.
* @param[in] module Module with functions.
*/
void UnreachableFuncs::removeFuncsThatCanBeOptimized(
		const FuncSet &funcsThatCannotBeOptimized, Module &module) const {
	FuncSet toRemove(getFuncsThatCanBeOptimized(funcsThatCannotBeOptimized,
		module));
	removeFuncsFromModule(toRemove);
}

/**
* @brief Removes functions from current module.
*
* @param[in] funcsToRemove Functions to remove.
*/
void UnreachableFuncs::removeFuncsFromModule(
		const FuncSet &funcsToRemove) const {
	CallGraph &callGraph(getAnalysis<CallGraphWrapperPass>().getCallGraph());
	for (Function *func : funcsToRemove) {
		removeFuncFromModule(*func, callGraph);
		NumFuncsRemoved++;
	}
}

} // namespace bin2llvmir
} // namespace retdec
