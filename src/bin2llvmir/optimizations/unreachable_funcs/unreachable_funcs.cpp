/**
* @file src/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.cpp
* @brief Implementation of UnreachableFuncs optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <string>

#include <llvm/IR/Constants.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/reachable_funcs_analysis.h"
#include "retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Removes function from current module.
*
* @param[in] funcToRemove Function to remove.
* @param[in] callGraph Call graph of module.
*/
void removeFuncFromModule(Function& funcToRemove, CallGraph& callGraph)
{
	CallGraphNode* funcToRemoveNode(callGraph[&funcToRemove]);
	for (auto& item : callGraph)
	{
		item.second->removeAnyCallEdgeTo(funcToRemoveNode);
	}
	funcToRemove.replaceAllUsesWith(UndefValue::get(funcToRemove.getType()));
	funcToRemoveNode->removeAllCalledFunctions();
	funcToRemove.deleteBody();

	callGraph.removeFunctionFromModule(funcToRemoveNode);
}

bool userCannotBeOptimized(User* user, const std::set<llvm::Function*>& funcs)
{
	if (auto* inst = dyn_cast<Instruction>(user))
	{
		auto* pf = inst->getFunction();
		if (pf == nullptr || hasItem(funcs, pf))
		{
			return true;
		}
	}
	else if (auto* ce = dyn_cast<ConstantExpr>(user))
	{
		for (auto* u : ce->users())
		{
			if (userCannotBeOptimized(u, funcs))
			{
				return true;
			}
		}
	}
	else
	{
		return true;
	}

	return false;
}

/**
* @brief Returns @c true if @a func can't be optimized, otherwise @c false.
*
* For more details what can't be optimized @see getFuncsThatCannotBeOptimized().
*/
bool cannotBeOptimized(Function& func, const std::set<llvm::Function*>& funcs)
{
	for (auto* u : func.users())
	{
		if (userCannotBeOptimized(u, funcs))
		{
			return true;
		}
	}

	return false;
}

} // anonymous namespace

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char UnreachableFuncs::ID = 0;

RegisterPass<UnreachableFuncs> UnreachableFuncsRegistered(
		"unreachable-funcs",
		"Unreachable functions optimization",
		false,
		false);

/**
* @brief Created a new unreachable functions optimizer.
*/
UnreachableFuncs::UnreachableFuncs() :
		ModulePass(ID),
		mainFunc(nullptr)
{

}

void UnreachableFuncs::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<CallGraphWrapperPass>();
}

bool UnreachableFuncs::runOnModule(Module& m)
{
	module = &m;
	config = ConfigProvider::getConfig(module);
	return run();
}

bool UnreachableFuncs::runOnModuleCustom(llvm::Module& m, Config* c)
{
	module = &m;
	config = c;
	return run();
}

bool UnreachableFuncs::run()
{
	if (config == nullptr)
	{
		return false;
	}
	if (config->getConfig().fileType.isShared()
			|| config->getConfig().fileType.isObject())
	{
		return false;
	}

	// The main function has to be a definition, not just a declaration. This
	// is needed when decompiling shared libraries containing an import of main.
	//
	mainFunc = config->getLlvmFunction(config->getConfig().getMainAddress());
	if (mainFunc == nullptr || mainFunc->isDeclaration())
	{
		return false;
	}

	callGraph = &getAnalysis<CallGraphWrapperPass>().getCallGraph();

	std::set<llvm::Function*> funcsThatCannotBeOptimized;
	getFuncsThatCannotBeOptimized(funcsThatCannotBeOptimized);
	removeFuncsThatCanBeOptimized(funcsThatCannotBeOptimized);

	return NumFuncsRemoved > 0;
}

void UnreachableFuncs::getFuncsThatCannotBeOptimized(
		std::set<llvm::Function*>& funcsThatCannotBeOptimized)
{
	funcsThatCannotBeOptimized.insert(mainFunc);

	addToSet(
			ReachableFuncsAnalysis::getReachableDefinedFuncsFor(
					*mainFunc,
					*module,
					*callGraph),
			funcsThatCannotBeOptimized);
	addToSet(
			ReachableFuncsAnalysis::getGloballyReachableFuncsFor(*module),
			funcsThatCannotBeOptimized);

	for (Function& func : *module)
	{
		if (func.isDeclaration())
		{
			funcsThatCannotBeOptimized.insert(&func);
		}

		if (cannotBeOptimized(func, funcsThatCannotBeOptimized))
		{
			funcsThatCannotBeOptimized.insert(&func);
		}
	}
}

void UnreachableFuncs::removeFuncsThatCanBeOptimized(
		const std::set<llvm::Function*>& funcsThatCannotBeOptimized)
{
	for (auto it = module->begin(), e = module->end(); it != e;)
	{
		llvm::Function& func = *it;
		++it;

		if (!hasItem(funcsThatCannotBeOptimized, &func))
		{
			removeFuncFromModule(func, *callGraph);
			NumFuncsRemoved++;
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
