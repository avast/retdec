/**
* @file src/llvmir2hll/support/unreachable_funcs_remover.cpp
* @brief Implementation of UnreachableFuncsRemover.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/graphs/cg/cg_builder.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/unreachable_funcs_remover.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/container.h"
#include "retdec/utils/non_copyable.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Computer of indirectly called functions from a module.
*/
class IndirectlyCalledFuncsComputer: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	/// Constructs a computer from the given module.
	explicit IndirectlyCalledFuncsComputer(ShPtr<Module> module): module(module) {}

	FuncSet getFuncsThatMayBeCalledIndirectly();

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Variable> var) override;
	/// @}

private:
	/// Module in which the functions are looked for.
	ShPtr<Module> module;

	/// Set of functions that may be called indirectly.
	FuncSet indirectlyCalledFuncs;
};

/**
* @brief Computes functions that may be called indirectly from the module
*        passed in the constructor and returns them.
*/
FuncSet IndirectlyCalledFuncsComputer::getFuncsThatMayBeCalledIndirectly() {
	indirectlyCalledFuncs.clear();

	// Check the right-hand side of every global variable...
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		if ((*i)->hasInitializer()) {
			(*i)->getInitializer()->accept(this);
		}
	}

	// Check the body of every function...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		visitStmt((*i)->getBody());
	}

	return indirectlyCalledFuncs;
}

void IndirectlyCalledFuncsComputer::visit(ShPtr<Variable> var) {
	ShPtr<Function> func(module->getFuncByName(var->getName()));
	if (func) {
		indirectlyCalledFuncs.insert(func);
	}
}

/**
* @brief Computes and returns functions that may be called indirectly in the
*        given module.
*/
FuncSet getFuncsThatMayBeCalledIndirectly(ShPtr<Module> module) {
	IndirectlyCalledFuncsComputer computer(module);
	return computer.getFuncsThatMayBeCalledIndirectly();
}

} // anonymous namespace

/**
* @brief Constructs a new remover.
*
* See removeFuncs() for the description of all parameters and preconditions.
*/
UnreachableFuncsRemover::UnreachableFuncsRemover(ShPtr<Module> module,
		const std::string &mainFuncName):
	module(module), mainFuncName(mainFuncName) {}

/**
* @brief Destructs the remover.
*/
UnreachableFuncsRemover::~UnreachableFuncsRemover() {}

/**
* @brief Removes functions that are not reachable from the main function.
*
* @param[in,out] module Module in which the functions will be removed.
* @param[in] mainFuncName Name of the main function.
*
* @return Functions that were removed.
*
* If there is no function named @a mainFuncName, this function does nothing.
* Functions that are only declared (i.e. not defined) are never removed.
*
* @par Preconditions
*  - @a module is non-null
*  - @a mainFuncName is not empty
*/
FuncVector UnreachableFuncsRemover::removeFuncs(ShPtr<Module> module,
		const std::string &mainFuncName) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION(!mainFuncName.empty(), "the name cannot be empty");

	ShPtr<UnreachableFuncsRemover> remover(new UnreachableFuncsRemover(
		module, mainFuncName));
	remover->performRemoval();
	return remover->removedFuncs;
}

/**
* @brief Performs the removal of functions.
*
* Updates @c removedFuncs. For more information, see the description of
* removeFuncs().
*/
void UnreachableFuncsRemover::performRemoval() {
	// If there is no main function, we should do nothing.
	ShPtr<Function> mainFunc(module->getFuncByName(mainFuncName));
	if (!mainFunc) {
		return;
	}

	// Use the call graph of the module to compute functions that are reachable
	// from main, either directly or in other function calls (the 'true'
	// argument below).
	ShPtr<CG> cg(CGBuilder::getCG(module));
	FuncSet reachableFuncs(cg->getCalledFuncs(mainFunc, true)->callees);
	// The main function has to be also considered as reachable from main.
	reachableFuncs.insert(mainFunc);

	// Include all functions that may be called by pointers into reachableFuncs
	// to prevent "use of undeclared variable" or "call of an undeclared
	// function" errors. These errors mean that we have removed a function
	// which is called indirectly by a pointer.
	// TODO When a function pointer appears in a function that is not directly
	//      reachable from main(), we still consider it as a possibly reachable
	//      function. Can we improve the implementation so when a function is
	//      left in the code, it is definitely reachable?
	FuncSet indirectlyCalledFuncs(getFuncsThatMayBeCalledIndirectly(module));
	addToSet(indirectlyCalledFuncs, reachableFuncs);

	// Remove defined functions that are not reachable from the module.
	// We have to iterate over a copy of the functions in the module because we
	// remove functions during the iteration.
	FuncVector allFuncs(module->func_begin(), module->func_end());
	for (const auto &func : allFuncs) {
		if (!hasItem(reachableFuncs, func) && func->isDefinition()) {
			module->removeFunc(func);
			removedFuncs.push_back(func);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
