/**
* @file src/llvmir2hll/obtainer/calls_in_module_obtainer.cpp
* @brief Implementation of the obtainer of information about function calls in
*        a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/obtainer/calls_in_module_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new obtainer.
*/
CallsInModuleObtainer::CallsInModuleObtainer(ShPtr<Module> module):
	OrderedAllVisitor(), module(module), currFunc(), foundCalls() {}

/**
* @brief Destructs the obtainer.
*/
CallsInModuleObtainer::~CallsInModuleObtainer() {}

/**
* @brief Returns a list of all function calls in the given @a module.
*
* @par Preconditions
*  - @a module is non-null
*/
CallsInModuleObtainer::Calls CallsInModuleObtainer::getCalls(
		ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<CallsInModuleObtainer> obtainer(new CallsInModuleObtainer(module));
	return obtainer->getCallsImpl();
}

/**
* @brief Implementation of getCalls().
*/
CallsInModuleObtainer::Calls CallsInModuleObtainer::getCallsImpl() {
	obtainCallsInGlobalVars();
	obtainCallsInFuncs();
	return foundCalls;
}

/**
* @brief Obtain calls in all global variables and puts them into @c foundCalls.
*/
void CallsInModuleObtainer::obtainCallsInGlobalVars() {
	for (auto i = module->global_var_begin(),
			e = module->global_var_begin(); i != e; ++i) {
		(*i)->accept(this);
	}
}

/**
* @brief Obtain calls in all functions and puts them into @c foundCalls.
*/
void CallsInModuleObtainer::obtainCallsInFuncs() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		obtainCallsInFunc(*i);
	}
}

/**
* @brief Obtain calls in all the given function and puts them into @c
*        foundCalls.
*/
void CallsInModuleObtainer::obtainCallsInFunc(ShPtr<Function> func) {
	currFunc = func;
	func->accept(this);
}

void CallsInModuleObtainer::visit(ShPtr<CallExpr> expr) {
	CallInfo ci = {
		expr,     // call
		lastStmt, // stmt
		currFunc, // func
		module    // module
	};
	foundCalls.push_back(ci);

	OrderedAllVisitor::visit(expr);
}

} // namespace llvmir2hll
} // namespace retdec
