/**
* @file src/llvmir2hll/llvm/llvm_debug_info_obtainer.cpp
* @brief Implementation of LLVMDebugInfoObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Module.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_debug_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Stores names of variables from debug information into @a module.
*
* @par Preconditions
*  - @a module is non-null
*/
void LLVMDebugInfoObtainer::obtainVarNames(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	// Check whether global variables have assigned names.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		auto var = (*i)->getVar();
		auto varNameFromDebug = module->getDebugNameForGlobalVar(var);
		if (!varNameFromDebug.empty()) {
			module->addDebugNameForVar(var, varNameFromDebug);
		}
	}

	// Check whether local variables and function parameters have assigned
	// requested names.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		auto func = *i;
		auto localVars = func->getLocalVars(true); // Include parameters.
		for (const auto &var : localVars) {
			auto varNameFromDebug = module->getDebugNameForLocalVar(func, var);
			if (!varNameFromDebug.empty()) {
				module->addDebugNameForVar(var, varNameFromDebug);
			}
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
