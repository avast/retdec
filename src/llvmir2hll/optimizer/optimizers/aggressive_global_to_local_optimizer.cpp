/**
* @file src/llvmir2hll/optimizer/optimizers/aggressive_global_to_local_optimizer.cpp
* @brief Implementation of AggressiveGlobalToLocalOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/aggressive_global_to_local_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
AggressiveGlobalToLocalOptimizer::AggressiveGlobalToLocalOptimizer(
			ShPtr<Module> module): Optimizer(module)  {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
AggressiveGlobalToLocalOptimizer::~AggressiveGlobalToLocalOptimizer() {}

void AggressiveGlobalToLocalOptimizer::doOptimization() {
	convertGlobalVarsToLocalVars();
}

/**
* @brief Converts all global variables to local variables.
*/
void AggressiveGlobalToLocalOptimizer::convertGlobalVarsToLocalVars() {
	// TODO The following algorithm may introduce local variables which are
	//      never used. Improve it by computing the global variables that are
	//      actually used in the function.

	// Since we are going to remove global variables from the module during
	// iteration, store them into a container and iterate over this copy.
	VarSet globalVars(module->getGlobalVars());

	// For each function...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		// For each global variable...
		for (const auto &var : globalVars) {
			// Skip global variables which have an assigned name from debug
			// information.
			if (module->hasAssignedDebugName(var)) {
				continue;
			}

			ShPtr<Expression> init(module->getInitForGlobalVar(var));
			convertGlobalVarToLocalVarInFunc(var, *i, init);
			module->removeGlobalVar(var);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
