/**
* @file src/llvmir2hll/optimizer/optimizers/unused_global_var_optimizer.cpp
* @brief Implementation of UnusedGlobalVarOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/unused_global_var_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

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
UnusedGlobalVarOptimizer::UnusedGlobalVarOptimizer(ShPtr<Module> module):
	Optimizer(module), globalVars(module->getGlobalVars()) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
UnusedGlobalVarOptimizer::~UnusedGlobalVarOptimizer() {}

void UnusedGlobalVarOptimizer::doOptimization() {
	computeUsedGlobalVars();
	removeUnusedGlobalVars();
}

void UnusedGlobalVarOptimizer::visit(ShPtr<Variable> var) {
	if (isGlobal(var)) {
		usedGlobalVars.insert(var);
	}
}

/**
* @brief Computes used global variables.
*/
void UnusedGlobalVarOptimizer::computeUsedGlobalVars() {
	// Initializers of global variables.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		if (ShPtr<Expression> init = (*i)->getInitializer()) {
			init->accept(this);
		}
	}

	// Function bodies.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(this);
	}
}

/**
* @brief Removes unused global variables from the module.
*/
void UnusedGlobalVarOptimizer::removeUnusedGlobalVars() {
	for (auto &var : globalVars) {
		if (!isUsed(var)) {
			module->removeGlobalVar(var);
		}
	}
}

/**
* @brief Is the given variable global?
*/
bool UnusedGlobalVarOptimizer::isGlobal(ShPtr<Variable> var) const {
	return hasItem(globalVars, var);
}

/**
* @brief Is the given global variable used?
*/
bool UnusedGlobalVarOptimizer::isUsed(ShPtr<Variable> var) const {
	return hasItem(usedGlobalVars, var);
}

} // namespace llvmir2hll
} // namespace retdec
