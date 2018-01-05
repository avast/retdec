/**
* @file src/llvmir2hll/optimizer/func_optimizer.cpp
* @brief Implementation of FuncOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new function optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
FuncOptimizer::FuncOptimizer(ShPtr<Module> module):
	Optimizer(module), currFunc() {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
FuncOptimizer::~FuncOptimizer() {}

/**
* @brief Performs the optimization on all functions in the module.
*
* This function calls runOnFunction() for each function in the module.
*
* Only redefine if you want to prescribe the order in which functions are
* optimized; otherwise, just override runOnFunction().
*/
void FuncOptimizer::doOptimization() {
	// For each function in the module...
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		runOnFunction(*i);
	}
}

/**
* @brief Performs all optimizations on the given function.
*
* @param[in,out] func Function to be optimized.
*
* By default, this function calls @c func->accept(this).
*/
void FuncOptimizer::runOnFunction(ShPtr<Function> func) {
	restart();
	currFunc = func;
	func->accept(this);
}

} // namespace llvmir2hll
} // namespace retdec
