/**
* @file src/llvmir2hll/optimizer/optimizer.cpp
* @brief Implementation of Optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

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
Optimizer::Optimizer(ShPtr<Module> module):
	OrderedAllVisitor(), module(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
Optimizer::~Optimizer() {}

/**
* @brief Performs all the optimizations of the specific optimizer.
*
* @return Optimized module.
*
* This function calls the following functions (in the specified order), so
* subclass any of them to implement the desired behavior.
*
*  (1) doInitialization()
*  (2) doOptimization()
*  (3) doFinalization()
*/
ShPtr<Module> Optimizer::optimize() {
	doInitialization();
	doOptimization();
	doFinalization();
	return module;
}

/**
* @brief Performs pre-optimization matters.
*
* This function is called before any optimizations are done.
*
* By default, this function does nothing.
*/
void Optimizer::doInitialization() {}

/**
* @brief Performs the optimization.
*
* This function is called after @c doInitialization() and before @c
* doFinalization(), and should perform all the optimizations of the specific
* optimizer.
*
* By default, this function does nothing.
*/
void Optimizer::doOptimization() {}

/**
* @brief Performs post-optimization matters.
*
* This function is called after all optimizations are done.
*
* By default, this function does nothing.
*/
void Optimizer::doFinalization() {}

} // namespace llvmir2hll
} // namespace retdec
