/**
* @file src/llvmir2hll/analysis/null_pointer_analysis.cpp
* @brief Implementation of NullPointerAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/null_pointer_analysis.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new analysis.
*
* For the description of parameters and preconditions, see create().
*/
NullPointerAnalysis::NullPointerAnalysis(ShPtr<Module> module):
	OrderedAllVisitor(), module(module), foundNullPointer(false) {}

/**
* @brief Destructs the analysis.
*/
NullPointerAnalysis::~NullPointerAnalysis() {}

/**
* @brief Returns @c true if @a module uses null pointers, @c false otherwise.
*
* @param[in] module Module to be checked.
*
* @par Preconditions
*  - @a module is non-null
*/
bool NullPointerAnalysis::useNullPointers(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	ShPtr<NullPointerAnalysis> analysis(new NullPointerAnalysis(module));
	analysis->analyzeNullPointersUsage();
	return analysis->foundNullPointer;
}

/**
* @brief Analyses the module for the use of null pointers.
*/
void NullPointerAnalysis::analyzeNullPointersUsage() {
	analyzeAllGlobalVariables();
	analyzeAllFunctions();
}

/**
* @brief Analyzes all global variables in the module for the use of null
*        pointers.
*/
void NullPointerAnalysis::analyzeAllGlobalVariables() {
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		(*i)->accept(this);
		if (foundNullPointer) {
			// Since we have already found a use of the null pointer, we may
			// stop the analysis.
			return;
		}
	}
}

/**
* @brief Analyzes all functions in the module for the use of null pointers.
*/
void NullPointerAnalysis::analyzeAllFunctions() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(this);
		if (foundNullPointer) {
			// Since we have already found a use of the null pointer, we may
			// stop the analysis.
			return;
		}
	}
}

void NullPointerAnalysis::visit(ShPtr<ConstNullPointer> constant) {
	foundNullPointer = true;
}

} // namespace llvmir2hll
} // namespace retdec
