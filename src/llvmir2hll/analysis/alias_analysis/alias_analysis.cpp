/**
* @file src/llvmir2hll/analysis/alias_analysis/alias_analysis.cpp
* @brief Implementation of AliasAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new analysis.
*/
AliasAnalysis::AliasAnalysis() {}

/**
* @brief Destructs the analysis.
*/
AliasAnalysis::~AliasAnalysis() {}

/**
* @brief Initializes the analysis.
*
* @param[in] module The module to be analyzed.
*
* This member function has to be called (1) when an instance of this class (or
* its subclass) is created and (2) whenever the current module is changed in a
* way that may change the results of the alias analysis.
*
* @par Preconditions
*  - @a module is non-null
*/
void AliasAnalysis::init(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	this->module = module;
	globalVars = module->getGlobalVars();
}

/**
* @brief Returns @c true if the analysis has been initialized, @c false
*        otherwise.
*/
bool AliasAnalysis::isInitialized() const {
	return module != nullptr;
}

} // namespace llvmir2hll
} // namespace retdec
