/**
* @file include/llvmir2hll/analysis/alias_analysis/alias_analysis_factory.h
* @brief Factory that creates instances of classes derived from AliasAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSIS_FACTORY_H
#define LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSIS_FACTORY_H

#include <string>

#include "llvmir2hll/support/factory.h"
#include "llvmir2hll/support/singleton.h"
#include "llvmir2hll/support/smart_ptr.h"

namespace llvmir2hll {

class AliasAnalysis;

/**
* @brief Factory that creates instances of classes derived from AliasAnalysis.
*/
using AliasAnalysisFactory = Singleton<
	Factory<
		// Type of the base class.
		AliasAnalysis,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<AliasAnalysis> (*)()
	>
>;

} // namespace llvmir2hll

#endif
