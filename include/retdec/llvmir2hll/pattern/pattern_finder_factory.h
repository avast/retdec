/**
* @file include/retdec/llvmir2hll/pattern/pattern_finder_factory.h
* @brief Factory that creates instances of classes derived from PatternFinder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is using the Object factory and Singleton design patterns.
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_FACTORY_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_FACTORY_H

#include <string>

#include "retdec/llvmir2hll/support/factory.h"
#include "retdec/llvmir2hll/support/singleton.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class PatternFinder;
class ValueAnalysis;

/**
* @brief Factory that creates instances of classes derived from PatternFinder.
*/
using PatternFinderFactory = Singleton<
	Factory<
		// Type of the base class.
		PatternFinder,
		// Type of the object's identifier.
		std::string,
		// Type of a function used to create instances.
		ShPtr<PatternFinder> (*)(ShPtr<ValueAnalysis>, ShPtr<CallInfoObtainer>)
	>
>;

} // namespace llvmir2hll
} // namespace retdec

#endif
