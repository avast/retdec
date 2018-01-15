/**
* @file src/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner.cpp
* @brief Implementation of NoActionPatternFinderRunner.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include "retdec/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a runner of pattern finders.
*/
NoActionPatternFinderRunner::NoActionPatternFinderRunner() {}

/**
* @brief Destructs the finder.
*/
NoActionPatternFinderRunner::~NoActionPatternFinderRunner() {}

/**
* @brief Does nothing.
*/
void NoActionPatternFinderRunner::doActionsBeforePatternFinderRuns(
		ShPtr<PatternFinder> pf) {}

/**
* @brief Does nothing.
*/
void NoActionPatternFinderRunner::doActionsAfterPatternFinderHasRun(
	ShPtr<PatternFinder> pf, const PatternFinder::Patterns &foundPatterns) {}

} // namespace llvmir2hll
} // namespace retdec
