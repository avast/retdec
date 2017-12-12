/**
* @file include/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner.h
* @brief Runner of pattern finders that performs no additional actions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNERS_NO_ACTION_PATTERN_FINDER_RUNNER_H
#define LLVMIR2HLL_PATTERN_PATTERN_FINDER_RUNNERS_NO_ACTION_PATTERN_FINDER_RUNNER_H

#include <vector>

#include "llvmir2hll/pattern/pattern_finder_runner.h"

namespace llvmir2hll {

/**
* @brief Runner of pattern finders that performs no additional actions.
*
* Instances of this class have reference object semantics.
*/
class NoActionPatternFinderRunner: public PatternFinderRunner {
public:
	NoActionPatternFinderRunner();
	virtual ~NoActionPatternFinderRunner() override;

private:
	virtual void doActionsBeforePatternFinderRuns(ShPtr<PatternFinder> pf) override;
	virtual void doActionsAfterPatternFinderHasRun(ShPtr<PatternFinder> pf,
		const PatternFinder::Patterns &foundPatterns) override;
};

} // namespace llvmir2hll

#endif
