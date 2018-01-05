/**
* @file tests/llvmir2hll/pattern/pattern_finder_runner_mock.h
* @brief A base class for all runners of pattern finders.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_PATTERN_TESTS_PATTERN_FINDER_RUNNER_MOCK_H
#define BACKEND_BIR_PATTERN_TESTS_PATTERN_FINDER_RUNNER_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/pattern/pattern_finder.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runner.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the PatternFinderRunner class.
*/
class PatternFinderRunnerMock: public PatternFinderRunner {
public:
	MOCK_METHOD1(doActionsBeforePatternFinderRuns, void (ShPtr<PatternFinder>));
	MOCK_METHOD2(doActionsAfterPatternFinderHasRun, void (ShPtr<PatternFinder>,
		const PatternFinder::Patterns &));
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
