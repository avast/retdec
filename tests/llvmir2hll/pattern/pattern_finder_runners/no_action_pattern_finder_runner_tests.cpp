/**
* @file tests/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner_tests.cpp
* @brief Tests for the @c no_action_pattern_finder_runner module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runners/no_action_pattern_finder_runner.h"
#include "llvmir2hll/pattern/pattern_finder_mock.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c no_action_pattern_finder_runner module.
*/
class NoActionPatternFinderRunnerTests: public TestsWithModule {};

TEST_F(NoActionPatternFinderRunnerTests,
RunWithOnePatternFinderOnlyCallsFindPatternOnThatFinder) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	StrictMock<PatternFinderMock> *pfMock(new StrictMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf(pfMock);

	// Expectations.
	PatternFinder::Patterns patterns;
	EXPECT_CALL(*pfMock, findPatterns(module))
		.WillOnce(Return(patterns));

	ShPtr<NoActionPatternFinderRunner> pfr(new NoActionPatternFinderRunner());

	// Test.
	pfr->run(pf, module);
}

TEST_F(NoActionPatternFinderRunnerTests,
RunWithTwoPatternFindersOnlyCallsFindPatternOnTheseFinders) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	StrictMock<PatternFinderMock> *pf1Mock(new StrictMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf1(pf1Mock);
	StrictMock<PatternFinderMock> *pf2Mock(new StrictMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf2(pf2Mock);
	PatternFinderRunner::PatternFinders pfs;
	pfs.push_back(pf1);
	pfs.push_back(pf2);

	// Expectations.
	PatternFinder::Patterns patterns;
	EXPECT_CALL(*pf1Mock, findPatterns(module))
		.WillOnce(Return(patterns));
	EXPECT_CALL(*pf2Mock, findPatterns(module))
		.WillOnce(Return(patterns));

	ShPtr<NoActionPatternFinderRunner> pfr(new NoActionPatternFinderRunner());

	// Test.
	pfr->run(pfs, module);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
