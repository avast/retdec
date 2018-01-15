/**
* @file tests/llvmir2hll/pattern/pattern_finder_runner_tests.cpp
* @brief Tests for the @c pattern_finder_runner module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "llvmir2hll/pattern/pattern_finder_mock.h"
#include "llvmir2hll/pattern/pattern_finder_runner_mock.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c pattern_finder_runner module.
*/
class PatternFinderRunnerTests: public TestsWithModule {};

TEST_F(PatternFinderRunnerTests,
RunWithOnePatternFinderProperlyCallsAllRequiredFunctions) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	NiceMock<PatternFinderMock> *pfMock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf(pfMock);
	NiceMock<PatternFinderRunnerMock> pfrMock;

	// Expectations.
	EXPECT_CALL(pfrMock, doActionsBeforePatternFinderRuns(pf));
	PatternFinder::Patterns patterns;
	EXPECT_CALL(*pfMock, findPatterns(module))
		.WillOnce(Return(patterns));
	EXPECT_CALL(pfrMock, doActionsAfterPatternFinderHasRun(pf, patterns));

	// Test.
	pfrMock.run(pf, module);
}

TEST_F(PatternFinderRunnerTests,
RunWithTwoPatternFindersProperlyCallsAllRequiredFunctions) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	NiceMock<PatternFinderMock> *pf1Mock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf1(pf1Mock);
	NiceMock<PatternFinderMock> *pf2Mock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf2(pf2Mock);
	PatternFinderRunner::PatternFinders pfs;
	pfs.push_back(pf1);
	pfs.push_back(pf2);
	NiceMock<PatternFinderRunnerMock> pfrMock;

	// Expectations.
	EXPECT_CALL(pfrMock, doActionsBeforePatternFinderRuns(pf1));
	PatternFinder::Patterns patterns;
	EXPECT_CALL(*pf1Mock, findPatterns(module))
		.WillOnce(Return(patterns));
	EXPECT_CALL(pfrMock, doActionsAfterPatternFinderHasRun(pf1, patterns));
	EXPECT_CALL(pfrMock, doActionsBeforePatternFinderRuns(pf2));
	EXPECT_CALL(*pf2Mock, findPatterns(module))
		.WillOnce(Return(patterns));
	EXPECT_CALL(pfrMock, doActionsAfterPatternFinderHasRun(pf2, patterns));

	// Test
	pfrMock.run(pfs, module);
}

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderRunnerTests,
RunWithOnePatternFinderAndNullModuleResultsIntoViolatedPrecondition) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	NiceMock<PatternFinderMock> *pfMock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf(pfMock);
	NiceMock<PatternFinderRunnerMock> pfrMock;

	// Test.
	ASSERT_DEATH(pfrMock.run(pf, ShPtr<Module>()), ".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderRunnerTests,
RunWithTwoPatternFinderAndNullModuleResultsIntoViolatedPrecondition) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	NiceMock<PatternFinderMock> *pfMock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf(pfMock);
	PatternFinderRunner::PatternFinders pfs;
	pfs.push_back(pf);
	pfs.push_back(pf); // Duplicate the pattern finder so we have two.
	NiceMock<PatternFinderRunnerMock> pfrMock;

	// Test.
	ASSERT_DEATH(pfrMock.run(pfs, ShPtr<Module>()), ".*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
