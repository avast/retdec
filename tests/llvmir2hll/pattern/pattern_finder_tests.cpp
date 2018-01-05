/**
* @file tests/llvmir2hll/pattern/pattern_finder_tests.cpp
* @brief Tests for the @c pattern_finder module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "llvmir2hll/pattern/pattern_finder_mock.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c pattern_finder module.
*/
class PatternFinderTests: public TestsWithModule {};

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderTests,
ConstructionWithNullValueAnalyzerResultsIntoViolatedPrecondition) {
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();
	ASSERT_DEATH(NiceMock<PatternFinderMock>(ShPtr<ValueAnalysis>(), cio),
		".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderTests,
ConstructionWithNullCallInfoObtainerResultsIntoViolatedPrecondition) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	ASSERT_DEATH(NiceMock<PatternFinderMock>(va, ShPtr<CallInfoObtainer>()),
		".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderTests,
ConstructionWithValueAnalysisInInvalidStateResultsIntoViolatedPrecondition) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	va->invalidateState();
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();
	ASSERT_DEATH(NiceMock<PatternFinderMock>(va, cio),
		".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(PatternFinderTests,
ConstructionWithUnititializedCallInfoObtainerResultsIntoViolatedPrecondition) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();
	ON_CALL(*cioMock, isInitialized())
		.WillByDefault(Return(false));
	ASSERT_DEATH(NiceMock<PatternFinderMock>(va, cio),
		".*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
