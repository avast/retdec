/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call_seq_pattern_finder_tests.cpp
* @brief Tests for the @c api_call_seq_pattern_finder module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_factory.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call_seq_pattern_finder.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c api_call_seq_pattern_finder module.
*/
class APICallSeqPatternFinderTests: public TestsWithModule {};

TEST_F(APICallSeqPatternFinderTests,
FinderHasNonEmptyId) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallSeqPatternFinder::create(va, cio));

	EXPECT_FALSE(pf->getId().empty());
}

TEST_F(APICallSeqPatternFinderTests,
FinderIsRegisteredAtFactory) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallSeqPatternFinder::create(va, cio));

	EXPECT_TRUE(PatternFinderFactory::getInstance().isRegistered(pf->getId()));
}

TEST_F(APICallSeqPatternFinderTests,
WhenNoAPICallsArePresentNoPatternsAreReturned) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallSeqPatternFinder::create(va, cio));
	PatternFinder::Patterns foundPatterns(pf->findPatterns(module));

	EXPECT_TRUE(foundPatterns.empty());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
