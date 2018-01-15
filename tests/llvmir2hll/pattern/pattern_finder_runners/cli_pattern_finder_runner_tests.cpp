/**
* @file tests/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner_tests.cpp
* @brief Tests for the @c cli_pattern_finder_runner module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_runners/cli_pattern_finder_runner.h"
#include "llvmir2hll/pattern/pattern_finder_mock.h"
#include "llvmir2hll/pattern/pattern_mock.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c cli_pattern_finder_runner module.
*/
class CLIPatternFinderRunnerTests: public TestsWithModule {};

TEST_F(CLIPatternFinderRunnerTests,
RunWithOnePatternFinderCallsFindPatternAndPrintOnThatFinder) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Mocks.
	NiceMock<PatternMock> *pMock(new NiceMock<PatternMock>());
	ShPtr<Pattern> p(pMock);
	NiceMock<PatternFinderMock> *pfMock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf(pfMock);

	std::string outputStr;
	llvm::raw_string_ostream os(outputStr);

	// Expectations.
	PatternFinder::Patterns patterns;
	patterns.push_back(p);
	EXPECT_CALL(*pfMock, findPatterns(module))
		.WillOnce(Return(patterns));
	const std::string PF_MOCK_ID("PatternFinderMock");
	EXPECT_CALL(*pfMock, getId())
		.WillOnce(Return(std::string(PF_MOCK_ID)));
	EXPECT_CALL(*pMock, print(_, _));

	ShPtr<CLIPatternFinderRunner> pfr(new CLIPatternFinderRunner(os));

	// Test.
	pfr->run(pf, module);
	ASSERT_FALSE(os.str().empty());
	// The ID of the pattern finder should be present in the output.
	EXPECT_TRUE(os.str().find(PF_MOCK_ID) != std::string::npos);
}

TEST_F(CLIPatternFinderRunnerTests,
RunWithTwoPatternFindersCallsFindPatternAndPrintOnTheseFinders) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	std::string outputStr;
	llvm::raw_string_ostream os(outputStr);

	// Mocks.
	NiceMock<PatternMock> *p1Mock(new NiceMock<PatternMock>());
	ShPtr<Pattern> p1(p1Mock);
	NiceMock<PatternMock> *p2Mock(new NiceMock<PatternMock>());
	ShPtr<Pattern> p2(p2Mock);
	NiceMock<PatternFinderMock> *pf1Mock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf1(pf1Mock);
	NiceMock<PatternFinderMock> *pf2Mock(new NiceMock<PatternFinderMock>(va, cio));
	ShPtr<PatternFinder> pf2(pf2Mock);
	PatternFinderRunner::PatternFinders pfs;
	pfs.push_back(pf1);
	pfs.push_back(pf2);

	// Expectations.
	PatternFinder::Patterns patterns1;
	patterns1.push_back(p1);
	EXPECT_CALL(*pf1Mock, findPatterns(module))
		.WillOnce(Return(patterns1));
	const std::string PF1_MOCK_ID("PatternFinderMock1");
	EXPECT_CALL(*pf1Mock, getId())
		.WillOnce(Return(std::string(PF1_MOCK_ID)));
	EXPECT_CALL(*p1Mock, print(_, _));
	PatternFinder::Patterns patterns2;
	patterns2.push_back(p2);
	EXPECT_CALL(*pf2Mock, findPatterns(module))
		.WillOnce(Return(patterns2));
	const std::string PF2_MOCK_ID("PatternFinderMock2");
	EXPECT_CALL(*pf2Mock, getId())
		.WillOnce(Return(std::string(PF2_MOCK_ID)));
	EXPECT_CALL(*p2Mock, print(_, _));

	ShPtr<CLIPatternFinderRunner> pfr(new CLIPatternFinderRunner(os));

	// Test.
	pfr->run(pfs, module);
	ASSERT_FALSE(os.str().empty());
	// The IDs of the pattern finders should be present in the output.
	EXPECT_TRUE(os.str().find(PF1_MOCK_ID) != std::string::npos);
	EXPECT_TRUE(os.str().find(PF2_MOCK_ID) != std::string::npos);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
