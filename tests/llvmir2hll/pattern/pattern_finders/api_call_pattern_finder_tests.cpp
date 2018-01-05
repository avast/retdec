/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call_pattern_finder_tests.cpp
* @brief Tests for the @c api_call_pattern_finder module.
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
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call_pattern_finder.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c api_call_pattern_finder module.
*/
class APICallPatternFinderTests: public TestsWithModule {};

TEST_F(APICallPatternFinderTests,
FinderHasNonEmptyId) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));

	EXPECT_FALSE(pf->getId().empty());
}

TEST_F(APICallPatternFinderTests,
FinderIsRegisteredAtFactory) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));

	EXPECT_TRUE(PatternFinderFactory::getInstance().isRegistered(pf->getId()));
}

TEST_F(APICallPatternFinderTests,
WhenNoAPICallsArePresentNoPatternsAreReturned) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));
	PatternFinder::Patterns foundPatterns(pf->findPatterns(module));

	EXPECT_TRUE(foundPatterns.empty());
}

TEST_F(APICallPatternFinderTests,
WhenThereIsAPICallAsStatementPatternContainingThisStatementIsReturned) {
	// Set-up the module
	//
	// void ShellExecute();
	//
	// void test() {
	//    ShellExecute();
	// }
	//
	ShPtr<Function> shellExecuteFunc(addFuncDecl("ShellExecute"));
	ShPtr<CallExpr> callExpr(CallExpr::create(shellExecuteFunc->getAsVar()));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));
	PatternFinder::Patterns foundPatterns(pf->findPatterns(module));

	ASSERT_EQ(1, foundPatterns.size());
	ShPtr<StmtsPattern> p(cast<StmtsPattern>(foundPatterns[0]));
	ASSERT_TRUE(p) << "the pattern is not of type StmtsPattern";
	ASSERT_FALSE(p->isEmpty());
	EXPECT_EQ(callStmt, *p->stmt_begin());
}

TEST_F(APICallPatternFinderTests,
UninterestingCallsAreSkipped) {
	// Set-up the module
	//
	// void foo();
	//
	// void test() {
	//    foo();
	// }
	//
	ShPtr<Function> fooFunc(addFuncDecl("foo"));
	ShPtr<CallExpr> callExpr(CallExpr::create(fooFunc->getAsVar()));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));
	PatternFinder::Patterns foundPatterns(pf->findPatterns(module));

	EXPECT_EQ(0, foundPatterns.size());
}

TEST_F(APICallPatternFinderTests,
WhenThereAreMoreAPICallsAsStatementsPatternsContainingTheseStatementsAreReturned) {
	// Set-up the module
	//
	// void ShellExecute();
	//
	// void test() {
	//    ShellExecute();
	//    ShellExecute();
	// }
	//
	ShPtr<Function> shellExecuteFunc(addFuncDecl("ShellExecute"));
	ShPtr<CallExpr> callExpr2(CallExpr::create(shellExecuteFunc->getAsVar()));
	ShPtr<CallStmt> callStmt2(CallStmt::create(callExpr2));
	ShPtr<CallExpr> callExpr1(CallExpr::create(shellExecuteFunc->getAsVar()));
	ShPtr<CallStmt> callStmt1(CallStmt::create(callExpr1, callStmt2));
	testFunc->setBody(callStmt1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<PatternFinder> pf(APICallPatternFinder::create(va, cio));
	PatternFinder::Patterns foundPatterns(pf->findPatterns(module));

	ASSERT_EQ(2, foundPatterns.size());
	ShPtr<StmtsPattern> p1(cast<StmtsPattern>(foundPatterns[0]));
	ASSERT_TRUE(p1) << "the pattern is not of type StmtsPattern";
	ASSERT_FALSE(p1->isEmpty());
	EXPECT_EQ(callStmt1, *p1->stmt_begin());
	ShPtr<StmtsPattern> p2(cast<StmtsPattern>(foundPatterns[1]));
	ASSERT_FALSE(p2->isEmpty());
	EXPECT_EQ(callStmt2, *p2->stmt_begin());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
