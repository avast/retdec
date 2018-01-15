/**
* @file tests/llvmir2hll/pattern/patterns/stmts_pattern_tests.cpp
* @brief Tests for the @c stmts_pattern module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::startsWith;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c stmts_pattern module.
*/
class StmtsPatternTests: public ::testing::Test {
protected:
	virtual void SetUp() override {
		// Create a `void testFunc()` function containing two statements, stmt1
		// and stmt2.
		stmt1 = EmptyStmt::create();
		stmts12.push_back(stmt1);
		stmt2 = ReturnStmt::create(ShPtr<Expression>(), stmt1);
		stmts12.push_back(stmt2);
		testFunc = FunctionBuilder("test")
			.definitionWithBody(stmt1)
			.build();
	}

protected:
	/// A testing function.
	ShPtr<Function> testFunc;

	/// The first statement in the function.
	ShPtr<Statement> stmt1;

	/// The second statement in the function.
	ShPtr<Statement> stmt2;

	/// A vector containing @c stmt1 and @c stmt2.
	StmtVector stmts12;
};

//
// isEmpty()
//

TEST_F(StmtsPatternTests,
IsEmptyPatternIsEmptyAfterCreationWithNoArguments) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	EXPECT_TRUE(p->isEmpty());
}

TEST_F(StmtsPatternTests,
IsEmptyPatternIsNotEmptyWhenPassedStatementIntoCreate) {
	ShPtr<StmtsPattern> p(StmtsPattern::create(stmt1));
	EXPECT_FALSE(p->isEmpty());
}

TEST_F(StmtsPatternTests,
IsEmptyPatternIsNotEmptyAfterAddingStatement) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	p->addStmt(stmt1);
	EXPECT_FALSE(p->isEmpty());
}

//
// getNumOfStmts()
//

TEST_F(StmtsPatternTests,
GetNumOfStmtsReturnsZeroOnEmptyPattern) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	EXPECT_EQ(0, p->getNumOfStmts());
}

TEST_F(StmtsPatternTests,
GetNumOfStmtsReturnsCorrectNumberOfStatmentsWhenStatementIsPassedToCreate) {
	ShPtr<StmtsPattern> p(StmtsPattern::create(stmt1));
	EXPECT_EQ(1, p->getNumOfStmts());
}

TEST_F(StmtsPatternTests,
GetNumOfStmtsReturnsCorrectNumberOfStatmentsWhenNonEmpty) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	p->addStmt(stmt1);
	EXPECT_EQ(1, p->getNumOfStmts());
	p->addStmt(stmt2);
	EXPECT_EQ(2, p->getNumOfStmts());
}

//
// stmt_begin() and stmt_end()
//

TEST_F(StmtsPatternTests,
IterationOverEmptyPatternDoesNotIterate) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	EXPECT_EQ(p->stmt_begin(), p->stmt_end());
}

TEST_F(StmtsPatternTests,
IterationOverNonEmptyPatternIteratesOverEveryElementInCorrectOrder) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	p->addStmt(stmt1);
	p->addStmt(stmt2);
	StmtVector stmtsInPattern(p->stmt_begin(), p->stmt_end());
	EXPECT_EQ(stmts12, stmtsInPattern);
}

//
// print()
//

namespace {

/**
* @brief Converts the given pattern into a string by utilizing print().
*/
std::string patternToString(ShPtr<StmtsPattern> p,
		const std::string &indentation = "") {
	std::string pStrRepr;
	llvm::raw_string_ostream os(pStrRepr);
	p->print(os, indentation);
	return os.str();
}

} // anonymous namespace

TEST_F(StmtsPatternTests,
PrintPrintsNothingForEmptyPattern) {
	ShPtr<StmtsPattern> p(StmtsPattern::create());
	std::string pStrRepr(patternToString(p));
	EXPECT_TRUE(pStrRepr.empty());
}

TEST_F(StmtsPatternTests,
PrintPrintsSomethingForNonEmptyPatternAndEndsWithNewLine) {
	ShPtr<StmtsPattern> p(StmtsPattern::create(stmt2));
	std::string pStrRepr(patternToString(p));
	EXPECT_FALSE(pStrRepr.empty());
	EXPECT_EQ('\n', *pStrRepr.rbegin());
}

TEST_F(StmtsPatternTests,
PrintTheResultForNonEmptyPatternStartsWithSpecifiedIndentationAndEndsWithNewLine) {
	ShPtr<StmtsPattern> p(StmtsPattern::create(stmt2));
	const std::string indentation("XXX");
	std::string pStrRepr(patternToString(p, indentation));
	EXPECT_TRUE(startsWith(pStrRepr, indentation));
	EXPECT_EQ('\n', *pStrRepr.rbegin());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
