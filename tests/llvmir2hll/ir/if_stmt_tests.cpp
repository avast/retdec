/**
* @file tests/llvmir2hll/ir/if_stmt_tests.cpp
* @brief Tests for the @c if_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c if_stmt module.
*/
class IfStmtTests: public Test {};

//
// removeClause()
//

TEST_F(IfStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheFirstClauseOfTwoClauses) {
	ShPtr<ConstInt> clause1Cond(ConstInt::create(1, 32));
	ShPtr<IfStmt> ifStmt(IfStmt::create(clause1Cond, BreakStmt::create()));
	ShPtr<ConstInt> clause2Cond(ConstInt::create(2, 32));
	ifStmt->addClause(clause2Cond, BreakStmt::create());

	ifStmt->removeClause(ifStmt->clause_begin());

	EXPECT_EQ(clause2Cond, ifStmt->getFirstIfCond());
	EXPECT_FALSE(ifStmt->hasElseIfClauses());
}

TEST_F(IfStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheLastClauseOfTwoClauses) {
	ShPtr<ConstInt> clause1Cond(ConstInt::create(1, 32));
	ShPtr<IfStmt> ifStmt(IfStmt::create(clause1Cond, BreakStmt::create()));
	ShPtr<ConstInt> clause2Cond(ConstInt::create(2, 32));
	ifStmt->addClause(clause2Cond, BreakStmt::create());

	ifStmt->removeClause(++ifStmt->clause_begin());

	EXPECT_EQ(clause1Cond, ifStmt->getFirstIfCond());
	EXPECT_FALSE(ifStmt->hasElseIfClauses());
}

TEST_F(IfStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheOnlyClause) {
	ShPtr<ConstInt> clause1Cond(ConstInt::create(1, 32));
	ShPtr<IfStmt> ifStmt(IfStmt::create(clause1Cond, BreakStmt::create()));

	ifStmt->removeClause(ifStmt->clause_begin());

	EXPECT_EQ(ifStmt->clause_begin(), ifStmt->clause_end());
}

//
// hasClauses()
//

TEST_F(IfStmtTests,
IfStmtWithJustTheIfClauseHasClauses) {
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), BreakStmt::create()));

	EXPECT_TRUE(ifStmt->hasClauses());
}

TEST_F(IfStmtTests,
IfStmtWithJustTheElseClauseHasClauses) {
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), BreakStmt::create()));
	ifStmt->removeClause(ifStmt->clause_begin());
	ifStmt->setElseClause(BreakStmt::create());

	EXPECT_TRUE(ifStmt->hasClauses());
}

TEST_F(IfStmtTests,
IfStmtWithoutAnyClausesHasNoClauses) {
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), BreakStmt::create()));
	ifStmt->removeClause(ifStmt->clause_begin());

	EXPECT_FALSE(ifStmt->hasClauses());
}

//
// hasIfClause()
//

TEST_F(IfStmtTests,
IfStmtWithIfClauseHasIfClause) {
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), BreakStmt::create()));

	EXPECT_TRUE(ifStmt->hasIfClause());
}

TEST_F(IfStmtTests,
IfStmtWithNoClausesHasNoIfClause) {
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), BreakStmt::create()));
	ifStmt->removeClause(ifStmt->clause_begin());

	EXPECT_FALSE(ifStmt->hasIfClause());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
