/**
* @file tests/llvmir2hll/ir/switch_stmt_tests.cpp
* @brief Tests for the @c switch_stmt module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c switch_stmt module.
*/
class SwitchStmtTests: public Test {};

//
// addClause()
//

TEST_F(SwitchStmtTests,
AddCaseClauseWorksCorrectlyWhenAddingNonDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	ShPtr<ConstInt> caseExpr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> caseBody(BreakStmt::create());
	switchStmt->addClause(caseExpr, caseBody);

	EXPECT_EQ(caseExpr, switchStmt->clause_begin()->first);
	EXPECT_EQ(caseBody, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
AddCaseClauseWorksCorrectlyWhenAddingDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	ShPtr<BreakStmt> caseBody(BreakStmt::create());
	switchStmt->addClause(ShPtr<Expression>(), caseBody);

	EXPECT_EQ(caseBody, switchStmt->clause_begin()->second);
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddCaseClauseViolatedPreconditionNoBody) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->addClause(ShPtr<Expression>(), ShPtr<Statement>()),
		".*addClause.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddCaseClauseViolatedPreconditionThereAlreadyIsDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->addDefaultClause(ContinueStmt::create());

	EXPECT_DEATH(switchStmt->addClause(ShPtr<Expression>(), BreakStmt::create()),
		".*addClause.*Precondition.*failed.*");
}
#endif

//
// removeClause()
//

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheFirstClauseOfTwoClauses) {
	ShPtr<ConstInt> controlExpr(ConstInt::create(0, 32));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(controlExpr));
	ShPtr<ConstInt> clause1Expr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> clause1Body(BreakStmt::create());
	switchStmt->addClause(clause1Expr, clause1Body);
	ShPtr<ConstInt> clause2Expr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> clause2Body(BreakStmt::create());
	switchStmt->addClause(clause2Expr, clause2Body);

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(clause2Expr, switchStmt->clause_begin()->first);
	EXPECT_EQ(clause2Body, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheLastClauseOfTwoClauses) {
	ShPtr<ConstInt> controlExpr(ConstInt::create(0, 32));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(controlExpr));
	ShPtr<ConstInt> clause1Expr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> clause1Body(BreakStmt::create());
	switchStmt->addClause(clause1Expr, clause1Body);
	ShPtr<ConstInt> clause2Expr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> clause2Body(BreakStmt::create());
	switchStmt->addClause(clause2Expr, clause2Body);

	switchStmt->removeClause(++switchStmt->clause_begin());

	EXPECT_EQ(clause1Expr, switchStmt->clause_begin()->first);
	EXPECT_EQ(clause1Body, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheOnlyClause) {
	ShPtr<ConstInt> controlExpr(ConstInt::create(0, 32));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(controlExpr));
	ShPtr<ConstInt> clauseExpr(ConstInt::create(1, 32));
	ShPtr<BreakStmt> clauseBody(BreakStmt::create());
	switchStmt->addClause(clauseExpr, clauseBody);

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(switchStmt->clause_end(), switchStmt->clause_begin());

}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheDefaultClause) {
	ShPtr<ConstInt> controlExpr(ConstInt::create(0, 32));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(controlExpr));
	switchStmt->addDefaultClause(BreakStmt::create());

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(switchStmt->clause_end(), switchStmt->clause_begin());
}

//
// getDefaultClauseBody()
//

TEST_F(SwitchStmtTests,
GetDefaultCaluseBodyReturnsClauseBodyIfThereIsDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	switchStmt->addClause(ShPtr<Expression>(), breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

TEST_F(SwitchStmtTests,
GetDefaultCaluseBodyReturnsNullPointerWhenThereIsNoDefaultCaluse) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_EQ(ShPtr<Statement>(), switchStmt->getDefaultClauseBody());
}

//
// addDefaultClause()
//

TEST_F(SwitchStmtTests,
AddDefaultClauseWorksCorrectlyWhenThereIsNoDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	switchStmt->addDefaultClause(breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddDefaultClauseViolatedPreconditionNoBody) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->addDefaultClause(ShPtr<Statement>()),
		".*addDefaultClause.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionThereAlreadyIsDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->addDefaultClause(ContinueStmt::create());

	EXPECT_DEATH(switchStmt->addDefaultClause(BreakStmt::create()),
		".*addDefaultClause.*Precondition.*failed.*");
}
#endif

//
// setDefaultClauseBody()
//

TEST_F(SwitchStmtTests,
SetDefaultClauseBodyWorksCorrectlyWhenThereIsDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->addClause(ShPtr<Expression>(), ContinueStmt::create());
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	switchStmt->setDefaultClauseBody(breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionNoBody) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->setDefaultClauseBody(ShPtr<Statement>()),
		".*setDefaultClauseBody.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionNoDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->setDefaultClauseBody(BreakStmt::create()),
		".*setDefaultClauseBody.*Precondition.*failed.*");
}
#endif

//
// removeDefaultClause()
//

TEST_F(SwitchStmtTests,
RemoveDefaultClauseWorksCorrectlyWhenThereAreNoClauses) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->removeDefaultClause();

	EXPECT_FALSE(switchStmt->hasDefaultClause());
}

TEST_F(SwitchStmtTests,
RemoveDefaultClauseWorksCorrectlyWhenThereIsDefaultClause) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->removeDefaultClause();

	EXPECT_FALSE(switchStmt->hasDefaultClause());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
