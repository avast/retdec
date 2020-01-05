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
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	ConstInt* caseExpr(ConstInt::create(1, 32));
	BreakStmt* caseBody(BreakStmt::create());
	switchStmt->addClause(caseExpr, caseBody);

	EXPECT_EQ(caseExpr, switchStmt->clause_begin()->first);
	EXPECT_EQ(caseBody, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
AddCaseClauseWorksCorrectlyWhenAddingDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	BreakStmt* caseBody(BreakStmt::create());
	switchStmt->addClause(Expression*(), caseBody);

	EXPECT_EQ(caseBody, switchStmt->clause_begin()->second);
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddCaseClauseViolatedPreconditionNoBody) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->addClause(Expression*(), Statement*()),
		".*addClause.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddCaseClauseViolatedPreconditionThereAlreadyIsDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->addDefaultClause(ContinueStmt::create());

	EXPECT_DEATH(switchStmt->addClause(Expression*(), BreakStmt::create()),
		".*addClause.*Precondition.*failed.*");
}
#endif

//
// removeClause()
//

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheFirstClauseOfTwoClauses) {
	ConstInt* controlExpr(ConstInt::create(0, 32));
	SwitchStmt* switchStmt(SwitchStmt::create(controlExpr));
	ConstInt* clause1Expr(ConstInt::create(1, 32));
	BreakStmt* clause1Body(BreakStmt::create());
	switchStmt->addClause(clause1Expr, clause1Body);
	ConstInt* clause2Expr(ConstInt::create(1, 32));
	BreakStmt* clause2Body(BreakStmt::create());
	switchStmt->addClause(clause2Expr, clause2Body);

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(clause2Expr, switchStmt->clause_begin()->first);
	EXPECT_EQ(clause2Body, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheLastClauseOfTwoClauses) {
	ConstInt* controlExpr(ConstInt::create(0, 32));
	SwitchStmt* switchStmt(SwitchStmt::create(controlExpr));
	ConstInt* clause1Expr(ConstInt::create(1, 32));
	BreakStmt* clause1Body(BreakStmt::create());
	switchStmt->addClause(clause1Expr, clause1Body);
	ConstInt* clause2Expr(ConstInt::create(1, 32));
	BreakStmt* clause2Body(BreakStmt::create());
	switchStmt->addClause(clause2Expr, clause2Body);

	switchStmt->removeClause(++switchStmt->clause_begin());

	EXPECT_EQ(clause1Expr, switchStmt->clause_begin()->first);
	EXPECT_EQ(clause1Body, switchStmt->clause_begin()->second);
}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheOnlyClause) {
	ConstInt* controlExpr(ConstInt::create(0, 32));
	SwitchStmt* switchStmt(SwitchStmt::create(controlExpr));
	ConstInt* clauseExpr(ConstInt::create(1, 32));
	BreakStmt* clauseBody(BreakStmt::create());
	switchStmt->addClause(clauseExpr, clauseBody);

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(switchStmt->clause_end(), switchStmt->clause_begin());

}

TEST_F(SwitchStmtTests,
RemoveClauseWorksCorrectlyWhenRemovingTheDefaultClause) {
	ConstInt* controlExpr(ConstInt::create(0, 32));
	SwitchStmt* switchStmt(SwitchStmt::create(controlExpr));
	switchStmt->addDefaultClause(BreakStmt::create());

	switchStmt->removeClause(switchStmt->clause_begin());

	EXPECT_EQ(switchStmt->clause_end(), switchStmt->clause_begin());
}

//
// getDefaultClauseBody()
//

TEST_F(SwitchStmtTests,
GetDefaultCaluseBodyReturnsClauseBodyIfThereIsDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	BreakStmt* breakStmt(BreakStmt::create());
	switchStmt->addClause(Expression*(), breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

TEST_F(SwitchStmtTests,
GetDefaultCaluseBodyReturnsNullPointerWhenThereIsNoDefaultCaluse) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_EQ(Statement*(), switchStmt->getDefaultClauseBody());
}

//
// addDefaultClause()
//

TEST_F(SwitchStmtTests,
AddDefaultClauseWorksCorrectlyWhenThereIsNoDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	BreakStmt* breakStmt(BreakStmt::create());
	switchStmt->addDefaultClause(breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
AddDefaultClauseViolatedPreconditionNoBody) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->addDefaultClause(Statement*()),
		".*addDefaultClause.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionThereAlreadyIsDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
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
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->addClause(Expression*(), ContinueStmt::create());
	BreakStmt* breakStmt(BreakStmt::create());
	switchStmt->setDefaultClauseBody(breakStmt);

	EXPECT_EQ(breakStmt, switchStmt->getDefaultClauseBody());
}

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionNoBody) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->setDefaultClauseBody(Statement*()),
		".*setDefaultClauseBody.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(SwitchStmtTests,
SetDefaultClauseBodyViolatedPreconditionNoDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));

	EXPECT_DEATH(switchStmt->setDefaultClauseBody(BreakStmt::create()),
		".*setDefaultClauseBody.*Precondition.*failed.*");
}
#endif

//
// removeDefaultClause()
//

TEST_F(SwitchStmtTests,
RemoveDefaultClauseWorksCorrectlyWhenThereAreNoClauses) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->removeDefaultClause();

	EXPECT_FALSE(switchStmt->hasDefaultClause());
}

TEST_F(SwitchStmtTests,
RemoveDefaultClauseWorksCorrectlyWhenThereIsDefaultClause) {
	SwitchStmt* switchStmt(SwitchStmt::create(ConstInt::create(1, 32)));
	switchStmt->removeDefaultClause();

	EXPECT_FALSE(switchStmt->hasDefaultClause());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
