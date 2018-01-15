/**
* @file tests/llvmir2hll/ir/statement_tests.cpp
* @brief Tests for the @c statement module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "llvmir2hll/ir/tests_with_module.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c statement module.
*/
class StatementTests: public TestsWithModule {};

//
// hasLabel()
//

TEST_F(StatementTests,
HasLabelReturnsFalseWhenStatementDoesNotHaveLabelSet) {
	auto stmt = EmptyStmt::create();

	ASSERT_FALSE(stmt->hasLabel());
}

TEST_F(StatementTests,
HasLabelReturnsTrueWhenStatementHasLabelSet) {
	auto stmt = EmptyStmt::create();
	stmt->setLabel("my_label");

	ASSERT_TRUE(stmt->hasLabel());
}

//
// removeLabel()
//

TEST_F(StatementTests,
RemoveLabelWorksCorrectlyWhenNoLabelWasAssigned) {
	auto stmt = EmptyStmt::create();
	stmt->removeLabel();
	ASSERT_FALSE(stmt->hasLabel());
}

TEST_F(StatementTests,
RemoveLabelWorksCorrectlyWhenLabelWasAssigned) {
	auto stmt = EmptyStmt::create();
	stmt->setLabel("my_label");
	stmt->removeLabel();
	ASSERT_FALSE(stmt->hasLabel());
}

//
// transferLabelFrom()
//

TEST_F(StatementTests,
TransferLabelFromTransfersLabelFromOtherStatementWhenItHasLabel) {
	auto stmt1 = EmptyStmt::create();
	auto stmt2 = EmptyStmt::create();
	stmt2->setLabel("my_label");

	stmt1->transferLabelFrom(stmt2);

	ASSERT_FALSE(stmt2->hasLabel());
	ASSERT_EQ("my_label", stmt1->getLabel());
}

TEST_F(StatementTests,
TransferLabelFromDoesNothingWhenStatementHasNoLabel) {
	auto stmt1 = EmptyStmt::create();
	auto stmt2 = EmptyStmt::create();

	stmt1->transferLabelFrom(stmt2);

	ASSERT_FALSE(stmt1->hasLabel());
	ASSERT_FALSE(stmt2->hasLabel());
}

//
// transferLabelTo()
//

TEST_F(StatementTests,
TransferLabelToTransfersLabelToOtherStatementWhenStatementHasLabel) {
	auto stmt1 = EmptyStmt::create();
	stmt1->setLabel("my_label");
	auto stmt2 = EmptyStmt::create();

	stmt1->transferLabelTo(stmt2);

	ASSERT_FALSE(stmt1->hasLabel());
	ASSERT_EQ("my_label", stmt2->getLabel());
}

TEST_F(StatementTests,
TransferLabelToDoesNothingWhenStatementHasNoLabel) {
	auto stmt1 = EmptyStmt::create();
	auto stmt2 = EmptyStmt::create();

	stmt1->transferLabelTo(stmt2);

	ASSERT_FALSE(stmt1->hasLabel());
	ASSERT_FALSE(stmt2->hasLabel());
}

//
// redirectGotosTo()
//

TEST_F(StatementTests,
RedirectGotosToDoesNothingWhenStatementIsNotGotoTarget) {
	auto stmt1 = EmptyStmt::create();
	auto stmt2 = EmptyStmt::create();

	stmt1->redirectGotosTo(stmt2);

	ASSERT_FALSE(stmt1->isGotoTarget());
	ASSERT_FALSE(stmt2->isGotoTarget());
}

TEST_F(StatementTests,
RedirectGotosToRedirectsGotos) {
	auto origTarget = EmptyStmt::create();
	auto newTarget = EmptyStmt::create();
	auto gotoStmt = GotoStmt::create(origTarget);

	origTarget->redirectGotosTo(newTarget);

	ASSERT_TRUE(newTarget->isGotoTarget());
	ASSERT_TRUE(newTarget->hasPredecessors());
	ASSERT_FALSE(origTarget->isGotoTarget());
	ASSERT_FALSE(origTarget->hasPredecessors());
}

TEST_F(StatementTests,
RedirectGotosToTransfersLabels) {
	auto origTarget = EmptyStmt::create();
	origTarget->setLabel("my_label");
	auto newTarget = EmptyStmt::create();
	auto gotoStmt = GotoStmt::create(origTarget);

	origTarget->redirectGotosTo(newTarget);

	ASSERT_EQ("my_label", newTarget->getLabel());
	ASSERT_FALSE(origTarget->hasLabel());
}

//
// removeLastStatement()
//

TEST_F(StatementTests,
RemoveLastStatementWorksCorrectlyWhenStmtsIsJustSingleStatement) {
	testFunc->setBody(BreakStmt::create());

	Statement::removeLastStatement(testFunc->getBody());

	EXPECT_TRUE(isa<EmptyStmt>(testFunc->getBody()));
}

TEST_F(StatementTests,
RemoveLastStatementWorksCorrectlyWhenStmtsHasMoreThanOneStatement) {
	ShPtr<Statement> stmt1(BreakStmt::create());
	ShPtr<Statement> stmt2(EmptyStmt::create(stmt1));
	ShPtr<Statement> stmt3(EmptyStmt::create(stmt2));

	Statement::removeLastStatement(stmt1);

	EXPECT_FALSE(stmt2->hasSuccessor());
}

#if DEATH_TESTS_ENABLED
TEST_F(StatementTests,
RemoveLastStatementViolatedPreconditionNullStmts) {
	EXPECT_DEATH(Statement::removeLastStatement(ShPtr<Statement>()),
		".*removeLastStatement.*Precondition.*failed.*");
}
#endif

//
// isStatementInStatements()
//

TEST_F(StatementTests,
IsStatementInStatementsReturnsTrueWhenStatementIsInBlockOfStatements) {
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	breakStmt->setSuccessor(returnStmt);
	returnStmt->setSuccessor(emptyStmt);

	EXPECT_TRUE(Statement::isStatementInStatements(returnStmt, breakStmt));
}

TEST_F(StatementTests,
IsStatementInStatementsReturnsFalseWhenStatementIsNotInBlockOfStatements) {
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	ShPtr<ContinueStmt> continueStmt(ContinueStmt::create());
	breakStmt->setSuccessor(returnStmt);
	returnStmt->setSuccessor(emptyStmt);

	EXPECT_FALSE(Statement::isStatementInStatements(continueStmt, breakStmt));
}

TEST_F(StatementTests,
IsStatementInStatementsReturnsFalseWhenStatementIsInNestedBlock) {
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstBool::create(true), emptyStmt));
	breakStmt->setSuccessor(returnStmt);
	returnStmt->setSuccessor(ifStmt);

	EXPECT_FALSE(Statement::isStatementInStatements(emptyStmt, breakStmt));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
