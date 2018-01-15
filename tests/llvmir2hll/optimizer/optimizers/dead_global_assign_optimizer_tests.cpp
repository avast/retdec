/**
* @file tests/llvmir2hll/optimizer/optimizers/dead_global_assign_optimizer_tests.cpp
* @brief Tests for the @c dead_global_assign_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/obtainer/call_info_obtainer_mock.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_global_assign_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c dead_global_assign_optimizer module.
*/
class DeadGlobalAssignOptimizerTests: public TestsWithModule {};

TEST_F(DeadGlobalAssignOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	ShPtr<DeadGlobalAssignOptimizer> optimizer(
		new DeadGlobalAssignOptimizer(module, va, cio));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(DeadGlobalAssignOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
OptimizeAssignmentDirectlyBeforeOtherAssignment) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;      <-- this can be removed
	//    g = 2;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), assignG2));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG2, testFunc->getBody()) <<
		"expected `" << assignG2 <<
		"`, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
OptimizeAssignmentBeforeOtherAssignmentWithHarmlessStatementsInBetween) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;      <-- this can be removed
	//    int i = 4;
	//    int j = 5;
	//    g = 2;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<Variable> varJ(Variable::create("j", IntType::create(32)));
	testFunc->addLocalVar(varJ);
	ShPtr<VarDefStmt> varDefJ(VarDefStmt::create(varJ, ConstInt::create(5, 32), assignG2));
	ShPtr<Variable> varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	ShPtr<VarDefStmt> varDefI(VarDefStmt::create(varI, ConstInt::create(4, 32), varDefJ));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), varDefI));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(varDefI, testFunc->getBody()) <<
		"expected `" << varDefI <<
		"`, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
OptimizeAssignmentIfVariableIsAlwaysModifiedBeforeReadInFuncCall) {
	// Set-up the module.
	//
	// int g;
	//
	// void foo(); /* always modifies g */
	//
	// void test() {
	//    g = 1;      <-- this can be removed
	//    f();
	// }
	//
	addFuncDecl("foo");
	ShPtr<Function> fooFunc(module->getFuncByName("foo"));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<CallExpr> fooCallExpr(CallExpr::create(fooFunc->getAsVar()));
	ShPtr<CallStmt> fooCallStmt(CallStmt::create(fooCallExpr));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), fooCallStmt));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();
	NiceMock<CallInfoMock> *ciMock = new NiceMock<CallInfoMock>(fooCallExpr);
	ON_CALL(*ciMock, isAlwaysModifiedBeforeRead(varG))
		.WillByDefault(Return(true));
	ON_CALL(*ciMock, isAlwaysModified(varG))
		.WillByDefault(Return(true));
	ShPtr<CallInfo> ci(ciMock);
	ON_CALL(*cioMock, getCallInfo(fooCallExpr, testFunc))
		.WillByDefault(Return(ci));

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(fooCallStmt, testFunc->getBody()) <<
		"expected `" << fooCallStmt <<
		"`, got `" << testFunc->getBody() << "`";

	// The following HACK is needed; otherwise, the test hangs (see
	// http://code.google.com/p/googlemock/issues/detail?id=114#makechanges).
	cio.reset();
}

TEST_F(DeadGlobalAssignOptimizerTests,
OptimizeAssignmentBeforeOtherAssignmentsInIfStatement) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;      <-- this can be removed
	//    if (1) {
	//        g = 2;
	//    } else {
	//        g = 3;
	//    }
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG3(AssignStmt::create(varG, ConstInt::create(3, 32)));
	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignG2));
	ifStmt->setElseClause(assignG3);
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), ifStmt));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(ifStmt, testFunc->getBody()) <<
		"expected `" << ifStmt <<
		"`, got `" << testFunc->getBody() << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
DoNotOptimizeIfGlobalVariableIsNotInternal) {
	// Set-up the module.
	//
	// int g; // external
	//
	// void test() {
	//    g = 1;      <-- this cannot be removed
	//    g = 2;      <-- this cannot be removed
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	varG->markAsExternal(); // external
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG2(AssignStmt::create(varG, ConstInt::create(2, 32)));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), assignG2));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG1, stmt1) <<
		"expected `" << assignG1 <<
		"`, got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << stmt1 << "` to have a successor";
	EXPECT_EQ(assignG2, stmt2) <<
		"expected `" << assignG2 <<
		"`, got `" << stmt2 << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
DoNotOptimizeAssignmentsToLocalVariables) {
	// Set-up the module.
	//
	// void test(int a) {
	//    a = 1;      <-- this cannot be removed
	//    a = 2;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addParam(varA);
	ShPtr<AssignStmt> assignA2(AssignStmt::create(varA, ConstInt::create(2, 32)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32), assignA2));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected a non-empty body";
	EXPECT_EQ(assignA1, stmt1) <<
		"expected `" << assignA1 <<
		"`, got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << stmt1 << "` to have a successor";
	EXPECT_EQ(assignA2, stmt2) <<
		"expected `" << assignA2 <<
		"`, got `" << stmt2 << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
DoNotOptimizeAssignmentIfThisIsTheOnlyModificationOfGlobalVar) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;      <-- this cannot be removed
	//    return;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), returnStmt));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ShPtr<Statement> stmt1(testFunc->getBody());
	ASSERT_TRUE(stmt1) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG1, stmt1) <<
		"expected `" << assignG1 <<
		"`, got `" << stmt1 << "`";
	ShPtr<Statement> stmt2(stmt1->getSuccessor());
	ASSERT_TRUE(stmt2) <<
		"expected `" << stmt1 << "` to have a successor";
	EXPECT_EQ(returnStmt, stmt2) <<
		"expected `" << returnStmt <<
		"`, got `" << stmt2 << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
DoNotOptimizeIfTheAssignIsTheLastStatement) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;      <-- this cannot be removed
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32)));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG1, testFunc->getBody()) <<
		"expected `" << assignG1 <<
		"`, got `" << testFunc->getBody() << "`";
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got `" <<
		testFunc->getBody()->getSuccessor() << "`";
}

TEST_F(DeadGlobalAssignOptimizerTests,
DoNotOptimizeAssignmentIfVariableIsNotAlwaysModifiedBeforeReadInFuncCall) {
	// Set-up the module.
	//
	// int g;
	//
	// void foo(); /* it may read g before modifying it */
	//
	// void test() {
	//    g = 1;      <-- this cannot be removed
	//    f();
	// }
	//
	addFuncDecl("foo");
	ShPtr<Function> fooFunc(module->getFuncByName("foo"));
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<CallExpr> fooCallExpr(CallExpr::create(fooFunc->getAsVar()));
	ShPtr<CallStmt> fooCallStmt(CallStmt::create(fooCallExpr));
	ShPtr<AssignStmt> assignG1(AssignStmt::create(varG, ConstInt::create(1, 32), fooCallStmt));
	testFunc->setBody(assignG1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	INSTANTIATE_CALL_INFO_OBTAINER_MOCK();
	NiceMock<CallInfoMock> *ciMock = new NiceMock<CallInfoMock>(fooCallExpr);
	ON_CALL(*ciMock, isAlwaysModifiedBeforeRead(varG))
		.WillByDefault(Return(false));
	ShPtr<CallInfo> ci(ciMock);
	ON_CALL(*cioMock, getCallInfo(fooCallExpr, testFunc))
		.WillByDefault(Return(ci));

	// Optimize the module.
	Optimizer::optimize<DeadGlobalAssignOptimizer>(module, va, cio);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	EXPECT_EQ(assignG1, testFunc->getBody()) <<
		"expected `" << assignG1 <<
		"`, got `" << testFunc->getBody() << "`";

	// The following HACK is needed; otherwise, the test hangs (see
	// http://code.google.com/p/googlemock/issues/detail?id=114#makechanges).
	cio.reset();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
