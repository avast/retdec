/**
* @file tests/llvmir2hll/analysis/goto_target_analysis_tests.cpp
* @brief Tests for the @c goto_target_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/goto_target_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c goto_target_analysis module.
*/
class GotoTargetAnalysisTests: public TestsWithModule {};

TEST_F(GotoTargetAnalysisTests,
EmptyFunctionDoesNotHaveAnyGotoTargets) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	// Check the result of hasGotoTargets().
	EXPECT_FALSE(GotoTargetAnalysis::hasGotoTargets(
		testFunc->getBody()));

	// Check the result of getGotoTargets().
	StmtSet gotoTargets(GotoTargetAnalysis::getGotoTargets(
		testFunc->getBody()));
	EXPECT_TRUE(gotoTargets.empty());
}

TEST_F(GotoTargetAnalysisTests,
SingleGotoTargetAsTheFirstStatementInFunction) {
	// Set-up the module.
	//
	// void test() {
	//   lab:
	//     int a;
	//     goto lab;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(varDefA));
	varDefA->setSuccessor(gotoStmt);
	testFunc->setBody(varDefA);

	// Check the result of hasGotoTargets().
	EXPECT_TRUE(GotoTargetAnalysis::hasGotoTargets(
		testFunc->getBody()));

	// Check the result of getGotoTargets().
	StmtSet gotoTargets(GotoTargetAnalysis::getGotoTargets(
		testFunc->getBody()));
	StmtSet refGotoTargets;
	refGotoTargets.insert(varDefA);
	ASSERT_EQ(refGotoTargets, gotoTargets);
}

TEST_F(GotoTargetAnalysisTests,
MoreStatementsBeforeAndAfterGotoTarget) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	//     a = 1;
	//   lab:
	//     int b;
	//     b = 1;
	//     goto lab;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA, ConstInt::create(1, 32)));
	ShPtr<AssignStmt> assignB1(AssignStmt::create(varB, ConstInt::create(1, 32)));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(varDefB));
	assignB1->setSuccessor(gotoStmt);
	varDefB->setSuccessor(assignB1);
	assignA1->setSuccessor(varDefB);
	varDefA->setSuccessor(assignA1);
	testFunc->setBody(varDefA);

	// Check the result of hasGotoTargets().
	EXPECT_TRUE(GotoTargetAnalysis::hasGotoTargets(
		testFunc->getBody()));

	// Check the result of getGotoTargets().
	StmtSet gotoTargets(GotoTargetAnalysis::getGotoTargets(
		testFunc->getBody()));
	StmtSet refGotoTargets;
	refGotoTargets.insert(varDefB);
	ASSERT_EQ(refGotoTargets, gotoTargets);
}

TEST_F(GotoTargetAnalysisTests,
TwoGotoTargetsAndIfStmt) {
	// Set-up the module.
	//
	// void test() {
	//   lab:
	//     if (1) {
	//         int a;
	//         goto lab;
	//     } else {
	//       lab2:
	//         int b;
	//         goto lab2;
	//     }
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), varDefA));
	ShPtr<GotoStmt> gotoIfStmt(GotoStmt::create(ifStmt));
	varDefA->setSuccessor(gotoIfStmt);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<GotoStmt> gotoVarDefB(GotoStmt::create(varDefB));
	varDefB->setSuccessor(gotoVarDefB);
	ifStmt->setElseClause(varDefB);
	testFunc->setBody(ifStmt);

	// Check the result of hasGotoTargets().
	EXPECT_TRUE(GotoTargetAnalysis::hasGotoTargets(
		testFunc->getBody()));

	// Check the result of getGotoTargets().
	StmtSet gotoTargets(GotoTargetAnalysis::getGotoTargets(
		testFunc->getBody()));
	StmtSet refGotoTargets;
	refGotoTargets.insert(ifStmt);
	refGotoTargets.insert(varDefB);
	ASSERT_EQ(refGotoTargets, gotoTargets);
}

TEST_F(GotoTargetAnalysisTests,
GotoLabelAfterIfStmt) {
	// Set-up the module.
	//
	// void test() {
	//   int a;
	//   int b;
	//   if (1) {
	//       b = a + 1;
	//   }
	//   label: a = a + 1;
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(varA, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, addOpExpr));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignStmtB));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, addOpExpr));
	ShPtr<GotoStmt> gotoAssign(GotoStmt::create(assignStmtA));
	varDefA->setSuccessor(varDefB);
	varDefB->setSuccessor(ifStmt);
	ifStmt->setSuccessor(assignStmtA);

	testFunc->setBody(varDefA);

	// Check the result of hasGotoTargets().
	EXPECT_TRUE(GotoTargetAnalysis::hasGotoTargets(ifStmt));

	// Check the result of getGotoTargets().
	StmtSet gotoTargets(GotoTargetAnalysis::getGotoTargets(
		testFunc->getBody()));
	StmtSet refGotoTargets;
	refGotoTargets.insert(assignStmtA);
	ASSERT_EQ(refGotoTargets, gotoTargets);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
