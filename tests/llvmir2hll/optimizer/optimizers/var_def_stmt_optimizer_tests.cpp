/**
* @file tests/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer_tests.cpp
* @brief Tests for the @c var_def_stmt_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/assertions.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/var_def_stmt_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c var_def_stmt_optimizer module.
*/
class VarDefStmtOptimizerTests: public TestsWithModule {};

TEST_F(VarDefStmtOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<VarDefStmtOptimizer> optimizer(new VarDefStmtOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(VarDefStmtOptimizerTests,
SimpleOptimizeToAssignStmtOptimize) {
	// void test() {
	//     int a;
	//     a = b + c;
	//     return a;
	// }
	// Can be optimized to.
	// void test() {
	//     int a = b + c;
	//     return a;
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(varB, varC));
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, addOpExpr, returnA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignA));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefStmt(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefStmt) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_TRUE(outVarDefStmt->hasInitializer()) <<
		"expected VarDefStmt with initializer";
	ASSERT_EQ(outVarDefStmt->getVar(), varA) <<
		"expected Variable A, got " << outVarDefStmt->getVar();
	ShPtr<AddOpExpr> outAddOpExpr(cast<AddOpExpr>(outVarDefStmt->getInitializer()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected AddOpExpr, got " << outVarDefStmt->getInitializer();
	ASSERT_EQ(addOpExpr, outAddOpExpr) <<
		"expected AddOpExpr, got" << outVarDefStmt->getInitializer();
}

TEST_F(VarDefStmtOptimizerTests,
SimpleOptimizeToAssignStmtNotOptimize) {
	// void test() {
	//     int a;
	//     a = a + c;
	//     return a;
	// }
	// Can't be optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varC);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(varA, varC));
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, addOpExpr, returnA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignA));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefStmt(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefStmt) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_FALSE(outVarDefStmt->hasInitializer()) <<
		"expected VarDefStmt without initializer";
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToCloserOptimize) {
	// void test() {
	//     int c;
	//     int a;
	//     int b;
	//     if (1) {
	//         a = c;
	//     }
	//     c = a;
	// }
	// Can be optimized to:
	// void test() {
	//     int b;
	//     int a;
	//     int c;
	//     if (1) {
	//         a = c;
	//     }
	//     c = a;
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<AssignStmt> assignCA(AssignStmt::create(varC, varA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAC, assignCA));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), ifStmt));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefB(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefB) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefB->getVar(), outVarDefB->getVar()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ASSERT_EQ(varDefB->getInitializer(), outVarDefB->getInitializer()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outVarDefB->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outVarDefB->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefA;
	ASSERT_EQ(varDefA->getInitializer(), outVarDefA->getInitializer()) <<
		"expected " << varDefA << ", got " << outVarDefA;
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outVarDefA->getSuccessor()));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outVarDefA->getSuccessor();
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ASSERT_EQ(varDefA->getInitializer(), outVarDefC->getInitializer()) <<
		"expected " << varDefC << ", got " << outVarDefC;
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToCloserWithAssignAfterWhileOptimize) {
	// void test() {
	//     int c;
	//     int a;
	//     int b;
	//     while (1) {
	//         a = c;
	//     }
	//     a = c;
	// }
	// Can be optimized to:
	// void test() {
	//     int b;
	//     int a;
	//     int c;
	//     while (1) {
	//         a = c;
	//     }
	//     a = c;
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<WhileLoopStmt> whileStmt(WhileLoopStmt::create(ConstInt::create(1, 32), assignAC, assignAC));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), whileStmt));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) << "expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefB(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefB) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefB->getVar(), outVarDefB->getVar()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ASSERT_EQ(varDefB->getInitializer(), outVarDefB->getInitializer()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outVarDefB->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outVarDefB->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefA;
	ASSERT_EQ(varDefA->getInitializer(), outVarDefA->getInitializer()) <<
		"expected " << varDefA << ", got " << outVarDefA;
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outVarDefA->getSuccessor()));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outVarDefA->getSuccessor();
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ASSERT_EQ(varDefC->getInitializer(), outVarDefC->getInitializer()) <<
		"expected " << varDefC << ", got " << outVarDefC;
}

TEST_F(VarDefStmtOptimizerTests,
GotoStmtOptimize) {
	// void test() {
	//     int a;
	//     if (1) {
	//         goto return a;
	//     }
	//     a = 1;
	//     return a;
	// }
	// Can be optimized to:
	// void test() {
	//     if (1) {
	//         goto return a;
	//     }
	//     int a = 1;
	//     return a;
	// }

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, ConstInt::create(1, 32), returnA));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(returnA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), gotoStmt, assignA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), ifStmt));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) << "expected IfStmt, got" << testFunc->getBody();
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(ifStmt->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << ifStmt->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefA;
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToCloserWhileOptimize) {
	// void test() {
	//     int c;
	//     int a;
	//     int b;
	//     while (1) {
	//         a = c;
	//     }
	// }
	// Can be optimized to:
	// void test() {
	//     int b;
	//     while (1) {
	//         int c;
	//         int a = c;
	//     }
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<WhileLoopStmt> whileStmt(WhileLoopStmt::create(ConstInt::create(1, 32), assignAC));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), whileStmt));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefB(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefB) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefB->getVar(), outVarDefB->getVar()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ASSERT_EQ(varDefB->getInitializer(), outVarDefB->getInitializer()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ShPtr<WhileLoopStmt> outWhileLoop(cast<WhileLoopStmt>(outVarDefB->getSuccessor()));
	ASSERT_TRUE(outWhileLoop) <<
		"expected while loop, got " << outVarDefB->getSuccessor();
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outWhileLoop->getBody()));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outWhileLoop->getBody();
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ASSERT_EQ(varDefC->getInitializer(), outVarDefC->getInitializer()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outVarDefC->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outVarDefA->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefC;
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToCloserForOptimize) {
	// void test() {
	//     int c;
	//     int a;
	//     int b;
	//     for (b = 1; 1; b++) {
	//         a = c;
	//     }
	// }
	// Can be optimized to:
	// void test() {
	//     int b;
	//     for (b = 1; 1; b++) {
	//         int c;
	//         int a = c;
	//     }
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<ForLoopStmt> forStmt(ForLoopStmt::create(varB, ConstInt::create(1, 32),
		ConstInt::create(1, 32),ConstInt::create(1, 32), assignAC));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), forStmt));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefB(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefB) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefB->getVar(), outVarDefB->getVar()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ASSERT_EQ(varDefB->getInitializer(), outVarDefB->getInitializer()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ShPtr<ForLoopStmt> outForLoop(cast<ForLoopStmt>(outVarDefB->getSuccessor()));
	ASSERT_TRUE(outForLoop) <<
		"expected for loop, got " << outVarDefB->getSuccessor();
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outForLoop->getBody()));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outForLoop->getBody();
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ASSERT_EQ(varDefC->getInitializer(), outVarDefC->getInitializer()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outVarDefC->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outVarDefA->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefC;
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToCloserSwitchStmtOptimize) {
	// void test() {
	//     int c;
	//     int a;
	//     int b;
	//     switch (b) {
	//         case 1:
	//            a = c;
	//     }
	// }
	// Can be optimized to:
	// void test() {
	//     int b;
	//     switch (b) {
	//         case 1:
	//            int c;
	//            int a = c;
	//     }
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(varB));
	switchStmt->addClause(ConstInt::create(1, 32), assignAC);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), switchStmt));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefB(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefB) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefB->getVar(), outVarDefB->getVar()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ASSERT_EQ(varDefB->getInitializer(), outVarDefB->getInitializer()) <<
		"expected " << varDefB << ", got " << outVarDefB;
	ShPtr<SwitchStmt> outSwitchLoop(cast<SwitchStmt>(outVarDefB->getSuccessor()));
	ASSERT_TRUE(outSwitchLoop) <<
		"expected switch, got " << outVarDefB->getSuccessor();
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outSwitchLoop->clause_begin()->second));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outSwitchLoop->clause_begin()->second;
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ASSERT_EQ(varDefC->getInitializer(), outVarDefC->getInitializer()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outVarDefC->getSuccessor()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outVarDefA->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefC;
}

TEST_F(VarDefStmtOptimizerTests,
MoveVarDefStmtToAssignInIfOptimize) {
	// void test() {
	//     int a;
	//     if (1) {
	//         a = c;
	//     }
	// }
	// Can be optimized to:
	// void test() {
	//     if (1) {
	//        int a = c;
	//     }
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<AssignStmt> assignAC(AssignStmt::create(varA, varC));
	ShPtr<IfStmt> ifStmt(IfStmt::create(ConstInt::create(1, 32), assignAC));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), ifStmt));
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << testFunc->getBody();
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outIfStmt->getFirstIfBody()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outIfStmt->getFirstIfBody();
	ASSERT_EQ(outVarDefA->getVar(), varA) <<
		"expected " << varA << ", got " << outVarDefA->getVar();
	ShPtr<Variable> outVarC(cast<Variable>(outVarDefA->getInitializer()));
	ASSERT_TRUE(outVarC) <<
		"expected "<< varC << ", got " << outVarDefA->getInitializer();
	ASSERT_EQ(outVarC, varC) <<
		"expected " << varC << ", got " << outVarC;
}

TEST_F(VarDefStmtOptimizerTests,
NotEasyIfOptimize) {
	// void test() {
	//     int a;
	//     int c;
	//     int l;
	//     l = 1;
	//     if (1) {
	//         if (1) {
	//            a = 5;
	//            c = 4;
	//         }
	//         a = 2;
	//     } else if (3) {
	//         c = 4;
	//     }
	// }
	// Can be optimized to:
	// void test() {
	//     int l = 1;
	//     int c;
	//     if (1) {
	//         int a;
	//         if (1) {
	//            a = 5;
	//            c = 4;
	//         }
	//         a = 2;
	//     } else if (3) {
	//         c = 4;
	//     }
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varL(Variable::create("l", IntType::create(32)));
	testFunc->addLocalVar(varL);
	ShPtr<AssignStmt> assignA5(AssignStmt::create(varA, ConstInt::create(5, 32)));
	ShPtr<AssignStmt> assignC4(AssignStmt::create(varC, ConstInt::create(4, 32)));
	ShPtr<AssignStmt> assignA2(AssignStmt::create(varA, ConstInt::create(2, 32)));
	assignA5->setSuccessor(assignC4);
	ShPtr<IfStmt> ifStmtBot(IfStmt::create(ConstInt::create(3, 32), assignA5));
	ifStmtBot->setSuccessor(assignA2);
	ShPtr<IfStmt> ifStmtTop(IfStmt::create(ConstInt::create(1, 32), ifStmtBot));
	ifStmtTop->addClause(ConstInt::create(3, 32), assignC4);
	ShPtr<AssignStmt> assignL1(AssignStmt::create(varL, ConstInt::create(1, 32), ifStmtTop));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), assignL1));
	ShPtr<VarDefStmt> varDefC(VarDefStmt::create(varC, ShPtr<Expression>(), varDefA));
	ShPtr<VarDefStmt> varDefL(VarDefStmt::create(varL, ShPtr<Expression>(), varDefC));
	testFunc->setBody(varDefL);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<VarDefStmt> outVarDefL(cast<VarDefStmt>(testFunc->getBody()));
	ASSERT_TRUE(outVarDefL) <<
		"expected VarDefStmt, got " << testFunc->getBody();
	ASSERT_EQ(varDefL->getVar(), outVarDefL->getVar()) <<
		"expected " << varDefL << ", got " << outVarDefL;
	ShPtr<VarDefStmt> outVarDefC(cast<VarDefStmt>(outVarDefL->getSuccessor()));
	ASSERT_TRUE(outVarDefC) <<
		"expected VarDefStmt, got " << outVarDefL->getSuccessor();
	ASSERT_EQ(varDefC->getVar(), outVarDefC->getVar()) <<
		"expected " << varDefC << ", got " << outVarDefC;
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(outVarDefC->getSuccessor()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << outVarDefC->getSuccessor();
	ShPtr<VarDefStmt> outVarDefA(cast<VarDefStmt>(outIfStmt->getFirstIfBody()));
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << outIfStmt->getFirstIfBody();
	ASSERT_EQ(outVarDefA->getVar(), varA) <<
		"expected " << varA << ", got " << outVarDefA->getVar();
}

TEST_F(VarDefStmtOptimizerTests,
PreservesGotoTargetsAndLabelsWhenPrepending) {
	//
	// void test() {
	//     int a;
	//     g = 1;
	//   my_label:
	//     g = a;
	//     goto lab;
	// }
	//
	// can be optimized to
	//
	// void test() {
	//     g = 1;
	//   my_label:
	//     int a;
	//     g = a;
	//     goto lab;
	// }
	//
	auto varG = Variable::create("g", IntType::create(32));
	module->addGlobalVar(varG);
	auto varA = Variable::create("a", IntType::create(32));
	testFunc->addLocalVar(varA);
	auto varDefA = VarDefStmt::create(varA);
	auto assignG1 = AssignStmt::create(varG, ConstInt::create(1, 32));
	varDefA->setSuccessor(assignG1);
	auto assignGA = AssignStmt::create(varG, varA);
	assignGA->setLabel("my_label");
	assignG1->setSuccessor(assignGA);
	auto gotoStmt = GotoStmt::create(assignGA);
	assignGA->setSuccessor(gotoStmt);
	testFunc->setBody(varDefA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	auto outVarDefA = cast<VarDefStmt>(assignG1->getSuccessor());
	ASSERT_TRUE(outVarDefA) <<
		"expected VarDefStmt, got " << assignG1->getSuccessor();
	ASSERT_EQ(varDefA->getVar(), outVarDefA->getVar()) <<
		"expected " << varDefA << ", got " << outVarDefA;
	ASSERT_TRUE(outVarDefA->isGotoTarget());
	ASSERT_EQ("my_label", outVarDefA->getLabel());
	ASSERT_FALSE(assignGA->isGotoTarget());
	ASSERT_FALSE(assignGA->hasLabel());
}

TEST_F(VarDefStmtOptimizerTests,
MarksUForLoopInitAsDefinitionWhenVarIsDefinedInInitPart) {
	//
	// void test() {
	//     int i;
	//     for (i = 1; ;) {
	//     }
	// }
	//
	// can be optimized to:
	//
	// void test() {
	//     for (int i = 1; ;) {
	//     }
	// }
	//
	auto varI = Variable::create("i", IntType::create(32));
	testFunc->addLocalVar(varI);
	auto varDefI = VarDefStmt::create(varI);
	auto loop = UForLoopStmt::create(
		AssignOpExpr::create(varI, ConstInt::create(1, 32)),
		ShPtr<Expression>(),
		ShPtr<Expression>(),
		EmptyStmt::create()
	);
	varDefI->setSuccessor(loop);
	testFunc->setBody(varDefI);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<VarDefStmtOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_BIR_EQ(loop, testFunc->getBody());
	ASSERT_TRUE(loop->isInitDefinition());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
