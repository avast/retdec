/**
* @file tests/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer_tests.cpp
* @brief Tests for the @c pre_while_true_loop_conv_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/pre_while_true_loop_conv_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c pre_while_true_loop_conv_optimizer module.
*/
class PreWhileTrueLoopConvOptimizerTests: public TestsWithModule {};

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	PreWhileTrueLoopConvOptimizer* optimizer(new PreWhileTrueLoopConvOptimizer(
		module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizeCase1Simplest) {
	// Set-up the module.
	//
	// void test() {
	//     int tmp;
	//     int i;
	//     i = 1;
	//     while (true) {
	//         tmp = i + 1;
	//         if (tmp >= 1) {
	//             break;
	//         }
	//         i = tmp;
	//     }
	// }
	//
	// is optimized to
	//
	// void test() {
	//     int i;
	//     i = 1;
	//     while (true) {
	//         if (i + 1 >= 1) {
	//             break;
	//         }
	//         i = i + 1;
	//     }
	// }
	//
	Variable* varTmp(Variable::create("tmp", IntType::create(32)));
	testFunc->addLocalVar(varTmp);
	Variable* varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	AssignStmt* assignITmp(AssignStmt::create(varI, varTmp));
	BreakStmt* breakIf(BreakStmt::create());
	Expression* ifCond(GtEqOpExpr::create(varTmp, ConstInt::create(1, 32)));
	IfStmt* ifStmt(IfStmt::create(ifCond, breakIf, assignITmp));
	AssignStmt* assignTmpI1(AssignStmt::create(varTmp,
		AddOpExpr::create(varI, ConstInt::create(1, 32)), ifStmt));
	WhileLoopStmt* whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), assignTmpI1));
	AssignStmt* assignI1(AssignStmt::create(varI, ConstInt::create(1, 32), whileLoop));
	VarDefStmt* varDefI(VarDefStmt::create(varI, Expression*(), assignI1));
	VarDefStmt* varDefTmp(VarDefStmt::create(varTmp, Expression*(), varDefI));
	testFunc->setBody(varDefTmp);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	EXPECT_EQ(varDefI, testFunc->getBody()) <<
		"expected `" << varDefI << "`, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(ifStmt, whileLoop->getBody()) <<
		"expected `" << ifStmt << "`, got `" << whileLoop->getBody() << "`";
	AssignStmt* afterIfStmt(cast<AssignStmt>(ifStmt->getSuccessor()));
	EXPECT_EQ(varI, afterIfStmt->getLhs()) <<
		"expected `" << varI << "`, got `" << afterIfStmt->getLhs() << "`";
	AddOpExpr* afterIfStmtRhs(cast<AddOpExpr>(afterIfStmt->getRhs()));
	ASSERT_TRUE(afterIfStmtRhs) <<
		"expected `" << afterIfStmtRhs << "`, got `" << afterIfStmt->getRhs() << "`";
	EXPECT_EQ(varI, afterIfStmtRhs->getFirstOperand()) <<
		"expected `" << varI << "`, got `" << afterIfStmtRhs->getFirstOperand() << "`";
	GtEqOpExpr* newIfCond(cast<GtEqOpExpr>(ifStmt->getFirstIfCond()));
	ASSERT_TRUE(newIfCond) <<
		"expected `" << newIfCond << "`, got `" << ifStmt->getFirstIfCond() << "`";
	EXPECT_TRUE(isa<AddOpExpr>(newIfCond->getFirstOperand())) <<
		"expected AddOpExpr, got `" << newIfCond->getFirstOperand() << "`";
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizeCase2Simplest) {
	// Set-up the module.
	//
	// void test() {
	//     int tmp;
	//     int i;
	//     i = 1;
	//     while (true) {
	//         tmp = i;
	//         i = tmp + 1;
	//         if (tmp == 100) {
	//             break;
	//         }
	//     }
	// }
	//
	// is optimized to
	//
	// void test() {
	//     int i;
	//     i = 1;
	//     while (true) {
	//         if (i == 100) {
	//             break;
	//         }
	//         i = i + 1
	//     }
	// }
	//
	Variable* varTmp(Variable::create("tmp", IntType::create(32)));
	testFunc->addLocalVar(varTmp);
	Variable* varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	BreakStmt* breakIf(BreakStmt::create());
	Expression* ifCond(EqOpExpr::create(varTmp, ConstInt::create(100, 32)));
	IfStmt* ifStmt(IfStmt::create(ifCond, breakIf));
	AssignStmt* assignITmp1(AssignStmt::create(varI,
		AddOpExpr::create(varTmp, ConstInt::create(1, 32)), ifStmt));
	AssignStmt* assignTmpI(AssignStmt::create(varTmp, varI, assignITmp1));
	WhileLoopStmt* whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), assignTmpI));
	AssignStmt* assignI1(AssignStmt::create(varI, ConstInt::create(1, 32), whileLoop));
	VarDefStmt* varDefI(VarDefStmt::create(varI, Expression*(), assignI1));
	VarDefStmt* varDefTmp(VarDefStmt::create(varTmp, Expression*(), varDefI));
	testFunc->setBody(varDefTmp);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	EXPECT_EQ(varDefI, testFunc->getBody()) <<
		"expected `" << varDefI << "`, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(ifStmt, whileLoop->getBody()) <<
		"expected `" << ifStmt << "`, got `" << whileLoop->getBody() << "`";
	AssignStmt* afterIfStmt(cast<AssignStmt>(ifStmt->getSuccessor()));
	ASSERT_TRUE(afterIfStmt) <<
		"expected a successor of `" << ifStmt << "`";
	EXPECT_EQ(varI, afterIfStmt->getLhs()) <<
		"expected `" << varI << "`, got `" << afterIfStmt->getLhs() << "`";
	AddOpExpr* afterIfStmtRhs(cast<AddOpExpr>(afterIfStmt->getRhs()));
	ASSERT_TRUE(afterIfStmtRhs) <<
		"expected `" << afterIfStmtRhs << "`, got `" << afterIfStmt->getRhs() << "`";
	EXPECT_EQ(varI, afterIfStmtRhs->getFirstOperand()) <<
		"expected `" << varI << "`, got `" << afterIfStmtRhs->getFirstOperand() << "`";
	EqOpExpr* newIfCond(cast<EqOpExpr>(ifStmt->getFirstIfCond()));
	ASSERT_TRUE(newIfCond) <<
		"expected `" << newIfCond << "`, got `" << ifStmt->getFirstIfCond() << "`";
	EXPECT_EQ(varI, newIfCond->getFirstOperand()) <<
		"expected `" << varI << "`, got `" << newIfCond->getFirstOperand() << "`";
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizeCase3Simplest) {
	// Set-up the module.
	//
	// void test() {
	//     int x;
	//     int i;
	//     i = 0;
	//     if (i >= x) {
	//         return;
	//     }
	//     while (true) { }
	// }
	//
	// is optimized to
	//
	// void test() {
	//     int x;
	//     int i;
	//     if (0 >= x) {
	//         return;
	//     }
	//     i = 0;
	//     while (true) { }
	// }
	//
	Variable* varX(Variable::create("x", IntType::create(32)));
	testFunc->addLocalVar(varX);
	Variable* varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	WhileLoopStmt* whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), EmptyStmt::create()));
	BinaryOpExpr* ifCond(GtEqOpExpr::create(varI, varX));
	ReturnStmt* returnStmt(ReturnStmt::create());
	IfStmt* ifStmt(IfStmt::create(ifCond, returnStmt, whileLoop));
	AssignStmt* assignI0(AssignStmt::create(varI, ConstInt::create(0, 32), ifStmt));
	VarDefStmt* varDefI(VarDefStmt::create(varI, Expression*(), assignI0));
	VarDefStmt* varDefX(VarDefStmt::create(varX, Expression*(), varDefI));
	testFunc->setBody(varDefX);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	EXPECT_EQ(assignI0, ifStmt->getSuccessor()) <<
		"expected `" << assignI0 << "`, got `" << ifStmt->getSuccessor() << "`";
	EXPECT_EQ(varDefI, ifStmt->getUniquePredecessor()) <<
		"expected `" << varDefI << "`, got `" << ifStmt->getUniquePredecessor() << "`";
	ASSERT_TRUE(isa<ConstInt>(ifCond->getFirstOperand())) <<
		"expected `ConstInt`, got `" << ifCond->getFirstOperand() << "`";
	EXPECT_TRUE(cast<ConstInt>(ifCond->getFirstOperand())->isZero()) <<
		"expected `0`, got `" << ifCond->getFirstOperand() << "`";
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizeCase4Simplest) {
	// Set-up the module.
	//
	// void test() {
	//     int tmp;
	//     int i;
	//     i = 1;
	//     while (true) {
	//         tmp = test();
	//         if (i >= tmp) {
	//             break;
	//         }
	//         i = i + 1;
	//     }
	// }
	//
	// is optimized to
	//
	// void test() {
	//     int i;
	//     i = 1;
	//     while (true) {
	//         if (i >= test()) {
	//             break;
	//         }
	//         i = i + 1;
	//     }
	// }
	//
	Variable* varTmp(Variable::create("tmp", IntType::create(32)));
	testFunc->addLocalVar(varTmp);
	Variable* varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	AssignStmt* assignII1(AssignStmt::create(varI,
		AddOpExpr::create(varI, ConstInt::create(1, 32))));
	BreakStmt* breakIf(BreakStmt::create());
	GtEqOpExpr* ifCond(GtEqOpExpr::create(varI, varTmp));
	IfStmt* ifStmt(IfStmt::create(ifCond, breakIf, assignII1));
	CallExpr* callExpr(CallExpr::create(testFunc->getAsVar()));
	AssignStmt* assignTmpTest(AssignStmt::create(varTmp, callExpr, ifStmt));
	WhileLoopStmt* whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), assignTmpTest));
	AssignStmt* assignI1(AssignStmt::create(varI, ConstInt::create(1, 32), whileLoop));
	VarDefStmt* varDefI(VarDefStmt::create(varI, Expression*(), whileLoop));
	VarDefStmt* varDefTmp(VarDefStmt::create(varTmp, Expression*(), varDefI));
	testFunc->setBody(varDefTmp);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	EXPECT_EQ(varDefI, testFunc->getBody()) <<
		"expected `" << varDefI << "`, got `" << testFunc->getBody() << "`";
	EXPECT_EQ(ifStmt, whileLoop->getBody()) <<
		"expected `" << ifStmt << "`, got `" << whileLoop->getBody() << "`";
	EXPECT_EQ(callExpr, ifCond->getSecondOperand()) <<
		"expected `" << callExpr << "`, got `" << ifCond->getSecondOperand() << "`";
}

TEST_F(PreWhileTrueLoopConvOptimizerTests,
OptimizeCase5Simplest) {
	// Set-up the module.
	//
	// void test() {
	//     int i;
	//     i = 1;
	//     while (true) {
	//         i = i + 1;
	//         if (i == 100) {
	//             break;
	//         }
	//     }
	// }
	//
	// is optimized to
	//
	// void test() {
	//     int i;
	//     i = 1;
	//     while (true) {
	//         if (i + 1 == 100) {
	//             break;
	//         }
	//         i = i + 1
	//     }
	// }
	//
	Variable* varI(Variable::create("i", IntType::create(32)));
	testFunc->addLocalVar(varI);
	BreakStmt* breakIf(BreakStmt::create());
	BinaryOpExpr* ifCond(EqOpExpr::create(varI, ConstInt::create(100, 32)));
	IfStmt* ifStmt(IfStmt::create(ifCond, breakIf));
	AssignStmt* assignII1(AssignStmt::create(varI,
		AddOpExpr::create(varI, ConstInt::create(1, 32)), ifStmt));
	WhileLoopStmt* whileLoop(WhileLoopStmt::create(
		ConstBool::create(true), assignII1));
	AssignStmt* assignI1(AssignStmt::create(varI, ConstInt::create(1, 32), whileLoop));
	VarDefStmt* varDefI(VarDefStmt::create(varI, Expression*(), assignI1));
	testFunc->setBody(varDefI);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<PreWhileTrueLoopConvOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(ifStmt->getSuccessor()) <<
		"expected the if statement to have a successor";
	EXPECT_TRUE(isa<AddOpExpr>(ifCond->getFirstOperand())) <<
		"expected the left-hand side of the if condition to be an addition, " <<
		"got `" << ifStmt->getSuccessor() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
