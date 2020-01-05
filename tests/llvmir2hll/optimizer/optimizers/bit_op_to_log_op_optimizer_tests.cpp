/**
* @file tests/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer_tests.cpp
* @brief Tests for the @c bit_and_op_expr module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c bit_and_op_expr module.
*/
class BitOpToLogOpOptimizerTests: public TestsWithModule {};

TEST_F(BitOpToLogOpOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	BitOpToLogOpOptimizer* optimizer(new BitOpToLogOpOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(BitOpToLogOpOptimizerTests,
CondWithDivideZeroBitOrNotOptimize) {
	// void test() {
	//     c = b / c;
	//     a = b | c;
	//     while((b | (c / 0)) && (b | c)) {
	//         b = b | c;
	//	   }
	//     b = b / c;
	//     return a;
	// }
	// Expected output:
	// void test() {
	//     c = b / c;
	//     a = b | c;
	//     while((b | (c / 0)) and (b or c)) {
	//         b = b | c;
	//	   }
	//     b = b / c;
	//     return a;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ReturnStmt* returnA(ReturnStmt::create(varA));
	DivOpExpr* divBC(DivOpExpr::create(varB, varC));
	AssignStmt* assignB(AssignStmt::create(varB, divBC, returnA));
	DivOpExpr* divOpCZero(DivOpExpr::create(varC, ConstInt::create(0, 64,
		false)));
	BitOrOpExpr* bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	AndOpExpr* andOpExpr(AndOpExpr::create(bitOrOpBDiv, bitOrOpBC1));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC2));
	WhileLoopStmt* whileLoopStmt(WhileLoopStmt::create(andOpExpr,
		assignBBitOr, assignB));
	AssignStmt* assignA(AssignStmt::create(varA, bitOrOpBC2, whileLoopStmt));
	AssignStmt* assignC(AssignStmt::create(varC, divBC, assignA));
	testFunc->setBody(assignC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	AssignStmt* outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtC) <<
		"expected AssignStmt, got " << testFunc->getBody();
	AssignStmt* outAssignStmtA(cast<AssignStmt>(outAssignStmtC->getSuccessor()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << outAssignStmtC->getSuccessor();
	BitOrOpExpr* outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	WhileLoopStmt* outWhileStmt(cast<WhileLoopStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outWhileStmt) <<
		"expected WhileStmt, got " << outAssignStmtA->getSuccessor();
	AndOpExpr* outAndOpExpr(cast<AndOpExpr>(outWhileStmt->getCondition()));
	ASSERT_TRUE(outAndOpExpr) <<
		"expected AndOpExpr, got " << outWhileStmt->getCondition();
	OrOpExpr* outOrOpExpr(cast<OrOpExpr>(outAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outAndOpExpr->getSecondOperand();
	BitOrOpExpr* outBitOrOpDiv(cast<BitOrOpExpr>(outAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outBitOrOpDiv) <<
		"expected BitOrOpExpr, got " << outAndOpExpr->getFirstOperand();
	AssignStmt* outAssignStmtB(cast<AssignStmt>(outWhileStmt->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << outWhileStmt->getBody();
	BitOrOpExpr* outBitOrBody(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrBody) <<
		"expected AssignStmt, got " << outAssignStmtB->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
ElseIfClausesOrNotOptimize) {
	// void test() {
	//     a = b | c;
	//     if (b | c) {
	//         b = b | c;
	//     } else if ((b | (c / 0)) {
	//         b = b | c;
	//     } else if (b) {
	//         b = b | c;
	//     }
	//     return a;
	// }
	// Expected output:
	// void test() {
	//     a = b | c;
	//     if (b or c) {
	//         b = b | c;
	//     } else if ((b | (c / 0)) {
	//         b = b | c;
	//     } else if (b) {
	//         b = b | c;
	//     }
	//     return a;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	DivOpExpr* divOpCZero(DivOpExpr::create(varC, ConstInt::create(0, 64,
		false)));
	BitOrOpExpr* bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC3(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC3));
	ReturnStmt* returnA(ReturnStmt::create(varA));
	IfStmt* ifStmt(IfStmt::create(bitOrOpBC2, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBDiv, assignBBitOr);
	ifStmt->addClause(varB, assignBBitOr);
	AssignStmt* assignA(AssignStmt::create(varA, bitOrOpBC1, ifStmt));
	testFunc->setBody(assignA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	IfStmt* outIfStmt(cast<IfStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << outAssignStmtA->getSuccessor();
	OrOpExpr* outOrOpExpr(cast<OrOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	BitOrOpExpr* outBitOrOpExpr(cast<BitOrOpExpr>(elseif->first));
	ASSERT_TRUE(outBitOrOpExpr) <<
		"expected BitOrOpExpr, got " << (elseif->first);
	AssignStmt* outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	BitOrOpExpr* outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	AssignStmt* outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	BitOrOpExpr* outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
	ASSERT_TRUE(outBitOrOpBC2) <<
		"expected BitOrOpExpr, got " << outAssignStmtB1->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
ElseIfClausesAndArrayCallNotOptimize) {
	// void test() {
	//     if (b & (c + call(b + 2))) {
	//         b = b | c;
	//     } else if ((b & (c + a[5])) {
	//         b = b | c;
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     if (b & (c + call(b + 2))) {
	//         b = b | c;
	//     } else if ((b & (c + a[5])) {
	//         b = b | c;
	//     }
	//     return b;
	// }
	ArrayIndexOpExpr* arrayA(ArrayIndexOpExpr::create(Variable::create("a",
		IntType::create(32)), ConstInt::create(6, 64, false)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ExprVector args;
	AddOpExpr* addOpExpr(AddOpExpr::create(varB, ConstInt::create(2,64)));
	args.push_back(addOpExpr);
	CallExpr* callExpr(CallExpr::create(varB, args));
	AddOpExpr* addOpExprCCall(AddOpExpr::create(varC, callExpr));
	AddOpExpr* addOpExprBArray(AddOpExpr::create(varC, arrayA));
	BitAndOpExpr* bitAndOpBAddOp(BitAndOpExpr::create(varB, addOpExprCCall));
	BitAndOpExpr* bitAndOpBArray(BitAndOpExpr::create(varB, addOpExprBArray));
	BitOrOpExpr* bitOrOpBC(BitOrOpExpr::create(varB, varC));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	IfStmt* ifStmt(IfStmt::create(bitAndOpBAddOp, assignBBitOr, returnA));
	ifStmt->addClause(bitAndOpBArray, assignBBitOr);
	testFunc->setBody(ifStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	IfStmt* outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << testFunc->getBody();
	BitAndOpExpr* outBitAndOp1(cast<BitAndOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outBitAndOp1) <<
		"expected BitAndOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	BitAndOpExpr* outBitAndOp2(cast<BitAndOpExpr>(elseif->first));
	ASSERT_TRUE(outBitAndOp2) <<
		"expected BitAndOpExpr, got " << (elseif->first);
	AssignStmt* outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	BitOrOpExpr* outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	AssignStmt* outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	BitOrOpExpr* outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
	ASSERT_TRUE(outBitOrOpBC2) <<
		"expected BitOrOpExpr, got " << outAssignStmtB1->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitAndBitOrCallNotOptimize) {
	// void test() {
	//     switch (a | (b & (c | (d & (b + call(a)))))) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (b & (c | (d & (b + call(a)))))) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	Variable* varD(Variable::create("d", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	testFunc->addLocalVar(varD);
	ExprVector args;
	args.push_back(varA);
	CallExpr* callExpr(CallExpr::create(varB, args));
	AddOpExpr* addOpExprBCall(AddOpExpr::create(varB, callExpr));
	BitAndOpExpr* bitAndOpDBCall(BitAndOpExpr::create(varD, addOpExprBCall));
	BitOrOpExpr* bitOrOpCDBCall(BitOrOpExpr::create(varC, bitAndOpDBCall));
	BitAndOpExpr* bitAndOpBCDBCall(BitAndOpExpr::create(varB, bitOrOpCDBCall));
	BitOrOpExpr* bitOrOpABCDBCall(BitOrOpExpr::create(varA, bitAndOpBCDBCall));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpABCDBCall, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
	BitAndOpExpr* outBitAndOpB(cast<BitAndOpExpr>(outBitOrOpA->getSecondOperand()));
	ASSERT_TRUE(outBitAndOpB) <<
		"expected BitAndOpExpr, got " << outBitOrOpA->getSecondOperand();
	BitOrOpExpr* outBitOrOpC(cast<BitOrOpExpr>(outBitAndOpB->getSecondOperand()));
	ASSERT_TRUE(outBitOrOpC) <<
		"expected BitOrOpExpr, got " << outBitAndOpB->getSecondOperand();
	BitAndOpExpr* outBitAndOpD(cast<BitAndOpExpr>(outBitOrOpC->getSecondOperand()));
	ASSERT_TRUE(outBitAndOpD) <<
		"expected BitAndOpExpr, got " << outBitOrOpC->getSecondOperand();
}

TEST_F(BitOpToLogOpOptimizerTests,
CondWithDivideBitOrOptimize) {
	// void test() {
	//     c = b / c;
	//     a = b | c;
	//     while((b | (c / 1)) and (b | c)) {
	//         b = b | c;
	//	   }
	//     b = b / c;
	//     return a;
	// }
	// Expected output:
	// void test() {
	//     c = b / c;
	//     a = b | c;
	//     while((b or (c / 1)) and (b or c)) {
	//         b = b | c;
	//	   }
	//     b = b / c;
	//     return a;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ReturnStmt* returnA(ReturnStmt::create(varA));
	DivOpExpr* divBC(DivOpExpr::create(varB, varC));
	AssignStmt* assignB(AssignStmt::create(varB, divBC, returnA));
	DivOpExpr* divOpCZero(DivOpExpr::create(varC, ConstInt::create(1, 64,
		false)));
	BitOrOpExpr* bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	AndOpExpr* andOpExpr(AndOpExpr::create(bitOrOpBDiv, bitOrOpBC1));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC2));
	WhileLoopStmt* whileLoopStmt(WhileLoopStmt::create(andOpExpr,
		assignBBitOr, assignB));
	AssignStmt* assignA(AssignStmt::create(varA, bitOrOpBC2, whileLoopStmt));
	AssignStmt* assignC(AssignStmt::create(varC, divBC, assignA));
	testFunc->setBody(assignC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	AssignStmt* outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtC) <<
		"expected AssignStmt, got " << testFunc->getBody();
	AssignStmt* outAssignStmtA(cast<AssignStmt>(outAssignStmtC->getSuccessor()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << outAssignStmtC->getSuccessor();
	BitOrOpExpr* outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	WhileLoopStmt* outWhileStmt(cast<WhileLoopStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outWhileStmt) <<
		"expected WhileStmt, got " << outAssignStmtA->getSuccessor();
	AndOpExpr* outAndOpExpr(cast<AndOpExpr>(outWhileStmt->getCondition()));
	ASSERT_TRUE(outAndOpExpr) <<
		"expected AndOpExpr, got " << outWhileStmt->getCondition();
	OrOpExpr* outOrOpExpr(cast<OrOpExpr>(outAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outAndOpExpr->getSecondOperand();
	OrOpExpr* outOrOpDiv(cast<OrOpExpr>(outAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOrOpDiv) <<
		"expected OrOpExpr, got " << outAndOpExpr->getFirstOperand();
	AssignStmt* outAssignStmtB(cast<AssignStmt>(outWhileStmt->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << outWhileStmt->getBody();
	BitOrOpExpr* outBitOrBody(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrBody) <<
		"expected AssignStmt, got " << outAssignStmtB->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
ElseIfClausesOrOptimize) {
	// void test() {
	//     a = b | c;
	//     if (b | c) {
	//         b = b | c;
	//     } else if ((b | (c / 5)) {
	//         b = b | c;
	//     } else if (b) {
	//         b = b | c;
	//     }
	//     return a;
	// }
	// Expected output:
	// void test() {
	//     a = b | c;
	//     if (b or c) {
	//         b = b | c;
	//     } else if ((b or (c / 5)) {
	//         b = b | c;
	//     } else if (b) {
	//         b = b | c;
	//     }
	//     return a;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	DivOpExpr* divOpCZero(DivOpExpr::create(varC, ConstInt::create(5, 64, false)));
	BitOrOpExpr* bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBC3(BitOrOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC3));
	ReturnStmt* returnA(ReturnStmt::create(varA));
	IfStmt* ifStmt(IfStmt::create(bitOrOpBC2, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBDiv, assignBBitOr);
	ifStmt->addClause(varB, assignBBitOr);
	AssignStmt* assignA(AssignStmt::create(varA, bitOrOpBC1, ifStmt));
	testFunc->setBody(assignA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	AssignStmt* outAssignStmtA(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	IfStmt* outIfStmt(cast<IfStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << outAssignStmtA->getSuccessor();
	OrOpExpr* outOrOp1(cast<OrOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outOrOp1) <<
		"expected OrOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	OrOpExpr* outOrOp2(cast<OrOpExpr>(elseif->first));
	ASSERT_TRUE(outOrOp2) <<
		"expected OrOpExpr, got " << (elseif->first);
	AssignStmt* outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	BitOrOpExpr* outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	AssignStmt* outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	BitOrOpExpr* outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
	ASSERT_TRUE(outBitOrOpBC2) <<
		"expected BitOrOpExpr, got " << outAssignStmtB1->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
ElseIfClausesOptimize) {
	// void test() {
	//     if (b & (c + b) {
	//         b = b | c;
	//     } else if ((b | (c + b)) {
	//         b = b | c;
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     if (b & (c + b) {
	//         b = b | c;
	//     } else if ((b or (c + b)) {
	//         b = b | c;
	//     }
	//     return b;
	// }
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	AddOpExpr* addOpExprCB(AddOpExpr::create(varC, varB));
	BitAndOpExpr* bitAndOpBAddOp(BitAndOpExpr::create(varB, addOpExprCB));
	BitOrOpExpr* bitOrOpBAddOp(BitOrOpExpr::create(varB, addOpExprCB));
	BitOrOpExpr* bitOrOpBC(BitOrOpExpr::create(varB, varC));
	AssignStmt* assignBBitOr(AssignStmt::create(varB, bitOrOpBC));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	IfStmt* ifStmt(IfStmt::create(bitAndOpBAddOp, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBAddOp, assignBBitOr);
	testFunc->setBody(ifStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	IfStmt* outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << testFunc->getBody();
	BitAndOpExpr* outBitAndOp1(cast<BitAndOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outBitAndOp1) <<
		"expected BitAndOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	OrOpExpr* outOrOp(cast<OrOpExpr>(elseif->first));
	ASSERT_TRUE(outOrOp) <<
		"expected OrOpExpr, got " << (elseif->first);
	AssignStmt* outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	BitOrOpExpr* outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	AssignStmt* outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	BitOrOpExpr* outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
	ASSERT_TRUE(outBitOrOpBC2) <<
		"expected BitOrOpExpr, got " << outAssignStmtB1->getRhs();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrDivNotOptimize) {
	// void test() {
	//     switch (a | (b / c)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (b / c)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	DivOpExpr* divOpExpr(DivOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitAndBoolOptimize) {
	// void test() {
	//     switch (a & b)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a and b) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(1)));
	Variable* varB(Variable::create("b", IntType::create(1)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	BitAndOpExpr* bitAndOp(BitAndOpExpr::create(varA, varB));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitAndOp, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	AndOpExpr* outAndOp(cast<AndOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outAndOp) <<
		"expected AndOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrModSecOpVarNotOptimize) {
	// void test() {
	//     switch (a | (b % c)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (b % c)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ModOpExpr* modOpExpr(ModOpExpr::create(varB, varC));
	BitOrOpExpr* bitOrOpAMod(BitOrOpExpr::create(varA, modOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAMod, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrModSecOpZeroNotOptimize) {
	// void test() {
	//     switch (a | (b % 0)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (b % 0)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ModOpExpr* modOpExpr(ModOpExpr::create(varB, ConstInt::create(0, 32)));
	BitOrOpExpr* bitOrOpAMod(BitOrOpExpr::create(varA, modOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAMod, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrDivSecOpNegativeOneNotOptimize) {
	// void test() {
	//     switch (a | (b / -1)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (b / -1)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	DivOpExpr* divOpExpr(DivOpExpr::create(varB, ConstInt::create(-1, 32, true)));
	BitOrOpExpr* bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrDivNegativeOneFirstOpFloatTypeSecOpOptimize) {
	// void test() {
	//     switch (a | (b / -1)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a || (b / -1)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", FloatType::create(16)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	DivOpExpr* divOpExpr(DivOpExpr::create(varB, ConstInt::create(-1, 32, true)));
	BitOrOpExpr* bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	OrOpExpr* outOrOpA(cast<OrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outOrOpA) <<
		"expected OrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
SwitchBitOrMulNegativeOneSecOpNotOptimize) {
	// void test() {
	//     switch (a | (-1 * b)) {
	//     }
	//     return b;
	// }
	// Expected output:
	// void test() {
	//     switch (a | (-1 * b)) {
	//     }
	//     return b;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	MulOpExpr* mulOpExpr(MulOpExpr::create(ConstInt::create(-1, 32, true), varB));
	BitOrOpExpr* bitOrOpAdiv(BitOrOpExpr::create(varA, mulOpExpr));
	ReturnStmt* returnA(ReturnStmt::create(varB));
	SwitchStmt* switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	BitOrOpExpr* outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
}

TEST_F(BitOpToLogOpOptimizerTests,
DoNotOptimizeExpressionsNestedInOtherExpressionsInConditions) {
	// We can optimize only expressions directly appearing in conditions.
	// Expressions nested in other expressions cannot be optimized because that
	// may change the meaning of the expression (bit operations -> bool
	// operations are only valid in boolean context, such as conditions).

	// void test() {
	//     switch (a + (b & c)) {
	//     }
	//     return a;
	// }
	// Expected output:
	// void test() {
	//     switch (a + (b & c)) {
	//     }
	//     return a;
	// }
	Variable* varA(Variable::create("a", IntType::create(32)));
	Variable* varB(Variable::create("b", IntType::create(32)));
	Variable* varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	BitAndOpExpr* bitAndOpExprBC(BitAndOpExpr::create(varB, varC));
	AddOpExpr* addOpABC(AddOpExpr::create(varA, bitAndOpExprBC));
	ReturnStmt* returnA(ReturnStmt::create(varA));
	SwitchStmt* switchStmt(SwitchStmt::create(addOpABC, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	SwitchStmt* outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	AddOpExpr* outAddOpA(cast<AddOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outAddOpA) <<
		"expected AddOpExpr, got " << switchStmt->getControlExpr();
	BitAndOpExpr* outBitAndOpBC(cast<BitAndOpExpr>(outAddOpA->getSecondOperand()));
	ASSERT_TRUE(outBitAndOpBC) <<
		"expected BitAndOpExpr, got " << outAddOpA->getSecondOperand();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
