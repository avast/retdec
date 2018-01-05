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

	ShPtr<BitOpToLogOpOptimizer> optimizer(new BitOpToLogOpOptimizer(module, va));

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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<DivOpExpr> divBC(DivOpExpr::create(varB, varC));
	ShPtr<AssignStmt> assignB(AssignStmt::create(varB, divBC, returnA));
	ShPtr<DivOpExpr> divOpCZero(DivOpExpr::create(varC, ConstInt::create(0, 64,
		false)));
	ShPtr<BitOrOpExpr> bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(bitOrOpBDiv, bitOrOpBC1));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC2));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(andOpExpr,
		assignBBitOr, assignB));
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, bitOrOpBC2, whileLoopStmt));
	ShPtr<AssignStmt> assignC(AssignStmt::create(varC, divBC, assignA));
	testFunc->setBody(assignC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<AssignStmt> outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtC) <<
		"expected AssignStmt, got " << testFunc->getBody();
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(outAssignStmtC->getSuccessor()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << outAssignStmtC->getSuccessor();
	ShPtr<BitOrOpExpr> outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	ShPtr<WhileLoopStmt> outWhileStmt(cast<WhileLoopStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outWhileStmt) <<
		"expected WhileStmt, got " << outAssignStmtA->getSuccessor();
	ShPtr<AndOpExpr> outAndOpExpr(cast<AndOpExpr>(outWhileStmt->getCondition()));
	ASSERT_TRUE(outAndOpExpr) <<
		"expected AndOpExpr, got " << outWhileStmt->getCondition();
	ShPtr<OrOpExpr> outOrOpExpr(cast<OrOpExpr>(outAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outAndOpExpr->getSecondOperand();
	ShPtr<BitOrOpExpr> outBitOrOpDiv(cast<BitOrOpExpr>(outAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outBitOrOpDiv) <<
		"expected BitOrOpExpr, got " << outAndOpExpr->getFirstOperand();
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(outWhileStmt->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << outWhileStmt->getBody();
	ShPtr<BitOrOpExpr> outBitOrBody(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<DivOpExpr> divOpCZero(DivOpExpr::create(varC, ConstInt::create(0, 64,
		false)));
	ShPtr<BitOrOpExpr> bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC3(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC3));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(bitOrOpBC2, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBDiv, assignBBitOr);
	ifStmt->addClause(varB, assignBBitOr);
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, bitOrOpBC1, ifStmt));
	testFunc->setBody(assignA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << outAssignStmtA->getSuccessor();
	ShPtr<OrOpExpr> outOrOpExpr(cast<OrOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	ShPtr<BitOrOpExpr> outBitOrOpExpr(cast<BitOrOpExpr>(elseif->first));
	ASSERT_TRUE(outBitOrOpExpr) <<
		"expected BitOrOpExpr, got " << (elseif->first);
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	ShPtr<AssignStmt> outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	ShPtr<BitOrOpExpr> outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
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
	ShPtr<ArrayIndexOpExpr> arrayA(ArrayIndexOpExpr::create(Variable::create("a",
		IntType::create(32)), ConstInt::create(6, 64, false)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ExprVector args;
	ShPtr<AddOpExpr> addOpExpr(AddOpExpr::create(varB, ConstInt::create(2,64)));
	args.push_back(addOpExpr);
	ShPtr<CallExpr> callExpr(CallExpr::create(varB, args));
	ShPtr<AddOpExpr> addOpExprCCall(AddOpExpr::create(varC, callExpr));
	ShPtr<AddOpExpr> addOpExprBArray(AddOpExpr::create(varC, arrayA));
	ShPtr<BitAndOpExpr> bitAndOpBAddOp(BitAndOpExpr::create(varB, addOpExprCCall));
	ShPtr<BitAndOpExpr> bitAndOpBArray(BitAndOpExpr::create(varB, addOpExprBArray));
	ShPtr<BitOrOpExpr> bitOrOpBC(BitOrOpExpr::create(varB, varC));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(bitAndOpBAddOp, assignBBitOr, returnA));
	ifStmt->addClause(bitAndOpBArray, assignBBitOr);
	testFunc->setBody(ifStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << testFunc->getBody();
	ShPtr<BitAndOpExpr> outBitAndOp1(cast<BitAndOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outBitAndOp1) <<
		"expected BitAndOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	ShPtr<BitAndOpExpr> outBitAndOp2(cast<BitAndOpExpr>(elseif->first));
	ASSERT_TRUE(outBitAndOp2) <<
		"expected BitAndOpExpr, got " << (elseif->first);
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	ShPtr<AssignStmt> outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	ShPtr<BitOrOpExpr> outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	ShPtr<Variable> varD(Variable::create("d", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	testFunc->addLocalVar(varD);
	ExprVector args;
	args.push_back(varA);
	ShPtr<CallExpr> callExpr(CallExpr::create(varB, args));
	ShPtr<AddOpExpr> addOpExprBCall(AddOpExpr::create(varB, callExpr));
	ShPtr<BitAndOpExpr> bitAndOpDBCall(BitAndOpExpr::create(varD, addOpExprBCall));
	ShPtr<BitOrOpExpr> bitOrOpCDBCall(BitOrOpExpr::create(varC, bitAndOpDBCall));
	ShPtr<BitAndOpExpr> bitAndOpBCDBCall(BitAndOpExpr::create(varB, bitOrOpCDBCall));
	ShPtr<BitOrOpExpr> bitOrOpABCDBCall(BitOrOpExpr::create(varA, bitAndOpBCDBCall));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpABCDBCall, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outBitOrOpA) <<
		"expected BitOrOpExpr, got " << switchStmt->getControlExpr();
	ShPtr<BitAndOpExpr> outBitAndOpB(cast<BitAndOpExpr>(outBitOrOpA->getSecondOperand()));
	ASSERT_TRUE(outBitAndOpB) <<
		"expected BitAndOpExpr, got " << outBitOrOpA->getSecondOperand();
	ShPtr<BitOrOpExpr> outBitOrOpC(cast<BitOrOpExpr>(outBitAndOpB->getSecondOperand()));
	ASSERT_TRUE(outBitOrOpC) <<
		"expected BitOrOpExpr, got " << outBitAndOpB->getSecondOperand();
	ShPtr<BitAndOpExpr> outBitAndOpD(cast<BitAndOpExpr>(outBitOrOpC->getSecondOperand()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<DivOpExpr> divBC(DivOpExpr::create(varB, varC));
	ShPtr<AssignStmt> assignB(AssignStmt::create(varB, divBC, returnA));
	ShPtr<DivOpExpr> divOpCZero(DivOpExpr::create(varC, ConstInt::create(1, 64,
		false)));
	ShPtr<BitOrOpExpr> bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(bitOrOpBDiv, bitOrOpBC1));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC2));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(andOpExpr,
		assignBBitOr, assignB));
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, bitOrOpBC2, whileLoopStmt));
	ShPtr<AssignStmt> assignC(AssignStmt::create(varC, divBC, assignA));
	testFunc->setBody(assignC);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<AssignStmt> outAssignStmtC(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtC) <<
		"expected AssignStmt, got " << testFunc->getBody();
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(outAssignStmtC->getSuccessor()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << outAssignStmtC->getSuccessor();
	ShPtr<BitOrOpExpr> outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	ShPtr<WhileLoopStmt> outWhileStmt(cast<WhileLoopStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outWhileStmt) <<
		"expected WhileStmt, got " << outAssignStmtA->getSuccessor();
	ShPtr<AndOpExpr> outAndOpExpr(cast<AndOpExpr>(outWhileStmt->getCondition()));
	ASSERT_TRUE(outAndOpExpr) <<
		"expected AndOpExpr, got " << outWhileStmt->getCondition();
	ShPtr<OrOpExpr> outOrOpExpr(cast<OrOpExpr>(outAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected OrOpExpr, got " << outAndOpExpr->getSecondOperand();
	ShPtr<OrOpExpr> outOrOpDiv(cast<OrOpExpr>(outAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOrOpDiv) <<
		"expected OrOpExpr, got " << outAndOpExpr->getFirstOperand();
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(outWhileStmt->getBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << outWhileStmt->getBody();
	ShPtr<BitOrOpExpr> outBitOrBody(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<DivOpExpr> divOpCZero(DivOpExpr::create(varC, ConstInt::create(5, 64, false)));
	ShPtr<BitOrOpExpr> bitOrOpBC1(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC2(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBC3(BitOrOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpBDiv(BitOrOpExpr::create(varB, divOpCZero));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC3));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<IfStmt> ifStmt(IfStmt::create(bitOrOpBC2, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBDiv, assignBBitOr);
	ifStmt->addClause(varB, assignBBitOr);
	ShPtr<AssignStmt> assignA(AssignStmt::create(varA, bitOrOpBC1, ifStmt));
	testFunc->setBody(assignA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<AssignStmt> outAssignStmtA(cast<AssignStmt>(testFunc->getBody()));
	ASSERT_TRUE(outAssignStmtA) <<
		"expected AssignStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC(cast<BitOrOpExpr>(outAssignStmtA->getRhs()));
	ASSERT_TRUE(outBitOrOpBC) <<
		"expected BitOrExpr, got " << outAssignStmtA->getRhs();
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(outAssignStmtA->getSuccessor()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << outAssignStmtA->getSuccessor();
	ShPtr<OrOpExpr> outOrOp1(cast<OrOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outOrOp1) <<
		"expected OrOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	ShPtr<OrOpExpr> outOrOp2(cast<OrOpExpr>(elseif->first));
	ASSERT_TRUE(outOrOp2) <<
		"expected OrOpExpr, got " << (elseif->first);
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	ShPtr<AssignStmt> outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	ShPtr<BitOrOpExpr> outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
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
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<AddOpExpr> addOpExprCB(AddOpExpr::create(varC, varB));
	ShPtr<BitAndOpExpr> bitAndOpBAddOp(BitAndOpExpr::create(varB, addOpExprCB));
	ShPtr<BitOrOpExpr> bitOrOpBAddOp(BitOrOpExpr::create(varB, addOpExprCB));
	ShPtr<BitOrOpExpr> bitOrOpBC(BitOrOpExpr::create(varB, varC));
	ShPtr<AssignStmt> assignBBitOr(AssignStmt::create(varB, bitOrOpBC));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(bitAndOpBAddOp, assignBBitOr, returnA));
	ifStmt->addClause(bitOrOpBAddOp, assignBBitOr);
	testFunc->setBody(ifStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<IfStmt> outIfStmt(cast<IfStmt>(testFunc->getBody()));
	ASSERT_TRUE(outIfStmt) <<
		"expected IfStmt, got " << testFunc->getBody();
	ShPtr<BitAndOpExpr> outBitAndOp1(cast<BitAndOpExpr>(outIfStmt->getFirstIfCond()));
	ASSERT_TRUE(outBitAndOp1) <<
		"expected BitAndOpExpr, got " << outIfStmt->getFirstIfCond();
	auto elseif = ++(outIfStmt->clause_begin());
	ShPtr<OrOpExpr> outOrOp(cast<OrOpExpr>(elseif->first));
	ASSERT_TRUE(outOrOp) <<
		"expected OrOpExpr, got " << (elseif->first);
	ShPtr<AssignStmt> outAssignStmtB(cast<AssignStmt>(ifStmt->getFirstIfBody()));
	ASSERT_TRUE(outAssignStmtB) <<
		"expected AssignStmt, got " << ifStmt->getFirstIfBody();
	ShPtr<BitOrOpExpr> outBitOrOpBC1(cast<BitOrOpExpr>(outAssignStmtB->getRhs()));
	ASSERT_TRUE(outBitOrOpBC1) <<
		"expected BitOrOpExpr, got " << outAssignStmtB->getRhs();
	ShPtr<AssignStmt> outAssignStmtB1(cast<AssignStmt>(elseif->second));
	ASSERT_TRUE(outAssignStmtB1) <<
		"expected AssignStmt, got " << (elseif->second);
	ShPtr<BitOrOpExpr> outBitOrOpBC2(cast<BitOrOpExpr>(outAssignStmtB1->getRhs()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(1)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(1)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<BitAndOpExpr> bitAndOp(BitAndOpExpr::create(varA, varB));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitAndOp, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<AndOpExpr> outAndOp(cast<AndOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<ModOpExpr> modOpExpr(ModOpExpr::create(varB, varC));
	ShPtr<BitOrOpExpr> bitOrOpAMod(BitOrOpExpr::create(varA, modOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAMod, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<ModOpExpr> modOpExpr(ModOpExpr::create(varB, ConstInt::create(0, 32)));
	ShPtr<BitOrOpExpr> bitOrOpAMod(BitOrOpExpr::create(varA, modOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAMod, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(varB, ConstInt::create(-1, 32, true)));
	ShPtr<BitOrOpExpr> bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", FloatType::create(16)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(varB, ConstInt::create(-1, 32, true)));
	ShPtr<BitOrOpExpr> bitOrOpAdiv(BitOrOpExpr::create(varA, divOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<OrOpExpr> outOrOpA(cast<OrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(ConstInt::create(-1, 32, true), varB));
	ShPtr<BitOrOpExpr> bitOrOpAdiv(BitOrOpExpr::create(varA, mulOpExpr));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(bitOrOpAdiv, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<BitOrOpExpr> outBitOrOpA(cast<BitOrOpExpr>(switchStmt->getControlExpr()));
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varA);
	testFunc->addLocalVar(varB);
	testFunc->addLocalVar(varC);
	ShPtr<BitAndOpExpr> bitAndOpExprBC(BitAndOpExpr::create(varB, varC));
	ShPtr<AddOpExpr> addOpABC(AddOpExpr::create(varA, bitAndOpExprBC));
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(addOpABC, returnA));
	testFunc->setBody(switchStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	Optimizer::optimize<BitOpToLogOpOptimizer>(module, va);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<SwitchStmt> outSwitchStmt(cast<SwitchStmt>(testFunc->getBody()));
	ASSERT_TRUE(outSwitchStmt) <<
		"expected SwitchStmt, got " << testFunc->getBody();
	ShPtr<AddOpExpr> outAddOpA(cast<AddOpExpr>(switchStmt->getControlExpr()));
	ASSERT_TRUE(outAddOpA) <<
		"expected AddOpExpr, got " << switchStmt->getControlExpr();
	ShPtr<BitAndOpExpr> outBitAndOpBC(cast<BitAndOpExpr>(outAddOpA->getSecondOperand()));
	ASSERT_TRUE(outBitAndOpBC) <<
		"expected BitAndOpExpr, got " << outAddOpA->getSecondOperand();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
