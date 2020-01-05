/**
* @file tests/llvmir2hll/optimizer/optimizers/bit_shift_optimizer_tests.cpp
* @brief Tests for the @c bit_shift_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_shift_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c bit_shift_optimizer module.
*/
class BitShiftOptimizerTests: public TestsWithModule {};

TEST_F(BitShiftOptimizerTests,
OptimizerHasNonEmptyID) {
	BitShiftOptimizer* optimizer(new BitShiftOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsVariableLeftShiftOptimized) {
	// return a << 2;
	//
	// Optimized to a * 4.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	BitShlOpExpr* returnExpr(
		BitShlOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	MulOpExpr* outMulOpExpr(cast<MulOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected MulOpExpr, got " << outReturnBody;
	Variable* outOp1(cast<Variable>(outMulOpExpr->getFirstOperand()));
	EXPECT_EQ(varA, outOp1);
	ConstInt* outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outMulOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(4, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
GlobalVarLeftShiftOptimized) {
	// int b = a << 2;
	// void test() {
	// }
	// int b = a * 4;
	// void test() {
	// }
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	BitShlOpExpr* bitShlOpExpr(
		BitShlOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	module->addGlobalVar(varB, bitShlOpExpr);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check whether BitShlOpExpr was changed to MulOpExpr.
	MulOpExpr* outMulOpExpr(cast<MulOpExpr>(module->getInitForGlobalVar(varB)));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected MulOpExpr, got " << module->getInitForGlobalVar(varB);
	Variable* outOp1(cast<Variable>(outMulOpExpr->getFirstOperand()));
	EXPECT_EQ(varA, outOp1);
	ConstInt* outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outMulOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(4, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsIntTypeExprOptimized) {
	// return (a + b) << 2;
	//
	// Optimized to (a + b) * 4.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			varB
	));
	BitShlOpExpr* returnExpr(
		BitShlOpExpr::create(
			addOpExpr,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	MulOpExpr* outMulOpExpr(cast<MulOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected MulOpExpr, got " << outReturnBody;
	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(outMulOpExpr->getFirstOperand()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected AddOpExpr, got " << outReturnBody;
	ConstInt* outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outMulOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(4, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsFloatTypeExprNotOptimized) {
	// return (a + b) << 2;
	//
	// Not optimized.
	//
	Variable* varA(Variable::create("a", FloatType::create(16)));
	Variable* varB(Variable::create("b", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			varB
	));
	BitShlOpExpr* returnExpr(
		BitShlOpExpr::create(
			addOpExpr,
			ConstInt::create(2, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShlOpExpr* outBitShlOpExpr(cast<BitShlOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShlOpExpr) <<
		"expected BitShlOpExpr, got " << outReturnBody;
	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(outBitShlOpExpr->getFirstOperand()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected AddOpExpr, got " << outReturnBody;
	ConstInt* outOp2(cast<ConstInt>(outBitShlOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShlOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(2, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
SecondOperandIsNegConstIntLeftShiftNotOptimized) {
	// return 5 << -1;
	//
	// Not optimized.
	//
	ConstInt* firstConstInt(ConstInt::create(5, 64));
	ConstInt* secConstInt(ConstInt::create(-1, 64));
	BitShlOpExpr* returnExpr(
		BitShlOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShlOpExpr* outBitShlOpExpr(cast<BitShlOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShlOpExpr) <<
		"expected BitShlOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outBitShlOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outBitShlOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	ConstInt* outOp2(cast<ConstInt>(outBitShlOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShlOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(secConstInt->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsSignedVariableRightShiftLogicNotOptimized) {
	// return (signed)a >> 2 (logical shift);
	//
	// Not optimized.
	//
	Variable* varA(Variable::create("a", IntType::create(16, true)));
	ConstInt* secConstInt(ConstInt::create(2, 64));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			varA,
			secConstInt,
			BitShrOpExpr::Variant::Logical
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShrOpExpr* outBitShrOpExpr(cast<BitShrOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShrOpExpr) <<
		"expected BitShrOpExpr, got " << outReturnBody;
	Variable* outOp1(cast<Variable>(outBitShrOpExpr->getFirstOperand()));
	EXPECT_EQ(varA, outOp1);
	ConstInt* outOp2(cast<ConstInt>(outBitShrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShrOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(secConstInt->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsUnsignedVariableRightShiftLogicOptimized) {
	// return (unsigned)a >> 2 (logical shift);
	//
	// Optimized to a / 4.
	//
	Variable* varA(Variable::create("a", IntType::create(16, false)));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			varA,
			ConstInt::create(2, 64),
			BitShrOpExpr::Variant::Logical
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	DivOpExpr* outDivOpExpr(cast<DivOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected DivOpExpr, got " << outReturnBody;
	Variable* outOp1(cast<Variable>(outDivOpExpr->getFirstOperand()));
	EXPECT_EQ(varA, outOp1);
	ConstInt* outOp2(cast<ConstInt>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outDivOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(4, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsNegConstIntRightShiftLogicNotOptimized) {
	// return -2 >> 5 (logical shift);
	//
	// Not optimized.
	//
	ConstInt* firstConstInt(ConstInt::create(-2, 64));
	ConstInt* secConstInt(ConstInt::create(5, 64));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			firstConstInt,
			secConstInt,
			BitShrOpExpr::Variant::Logical
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShrOpExpr* outBitShrOpExpr(cast<BitShrOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShrOpExpr) <<
		"expected BitShrOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outBitShrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outBitShrOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	ConstInt* outOp2(cast<ConstInt>(outBitShrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShrOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(secConstInt->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsNonNegConstIntRightShiftLogicOptimized) {
	// return 2 >> 2 (logical shift);
	//
	// Optimized to 2 / 4.
	//
	ConstInt* firstConstInt(ConstInt::create(2, 64));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			firstConstInt,
			ConstInt::create(2, 64),
			BitShrOpExpr::Variant::Logical
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	DivOpExpr* outDivOpExpr(cast<DivOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected DivOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outDivOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	ConstInt* outOp2(cast<ConstInt>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outDivOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(4, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
FirstOperandIsNegConstIntRightArithmeticalShiftNotOptimized) {
	// return -2 >> 2 (arithmetical shift);
	//
	// Not optimized.
	//
	ConstInt* firstConstInt(ConstInt::create(-2, 64));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			firstConstInt,
			ConstInt::create(2, 64),
			BitShrOpExpr::Variant::Arithmetical
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShrOpExpr* outBitShrOpExpr(cast<BitShrOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShrOpExpr) <<
		"expected BitShrOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outBitShrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outBitShrOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	ConstInt* outOp2(cast<ConstInt>(outBitShrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShrOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(ConstInt::create(2, 64)->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
SecondOperandIsNegConstIntRightArithmeticalShiftNotOptimized) {
	// return 5 >> -2 (arithmetical shift);
	//
	// Not optimized.
	//
	ConstInt* firstConstInt(ConstInt::create(5, 64));
	ConstInt* secConstInt(ConstInt::create(-2, 64));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShrOpExpr* outBitShrOpExpr(cast<BitShrOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShrOpExpr) <<
		"expected BitShrOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outBitShrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outBitShrOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	ConstInt* outOp2(cast<ConstInt>(outBitShrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected ConstInt, got " << outBitShrOpExpr->getSecondOperand()->getType();
	EXPECT_EQ(secConstInt->getValue(), outOp2->getValue());
}

TEST_F(BitShiftOptimizerTests,
SecondOperandIsVariableRightArithmeticalShiftNotOptimized) {
	// return 2 >> a (arithmetical shift);
	//
	// Not optimized.
	//
	ConstInt* firstConstInt(ConstInt::create(2, 64));
	Variable* varA(Variable::create("a", IntType::create(16)));
	BitShrOpExpr* returnExpr(
		BitShrOpExpr::create(
			firstConstInt,
			varA
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	// Optimize the module.
	Optimizer::optimize<BitShiftOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ReturnStmt* outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected ReturnStmt, got " << testFunc->getBody();
	BitShrOpExpr* outBitShrOpExpr(cast<BitShrOpExpr>(outReturnBody->getRetVal()));
	ASSERT_TRUE(outBitShrOpExpr) <<
		"expected BitShrOpExpr, got " << outReturnBody;
	ConstInt* outOp1(cast<ConstInt>(outBitShrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected ConstInt, got " << outBitShrOpExpr->getFirstOperand()->getType();
	EXPECT_EQ(firstConstInt->getValue(), outOp1->getValue());
	Variable* outOp2(cast<Variable>(outBitShrOpExpr->getSecondOperand()));
	EXPECT_EQ(varA, outOp2);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
