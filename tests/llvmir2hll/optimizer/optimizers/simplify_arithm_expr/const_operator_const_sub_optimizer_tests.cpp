/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/const_operator_const_sub_optimizer_tests.cpp
* @brief Tests for the @c const_operator_const_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/const_operator_const_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_operator_const_sub_optimizer module.
*/
class ConstOperatorConstSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<ConstOperatorConstSubOptimizer>(
			new ConstOperatorConstSubOptimizer(evaluator));
	}

protected:
	ShPtr<ConstOperatorConstSubOptimizer> optimizer;
};

TEST_F(ConstOperatorConstSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator +
//

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntAddOptimized) {
	// return 2 + 5;
	//
	// Optimized to return 7.
	//
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(5, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(7, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstFloatConstFloatAddOptimized) {
	// return 2.0 + 5.0;
	//
	// Optimized to return 7.0.
	//
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(5.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(7.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstOperatorConstSubOptimizerTest) {
	// return 2 + 4.0;
	//
	// Not optimized.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(2, 64));
	ShPtr<ConstFloat> firstConstFloat(ConstFloat::create(llvm::APFloat(4.0)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			firstConstInt,
			firstConstFloat
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<AddOpExpr> outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstFloat> outOp2(cast<ConstFloat>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstFloat`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	llvm::APFloat f = llvm::APFloat(4.0);
	EXPECT_TRUE(f.compare(outOp2->getValue()));
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntOverflowAddNotOptimized) {
	// return 7 + 7;
	//
	// Not optimized.
	//
	ShPtr<ConstInt> opConstInt(ConstInt::create(7, 4));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			opConstInt,
			opConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<AddOpExpr> outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), opConstInt->getValue()) <<
		"expected `" << opConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), opConstInt->getValue()) <<
		"expected `" << opConstInt << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator -
//

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntSubOptimized) {
	// return 2 - 5;
	//
	// Optimized to return -3.
	//
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(5, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(-3, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstFloatConstFloatSubOptimized) {
	// return 2.0 - 5.0;
	//
	// Optimized to return -3.0.
	//
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.0)),
			ConstFloat::create(llvm::APFloat(5.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(-3.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntDiffBitWidthSubNotOptimized) {
	// return 2(BitWidth 64) - 4(BitWidth 32);
	//
	// Not optimized.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(2, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(4, 32));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator *
//

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntMulOptimized) {
	// return 2 * 5;
	//
	// Optimized to return 10.
	//
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(5, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(10, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntMulNegativeOneNotOptimized) {
	// return -8 * -1;
	//
	// Not optimized. -8 can't be optimized to 8 on 4 bits.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(-8, 4));
	ShPtr<ConstInt> secConstInt(ConstInt::create(-1, 4));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<MulOpExpr> outMulOpExpr(cast<MulOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected `MulOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outMulOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outMulOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outMulOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstFloatConstFloatMulOptimized) {
	// return 2.5 * 3.0;
	//
	// Optimized to return 7.5.
	//
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			ConstFloat::create(llvm::APFloat(2.5)),
			ConstFloat::create(llvm::APFloat(3.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(7.5);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

//
// Tests for operator /
//

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntDivOptimized) {
	// return 6 / 3;
	//
	// Optimized to return 2.
	//
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			ConstInt::create(6, 64),
			ConstInt::create(3, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntRemainderDivNotOptimized) {
	// return 7 / 3;
	//
	// Not optimized.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(7, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(3, 64));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<DivOpExpr> outDivOpExpr(cast<DivOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected `DivOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntDivNegativeOneNotOptimized) {
	// return -8 / -1;
	//
	// Not optimized. -8 can't be optimized to 8 on 4 bits.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(-8, 4));
	ShPtr<ConstInt> secConstInt(ConstInt::create(-1, 4));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<DivOpExpr> outDivOpExpr(cast<DivOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected `DivOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstIntConstIntDivZeroNotOptimized) {
	// return 8 / 0;
	//
	// Not optimized.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(8, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(0, 64));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<DivOpExpr> outDivOpExpr(cast<DivOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected `DivOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> outOp1(cast<ConstInt>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(outOp1->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outDivOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstFloatConstFloatDivOptimized) {
	// return 9.0 / 3.0;
	//
	// Optimized to return 3.0.
	//
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			ConstFloat::create(llvm::APFloat(9.0)),
			ConstFloat::create(llvm::APFloat(3.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(3.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

TEST_F(ConstOperatorConstSubOptimizerTests,
ConstFloatConstFloatDivZeroNotOptimized) {
	// return 9.0 / 0.0;
	//
	// Not optimized.
	//
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			ConstFloat::create(llvm::APFloat(9.0)),
			ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<DivOpExpr> outDivOpExpr(cast<DivOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected `DivOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstFloat> outOp1(cast<ConstFloat>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstFloat`, "
		"got `" << outDivOpExpr->getFirstOperand() << "`";
	llvm::APFloat f1 = llvm::APFloat(9.0);
	EXPECT_TRUE(f1.compare(outOp1->getValue()));
	ShPtr<ConstFloat> outOp2(cast<ConstFloat>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstFloat`, "
		"got `" << outDivOpExpr->getSecondOperand() << "`";
	llvm::APFloat f2 = llvm::APFloat(0.0);
	EXPECT_TRUE(f2.compare(outOp2->getValue()));
}

//
// Tests for operator &
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntBitAndOptimized) {
	// return 20 & 12;
	//
	// Optimized to return 4.
	//
	ShPtr<BitAndOpExpr> returnExpr(
		BitAndOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(4, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsNegConstIntSecOpIsNegConstIntBitAndOptimized) {
	// return -20 & -12;
	//
	// Optimized to return -28.
	//
	ShPtr<BitAndOpExpr> returnExpr(
		BitAndOpExpr::create(
			ConstInt::create(-20, 64),
			ConstInt::create(-12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(-28, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
SecOpIsConstIntBitAndNotOptimized) {
	// return a & 10;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<ConstInt> secConstInt(ConstInt::create(10, 64));
	ShPtr<BitAndOpExpr> returnExpr(
		BitAndOpExpr::create(
			varA,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<BitAndOpExpr> outBitAndOpExpr(cast<BitAndOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitAndOpExpr) <<
		"expected `BitAndOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outBitAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outBitAndOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outBitAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outBitAndOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator |
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntBitOrOptimized) {
	// return 20 | 12;
	//
	// Optimized to return 28.
	//
	ShPtr<BitOrOpExpr> returnExpr(
		BitOrOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(28, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsNegConstIntSecOpIsNegConstIntBitOrOptimized) {
	// return -20 | -12;
	//
	// Optimized to return -4.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(-20, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(-12, 64));
	ShPtr<BitOrOpExpr> returnExpr(
		BitOrOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(-4, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
SecOpIsConstIntBitOrNotOptimized) {
	// return a | 10;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<ConstInt> secConstInt(ConstInt::create(10, 64));
	ShPtr<BitOrOpExpr> returnExpr(
		BitOrOpExpr::create(
			varA,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<BitOrOpExpr> outBitOrOpExpr(cast<BitOrOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitOrOpExpr) <<
		"expected `BitOrOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outBitOrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outBitOrOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outBitOrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outBitOrOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator ^
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntBitXorOptimized) {
	// return 20 ^ 12;
	//
	// Optimized to return 24.
	//
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(24, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsNegConstIntSecOpIsNegConstIntBitXorOptimized) {
	// return -20 ^ -12;
	//
	// Optimized to return 24.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(-20, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(-12, 64));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(24, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ConstOperatorConstSubOptimizerTests,
SecOpIsConstIntBitXorNotOptimized) {
	// return a ^ 10;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<ConstInt> secConstInt(ConstInt::create(10, 64));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			varA,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<BitXorOpExpr> outBitXorOpExpr(cast<BitXorOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitXorOpExpr) <<
		"expected `BitXorOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outBitXorOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outBitXorOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outBitXorOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outBitXorOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator >
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntGtOptimized) {
	// return 20 > 12;
	//
	// Optimized to return true.
	//
	ShPtr<GtOpExpr> returnExpr(
		GtOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(true));
	EXPECT_EQ(outConstBool->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

//
// Tests for operator ==
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntEqOptimized) {
	// return 20 == 12;
	//
	// Optimized to return false.
	//
	ShPtr<EqOpExpr> returnExpr(
		EqOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(false));
	EXPECT_EQ(outConstBool->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

//
// Tests for operator !=
//

TEST_F(ConstOperatorConstSubOptimizerTests,
FirstOpIsConstIntSecOpIsConstIntNeqOptimized) {
	// return 20 != 12;
	//
	// Optimized to return true.
	//
	ShPtr<NeqOpExpr> returnExpr(
		NeqOpExpr::create(
			ConstInt::create(20, 64),
			ConstInt::create(12, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(true));
	EXPECT_EQ(outConstBool->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

//
// Tests for operator &&
//

TEST_F(ConstOperatorConstSubOptimizerTests,
TrueAndTrueOptimized) {
	// return true && true;
	//
	// Optimized to return true.
	//
	ShPtr<ConstBool> constBoolTrue(ConstBool::create(true));
	ShPtr<AndOpExpr> returnExpr(
		AndOpExpr::create(
			constBoolTrue,
			constBoolTrue
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(constBoolTrue->getValue(), outConstBool->getValue()) <<
		"expected `" << constBoolTrue << "`, "
		"got `" << outConstBool << "`";
}

//
// Tests for operator ||
//

TEST_F(ConstOperatorConstSubOptimizerTests,
TrueOrFalseOptimized) {
	// return true || false;
	//
	// Optimized to return true.
	//
	ShPtr<ConstBool> constBoolTrue(ConstBool::create(true));
	ShPtr<ConstBool> constBoolFalse(ConstBool::create(false));
	ShPtr<OrOpExpr> returnExpr(
		OrOpExpr::create(
			constBoolTrue,
			constBoolFalse
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(constBoolTrue->getValue(), outConstBool->getValue()) <<
		"expected `" << constBoolTrue << "`, "
		"got `" << outConstBool << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
