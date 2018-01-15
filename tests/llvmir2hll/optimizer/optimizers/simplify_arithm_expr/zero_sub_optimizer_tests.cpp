/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/zero_sub_optimizer_tests.cpp
* @brief Tests for the @c zero_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/zero_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c zero_sub_optimizer module.
*/
class ZeroSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<ZeroSubOptimizer>(new ZeroSubOptimizer(evaluator));
	}

protected:
	ShPtr<ZeroSubOptimizer> optimizer;
};

TEST_F(ZeroSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator +
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntAddOptimized) {
	// return 0 + a;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstInt::create(0, 64),
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntBigNumAddOptimized) {
	// return 0 + 143666440;
	//
	// Optimized to return 143666440;
	//
	ShPtr<ConstInt> secConstInt(ConstInt::create(143666440, 64));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstInt::create(0, 64, false),
			secConstInt

	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(secConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstFloatAddOptimized) {
	// return a + 0.0;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt->getRetVal() << "`";
}

//
// Tests for operator -
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntSubOptimized) {
	// return 0 - 2.0;
	//
	// Optimized to return -2.0.
	//
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			ConstInt::create(0, 64),
			ConstFloat::create(llvm::APFloat(2.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(-2.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstFloatSubOptimized) {
	// return a - 0.0;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroSecOpIsVariableSubOptimized) {
	// return 0 - a;
	//
	// Optimized to return a(NegOpExpr).
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			ConstInt::create(0, 64),
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NegOpExpr> outNegOpExpr(cast<NegOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outVariable(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outVariable) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outVariable) <<
		"expected `" << varA << "`, "
		"got `" << outVariable << "`";
}

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroSecOpIsNegOpExprSubOptimized) {
	// return 0 - a(NegOpExpr);
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<NegOpExpr> negOpExprVarA(NegOpExpr::create(varA));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			ConstInt::create(0, 64),
			negOpExprVarA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

//
// Tests for operator *
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntMulOptimized) {
	// return 0 * a;
	//
	// Optimized to return 0.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(0, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			firstConstInt,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(firstConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstFloatMulOptimized) {
	// return a * 0.0;
	//
	// Optimized to return 0.0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(0.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

//
// Tests for operator /
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntDivOptimized) {
	// return 0 / a;
	//
	// Optimized to return 0.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(0, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			firstConstInt,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(firstConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstFloatDivNotOptimized) {
	// return a / 0.0;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(0.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<DivOpExpr> outDivOpExpr(cast<DivOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outDivOpExpr) <<
		"expected `DivOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outDivOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outDivOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstFloat> outOp2(cast<ConstFloat>(outDivOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstFloat`, "
		"got `" << outDivOpExpr->getSecondOperand() << "`";
	llvm::APFloat f = llvm::APFloat(0.0);
	EXPECT_TRUE(f.compare(outOp2->getValue()));
}

//
// Tests for operator &
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntBitAndOptimized) {
	// return 0 & 16;
	//
	// Optimized to return 0.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(0, 64));
	ShPtr<BitAndOpExpr> returnExpr(
		BitAndOpExpr::create(
			firstConstInt,
			ConstInt::create(0, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(firstConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstIntBitAndOptimized) {
	// return a & 0;
	//
	// Optimized to return 0.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(0, 64));
	ShPtr<BitAndOpExpr> returnExpr(
		BitAndOpExpr::create(
			Variable::create("a", IntType::create(16, true)),
			firstConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(firstConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

//
// Tests for operator |
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntBitOrOptimized) {
	// return 0 | 16;
	//
	// Optimized to return 16;
	//
	ShPtr<ConstInt> secConstInt(ConstInt::create(16, 64));
	ShPtr<BitOrOpExpr> returnExpr(
		BitOrOpExpr::create(
			ConstInt::create(0, 64),
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(secConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstIntBitOrOptimized) {
	// return a | 0;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<BitOrOpExpr> returnExpr(
		BitOrOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

//
// Tests for operator ^
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntBitXorOptimized) {
	// return 0 ^ 16;
	//
	// Optimized to return 16;
	//
	ShPtr<ConstInt> secConstInt(ConstInt::create(16, 64));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			ConstInt::create(0, 64),
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(secConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstIntBitXorOptimized) {
	// return a ^ 0;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

//
// Tests for operator %
//

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstIntModUOptimized) {
	// return 0 %(Unsigned modulo) a;
	//
	// Optimized to return 0.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(0, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ModOpExpr> returnExpr(
		ModOpExpr::create(
			firstConstInt,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(firstConstInt->getValue(), outConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(ZeroSubOptimizerTests,
FirstOpIsZeroConstFloatModFOptimized) {
	// return 0.0 %(Floating-point modulo) a;
	//
	// Optimized to return 0.0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ModOpExpr> returnExpr(
		ModOpExpr::create(
			ConstFloat::create(llvm::APFloat(0.0)),
			varA,
			ModOpExpr::Variant::FMod
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(0.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

TEST_F(ZeroSubOptimizerTests,
SecOpIsZeroConstIntModNotOptimized) {
	// return a % 0;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> secConstInt(ConstInt::create(0, 64));
	ShPtr<ModOpExpr> returnExpr(
		ModOpExpr::create(
			varA,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ModOpExpr> outModOpExpr(cast<ModOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outModOpExpr) <<
		"expected `ModOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outModOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outModOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outModOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outModOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(outOp2->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outOp2 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
