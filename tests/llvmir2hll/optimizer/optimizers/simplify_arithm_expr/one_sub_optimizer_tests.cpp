/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/one_sub_optimizer_tests.cpp
* @brief Tests for the @c one_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/one_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c one_sub_optimizer module.
*/
class OneSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<OneSubOptimizer>(new OneSubOptimizer(evaluator));
	}

protected:
	ShPtr<OneSubOptimizer> optimizer;
};

TEST_F(OneSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator *
//

TEST_F(OneSubOptimizerTests,
SecOpIsOneConstIntMulOptimized) {
	// return a * 1;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

TEST_F(OneSubOptimizerTests,
FirstOpIsOneConstFloatMulOptimized) {
	// return 1.0 * a;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			ConstFloat::create(llvm::APFloat(1.0)),
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EXPECT_EQ(varA, returnStmt->getRetVal()) <<
		"expected `" << varA << "`, "
		"got `" << returnStmt << "`";
}

//
// Tests for operator /
//

TEST_F(OneSubOptimizerTests,
SecOpIsOneConstIntDivOptimized) {
	// return a / 1;
	//
	// Optimized to return a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			varA,
			ConstInt::create(1, 32)
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

TEST_F(OneSubOptimizerTests,
XorOpAndEqOpFirstOpOfXorIsOneOptimized) {
	// return 1 ^ (a == b);
	//
	// Optimized to retun a != b.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			varB
	));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			ConstInt::create(1, 64),
			eqOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outNeqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outNeqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(OneSubOptimizerTests,
EqOpAndXorOpSecOpOfXorIsOneOptimized) {
	// return (a == b) ^ 1;
	//
	// Optimized to retun a != b.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			varB
	));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			eqOpExpr,
			ConstInt::create(1, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outNeqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outNeqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(OneSubOptimizerTests,
EqOpAndXorOpSecOpOfXorIsTenNotOptimized) {
	// return (a == b) ^ 10;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<ConstInt> constInt(ConstInt::create(10, 64));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			varB
	));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			eqOpExpr,
			constInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<BitXorOpExpr> outBitXorOpExpr(cast<BitXorOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitXorOpExpr) <<
		"expected `BitXorOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<EqOpExpr> outEqOpExpr(cast<EqOpExpr>(outBitXorOpExpr->getFirstOperand()));
	ASSERT_TRUE(outEqOpExpr) <<
		"expected `EqOpExpr`, "
		"got `" << outBitXorOpExpr->getFirstOperand() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outEqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outEqOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
	ShPtr<ConstInt> outConstInt(cast<ConstInt>(outBitXorOpExpr->getSecondOperand()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << outBitXorOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(constInt, outConstInt) <<
		"expected `" << constInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(OneSubOptimizerTests,
EqOpWithCastsAndXorOpSecOpOfXorIsOneOptimized) {
	// return IntToPtr(IntToPtr((a == b))) ^ 1;
	//
	// Optimized to retun a != b.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			varB
	));
	ShPtr<IntToPtrCastExpr> intToPtrCastExprInner(
		IntToPtrCastExpr::create(
			eqOpExpr,
			IntType::create(16)
	));
	ShPtr<IntToPtrCastExpr> intToPtrCastExprOuter(
		IntToPtrCastExpr::create(
			intToPtrCastExprInner,
			IntType::create(16)
	));
	ShPtr<BitXorOpExpr> returnExpr(
		BitXorOpExpr::create(
			intToPtrCastExprOuter,
			ConstInt::create(1, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outNeqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outNeqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
