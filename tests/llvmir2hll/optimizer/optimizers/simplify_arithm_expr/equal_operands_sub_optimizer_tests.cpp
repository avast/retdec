/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/equal_operands_sub_optimizer_tests.cpp
* @brief Tests for the @c equal_operands_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/equal_operands_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c equal_operands_sub_optimizer module.
*/
class EqualOperandsSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<EqualOperandsSubOptimizer>(
			new EqualOperandsSubOptimizer(evaluator));
	}

protected:
	ShPtr<EqualOperandsSubOptimizer> optimizer;
};

TEST_F(EqualOperandsSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator +
//

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsAddOptimized) {
	// return a + a;
	//
	// Optimized to return 2 * a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			varA,
			varA
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
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outOp1->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outMulOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator -
//

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsSubIntTypeOptimized) {
	// return a - a;
	//
	// Optimized to return 0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(0, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsSubFloatTypeOptimized) {
	// return a - a;
	//
	// Optimized to return 0.0.
	//
	ShPtr<Variable> varA(Variable::create("a", FloatType::create(16)));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			varA,
			varA
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

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsDivIntTypeOptimized) {
	// return a / a;
	//
	// Optimized to return 1.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(1, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsDivFloatTypeOptimized) {
	// return a / a;
	//
	// Optimized to return 1.0.
	//
	ShPtr<Variable> varA(Variable::create("a", FloatType::create(16)));
	ShPtr<DivOpExpr> returnExpr(
		DivOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstFloat> outConstFloat(cast<ConstFloat>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstFloat) <<
		"expected `ConstFloat`, "
		"got `" << returnStmt->getRetVal() << "`";
	llvm::APFloat f = llvm::APFloat(1.0);
	EXPECT_TRUE(f.compare(outConstFloat->getValue()));
}

//
// Tests for operator ==
//

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsEqOpOptimized) {
	// return a == a;
	//
	// Optimized to return 1(ConstBool).
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<EqOpExpr> returnExpr(
		EqOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(1));
	EXPECT_EQ(result->getValue(), outConstBool->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsConstIntEqOpOptimized) {
	// return 2 == 2;
	//
	// Optimized to return 1(ConstBool).
	//
	ShPtr<EqOpExpr> returnExpr(
		EqOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(1));
	EXPECT_EQ(result->getValue(), outConstBool->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsEqOpFloatTypeNotOptimized) {
	// return a == a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", FloatType::create(16)));
	ShPtr<EqOpExpr> returnExpr(
		EqOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<EqOpExpr> outEqOpExpr(cast<EqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outEqOpExpr) <<
		"expected `EqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
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
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator !=
//

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsNeqOpOptimized) {
	// return a != a;
	//
	// Optimized to return 0(ConstBool).
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<NeqOpExpr> returnExpr(
		NeqOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(0));
	EXPECT_EQ(result->getValue(), outConstBool->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsConstIntNeqOpOptimized) {
	// return 2 != 2;
	//
	// Optimized to return 0(ConstBool).
	//
	ShPtr<NeqOpExpr> returnExpr(
		NeqOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> result(ConstBool::create(0));
	EXPECT_EQ(result->getValue(), outConstBool->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstBool << "`";
}

TEST_F(EqualOperandsSubOptimizerTests,
TwoSameOperandsNeqOpFloatTypeNotOptimized) {
	// return a != a;
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", FloatType::create(16)));
	ShPtr<NeqOpExpr> returnExpr(
		NeqOpExpr::create(
			varA,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
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
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
