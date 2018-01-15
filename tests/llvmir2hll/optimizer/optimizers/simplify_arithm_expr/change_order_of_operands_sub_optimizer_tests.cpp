/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/change_order_of_operands_sub_optimizer_tests.cpp
* @brief Tests for the @c change_order_of_operands_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/change_order_of_operands_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c change_order_of_operands_sub_optimizer module.
*/
class ChangeOrderOfOperandsSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<ChangeOrderOfOperandsSubOptimizer>(
			new ChangeOrderOfOperandsSubOptimizer(evaluator));
	}

protected:
	ShPtr<ChangeOrderOfOperandsSubOptimizer> optimizer;
};

TEST_F(ChangeOrderOfOperandsSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator *
//

TEST_F(ChangeOrderOfOperandsSubOptimizerTests,
SecOpIsNumFirstIsVarConstIntMulOptimized) {
	// return a * 3;
	//
	// Optimized to return 3 * a.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> constInt(ConstInt::create(3, 64));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			varA,
			constInt
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
	EXPECT_EQ(constInt, outOp1) <<
		"expected `" << constInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outMulOpExpr->getSecondOperand()));
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ChangeOrderOfOperandsSubOptimizerTests,
SecOpIsNumFirstIsNumMulNotOptimized) {
	// return 2 * 5;
	//
	// Not optimized in this sub optimization.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(2, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(5, 64));
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
	EXPECT_EQ(firstConstInt, outOp1) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outMulOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(secConstInt, outOp2) <<
		"expected `" << outOp2 << "`, "
		"got `" << secConstInt << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
