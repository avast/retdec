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
		ArithmExprEvaluator* evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ChangeOrderOfOperandsSubOptimizer*(
			new ChangeOrderOfOperandsSubOptimizer(evaluator));
	}

protected:
	ChangeOrderOfOperandsSubOptimizer* optimizer;
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
	Variable* varA(Variable::create("a", IntType::create(16)));
	ConstInt* constInt(ConstInt::create(3, 64));
	MulOpExpr* returnExpr(
		MulOpExpr::create(
			varA,
			constInt
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	MulOpExpr* outMulOpExpr(cast<MulOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected `MulOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outMulOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outMulOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(constInt, outOp1) <<
		"expected `" << constInt << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outMulOpExpr->getSecondOperand()));
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
	ConstInt* firstConstInt(ConstInt::create(2, 64));
	ConstInt* secConstInt(ConstInt::create(5, 64));
	MulOpExpr* returnExpr(
		MulOpExpr::create(
			firstConstInt,
			secConstInt
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	MulOpExpr* outMulOpExpr(cast<MulOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outMulOpExpr) <<
		"expected `MulOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outMulOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outMulOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(firstConstInt, outOp1) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outMulOpExpr->getSecondOperand()));
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
