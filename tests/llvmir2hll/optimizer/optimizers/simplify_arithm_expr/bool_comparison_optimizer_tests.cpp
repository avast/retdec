/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/bool_comparison_optimizer_tests.cpp
* @brief Tests for the @c bool_comparison_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/assertions.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/bool_comparison_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c bool_comparison_optimizer module.
*/
class BoolComparisonSubOptimizerTests: public TestsWithModule {
protected:
	BoolComparisonSubOptimizerTests();

protected:
	ShPtr<BoolComparisonSubOptimizer> optimizer;
};

BoolComparisonSubOptimizerTests::BoolComparisonSubOptimizerTests():
	optimizer(std::make_shared<BoolComparisonSubOptimizer>(
		StrictArithmExprEvaluator::create())) {}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizerHasNonEmptyID) {
	ASSERT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesEqualityComparisonToTrue) {
	// return a < 1 == true;
	//
	//     ->
	//
	// return a < 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto ltExpr = LtOpExpr::create(varA, ConstInt::create(1, 32));
	auto returnExpr = EqOpExpr::create(ltExpr, ConstBool::create(true));
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ASSERT_BIR_EQ(ltExpr, returnStmt->getRetVal());
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesEqualityComparisonToFalse) {
	// return a < 1 == false;
	//
	//     ->
	//
	// return a >= 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto const1 = ConstInt::create(1, 32);
	auto ltExpr = LtOpExpr::create(varA, const1);
	auto returnExpr = EqOpExpr::create(ltExpr, ConstBool::create(false));
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	auto result = cast<GtEqOpExpr>(returnStmt->getRetVal());
	ASSERT_TRUE(result);
	EXPECT_BIR_EQ(varA, result->getFirstOperand());
	EXPECT_BIR_EQ(const1, result->getSecondOperand());
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesNonEqualityComparisonToTrue) {
	// return a < 1 != true;
	//
	//     ->
	//
	// return a >= 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto const1 = ConstInt::create(1, 32);
	auto ltExpr = LtOpExpr::create(varA, const1);
	auto returnExpr = NeqOpExpr::create(ltExpr, ConstBool::create(true));
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	auto result = cast<GtEqOpExpr>(returnStmt->getRetVal());
	ASSERT_TRUE(result);
	EXPECT_BIR_EQ(varA, result->getFirstOperand());
	EXPECT_BIR_EQ(const1, result->getSecondOperand());
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesNonEqualityComparisonToFalse) {
	// return a < 1 != false;
	//
	//     ->
	//
	// return a < 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto ltExpr = LtOpExpr::create(varA, ConstInt::create(1, 32));
	auto returnExpr = NeqOpExpr::create(ltExpr, ConstBool::create(false));
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ASSERT_BIR_EQ(ltExpr, returnStmt->getRetVal());
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesNestedEqualityComparisons) {
	// return (a < 1 == true) == true;
	//
	//     ->
	//
	// return a < 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto ltExpr = LtOpExpr::create(varA, ConstInt::create(1, 32));
	auto returnExpr = EqOpExpr::create(
		EqOpExpr::create(ltExpr, ConstBool::create(true)),
		ConstBool::create(true)
	);
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ASSERT_BIR_EQ(ltExpr, returnStmt->getRetVal());
}

TEST_F(BoolComparisonSubOptimizerTests,
OptimizesNestedNonEqualityComparisons) {
	// return (a < 1 != false) != false;
	//
	//     ->
	//
	// return a < 1;

	auto varA = Variable::create("a", IntType::create(32));
	auto ltExpr = LtOpExpr::create(varA, ConstInt::create(1, 32));
	auto returnExpr = NeqOpExpr::create(
		NeqOpExpr::create(ltExpr, ConstBool::create(false)),
		ConstBool::create(false)
	);
	auto returnStmt = ReturnStmt::create(returnExpr);

	optimizer->tryOptimize(returnStmt->getRetVal());

	ASSERT_BIR_EQ(ltExpr, returnStmt->getRetVal());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
