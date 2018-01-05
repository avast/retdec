/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/ternary_operator_sub_optimizer_tests.cpp
* @brief Tests for the @c ternary_operator_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/ternary_operator_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c ternary_operator_sub_optimizer module.
*/
class TernaryOperatorSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<TernaryOperatorSubOptimizer>(
			new TernaryOperatorSubOptimizer(evaluator));
	}

protected:
	ShPtr<TernaryOperatorSubOptimizer> optimizer;
};

TEST_F(TernaryOperatorSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for Ternary Operator
//

TEST_F(TernaryOperatorSubOptimizerTests,
TernaryOperatorTrueValueOptimized) {
	// return true ? 1 : 2;
	//
	// Optimized to return 1.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(1, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(2, 64));
	ShPtr<ConstBool> boolConstant(ConstBool::create(1));
	ShPtr<TernaryOpExpr> returnExpr(
		TernaryOpExpr::create(
			boolConstant,
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(outConstInt->getValue(), firstConstInt->getValue()) <<
		"expected `" << firstConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(TernaryOperatorSubOptimizerTests,
TernaryOperatorFalseOptimized) {
	// return false ? 1 : 2;
	//
	// Optimized to return 2.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(1, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(2, 64));
	ShPtr<ConstBool> boolConstant(ConstBool::create(0));
	ShPtr<TernaryOpExpr> returnExpr(
		TernaryOpExpr::create(
			boolConstant,
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(outConstInt->getValue(), secConstInt->getValue()) <<
		"expected `" << secConstInt << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(TernaryOperatorSubOptimizerTests,
TernaryOperatorVariableNotOptimized) {
	// return a ? 1 : 2;
	//
	// Not optimized.
	//
	ShPtr<ConstInt> firstConstInt(ConstInt::create(1, 64));
	ShPtr<ConstInt> secConstInt(ConstInt::create(2, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<TernaryOpExpr> returnExpr(
		TernaryOpExpr::create(
			varA,
			firstConstInt,
			secConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<TernaryOpExpr> outTernaryOp(cast<TernaryOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outTernaryOp) <<
		"expected `TernaryOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
