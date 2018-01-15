/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negation_operator_sub_optimizer_tests.cpp
* @brief Tests for the @c negation_operator_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negation_operator_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c negation_operator_sub_optimizer module.
*/
class NegationOperatorSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<NegationOperatorSubOptimizer>(
			new NegationOperatorSubOptimizer(evaluator));
	}

protected:
	ShPtr<NegationOperatorSubOptimizer> optimizer;
};

TEST_F(NegationOperatorSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator !
//

TEST_F(NegationOperatorSubOptimizerTests,
NotGreaterOpIsOptimized) {
	// return !(a > 4);
	//
	// Optimized to return a <= 4.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(gtOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<LtEqOpExpr> outLtEqOpExpr(cast<LtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotEqOpExprIsOptimized) {
	// return !(a == 0);
	//
	// Optimized to return a != 0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(eqOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotAddOpExprNotOptimized) {
	// return !(a + 0);
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<NotOpExpr> outNotOpExpr(cast<NotOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNotOpExpr) <<
		"expected `NotOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<AddOpExpr> outAddOpExpr(cast<AddOpExpr>(outNotOpExpr->getOperand()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << outNotOpExpr->getOperand() << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotTrueIsOptimized) {
	// return !(True);
	//
	// Optimized to return False.
	//
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(ConstBool::create(true)));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<ConstBool> outConstBool(cast<ConstBool>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstBool) <<
		"expected `ConstBool`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstBool> resultExpr(ConstBool::create(false));
	EXPECT_EQ(outConstBool->getValue(), resultExpr->getValue()) <<
		"expected `" << resultExpr << "`, "
		"got `" << outConstBool << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotNotGreaterOpIsOptimized) {
	// return !!(a > 4);
	//
	// Optimized to return a > 4.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<NotOpExpr> notOpExpr(NotOpExpr::create(gtOpExpr));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(notOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<GtOpExpr> outGtOpExpr(cast<GtOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outGtOpExpr) <<
		"expected `GtOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotAndOpExprComplicatedIsOptimized) {
	// return !((a == 0) && (a > 4));
	//
	// Optimized to return a != 0 || a <= 4.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<AndOpExpr> andOpExpr(
		AndOpExpr::create(
			eqOpExpr,
			gtOpExpr
	));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(andOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<OrOpExpr> outOrOpExpr(cast<OrOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected `OrOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(outOrOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
		"got `" << outOrOpExpr->getFirstOperand() << "`";
	ShPtr<LtEqOpExpr> outLtEqOpExpr(cast<LtEqOpExpr>(outOrOpExpr->getSecondOperand()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << outOrOpExpr->getSecondOperand() << "`";
}

TEST_F(NegationOperatorSubOptimizerTests,
NotOrOpExprComplicatedIsOptimized) {
	// return !((a == 0) || (a > 4));
	//
	// Optimized to return a != 0 && a <= 4.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<OrOpExpr> orOpExpr(
		OrOpExpr::create(
			eqOpExpr,
			gtOpExpr
	));
	ShPtr<NotOpExpr> returnExpr(NotOpExpr::create(orOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<AndOpExpr> outAndOpExpr(cast<AndOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAndOpExpr) <<
		"expected `AndOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<NeqOpExpr> outNeqOpExpr(cast<NeqOpExpr>(outAndOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
		"got `" << outAndOpExpr->getFirstOperand() << "`";
	ShPtr<LtEqOpExpr> outLtEqOpExpr(cast<LtEqOpExpr>(outAndOpExpr->getSecondOperand()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << outAndOpExpr->getSecondOperand() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
