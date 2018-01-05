/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr_optimizer_tests.cpp
* @brief Tests for the @c simplify_arithm_expr_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c simplify_arithm_expr_optimizer module.
*/
class SimplifyArithmExprOptimizerTests: public TestsWithModule {
protected:
	void optimize(ShPtr<Module> module);
};

void SimplifyArithmExprOptimizerTests::optimize(ShPtr<Module> module) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
		create());
	Optimizer::optimize<SimplifyArithmExprOptimizer>(module, evaluator);
}

TEST_F(SimplifyArithmExprOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
		create());
	ShPtr<SimplifyArithmExprOptimizer> optimizer(
		new SimplifyArithmExprOptimizer(module, evaluator));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(SimplifyArithmExprOptimizerTests,
GlobalVarTestOptimized) {
	// int a = 2 + 5;
	// void test() {
	// }
	//
	// Optimized to
	// int a = 7;
	// void test() {
	// }
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			ConstInt::create(2, 64),
			ConstInt::create(5, 64)
	));
	module->addGlobalVar(varA, addOpExpr);

	optimize(module);

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(module->getInitForGlobalVar(varA)));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << module->getInitForGlobalVar(varA) << "`";
	ShPtr<ConstInt> result(ConstInt::create(7, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(SimplifyArithmExprOptimizerTests,
MultipleVarSubNumAddNumConstIntOptimized) {
	// return (a - 5) + 6;
	//
	// Optimized to return a + 1.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			subOpExpr,
			ConstInt::create(6, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimize(module);

	ShPtr<AddOpExpr> outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	ShPtr<ConstInt> result(ConstInt::create(1, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
}

TEST_F(SimplifyArithmExprOptimizerTests,
TestForXorNegationAndOrOpEqOpAndGtOpOptimization) {
	// return ((varA == 8) || ((varA > 9) ^ true))
	//
	// Optimized to return a <= 9.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> constInt9(ConstInt::create(9, 64));
	ShPtr<EqOpExpr> eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(8, 64)
	));
	ShPtr<GtOpExpr> gtOpExpr(
		GtOpExpr::create(
			varA,
			constInt9

	));
	ShPtr<BitXorOpExpr> bitXorOpExpr(
		BitXorOpExpr::create(
			gtOpExpr,
			ConstBool::create(true)
	));
	ShPtr<OrOpExpr> orOpExpr(
		OrOpExpr::create(
			eqOpExpr,
			bitXorOpExpr
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(orOpExpr));
	testFunc->setBody(returnStmt);

	optimize(module);

	ShPtr<LtEqOpExpr> outLtEqOpExpr(cast<LtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outVariable(cast<Variable>(outLtEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outVariable) <<
		"expected `Variable`, "
		"got `" << outLtEqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outLtEqOpExpr->getFirstOperand()) <<
		"expected `" << varA << "`, "
		"got `" << outLtEqOpExpr->getFirstOperand() << "`";
	ShPtr<ConstInt> outConstInt(cast<ConstInt>(outLtEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << outLtEqOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(constInt9->getValue(), outConstInt->getValue()) <<
		"expected `" << constInt9 << "`, "
		"got `" << outConstInt << "`";
}

TEST_F(SimplifyArithmExprOptimizerTests,
BiggerAddAndSubAndMulExpression) {
	// return (((3 + 7) - 2) + 5) * 4;
	//
	// Optimized to return 52.
	//
	ShPtr<AddOpExpr> addOpExprFirst(
		AddOpExpr::create(
			ConstInt::create(3, 64),
			ConstInt::create(7, 64)
	));
	ShPtr<SubOpExpr> subOpExpr(
		SubOpExpr::create(
			addOpExprFirst,
			ConstInt::create(2, 64)
	));
	ShPtr<AddOpExpr> addOpExprSec(
		AddOpExpr::create(
			subOpExpr,
			ConstInt::create(5, 64)
	));
	ShPtr<MulOpExpr> returnExpr(
		MulOpExpr::create(
			addOpExprSec,
			ConstInt::create(4, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));
	testFunc->setBody(returnStmt);

	optimize(module);

	ShPtr<ConstInt> outConstInt(cast<ConstInt>(returnStmt->getRetVal()));
	ASSERT_TRUE(outConstInt) <<
		"expected `ConstInt`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<ConstInt> result(ConstInt::create(52, 64));
	EXPECT_EQ(result->getValue(), outConstInt->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outConstInt << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
