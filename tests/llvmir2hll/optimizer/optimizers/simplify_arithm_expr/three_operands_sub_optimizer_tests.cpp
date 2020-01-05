/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer_tests.cpp
* @brief Tests for the @c three_operands_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c three_operands_sub_optimizer module.
*/
class ThreeOperandsSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ArithmExprEvaluator* evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ThreeOperandsSubOptimizer*(
			new ThreeOperandsSubOptimizer(evaluator));
	}

protected:
	ThreeOperandsSubOptimizer* optimizer;
};

TEST_F(ThreeOperandsSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator +
//

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumAddVarAddNumConstIntOptimized) {
	// return 3 + (a + 2);
	//
	// Optimized to return 5 + a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			ConstInt::create(3, 64),
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(5, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumAddVarSubNumConstIntOptimized) {
	// return 3 + (a - 5);
	//
	// Optimized to return -2 + a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			ConstInt::create(3, 64),
			subOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(-2, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumAddVarSubNum2ConstIntOptimized) {
	// return 3 + (-5 - a);
	//
	// Optimized to return -2 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(-5, 64),
			varA
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			ConstInt::create(3, 64),
			subOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(-2, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumAddVarSubNumConstFloatOptimized) {
	// return 3.0 + (a - 5.0);
	//
	// Optimized to return - 2.0 + a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(5.0))
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			ConstFloat::create(llvm::APFloat(3.0)),
			subOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstFloat* outOp1(cast<ConstFloat>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstFloat`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	llvm::APFloat f = llvm::APFloat(-2.0);
	EXPECT_TRUE(f.compare(outOp1->getValue()));
	Variable* outOp2(cast<Variable>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleVarSubNumAddNumConstIntOptimized) {
	// return (a - 5) + 6;
	//
	// Optimized to return a - -1.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			subOpExpr,
			ConstInt::create(6, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(-1, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubVarAddNumConstIntOptimized) {
	// return (-5 - a) + 6;
	//
	// Optimized to return 1 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(-5, 64),
			varA
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			subOpExpr,
			ConstInt::create(6, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(1, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleVarAddNumAddNumConstIntOptimized) {
	// return (a + 2) + 3;
	//
	// Optimized to return 5 + a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	AddOpExpr* returnExpr(
		AddOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(5, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator -
//

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubVarAddNumConstInt2Optimized) {
	// return 3 - (a + 4);
	//
	// Optimized to return -1 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			ConstInt::create(3, 64),
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(-1, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubNumAddVarConstIntOptimized) {
	// return 3 - (-5 + a);
	//
	// Optimized to return 8 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			ConstInt::create(-5, 64),
			varA

	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			ConstInt::create(3, 64),
			addOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(8, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubNumSubVarConstIntOptimized) {
	// return 3 - (-5 - a);
	//
	// Optimized to return 8 + a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(-5, 64),
			varA
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			ConstInt::create(3, 64),
			subOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	AddOpExpr* outAddOpExpr(cast<AddOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outAddOpExpr) <<
		"expected `AddOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outAddOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outAddOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(8, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outAddOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outAddOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubVarSubNumConstIntOptimized) {
	// return 3 - (a - 5);
	//
	// Optimized to return 8 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			ConstInt::create(3, 64),
			subOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(8, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleVarAddNumSubNumConstIntOptimized) {
	// return (a + 5) - 6;
	//
	// Optimized to return a - 1.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(5, 64)
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			addOpExpr,
			ConstInt::create(6, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(1, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubVarSubNumConstInt2Optimized) {
	// return (-5 - a) - 6;
	//
	// Optimized to return -11 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(-5, 64),
			varA
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			subOpExpr,
			ConstInt::create(6, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(-11, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleVarSubNumSubNumConstIntOptimized) {
	// return (a - 2) - 3;
	//
	// Optimized to return a - 5.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			subOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(5, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
MultipleNumSubVarSubNumConstInt3Optimized) {
	// return (-2 - a) - 3;
	//
	// Optimized to return -5 - a.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(-2, 64),
			varA
	));
	SubOpExpr* returnExpr(
		SubOpExpr::create(
			subOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	SubOpExpr* outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ConstInt* outOp1(cast<ConstInt>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	ConstInt* result(ConstInt::create(-5, 64));
	EXPECT_EQ(outOp1->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp1 << "`";
	Variable* outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varA, outOp2) <<
		"expected `" << varA << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator <
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarLtNumOptimized) {
	// return (2 - a) < 3;
	//
	// Optimized to return a(negOpExpr) < 1.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	LtOpExpr* returnExpr(
		LtOpExpr::create(
			subOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	LtOpExpr* outLtOpExpr(cast<LtOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtOpExpr) <<
		"expected `LtOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outLtOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outLtOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outLtOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outLtOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(1, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumLtNumOptimized) {
	// return (a + 2) < 3;
	//
	// Optimized to return a < 1.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	LtOpExpr* returnExpr(
		LtOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	LtOpExpr* outLtOpExpr(cast<LtOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtOpExpr) <<
		"expected `LtOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outLtOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outLtOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outLtOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outLtOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(1, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator <=
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarLtEqNumOptimized) {
	// return (2 - a) <= 4;
	//
	// Optimized to return a(negOpExpr) <= 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	LtEqOpExpr* returnExpr(
		LtEqOpExpr::create(
			subOpExpr,
			ConstInt::create(4, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	LtEqOpExpr* outLtEqOpExpr(cast<LtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outLtEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outLtEqOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outLtEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outLtEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumLtEqNumOptimized) {
	// return (a + 1) <= 3;
	//
	// Optimized to return a < 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	LtEqOpExpr* returnExpr(
		LtEqOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	LtEqOpExpr* outLtEqOpExpr(cast<LtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outLtEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outLtEqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outLtEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outLtEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator >
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarGtNumOptimized) {
	// return (2 - a) > 4;
	//
	// Optimized to return a(negOpExpr) > 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	GtOpExpr* returnExpr(
		GtOpExpr::create(
			subOpExpr,
			ConstInt::create(4, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	GtOpExpr* outGtOpExpr(cast<GtOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outGtOpExpr) <<
		"expected `GtOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outGtOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outGtOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outGtOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outGtOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumGtNumOptimized) {
	// return (a + 1) > 3;
	//
	// Optimized to return a > 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	GtOpExpr* returnExpr(
		GtOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	GtOpExpr* outGtOpExpr(cast<GtOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outGtOpExpr) <<
		"expected `GtOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outGtOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outGtOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outGtOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outGtOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator >=
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarGtEqNumOptimized) {
	// return (2 - a) >= 4;
	//
	// Optimized to return a(negOpExpr) >= 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	GtEqOpExpr* returnExpr(
		GtEqOpExpr::create(
			subOpExpr,
			ConstInt::create(4, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	GtEqOpExpr* outGtEqOpExpr(cast<GtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outGtEqOpExpr) <<
		"expected `GtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outGtEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outGtEqOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outGtEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outGtEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumGtEqNumOptimized) {
	// return (a + 1) > 3;
	//
	// Optimized to return a > 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	GtEqOpExpr* returnExpr(
		GtEqOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	GtEqOpExpr* outGtEqOpExpr(cast<GtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outGtEqOpExpr) <<
		"expected `GtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outGtEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outGtEqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outGtEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outGtEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator ==
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarEqNumOptimized) {
	// return (2 - a) == 4;
	//
	// Optimized to return a(negOpExpr) == 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	EqOpExpr* returnExpr(
		EqOpExpr::create(
			subOpExpr,
			ConstInt::create(4, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EqOpExpr* outEqOpExpr(cast<EqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outEqOpExpr) <<
		"expected `EqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outEqOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumEqNumOptimized) {
	// return (a + 1) == 3;
	//
	// Optimized to return a == 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	EqOpExpr* returnExpr(
		EqOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	EqOpExpr* outEqOpExpr(cast<EqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outEqOpExpr) <<
		"expected `EqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outEqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outEqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outEqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outEqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator !=
//

TEST_F(ThreeOperandsSubOptimizerTests,
NumSubVarNeqNumOptimized) {
	// return (2 - a) != 4;
	//
	// Optimized to return a(negOpExpr) != 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	SubOpExpr* subOpExpr(
		SubOpExpr::create(
			ConstInt::create(2, 64),
			varA
	));
	NeqOpExpr* returnExpr(
		NeqOpExpr::create(
			subOpExpr,
			ConstInt::create(4, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	NeqOpExpr* outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	NegOpExpr* outNegOpExpr(cast<NegOpExpr>(outNeqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outNegOpExpr) <<
		"expected `NegOpExpr`, "
		"got `" << outNeqOpExpr->getFirstOperand() << "`";
	Variable* outOp1(cast<Variable>(outNegOpExpr->getOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNegOpExpr->getOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outNeqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outNeqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
VarAddNumNeqNumOptimized) {
	// return (a + 1) == 3;
	//
	// Optimized to return a == 2.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	AddOpExpr* addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	NeqOpExpr* returnExpr(
		NeqOpExpr::create(
			addOpExpr,
			ConstInt::create(3, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	NeqOpExpr* outNeqOpExpr(cast<NeqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNeqOpExpr) <<
		"expected `NeqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	Variable* outOp1(cast<Variable>(outNeqOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outNeqOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ConstInt* outOp2(cast<ConstInt>(outNeqOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outNeqOpExpr->getSecondOperand() << "`";
	ConstInt* result(ConstInt::create(2, 64));
	EXPECT_EQ(outOp2->getValue(), result->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator ^
//

TEST_F(ThreeOperandsSubOptimizerTests,
GtOpExprWithBitXorOpExprWithTrueOptimized) {
	// return (a > 2) ^ True;
	//
	// Optimized to return !(a > 2).
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	GtOpExpr* gtOpExpr(
		GtOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	BitXorOpExpr* bitXorOpExpr(
		BitXorOpExpr::create(
			gtOpExpr,
			ConstBool::create(true)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(bitXorOpExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	NotOpExpr* outNotOpExpr(cast<NotOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outNotOpExpr) <<
		"expected `NotOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(gtOpExpr, outNotOpExpr->getOperand()) <<
		"expected `" << gtOpExpr << "`, "
		"got `" << outNotOpExpr->getOperand() << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
GtOpExprWithBitXorOpExprWithFalseNotOptimized) {
	// return (a == 2) ^ False;
	//
	// Not optimized.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	BitXorOpExpr* bitXorOpExpr(
		BitXorOpExpr::create(
			eqOpExpr,
			ConstBool::create(false)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(bitXorOpExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	BitXorOpExpr* outBitXorOpExpr(cast<BitXorOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitXorOpExpr) <<
		"expected `BitXorOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(bitXorOpExpr, outBitXorOpExpr) <<
		"expected `" << bitXorOpExpr << "`, "
		"got `" << outBitXorOpExpr << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
GtOpExprWithBitXorOpExprWithConstIntNotOptimized) {
	// return (a == 2) ^ 24;
	//
	// Not optimized.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	BitXorOpExpr* bitXorOpExpr(
		BitXorOpExpr::create(
			eqOpExpr,
			ConstInt::create(24, 64)
	));
	ReturnStmt* returnStmt(ReturnStmt::create(bitXorOpExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	BitXorOpExpr* outBitXorOpExpr(cast<BitXorOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outBitXorOpExpr) <<
		"expected `BitXorOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(bitXorOpExpr, outBitXorOpExpr) <<
		"expected `" << bitXorOpExpr << "`, "
		"got `" << outBitXorOpExpr << "`";
}

//
// Tests for operator ^
//

TEST_F(ThreeOperandsSubOptimizerTests,
OrOpExprWithFirstOpEqOpExprAndSecOpLtEqOpExprOptimized) {
	// return (varA == 2) || (varA <= 4);
	//
	// Optimized to (varA <=4)
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	OrOpExpr* orOpExpr(
		OrOpExpr::create(
			eqOpExpr,
			ltEqOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(orOpExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	LtEqOpExpr* outLtEqOpExpr(cast<LtEqOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outLtEqOpExpr) <<
		"expected `LtEqOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(ltEqOpExpr, outLtEqOpExpr) <<
		"expected `" << ltEqOpExpr << "`, "
		"got `" << outLtEqOpExpr << "`";
}

TEST_F(ThreeOperandsSubOptimizerTests,
OrOpExprWithFirstOpEqOpExprAndSecOpLtEqOpExprNotOptimized) {
	// return (varA == 2) || (varA <= 1);
	//
	// Not optimized.
	//
	Variable* varA(Variable::create("a", IntType::create(16)));
	EqOpExpr* eqOpExpr(
		EqOpExpr::create(
			varA,
			ConstInt::create(2, 64)
	));
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(
			varA,
			ConstInt::create(1, 64)
	));
	OrOpExpr* orOpExpr(
		OrOpExpr::create(
			eqOpExpr,
			ltEqOpExpr
	));
	ReturnStmt* returnStmt(ReturnStmt::create(orOpExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	OrOpExpr* outOrOpExpr(cast<OrOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outOrOpExpr) <<
		"expected `OrOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	EXPECT_EQ(outOrOpExpr, orOpExpr) <<
		"expected `" << orOpExpr << "`, "
		"got `" << outOrOpExpr << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
