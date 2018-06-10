/**
* @file tests/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negative_operand_sub_optimizer_tests.cpp
* @brief Tests for the @c negative_operand_sub_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/negative_operand_sub_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c negative_operand_sub_optimizer module.
*/
class NegativeOperandSubOptimizerTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		ShPtr<ArithmExprEvaluator> evaluator(StrictArithmExprEvaluator::
			create());
		optimizer = ShPtr<NegativeOperandSubOptimizer>(
			new NegativeOperandSubOptimizer(evaluator));
	}

protected:
	ShPtr<NegativeOperandSubOptimizer> optimizer;
};

TEST_F(NegativeOperandSubOptimizerTests,
OptimizerHasNonEmptyID) {
	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

//
// Tests for operator +
//

TEST_F(NegativeOperandSubOptimizerTests,
SecOpIsNegativeConstIntAddOptimized) {
	// return a + -2;
	//
	// Optimized to return a - 2.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(-2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outOp2->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(NegativeOperandSubOptimizerTests,
SecOpIsNegativeConstFloatAddOptimized) {
	// return a + -4.0;
	//
	// Optimized to return a - 4.0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			varA,
			ConstFloat::create(llvm::APFloat(-4.0))
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstFloat> outOp2(cast<ConstFloat>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstFloat`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	llvm::APFloat f = llvm::APFloat(4.0);
	EXPECT_TRUE(f.compare(outOp2->getValue()));
}

TEST_F(NegativeOperandSubOptimizerTests,
SecOpIsNegOpExprAddOptimized) {
	// return a + -b(NegOpExpr);
	//
	// Optimized to return a - b.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<NegOpExpr> negOpExprVarB(NegOpExpr::create(varB));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			varA,
			negOpExprVarB
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(NegativeOperandSubOptimizerTests,
FirstOpIsNegativeConstIntAddOptimized) {
	// return -2 + a;
	//
	// Optimized to return a - 2.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstInt::create(-2, 64),
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outOp2->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(NegativeOperandSubOptimizerTests,
FirstOpIsNegativeConstFloatAddOptimized) {
	// return -4.0 + a;
	//
	// Optimized to return a - 4.0.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			ConstFloat::create(llvm::APFloat(-4.0)),
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstFloat> outOp2(cast<ConstFloat>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstFloat`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	llvm::APFloat f = llvm::APFloat(4.0);
	EXPECT_TRUE(f.compare(outOp2->getValue()));
}

TEST_F(NegativeOperandSubOptimizerTests,
FirstOpIsNegOpExprAddOptimized) {
	// return -b(NegOpExpr) + a;
	//
	// Optimized to return a - b.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16, true)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16, true)));
	ShPtr<NegOpExpr> negOpExprVarB(NegOpExpr::create(varB));
	ShPtr<AddOpExpr> returnExpr(
		AddOpExpr::create(
			negOpExprVarB,
			varA
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

	ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<Variable> outOp2(cast<Variable>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(varB, outOp2) <<
		"expected `" << varB << "`, "
		"got `" << outOp2 << "`";
}

//
// Tests for operator -
//

TEST_F(NegativeOperandSubOptimizerTests,
SecOpIsNegConstIntSubFewBitsNotOptimized) {
	// return a - -128;
	//
	// Not optimized. -128 can't be optimized to 128 on 8 bits.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(8)));
	ShPtr<ConstInt> secOpConstInt = ConstInt::create(-128, 8);
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			varA,
			secOpConstInt
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

		ShPtr<SubOpExpr> outSubOpExpr(cast<SubOpExpr>(returnStmt->getRetVal()));
	ASSERT_TRUE(outSubOpExpr) <<
		"expected `SubOpExpr`, "
		"got `" << returnStmt->getRetVal() << "`";
	ShPtr<Variable> outOp1(cast<Variable>(outSubOpExpr->getFirstOperand()));
	ASSERT_TRUE(outOp1) <<
		"expected `Variable`, "
		"got `" << outSubOpExpr->getFirstOperand() << "`";
	EXPECT_EQ(varA, outOp1) <<
		"expected `" << varA << "`, "
		"got `" << outOp1 << "`";
	ShPtr<ConstInt> outOp2(cast<ConstInt>(outSubOpExpr->getSecondOperand()));
	ASSERT_TRUE(outOp2) <<
		"expected `ConstInt`, "
		"got `" << outSubOpExpr->getSecondOperand() << "`";
	EXPECT_EQ(secOpConstInt->getValue(), outOp2->getValue()) <<
		"expected `" << secOpConstInt << "`, "
		"got `" << outOp2 << "`";
}

TEST_F(NegativeOperandSubOptimizerTests,
SecOpIsNegConstIntSubOptimized) {
	// return a - -2;
	//
	// Optimized to return a + 2.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<SubOpExpr> returnExpr(
		SubOpExpr::create(
			varA,
			ConstInt::create(-2, 64)
	));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(returnExpr));

	optimizer->tryOptimize(returnStmt->getRetVal());

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
	ShPtr<ConstInt> result(ConstInt::create(2, 64));
	EXPECT_EQ(result->getValue(), outOp2->getValue()) <<
		"expected `" << result << "`, "
		"got `" << outOp2 << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
