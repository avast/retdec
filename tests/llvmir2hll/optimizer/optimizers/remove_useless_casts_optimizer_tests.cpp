/**
* @file tests/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer_tests.cpp
* @brief Tests for the @c remove_useless_casts_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c remove_useless_casts_optimizer module.
*/
class RemoveUselessCastsOptimizerTests: public TestsWithModule {};

TEST_F(RemoveUselessCastsOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<RemoveUselessCastsOptimizer> optimizer(
		new RemoveUselessCastsOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(RemoveUselessCastsOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<RemoveUselessCastsOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(RemoveUselessCastsOptimizerTests,
Case1OptimizeBitCastExpr) {
	// Set-up the module.
	//
	// void test() {
	//     int32_t a;
	//     int32_t b;
	//     a = (int32_t)b; // BitCastExpr
	// }
	//
	// will be optimized to
	//
	// void test() {
	//     int32_t a;
	//     int32_t b;
	//     a = b;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<BitCastExpr> castB(BitCastExpr::create(varB, IntType::create(32)));
	ShPtr<AssignStmt> assignACastB(AssignStmt::create(varA, castB));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignACastB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<RemoveUselessCastsOptimizer>(module);

	// Check that the output is correct.
	ASSERT_EQ(varB, assignACastB->getRhs()) <<
		"expected `" << varB << "`, got `"
			<< assignACastB->getRhs() << "`";
}

TEST_F(RemoveUselessCastsOptimizerTests,
Case1OptimizeExtCastExpr) {
	// Set-up the module.
	//
	// void test() {
	//     int32_t a;
	//     int32_t b;
	//     a = (int32_t)b; // ExtCastExpr
	// }
	//
	// will be optimized to
	//
	// void test() {
	//     int32_t a;
	//     int32_t b;
	//     a = b;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ExtCastExpr> castB(ExtCastExpr::create(varB, IntType::create(32)));
	ShPtr<AssignStmt> assignACastB(AssignStmt::create(varA, castB));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignACastB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<RemoveUselessCastsOptimizer>(module);

	// Check that the output is correct.
	ASSERT_EQ(varB, assignACastB->getRhs()) <<
		"expected `" << varB << "`, got `"
			<< assignACastB->getRhs() << "`";
}

TEST_F(RemoveUselessCastsOptimizerTests,
Case1DotNotOptimizeIfCastTypeMismatch) {
	// Set-up the module.
	//
	// void test() {
	//     int32_t a;
	//     int32_t b;
	//     a = (int8_t)b; // ExtCastExpr
	// }
	//
	// It should not be optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ExtCastExpr> castB(ExtCastExpr::create(varB, IntType::create(8)));
	ShPtr<AssignStmt> assignACastB(AssignStmt::create(varA, castB));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignACastB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<RemoveUselessCastsOptimizer>(module);

	// Check that the output is correct.
	ASSERT_EQ(castB, assignACastB->getRhs()) <<
		"expected `" << castB << "`, got `"
			<< assignACastB->getRhs() << "`";
}

TEST_F(RemoveUselessCastsOptimizerTests,
Case1DotNotOptimizeIfRhsVarTypeMismatch) {
	// Set-up the module.
	//
	// void test() {
	//     int32_t a;
	//     int8_t b;
	//     a = (int32_t)b; // ExtCastExpr
	// }
	//
	// It should not be optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(8)));
	testFunc->addLocalVar(varB);
	ShPtr<ExtCastExpr> castB(ExtCastExpr::create(varB, IntType::create(32)));
	ShPtr<AssignStmt> assignACastB(AssignStmt::create(varA, castB));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignACastB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<RemoveUselessCastsOptimizer>(module);

	// Check that the output is correct.
	ASSERT_EQ(castB, assignACastB->getRhs()) <<
		"expected `" << castB << "`, got `"
			<< assignACastB->getRhs() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
