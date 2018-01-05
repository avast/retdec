/**
* @file tests/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer_tests.cpp
* @brief Tests for the @c no_init_var_def_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c no_init_var_def_optimizer module.
*/
class NoInitVarDefOptimizerTests: public TestsWithModule {};

TEST_F(NoInitVarDefOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<NoInitVarDefOptimizer> optimizer(
		new NoInitVarDefOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(NoInitVarDefOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<NoInitVarDefOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(NoInitVarDefOptimizerTests,
VarDefStmtsWithNoInitializerAreCorrectlyOptimized) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	//     return;
	//     int b;
	// }
	//
	// is optimized to
	//
	// void test() {
	//     return;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(ShPtr<Expression>(), varDefB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), returnStmt));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<NoInitVarDefOptimizer>(module);

	// Check that the output is correct.
	EXPECT_EQ(returnStmt, testFunc->getBody()) <<
		"expected `" << returnStmt << "`, got `" << testFunc->getBody() << "`";
}

TEST_F(NoInitVarDefOptimizerTests,
VarDefStmtsWithInitializerAreNotOptimized) {
	// Set-up the module.
	//
	// void test() {
	//     int a = 4;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstInt::create(4, 32)));
	testFunc->setBody(varDefA);

	// Optimize the module.
	Optimizer::optimize<NoInitVarDefOptimizer>(module);

	// Check that the output is correct.
	EXPECT_EQ(varDefA, testFunc->getBody()) <<
		"expected `" << varDefA << "`, got `" << testFunc->getBody() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
