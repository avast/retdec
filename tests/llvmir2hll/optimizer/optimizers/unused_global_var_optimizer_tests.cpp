/**
* @file tests/llvmir2hll/optimizer/optimizers/unused_global_var_optimizer_tests.cpp
* @brief Tests for the @c unused_global_var_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/unused_global_var_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unused_global_var_optimizer module.
*/
class UnusedGlobalVarOptimizerTests: public TestsWithModule {};

TEST_F(UnusedGlobalVarOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<UnusedGlobalVarOptimizer> optimizer(
		new UnusedGlobalVarOptimizer(module)
	);

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(UnusedGlobalVarOptimizerTests,
DoesNotRemoveGlobalVarWhenItIsUsedInFunction) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//    g = 1;
	// }
	//
	auto varG = Variable::create("g", IntType::create(32));
	module->addGlobalVar(varG);
	auto assignG1 = AssignStmt::create(varG, ConstInt::create(1, 32));
	testFunc->setBody(assignG1);

	// Optimize the module.
	Optimizer::optimize<UnusedGlobalVarOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(module->hasGlobalVar("g"));
}

TEST_F(UnusedGlobalVarOptimizerTests,
DoesNotRemoveGlobalVarWhenItIsUsedInInitializerOfOtherGlobalVar) {
	// Set-up the module.
	//
	// int g;
	// int h = g;
	//
	// void test() {
	//    h = 1;
	// }
	//
	auto varG = Variable::create("g", IntType::create(32));
	module->addGlobalVar(varG);
	auto varH = Variable::create("h", IntType::create(32));
	module->addGlobalVar(varH, varG);
	auto assignH1 = AssignStmt::create(varH, ConstInt::create(1, 32));
	testFunc->setBody(assignH1);

	// Optimize the module.
	Optimizer::optimize<UnusedGlobalVarOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(module->hasGlobalVar("g"));
}

TEST_F(UnusedGlobalVarOptimizerTests,
RemovesGlobalVarWhenItIsNotUsed) {
	// Set-up the module.
	//
	// int g;
	//
	auto varG = Variable::create("g", IntType::create(32));
	module->addGlobalVar(varG);

	// Optimize the module.
	Optimizer::optimize<UnusedGlobalVarOptimizer>(module);

	// Check that the output is correct.
	ASSERT_FALSE(module->hasGlobalVar("g"));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
