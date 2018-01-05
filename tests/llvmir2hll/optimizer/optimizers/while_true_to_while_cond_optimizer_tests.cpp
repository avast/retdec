/**
* @file tests/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer_tests.cpp
* @brief Tests for the @c while_true_to_while_cond_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_while_cond_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c while_true_to_while_cond_optimizer module.
*/
class WhileTrueToWhileCondOptimizerTests: public TestsWithModule {};

TEST_F(WhileTrueToWhileCondOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<WhileTrueToWhileCondOptimizer> optimizer(
		new WhileTrueToWhileCondOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(WhileTrueToWhileCondOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<WhileTrueToWhileCondOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
