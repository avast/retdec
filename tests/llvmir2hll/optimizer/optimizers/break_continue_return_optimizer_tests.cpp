/**
* @file tests/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer_tests.cpp
* @brief Tests for the @c break_continue_return_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c break_continue_return_optimizer module.
*/
class BreakContinueReturnOptimizerTests: public TestsWithModule {};

TEST_F(BreakContinueReturnOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<BreakContinueReturnOptimizer> optimizer(
		new BreakContinueReturnOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(BreakContinueReturnOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<BreakContinueReturnOptimizer>(module);

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
