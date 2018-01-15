/**
* @file tests/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer_tests.cpp
* @brief Tests for the @c loop_last_continue_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/loop_last_continue_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c loop_last_continue_optimizer module.
*/
class LastLoopContinueOptimizerTests: public TestsWithModule {};

TEST_F(LastLoopContinueOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<LoopLastContinueOptimizer> optimizer(
		new LoopLastContinueOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(LastLoopContinueOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<LoopLastContinueOptimizer>(module);

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
