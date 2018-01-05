/**
* @file tests/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer_tests.cpp
* @brief Tests for the @c if_before_loop_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_before_loop_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c if_before_loop_optimizer module.
*/
class IfBeforeLoopOptimizerTests: public TestsWithModule {};

TEST_F(IfBeforeLoopOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<IfBeforeLoopOptimizer> optimizer(new IfBeforeLoopOptimizer(module, va));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(IfBeforeLoopOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<IfBeforeLoopOptimizer>(module, va);

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
