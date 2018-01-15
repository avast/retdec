/**
* @file tests/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer_tests.cpp
* @brief Tests for the @c while_true_to_for_loop_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/while_true_to_for_loop_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c while_true_to_for_loop_optimizer module.
*/
class WhileTrueToForLoopOptimizerTests: public TestsWithModule {
protected:
	WhileTrueToForLoopOptimizerTests();

protected:
	/// Evaluator of expressions to be used in tests.
	ShPtr<ArithmExprEvaluator> arithmExprEvaluator;
};

WhileTrueToForLoopOptimizerTests::WhileTrueToForLoopOptimizerTests():
	arithmExprEvaluator(StrictArithmExprEvaluator::create()) {}

TEST_F(WhileTrueToForLoopOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<WhileTrueToForLoopOptimizer> optimizer(new WhileTrueToForLoopOptimizer(
		module, va, arithmExprEvaluator));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(WhileTrueToForLoopOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	// Optimize the module.
	Optimizer::optimize<WhileTrueToForLoopOptimizer>(module, va, arithmExprEvaluator);

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
