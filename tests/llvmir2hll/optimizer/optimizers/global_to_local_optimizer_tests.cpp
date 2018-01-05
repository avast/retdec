/**
* @file tests/llvmir2hll/optimizer/optimizers/global_to_local_optimizer_tests.cpp
* @brief Tests for the @c global_to_local_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/optim_call_info_obtainer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/global_to_local_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c global_to_local_optimizer module.
*/
class GlobalToLocalOptimizerTests: public TestsWithModule {};

TEST_F(GlobalToLocalOptimizerTests,
OptimizerHasNonEmptyID) {
	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);

	ShPtr<GlobalToLocalOptimizer> optimizer(new GlobalToLocalOptimizer(
		module, va, OptimCallInfoObtainer::create()));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
