/**
* @file tests/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer_tests.cpp
* @brief Tests for the @c empty_array_to_string_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c empty_array_to_string_optimizer module.
*/
class EmptyArrayToStringOptimizerTests: public TestsWithModule {};

TEST_F(EmptyArrayToStringOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<EmptyArrayToStringOptimizer> optimizer(
		new EmptyArrayToStringOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
