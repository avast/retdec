/**
* @file tests/bin2llvmir/optimizations/inst_opt/inst_opt_pass_tests.cpp
* @brief Tests for the @c InstructionOptimizer pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt_pass.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c InstructionOptimizer pass.
 *
 * This does not test all optimizations, those are tested in
 * @c inst_opt_tests.cpp module. This only tests that pass does something.
 */
class InstructionOptimizerTests: public LlvmIrTests
{
	protected:
		InstructionOptimizer pass;
};

//
// no optimization
//

TEST_F(InstructionOptimizerTests, noOptimizationReturnsFalse)
{
	bool b = pass.runOnModule(*module);

	EXPECT_FALSE(b);
}

TEST_F(InstructionOptimizerTests, optimizationReturnsTrue)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 0
			ret i32 %b
		}
	)");

	bool ret = pass.runOnModuleCustom(*module);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
