/**
* @file tests/bin2llvmir/analyses/tests/reaching_definitions_tests.cpp
* @brief Tests for the uses analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * Test reaching definition analysis.
 *
 * Richt now, this is just an example, how to create LLVM Module from string,
 * instead of manually constructing it instruction by instruction.
 * => Nowhing useful is tested at the moment.
 */
class ReachingDefinitionsTests: public LlvmIrTests
{
	protected:
		ReachingDefinitionsAnalysis RDA;
};

TEST_F(ReachingDefinitionsTests,
DummyTest)
{
	parseInput(R"(
		@glob0 = global i32 0
		define void @func1() {
			%x = load i32, i32* @glob0
			ret void
		}
	)");

	RDA.runOnModule(*module);

	EXPECT_NE( nullptr, module->getGlobalVariable("glob0") );
	EXPECT_EQ( nullptr, module->getGlobalVariable("glob1") );
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
