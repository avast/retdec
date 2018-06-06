/**
* @file tests/bin2llvmir/optimizations/asm_inst_remover/tests/asm_inst_remover_tests.cpp
* @brief Tests for the @c AsmInstructionRemover pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/asm_inst_remover/asm_inst_remover.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c AsmInstructionRemover pass.
 */
class AsmInstructionRemoverTests: public LlvmIrTests
{
	protected:
		AsmInstructionRemover pass;
};

//
// runOnModule()
//

TEST_F(AsmInstructionRemoverTests, passDoesNotSegfaultAndReturnsFalseIfConfigForModuleDoesNotExists)
{
	bool b = pass.runOnModule(*module);

	EXPECT_FALSE(b);
}

TEST_F(AsmInstructionRemoverTests, passDoesNotSegfaultAndReturnsFalseIfNullptrConfigPassed)
{
	bool b = pass.runOnModuleCustom(*module);

	EXPECT_FALSE(b);
}

TEST_F(AsmInstructionRemoverTests, passRemovesEverythingRelatedToLlvmToAsmMapping)
{
	parseInput(R"(
		@reg = global i32 0
		@specialGv = internal global i32 0
		define i32 @func() {
			%a = load i32, i32* @reg
			store i32 4096, i32* @specialGv
			%b = add i32 %a, 1234
			store i32 8192, i32* @specialGv
			store i32 %b, i32* @reg
			%c = load i32, i32* @reg
			store i32 12288, i32* @specialGv
			ret i32 %c
		}
	)");
	auto* gv = getGlobalByName("specialGv");
	AsmInstruction::setLlvmToAsmGlobalVariable(module.get(), gv);
	auto s = retdec::config::Storage::inRegister("esp");
	auto r = retdec::config::Object("esp", s);

	bool b = pass.runOnModuleCustom(*module);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @func() {
			%a = load i32, i32* @reg
			%v0_1000 = add i32 %a, 1234
			store i32 %v0_1000, i32* @reg
			%v0_2000 = load i32, i32* @reg
			ret i32 %v0_2000
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
