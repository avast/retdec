/**
* @file tests/bin2llvmir/optimizations/stack_pointer_ops/tests/stack_pointer_ops_tests.cpp
* @brief Tests for the @c StackPointerOpsRemove pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/stack_pointer_ops/stack_pointer_ops.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/abi/x86.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c InstOpt pass.
 */
class StackPointerOpsRemoveTests: public LlvmIrTests
{
	protected:
		StackPointerOpsRemove pass;
};

//
// runOnModule()
//

TEST_F(StackPointerOpsRemoveTests, passDoesNotSegfaultAndReturnsFalseIfConfigForModuleDoesNotExists)
{
	bool b = pass.runOnModule(*module);

	EXPECT_FALSE(b);
}

TEST_F(StackPointerOpsRemoveTests, passDoesNotSegfaultAndReturnsFalseIfNullptrConfigPassed)
{
	bool b = pass.runOnModuleCustom(*module, nullptr);

	EXPECT_FALSE(b);
}

TEST_F(StackPointerOpsRemoveTests, passRemovesAllStoresToStackRegistersEvenIfTheyHaveUses)
{
	parseInput(R"(
		@esp = global i32 0
		define void @func() {
			%a = load i32, i32* @esp
			%b = add i32 %a, 1234
			store i32 %b, i32* @esp
			%c = load i32, i32* @esp
			ret void
		}
	)");
	auto* esp = getGlobalByName("esp");
	auto c = Config::empty(module.get());
	AbiX86 abi(module.get(), &c);
	abi.addRegister(X86_REG_ESP, esp);

	bool b = pass.runOnModuleCustom(*module, &abi);

	std::string exp = R"(
		@esp = global i32 0
		define void @func() {
			%a = load i32, i32* @esp
			%b = add i32 %a, 1234
			%c = load i32, i32* @esp
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
}

TEST_F(StackPointerOpsRemoveTests, passKeepsAllStoresToNonStackPointerRegisters)
{
	parseInput(R"(
		@eax = global i32 0
		define void @func() {
			%a = load i32, i32* @eax
			%b = add i32 %a, 1234
			store i32 %b, i32* @eax
			ret void
		}
	)");
	auto* eax = getGlobalByName("eax");
	auto c = Config::empty(module.get());
	AbiX86 abi(module.get(), &c);
	abi.addRegister(X86_REG_EAX, eax);

	bool b = pass.runOnModuleCustom(*module, &abi);

	std::string exp = R"(
		@eax = global i32 0
		define void @func() {
			%a = load i32, i32* @eax
			%b = add i32 %a, 1234
			store i32 %b, i32* @eax
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(b);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
