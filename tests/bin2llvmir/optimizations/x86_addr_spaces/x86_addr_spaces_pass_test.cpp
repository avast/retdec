/**
* @file tests/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_pass_test.cpp
* @brief Tests for the @c X86AddressSpacesPass pass.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces_pass.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c X86AddressSpacesPass pass.
 *
 * This does not test optimizations, those are tested in
 * @c x86_addr_spaces_test.cpp module.
 * This only tests that the pass does something.
 */
class X86AddressSpacesPassTests: public LlvmIrTests
{
	protected:
	X86AddressSpacesPass pass;
};

TEST_F(X86AddressSpacesPassTests, noOptimizationReturnsFalse)
{
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();

	bool ret = pass.runOnModuleCustom(*module, &c);

	EXPECT_FALSE(ret);
}

TEST_F(X86AddressSpacesPassTests, optimizationReturnsTrue)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = load i32, i32 addrspace(257)* inttoptr (i32 24 to i32 addrspace(257)*)
			ret i32 %a
		}
	)");
	auto c = Config::empty(module.get());
	c.getConfig().architecture.setIsX86();

	bool ret = pass.runOnModuleCustom(*module, &c);

	std::string exp = R"(
		define i32 @fnc() {
			%a = call i32 @__readfsdword(i32 24)
			ret i32 %a
		}
		declare i32 @__readfsdword(i32)
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
