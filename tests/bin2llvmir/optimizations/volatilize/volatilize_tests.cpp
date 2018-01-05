/**
* @file tests/bin2llvmir/optimizations/volatilize/tests/volatilize_tests.cpp
* @brief Tests for the @c Volatilize pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/volatilize/volatilize.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c Volatilize pass.
 */
class VolatilizeTests: public LlvmIrTests
{
	protected:
		Volatilize pass;
};

TEST_F(VolatilizeTests, VolatilizeUnvolatilizeAllKindsOfLoadAndStores)
{
	std::string orig = R"(
			@r = global i32 0
			define void @func() {
				%a = alloca i32
				%b = load i32, i32* @r
				store i32 %b, i32* @r
				store i32 %b, i32* %a
				%c = load i32, i32* %a
				%d = inttoptr i32 %c to i32*
				store i32 %c, i32* %d
				%e = load i32, i32* %d
				ret void
			})";
	parseInput(orig);

	// Volatilize.
	//
	pass.runOnModule(*module);

	std::string exp = R"(
		@r = global i32 0
		define void @func() {
			%a = alloca i32
			%b = load volatile i32, i32* @r
			store volatile i32 %b, i32* @r
			store volatile i32 %b, i32* %a
			%c = load volatile i32, i32* %a
			%d = inttoptr i32 %c to i32*
			store volatile i32 %c, i32* %d
			%e = load volatile i32, i32* %d
			ret void
		})";
	checkModuleAgainstExpectedIr(exp);

	// Unvolatilize.
	//
	pass.runOnModule(*module);
	checkModuleAgainstExpectedIr(orig);
}

TEST_F(VolatilizeTests, KeepAlreadyVolatileLoadsAndStoresVolatile)
{
	std::string orig = R"(
			@r = global i32 0
			define void @func() {
				%a = load i32, i32* @r
				store i32 %a, i32* @r
				%b = load volatile i32, i32* @r
				store volatile i32 %b, i32* @r
				ret void
			})";
	parseInput(orig);

	// Volatilize.
	//
	pass.runOnModule(*module);

	std::string exp = R"(
			@r = global i32 0
			define void @func() {
				%a = load volatile i32, i32* @r
				store volatile i32 %a, i32* @r
				%b = load volatile i32, i32* @r
				store volatile i32 %b, i32* @r
				ret void
			})";
	checkModuleAgainstExpectedIr(exp);

	// Unvolatilize.
	//
	pass.runOnModule(*module);
	checkModuleAgainstExpectedIr(orig);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
