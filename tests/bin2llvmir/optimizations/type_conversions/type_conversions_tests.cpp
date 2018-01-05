/**
* @file tests/bin2llvmir/optimizations/type_conversions/tests/type_conversions_tests.cpp
* @brief Tests for the @c TypeConversions pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/type_conversions/type_conversions.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c InstOpt pass.
 */
class TypeConversionsTests: public LlvmIrTests
{
	protected:
		TypeConversions pass;
};

//
// removePtrToIntToPtr
//

TEST_F(TypeConversionsTests, removePtrToIntToPtr_replaces2InstructionsWithBitcast)
{
	parseInput(R"(
		@r = global i32* null
		declare i32 @print (i8*)
		define void @func() {
			%a = load i32*, i32** @r
			%b = ptrtoint i32* %a to i32
			%c = inttoptr i32 %b to i8*
			%d = call i32 @print(i8* %c)
			ret void
		}
	)");

	pass.runOnModule(*module);

	std::string exp = R"(
		@r = global i32* null
		declare i32 @print (i8*)
		define void @func() {
			%a = load i32*, i32** @r
			%1 = bitcast i32* %a to i8*
			%d = call i32 @print(i8* %1)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// runInInstruction()
//

TEST_F(TypeConversionsTests, runInInstruction_replacesByArgument)
{
	parseInput(R"(
		declare void @print (float)
		define void @func(float %a) {
			%b = bitcast float %a to i32
			%c = bitcast i32 %b to float
			call void @print(float %c)
			ret void
		}
	)");

	pass.runOnModule(*module);

	std::string exp = R"(
		declare void @print (float)
		define void @func(float %a) {
			%b = bitcast float %a to i32
			call void @print(float %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeConversionsTests, runInInstruction_replacesByLocal)
{
	parseInput(R"(
		declare void @print (float*)
		define void @func() {
			%a = alloca float
			%b = bitcast float* %a to i32*
			%c = bitcast i32* %b to float*
			call void @print(float* %c)
			ret void
		}
	)");

	pass.runOnModule(*module);

	std::string exp = R"(
		declare void @print (float*)
		define void @func() {
			%a = alloca float
			%b = bitcast float* %a to i32*
			call void @print(float* %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeConversionsTests, runInInstruction_replacesByGlobal)
{
	parseInput(R"(
		@gv = global float 0.000000e+00
		declare void @print (float*)
		define void @func() {
			%a = bitcast float* @gv to i32*
			%b = ptrtoint i32* %a to i32
			%c = inttoptr i32 %b to i32*
			%d = bitcast i32* %c to float*
			call void @print(float* %d)
			ret void
		}
	)");

	pass.runOnModule(*module);

	std::string exp = R"(
		@gv = global float 0.000000e+00
		declare void @print (float*)
		define void @func() {
			%a = bitcast float* @gv to i32*
			%1 = bitcast i32* %a to i32*
			call void @print(float* @gv)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeConversionsTests, runInInstruction_replacesByInstruction)
{
	parseInput(R"(
		@gv = global float 0.000000e+00
		declare void @print (float)
		define void @func() {
			%a = load float, float* @gv
			%b = bitcast float %a to i32
			%c = bitcast i32 %b to float
			call void @print(float %c)
			ret void
		}
	)");

	pass.runOnModule(*module);

	std::string exp = R"(
		@gv = global float 0.000000e+00
		declare void @print (float)
		define void @func() {
			%a = load float, float* @gv
			%b = bitcast float %a to i32
			call void @print(float %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
