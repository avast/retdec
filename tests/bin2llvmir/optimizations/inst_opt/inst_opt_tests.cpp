/**
* @file tests/bin2llvmir/optimizations/inst_opt/inst_opt_tests.cpp
* @brief Tests for the @c inst_opt::optimize().
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c inst_opt::optimize().
 */
class OptimizeTests: public LlvmIrTests
{

};

//
// no optimization
//

TEST_F(OptimizeTests, noOptimizationReturnsFalse)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// add zero
//

TEST_F(OptimizeTests, addValZero)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 0
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

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

TEST_F(OptimizeTests, addZeroVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 0, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

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

TEST_F(OptimizeTests, addValVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 10
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 10
			ret i32 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// sub zero
//

TEST_F(OptimizeTests, subValZero)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 0
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

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

TEST_F(OptimizeTests, subValVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 10
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 10
			ret i32 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// trunc zext
//

TEST_F(OptimizeTests, truncZext8)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = trunc i32 %a to i8
			%c = zext i8 %b to i32
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%c = and i32 %a, 255
			ret i32 %c
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, truncZext16)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = trunc i32 %a to i16
			%c = zext i16 %b to i32
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%c = and i32 %a, 65535
			ret i32 %c
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// xor X, X
//

TEST_F(OptimizeTests, xorXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = xor i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// xor load X, load X
//

TEST_F(OptimizeTests, xorLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = xor i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, xorLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = xor i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// or X, X
//

TEST_F(OptimizeTests, orXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = or i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 10
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// xor i1 X, Y
//

TEST_F(OptimizeTests, xor_i1_xy)
{
	parseInput(R"(
		@reg = global i1 1
		define i1 @fnc() {
			%a = load i1, i1* @reg
			%b = xor i1 %a, 1
			ret i1 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i1 1
		define i1 @fnc() {
			%a = load i1, i1* @reg
			%b = icmp ne i1 %a, 1
			ret i1 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// and i1 X, Y
//

TEST_F(OptimizeTests, and_i1_xy)
{
	parseInput(R"(
		@reg = global i1 1
		define i1 @fnc() {
			%a = load i1, i1* @reg
			%b = and i1 %a, 1
			ret i1 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i1 1
		define i1 @fnc() {
			%a = load i1, i1* @reg
			%b = icmp eq i1 %a, 1
			ret i1 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// and X, X
//

TEST_F(OptimizeTests, andXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = and i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 10
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// or load X, load X
//

TEST_F(OptimizeTests, orLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = or i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

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

TEST_F(OptimizeTests, orLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = or i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

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

//
// and load X, load X
//

TEST_F(OptimizeTests, andLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = and i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

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

TEST_F(OptimizeTests, andLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = and i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

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

//
// addSequence()
//

TEST_F(OptimizeTests, addSequence)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 1
			%c = add i32 %b, 2
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%c = add i32 %a, 3
			ret i32 %c
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//==============================================================================

//
// castSequence
//

TEST_F(OptimizeTests, castSequence_ptr_int_ptr)
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
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

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
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, castSequence_float_int_float_arg)
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
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		declare void @print (float)
		define void @func(float %a) {
			call void @print(float %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, castSequence_float_int_float_local)
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
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		declare void @print (float*)
		define void @func() {
			%a = alloca float
			call void @print(float* %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, castSequence_ptr_int_ptr_global)
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
	auto* b = getInstructionByName("b");
	auto* c = getInstructionByName("c");
	auto* d = getInstructionByName("d");

	bool ret = inst_opt::optimize(b);
	ret |= inst_opt::optimize(c);
	ret |= inst_opt::optimize(d);

	std::string exp = R"(
		@gv = global float 0.000000e+00
		declare void @print (float*)
		define void @func() {
			call void @print(float* @gv)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(OptimizeTests, castSequence_float_int_flot_global)
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
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@gv = global float 0.000000e+00
		declare void @print (float)
		define void @func() {
			%a = load float, float* @gv
			call void @print(float %a)
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
