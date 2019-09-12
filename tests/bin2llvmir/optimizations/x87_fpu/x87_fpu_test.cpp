/**
* @file tests/bin2llvmir/optimizations/x87_fpu/x87_fpu.cpp
* @brief Tests for the @c X87FpuAnalysis.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/x87_fpu/x87_fpu.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/utils/string.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {


/**
 * @brief Tests for the @c X87FpuAnalysis.
 */
class X87FpuAnalysisTests: public LlvmIrTests
{
protected:
	Abi *abi;
	Config config;

	X87FpuAnalysis pass;
	void setX86Environment(std::string architecture, std::string callingConvention);

	const std::string PREDEFINED_REGISTERS_AND_FUNCTIONS = R"(
		@fpu_stat_TOP = internal global i3 0
		@st0 = internal global x86_fp80 0xK00000000000000000000
		@st1 = internal global x86_fp80 0xK00000000000000000000
		@st2 = internal global x86_fp80 0xK00000000000000000000
		@st3 = internal global x86_fp80 0xK00000000000000000000
		@st4 = internal global x86_fp80 0xK00000000000000000000
		@st5 = internal global x86_fp80 0xK00000000000000000000
		@st6 = internal global x86_fp80 0xK00000000000000000000
		@st7 = internal global x86_fp80 0xK00000000000000000000
		@fpu_tag_0 = internal global i2 0
		@fpu_tag_1 = internal global i2 0
		@fpu_tag_2 = internal global i2 0
		@fpu_tag_3 = internal global i2 0
		@fpu_tag_4 = internal global i2 0
		@fpu_tag_5 = internal global i2 0
		@fpu_tag_6 = internal global i2 0
		@fpu_tag_7 = internal global i2 0

		declare void @__frontend_reg_store.fpu_tag(i3, i2)
		declare void @__frontend_reg_store.fpr(i3, x86_fp80)
		declare x86_fp80 @__frontend_reg_load.fpr(i3)
		declare i2 @__frontend_reg_load.fpu_tag(i3)
)";

	const std::string X86_16BIT_TEST = R"(
		;; x86-16bit don't pass arguments through fpu registers => begin FPU_TOP=8
		;; x86-16bit don't pass return value through fpu registers => end FPU_TOP=8
		define double @foo(double %arg0, double %arg1) {
			; st(0) = arg0
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %arg0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 %5)
			call void @__frontend_reg_store.fpr(i3 %2, x86_fp80 %3)

			; st(1)=arg1, st(0)=arg0
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = sub i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			%8 = fpext double %arg1 to x86_fp80
			%9 = fcmp oeq x86_fp80 %8, 0xK00000000000000000000
			%10 = select i1 %9, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %7, i2 %10)
			call void @__frontend_reg_store.fpr(i3 %7, x86_fp80 %8)

			;fmulp st(0),st(1) => st(0) = arg0 * arg1
			%11 = load i3, i3* @fpu_stat_TOP
			%12 = add i3 %11, 1
			store i3 %12, i3* @fpu_stat_TOP
			%13 = call x86_fp80 @__frontend_reg_load.fpr(i3 %11)
			%14 = call x86_fp80 @__frontend_reg_load.fpr(i3 %12)
			%15 = fmul x86_fp80 %13, %14
			%16 = fcmp oeq x86_fp80 %15, 0xK00000000000000000000
			%17 = select i1 %16, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %11, i2 -1)
			call void @__frontend_reg_store.fpu_tag(i3 %12, i2 %17)
			call void @__frontend_reg_store.fpr(i3 %12, x86_fp80 %15)

			; push x87 and return result
			%18 = load i3, i3* @fpu_stat_TOP
			%19 = add i3 %18, 1
			store i3 %19, i3* @fpu_stat_TOP
			%20 = call x86_fp80 @__frontend_reg_load.fpr(i3 %18)
			call void @__frontend_reg_store.fpu_tag(i3 %18, i2 -1)
			%21 = fptrunc x86_fp80 %20 to double
			ret double %21
		}

		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
			;; FPU_TOP=8
			%0 = call double @foo(double 1.000000e+00, double 2.000000e+00)
			;; FPU_TOP=8

			; st(0) = %0
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 %5)
			call void @__frontend_reg_store.fpr(i3 %2, x86_fp80 %3)

			; clear FPU_TOP
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = add i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %6, i2 -1)

			ret i32 0
		}
)";
const std::string X86_16BIT_TEST_RESULT_EXPECTED = R"(
		define double @foo(double %arg0, double %arg1) {
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %arg0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			store i2 %5, i2* @fpu_tag_0
			store x86_fp80 %3, x86_fp80* @st0
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = sub i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			%8 = fpext double %arg1 to x86_fp80
			%9 = fcmp oeq x86_fp80 %8, 0xK00000000000000000000
			%10 = select i1 %9, i2 1, i2 0
			store i2 %10, i2* @fpu_tag_1
			store x86_fp80 %8, x86_fp80* @st1
			%11 = load i3, i3* @fpu_stat_TOP
			%12 = add i3 %11, 1
			store i3 %12, i3* @fpu_stat_TOP
			%13 = load x86_fp80, x86_fp80* @st1
			%14 = load x86_fp80, x86_fp80* @st0
			%15 = fmul x86_fp80 %13, %14
			%16 = fcmp oeq x86_fp80 %15, 0xK00000000000000000000
			%17 = select i1 %16, i2 1, i2 0
			store i2 -1, i2* @fpu_tag_1
			store i2 %17, i2* @fpu_tag_0
			store x86_fp80 %15, x86_fp80* @st0
			%18 = load i3, i3* @fpu_stat_TOP
			%19 = add i3 %18, 1
			store i3 %19, i3* @fpu_stat_TOP
			%20 = load x86_fp80, x86_fp80* @st0
			store i2 -1, i2* @fpu_tag_0
			%21 = fptrunc x86_fp80 %20 to double
			ret double %21
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
			%0 = call double @foo(double 1.000000e+00, double 2.000000e+00)
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			store i2 %5, i2* @fpu_tag_0
			store x86_fp80 %3, x86_fp80* @st0
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = add i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			store i2 -1, i2* @fpu_tag_0
			ret i32 0
		}
)";
const std::string X86_32_64BIT_TEST = R"(
		;; x86-16bit don't pass arguments through fpu registers => begin FPU_TOP=8
		;; x86-16bit don't pass return value through fpu registers => end FPU_TOP=8
		define double @foo(double %arg0, double %arg1) {
			; st(0) = arg0
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %arg0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 %5)
			call void @__frontend_reg_store.fpr(i3 %2, x86_fp80 %3)

			; st(1)=arg1, st(0)=arg0
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = sub i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			%8 = fpext double %arg1 to x86_fp80
			%9 = fcmp oeq x86_fp80 %8, 0xK00000000000000000000
			%10 = select i1 %9, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %7, i2 %10)
			call void @__frontend_reg_store.fpr(i3 %7, x86_fp80 %8)

			;fmulp st(0),st(1) => st(0) = arg0 * arg1
			%11 = load i3, i3* @fpu_stat_TOP
			%12 = add i3 %11, 1
			store i3 %12, i3* @fpu_stat_TOP
			%13 = call x86_fp80 @__frontend_reg_load.fpr(i3 %11)
			%14 = call x86_fp80 @__frontend_reg_load.fpr(i3 %12)
			%15 = fmul x86_fp80 %13, %14
			%16 = fcmp oeq x86_fp80 %15, 0xK00000000000000000000
			%17 = select i1 %16, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %11, i2 -1)
			call void @__frontend_reg_store.fpu_tag(i3 %12, i2 %17)
			call void @__frontend_reg_store.fpr(i3 %12, x86_fp80 %15)

			; return result in st(0)
			%18 = load i3, i3* @fpu_stat_TOP
			%19 = call x86_fp80 @__frontend_reg_load.fpr(i3 %18)
			%20 = fptrunc x86_fp80 %19 to double
			ret double %20
		}

		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
			;; FPU_TOP=8
			%0 = call double @foo(double 1.000000e+00, double 2.000000e+00)
			;; FPU_TOP=7

			; FPU_TOP = 6
			; st(1)=1.000000e+00, st(0) = %0
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double 1.000000e+00 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 %5)
			call void @__frontend_reg_store.fpr(i3 %2, x86_fp80 %3)

			; FPU_TOP = 7
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = add i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %6, i2 -1)

			; FPU_TOP = 8
			%8 = load i3, i3* @fpu_stat_TOP
			%9 = add i3 %8, 1
			store i3 %9, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %8, i2 -1)

			ret i32 0
		}
)";
const std::string X86_32_64BIT_TEST_RESULT_EXPECTED = R"(
		define double @foo(double %arg0, double %arg1) {
			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double %arg0 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			store i2 %5, i2* @fpu_tag_0
			store x86_fp80 %3, x86_fp80* @st0
			%6 = load i3, i3* @fpu_stat_TOP
			%7 = sub i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			%8 = fpext double %arg1 to x86_fp80
			%9 = fcmp oeq x86_fp80 %8, 0xK00000000000000000000
			%10 = select i1 %9, i2 1, i2 0
			store i2 %10, i2* @fpu_tag_1
			store x86_fp80 %8, x86_fp80* @st1
			%11 = load i3, i3* @fpu_stat_TOP
			%12 = add i3 %11, 1
			store i3 %12, i3* @fpu_stat_TOP
			%13 = load x86_fp80, x86_fp80* @st1
			%14 = load x86_fp80, x86_fp80* @st0
			%15 = fmul x86_fp80 %13, %14
			%16 = fcmp oeq x86_fp80 %15, 0xK00000000000000000000
			%17 = select i1 %16, i2 1, i2 0
			store i2 -1, i2* @fpu_tag_1
			store i2 %17, i2* @fpu_tag_0
			store x86_fp80 %15, x86_fp80* @st0
			%18 = load i3, i3* @fpu_stat_TOP
			%19 = load x86_fp80, x86_fp80* @st0
			%20 = fptrunc x86_fp80 %19 to double
			ret double %20
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
			%0 = call double @foo(double 1.000000e+00, double 2.000000e+00)

			%1 = load i3, i3* @fpu_stat_TOP
			%2 = sub i3 %1, 1
			store i3 %2, i3* @fpu_stat_TOP
			%3 = fpext double 1.000000e+00 to x86_fp80
			%4 = fcmp oeq x86_fp80 %3, 0xK00000000000000000000
			%5 = select i1 %4, i2 1, i2 0
			store i2 %5, i2* @fpu_tag_1
			store x86_fp80 %3, x86_fp80* @st1

			%6 = load i3, i3* @fpu_stat_TOP
			%7 = add i3 %6, 1
			store i3 %7, i3* @fpu_stat_TOP
			store i2 -1, i2* @fpu_tag_1

			%8 = load i3, i3* @fpu_stat_TOP
			%9 = add i3 %8, 1
			store i3 %9, i3* @fpu_stat_TOP
			store i2 -1, i2* @fpu_tag_0

			ret i32 0
		}
)";
};

void X87FpuAnalysisTests::setX86Environment(std::string architecture, std::string callingConvention)
{
	config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : )" + architecture + R"(,
			"endian" : "little",
			"name" : "x86"
		},
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"callingConvention" : ")" + callingConvention + R"(",
				"startAddr" : "0x1000",
				"name" : "main"
			},
			{
				"callingConvention" : ")" + callingConvention + R"(",
				"name" : "foo"
			},
			{
				"callingConvention" : ")" + callingConvention + R"(",
				"name" : "boo"
			}
		]
	})");


	config.setLlvmX87TagStorePseudoFunction(getFunctionByName("__frontend_reg_store.fpu_tag"));
	config.setLlvmX87DataStorePseudoFunction(getFunctionByName("__frontend_reg_store.fpr"));
	config.setLlvmX87TagLoadPseudoFunction(getFunctionByName("__frontend_reg_load.fpu_tag"));
	config.setLlvmX87DataLoadPseudoFunction(getFunctionByName("__frontend_reg_load.fpr"));

	abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X87_REG_TOP, getGlobalByName("fpu_stat_TOP"));

	unsigned numberOfFpuRegisters = 8;
	for (unsigned i = 0; i < numberOfFpuRegisters; i++)
	{
		abi->addRegister(X86_REG_ST0 + i, getGlobalByName("st"+std::to_string(i)));
		abi->addRegister(X87_REG_TAG0 + i, getGlobalByName("fpu_tag_"+std::to_string(i)));
	}
}

//
// Architecture: 		16bit
// Calling convention: 	cdecl
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_16bit_cdecl)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST);

	setX86Environment("16", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_cdecl

//
// Architecture: 		16bit
// Calling convention: 	pascal
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_16bit_pascal)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST);

	setX86Environment("16", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_pascal

//
// Architecture: 		16bit
// Calling convention: 	fastcall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_16bit_fastcall)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST);

	setX86Environment("16", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_16BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_fastcall

// TODO 16bit watcom call convention

//
// Architecture: 		32bit
// Calling convention: 	cdecl
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_cdecl)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("32", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_cdecl

//
// Architecture: 		32bit
// Calling convention: 	stdcall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_stdcall)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("32", "stdcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_stdcall

//
// Architecture: 		32bit
// Calling convention: 	pascal
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_pascal)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("32", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_pascal

//
// Architecture: 		32bit
// Calling convention: 	fastcall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_fastcall)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("32", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
}

//
// Architecture: 		32bit
// Calling convention: 	thiscall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_thiscall)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("32", "thiscall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_fastcall // x86_32bit_thiscall

// TODO 32bit watcom call convention test

//
// Architecture: 		64bit
// Calling convention: 	x64 windows, linux, bsd, mac
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_64bit_x64_windows_linux_bsd_mac)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST);

	setX86Environment("64", "x64");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_64bit_x64_windows_linux_bsd_mac


TEST_F(X87FpuAnalysisTests, x86_workbench)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define i32 @foo() {
		bb:
			%0 = call i32 @boo()
			ret i32 %0
		}

		define i32 @boo() {
		bb:
			%0 = call i32 @moo()
			ret i32 %0
		}

		define i32 @moo() {
			ret i32 1
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
			%0 = call i32 @foo()
			ret i32 0
		}

)");

	setX86Environment("32", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + X86_32_64BIT_TEST_RESULT_EXPECTED;
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_64bit_x64_windows_linux_bsd_mac

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
