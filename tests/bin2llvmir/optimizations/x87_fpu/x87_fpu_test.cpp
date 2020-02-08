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
}; //X87FpuAnalysisTests

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

// Architecture: 		16bit
// Calling convention: 	cdecl
// Operation:			Call function with floating-point return value.

TEST_F(X87FpuAnalysisTests, x86_16bit_cdecl_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			; ...
			;; push st(0)
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			; ...
			; let assume here that st(0) is saved in memory and addr is stored to AX -> 16bit cdecl convention
			; ...
			;; pop st(0)
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			; ...
			ret void
		}
		define void @boo() {
		bb:
			; ...
			call void @foo()
			; fp return value is saved in memory and addr is in AX -> 16bit cdecl convention
			; ...
			ret void
		})");

	setX86Environment("16", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_cdecl_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_cdecl_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			; ...
			call void @foo()
			; ...
			ret void
		}
		define void @foo() {
		bb:
			; ...
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			; ...
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			; ...
			ret void
		})");

		setX86Environment("16", "cdecl");
		bool b = pass.runOnModuleCustom(*module, &config, abi);

		std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_cdecl_call_of_not_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_cdecl_analyze_fail)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("16", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_FALSE(b);
} // x86_16bit_cdecl_analyze_fail

// Architecture: 		16bit
// Calling convention: 	pascal
// Operation:			Call function with floating-point return value.

TEST_F(X87FpuAnalysisTests, x86_16bit_pascal_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			ret void
		})");

	setX86Environment("16", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_pascal_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_pascal_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("16", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_pascal_call_of_not_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_pascal_analyze_fail)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("16", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_FALSE(b);
} // x86_16bit_cdecl_analyze_fail

//
// Architecture: 		16bit
// Calling convention: 	fastcall
// Operation:			Call function returning floating-point value.
//

TEST_F(X87FpuAnalysisTests, x86_16bit_fastcall_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			ret void
		})");

	setX86Environment("16", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_fastcall_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_fastcall_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("16", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_16bit_fastcall_call_of_not_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_16bit_fastcall_analyze_fail)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("16", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_FALSE(b);
} // x86_16bit_fastcall_analyze_fail

//
// Architecture: 		16bit
// Calling convention: 	watcom
// Operation:			Call function returning floating-point value.
//
TEST_F(X87FpuAnalysisTests, x86_16bit_watcom)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			ret void
		})");

	setX86Environment("16", "watcom");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_TRUE(b);
} // x86_16bit_watcom

//
// Architecture: 		32bit
// Calling convention: 	cdecl
// Operation:			Call function with floating-point return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_cdecl_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_cdecl_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_32bit_cdecl_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "cdecl");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_cdecl_call_of_not_analyzed_function_success


//
// Architecture: 		32bit
// Calling convention: 	stdcall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_stdcall_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "stdcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_stdcall_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_32bit_stdcall_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "stdcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_stdcall_call_of_not_analyzed_function_success

//
// Architecture: 		32bit
// Calling convention: 	pascal
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_pascal_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_pascal_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_32bit_pascal_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "pascal");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_pascal_call_of_not_analyzed_function_success

//
// Architecture: 		32bit
// Calling convention: 	fastcall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_fastcall_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_fastcall_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_32bit_fastcall_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "fastcall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_fastcall_call_of_not_analyzed_function_success

//
// Architecture: 		32bit
// Calling convention: 	thiscall
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_thiscall_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "thiscall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_thiscall_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_32bit_thiscall_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "thiscall");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = load x86_fp80, x86_fp80* @st0
		  %2 = add i3 %0, 1
		  store i3 %2, i3* @fpu_stat_TOP
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_thiscall_call_of_not_analyzed_function_success

//
// Architecture: 		32bit
// Calling convention: 	watcom
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_watcom)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "watcom");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_FALSE(b);
} // x86_32bit_watcom

//
// Architecture: 		32bit
// Calling convention: 	unknown
// Operation:			Call function without floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_32bit_analyze_not_FP_return_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			%2 = load i3, i3* @fpu_stat_TOP
			call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
			%3 = add i3 %2, 1
			store i3 %3, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			ret void
		})");

	setX86Environment("32", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  store i2 -1, i2* @fpu_tag_0
		  %3 = add i3 %2, 1
		  store i3 %3, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_32bit_analyze_not_FP_return_success

TEST_F(X87FpuAnalysisTests, x86_32bit_analyze_not_FP_return_fail)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			ret void
		}
		define void @boo() {
		bb:
			;FPU stack is empty => foo return type is not FP
			call void @foo()
			; this call of foo behave like it retun value is FP
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = call x86_fp80 @__frontend_reg_load.fpr(i3 %0)
			%2 = add i3 %0, 1
			store i3 %2, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("32", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);
	EXPECT_FALSE(b);
} // x86_32bit_analyze_not_FP_return_fail

//
// Architecture: 		64bit
// Calling convention: 	x64 windows, linux, bsd, mac
// Operation:			Call function with floating-point arguments and return value.
//

TEST_F(X87FpuAnalysisTests, x86_64bit_call_of_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			; ...
			%2 = load i3, i3* @fpu_stat_TOP
			%3 = call x86_fp80 @__frontend_reg_load.fpr(i3 %2); this val will be saved to xmm0
			%4 = add i3 %2, 1
			store i3 %4, i3* @fpu_stat_TOP
			ret void
		}
		define void @boo() {
		bb:
			call void @foo()
			ret void
		})");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  %3 = load x86_fp80, x86_fp80* @st0
		  %4 = add i3 %2, 1
		  store i3 %4, i3* @fpu_stat_TOP
		  ret void
		}
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_64bit_call_of_analyzed_function_success

TEST_F(X87FpuAnalysisTests, x86_64bit_call_of_not_analyzed_function_success)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
			call void @foo()
			ret void
		}
		define void @foo() {
		bb:
			%0 = load i3, i3* @fpu_stat_TOP
			%1 = sub i3 %0, 1
			call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
			call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
			store i3 %1, i3* @fpu_stat_TOP
			; ...
			%2 = load i3, i3* @fpu_stat_TOP
			%3 = call x86_fp80 @__frontend_reg_load.fpr(i3 %2); this val will be saved to xmm0
			%4 = add i3 %2, 1
			store i3 %4, i3* @fpu_stat_TOP
			ret void
		})");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @boo() {
		bb:
		  call void @foo()
		  ret void
		}
		define void @foo() {
		bb:
		  %0 = load i3, i3* @fpu_stat_TOP
		  %1 = sub i3 %0, 1
		  store i2 0, i2* @fpu_tag_0
		  store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
		  store i3 %1, i3* @fpu_stat_TOP
		  %2 = load i3, i3* @fpu_stat_TOP
		  %3 = load x86_fp80, x86_fp80* @st0
		  %4 = add i3 %2, 1
		  store i3 %4, i3* @fpu_stat_TOP
		  ret void
		})";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // x86_64bit_call_of_not_analyzed_function_success

//
// BRANCH AND LOOPS
//

TEST_F(X87FpuAnalysisTests, if_branch_or_loop)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_true, label %dec_label_end_branch
			dec_label_if_true:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
				call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		})");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_true, label %dec_label_end_branch
			dec_label_if_true:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				store i2 0, i2* @fpu_tag_0
				store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				store i2 -1, i2* @fpu_tag_0
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // if_branch

TEST_F(X87FpuAnalysisTests, if_else_branch)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_true, label %dec_label_if_false
			dec_label_if_true:
				br label %dec_label_end_branch
			dec_label_if_false:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
				call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_true, label %dec_label_if_false
			dec_label_if_true:
				br label %dec_label_end_branch
			dec_label_if_false:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				store i2 0, i2* @fpu_tag_0
				store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				store i2 -1, i2* @fpu_tag_0
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // if_else_branch

TEST_F(X87FpuAnalysisTests, if_elseif_else_branch_or_switch)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_then_true, label %dec_label_if_then_false
			dec_label_if_then_true:
				br label %dec_label_end_branch
			dec_label_if_then_false:
			br i1 1, label %dec_label_else_if_true, label %dec_label_else_if_false
			dec_label_else_if_true:
				br label %dec_label_end_branch
			dec_label_else_if_false:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
				call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_then_true, label %dec_label_if_then_false
			dec_label_if_then_true:
				br label %dec_label_end_branch
			dec_label_if_then_false:
			br i1 1, label %dec_label_else_if_true, label %dec_label_else_if_false
			dec_label_else_if_true:
				br label %dec_label_end_branch
			dec_label_else_if_false:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				store i2 0, i2* @fpu_tag_0
				store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
				store i3 %1, i3* @fpu_stat_TOP
				%2 = load i3, i3* @fpu_stat_TOP
				store i2 -1, i2* @fpu_tag_0
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // if_elseif_else_branch

TEST_F(X87FpuAnalysisTests, nested_branch)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
			A:
				br i1 1, label %B, label %C
			B:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
				call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
				store i3 %1, i3* @fpu_stat_TOP
				br i1 1, label %D, label %E
			D:
				%2 = load i3, i3* @fpu_stat_TOP
				%3 = call x86_fp80 @__frontend_reg_load.fpr(i3 %2)
				br label %E
			E:
				%4 = load i3, i3* @fpu_stat_TOP
				%5 = add i3 %4, 1
				store i3 %5, i3* @fpu_stat_TOP
				br label %C
			C:
			ret void
		}
)");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
			A:
				br i1 1, label %B, label %C
			B:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				store i2 0, i2* @fpu_tag_0
				store x86_fp80 0xK3FFF8000000000000000, x86_fp80* @st0
				store i3 %1, i3* @fpu_stat_TOP
				br i1 1, label %D, label %E
			D:
				%2 = load i3, i3* @fpu_stat_TOP
				%3 = load x86_fp80, x86_fp80* @st0
				br label %E
			E:
				%4 = load i3, i3* @fpu_stat_TOP
				%5 = add i3 %4, 1
				store i3 %5, i3* @fpu_stat_TOP
				br label %C
			C:
			ret void
		}
)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
} // nested_branch

TEST_F(X87FpuAnalysisTests, if_else_branch_fail)
{
	parseInput(PREDEFINED_REGISTERS_AND_FUNCTIONS + R"(
		define void @foo() {
		bb:
			br i1 1, label %dec_label_if_true, label %dec_label_if_false
			dec_label_if_true:
				%0 = load i3, i3* @fpu_stat_TOP
				%1 = sub i3 %0, 1
				call void @__frontend_reg_store.fpu_tag(i3 %1, i2 0)
				call void @__frontend_reg_store.fpr(i3 %1, x86_fp80 0xK3FFF8000000000000000)
				store i3 %1, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_if_false:
				%2 = load i3, i3* @fpu_stat_TOP
				call void @__frontend_reg_store.fpu_tag(i3 %2, i2 -1)
				%3 = add i3 %2, 1
				store i3 %3, i3* @fpu_stat_TOP
				br label %dec_label_end_branch
			dec_label_end_branch:
			ret void
		}
)");

	setX86Environment("64", "unknown");
	bool b = pass.runOnModuleCustom(*module, &config, abi);

	EXPECT_FALSE(b);
} // if_else_branch_fail

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
