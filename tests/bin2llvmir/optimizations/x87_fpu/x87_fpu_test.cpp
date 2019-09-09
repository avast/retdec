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
	X87FpuAnalysis pass;
	Abi* setEnvironment(Config& config);
};

Abi* X87FpuAnalysisTests::setEnvironment(Config& config)
{
	config = Config::fromJsonString(module.get(), R"({
		"architecture" : {
			"bitSize" : 64,
			"endian" : "little",
			"name" : "x86"
		},
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	auto *st = getFunctionByName("__frontend_reg_store.fpu_tag");
	auto *sd = getFunctionByName("__frontend_reg_store.fpr");
	auto *lt = getFunctionByName("__frontend_reg_load.fpu_tag");
	auto *ld = getFunctionByName("__frontend_reg_load.fpr");
	config.setLlvmX87TagStorePseudoFunction(st);
	config.setLlvmX87DataStorePseudoFunction(sd);
	config.setLlvmX87TagLoadPseudoFunction(lt);
	config.setLlvmX87DataLoadPseudoFunction(ld);

	auto* fpu_stat_TOP = getGlobalByName("fpu_stat_TOP");
	auto* st0 = getGlobalByName("st0");
	auto* st1 = getGlobalByName("st1");
	auto* st2 = getGlobalByName("st2");
	auto* st3 = getGlobalByName("st3");
	auto* st4 = getGlobalByName("st4");
	auto* st5 = getGlobalByName("st5");
	auto* st6 = getGlobalByName("st6");
	auto* st7 = getGlobalByName("st7");
	auto* fpuTag0 = getGlobalByName("fpu_tag_0");
	auto* fpuTag1 = getGlobalByName("fpu_tag_1");
	auto* fpuTag2 = getGlobalByName("fpu_tag_2");
	auto* fpuTag3 = getGlobalByName("fpu_tag_3");
	auto* fpuTag4 = getGlobalByName("fpu_tag_4");
	auto* fpuTag5 = getGlobalByName("fpu_tag_5");
	auto* fpuTag6 = getGlobalByName("fpu_tag_6");
	auto* fpuTag7 = getGlobalByName("fpu_tag_7");
	Abi *abi;
	abi = AbiProvider::addAbi(module.get(), &config);
	abi->addRegister(X87_REG_TOP, fpu_stat_TOP);
	abi->addRegister(X86_REG_ST0, st0);
	abi->addRegister(X86_REG_ST1, st1);
	abi->addRegister(X86_REG_ST2, st2);
	abi->addRegister(X86_REG_ST3, st3);
	abi->addRegister(X86_REG_ST4, st4);
	abi->addRegister(X86_REG_ST5, st5);
	abi->addRegister(X86_REG_ST6, st6);
	abi->addRegister(X86_REG_ST7, st7);
	abi->addRegister(X87_REG_TAG0, fpuTag0);
	abi->addRegister(X87_REG_TAG1, fpuTag1);
	abi->addRegister(X87_REG_TAG2, fpuTag2);
	abi->addRegister(X87_REG_TAG3, fpuTag3);
	abi->addRegister(X87_REG_TAG4, fpuTag4);
	abi->addRegister(X87_REG_TAG5, fpuTag5);
	abi->addRegister(X87_REG_TAG6, fpuTag6);
	abi->addRegister(X87_REG_TAG7, fpuTag7);

	return abi;
}

//
// FMULP st(0), st(1)
//

TEST_F(X87FpuAnalysisTests, fmulp_stack_operation)
{
	parseInput(R"(
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

		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
			%0 = fpext double 1.0 to x86_fp80
			%1 = fpext double 2.0 to x86_fp80
			%2 = fpext double 2.0 to x86_fp80
			%3 = load i3, i3* @fpu_stat_TOP                             ; TOP -> 8
			%4 = sub i3 %3, 1                                           ; TOP -> 7
			%5 = fcmp oeq x86_fp80 %0, 0xK00000000000000000000          ; compute tag based on value to push
			%6 = select i1 %5, i2 1, i2 0                               ; compute tag based on value to push
			call void @__frontend_reg_store.fpu_tag(i3 %4, i2 %6)            ; set computed tag to the next empty tag slot
			call void @__frontend_reg_store.fpr(i3 %4, x86_fp80 %0)          ; set loaded value to the next empty data slot
			%7 = sub i3 %4, 1                                           ; TOP -> 6
			%8 = fcmp oeq x86_fp80 %1, 0xK00000000000000000000          ; compute tag based on value to push
			%9 = select i1 %8, i2 1, i2 0                               ; compute tag based on value to push
			call void @__frontend_reg_store.fpu_tag(i3 %7, i2 %9)            ; set computed tag to the next empty tag slot
			call void @__frontend_reg_store.fpr(i3 %7, x86_fp80 %1)          ; set loaded value to the next empty data slot
			%10 = add i3 %7, 1                                        ; TOP -> 7
			%11 = call x86_fp80 @__frontend_reg_load.fpr(i3 %10)       ; get st(0)
			%12 = call x86_fp80 @__frontend_reg_load.fpr(i3 %7)       ; get st(1)
			%13 = fmul x86_fp80 %11, %12                                ; st(0) * st(1)
			%14 = fcmp oeq x86_fp80 %13, 0xK00000000000000000000       ; compute tag based on value to set
			%15 = select i1 %14, i2 1, i2 0                            ; compute tag based on value to set
			call void @__frontend_reg_store.fpu_tag(i3 %10, i2 %15)    ; set computed tag to st(1) tag slot
			call void @__frontend_reg_store.fpr(i3 %10, x86_fp80 %13)  ; set computed value to st(1)
			call void @__frontend_reg_store.fpu_tag(i3 %7, i2 -1)    ; clear the current TOP tag slot
			store i3 %10, i3* @fpu_stat_TOP                           ; TOP -> 7
		  ret i32 0
		}

		declare void @__frontend_reg_store.fpu_tag(i3, i2)
		declare void @__frontend_reg_store.fpr(i3, x86_fp80)
		declare x86_fp80 @__frontend_reg_load.fpr(i3)
		declare i2 @__frontend_reg_load.fpu_tag(i3)
	)");

	Config config;
	auto abi = setEnvironment(config);

	bool b = pass.runOnModuleCustom(*module, &config, abi);

	std::string exp = R"(
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

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %0 = fpext double 1.000000e+00 to x86_fp80
		  %1 = fpext double 2.000000e+00 to x86_fp80
		  %2 = fpext double 2.000000e+00 to x86_fp80
		  %3 = load i3, i3* @fpu_stat_TOP
		  %4 = sub i3 %3, 1
		  %5 = fcmp oeq x86_fp80 %0, 0xK00000000000000000000
		  %6 = select i1 %5, i2 1, i2 0
		  store i2 %6, i2* @fpu_tag_0
		  store x86_fp80 %0, x86_fp80* @st0
		  %7 = sub i3 %4, 1
		  %8 = fcmp oeq x86_fp80 %1, 0xK00000000000000000000
		  %9 = select i1 %8, i2 1, i2 0
		  store i2 %9, i2* @fpu_tag_1
		  store x86_fp80 %1, x86_fp80* @st1
		  %10 = add i3 %7, 1
		  %11 = load x86_fp80, x86_fp80* @st0
		  %12 = load x86_fp80, x86_fp80* @st1
		  %13 = fmul x86_fp80 %11, %12
		  %14 = fcmp oeq x86_fp80 %13, 0xK00000000000000000000
		  %15 = select i1 %14, i2 1, i2 0
		  store i2 %15, i2* @fpu_tag_0
		  store x86_fp80 %13, x86_fp80* @st0
		  store i2 -1, i2* @fpu_tag_1
		  store i3 %10, i3* @fpu_stat_TOP
		  ret i32 0
		}
)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(b);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
