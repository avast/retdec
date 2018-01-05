/**
* @file tests/bin2llvmir/utils/tests/instcombine_tests.cpp
* @brief Tests for the @c InstructionCombiningPass pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* This is checking that LLVM's -instcombine is behaving as expected.
* If this fails, something in LLVM changed and we need to react, because
* otherwise it will start to screw up our code.
*/

#include <llvm/Transforms/InstCombine/InstCombine.h>

#include "retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c UnreachableFuncs pass.
 */
class InstCombinePassTests: public LlvmIrTests
{
	protected:
		void runOnModule()
		{
			LlvmIrTests::runOnModule<InstructionCombiningPass>();
		}
};

TEST_F(InstCombinePassTests, doNotUnpackStoresToAggregates)
{
	parseInput(R"(
		; We do not want -instcombine to optimize
		;
		;     store [10000 x %V] %a, [10000 x %V]* %b
		;
		; into
		;
		;     b[0] = a[0]
		;     b[1] = a[1]
		;     b[2] = a[2]
		;     ...
		;     b[9999] = a[9999]
		;
		; See commit 1e0c8e9af462d54622b6a986e170d858fdabf5df.

		%V = type { i32, i32, i32, float }

		declare [10000 x %V] @decompiler_undefined_function()
		declare void @decompiler_prevent_removal([10000 x %V]*)

		define i32 @main(i32 %argc, i8** %argv) {
		  %a = alloca [10000 x %V]
		  %a_x = call [10000 x %V] @decompiler_undefined_function()
		  store [10000 x %V] %a_x, [10000 x %V]* %a
		  call void @decompiler_prevent_removal([10000 x %V]* %a)
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		%V = type { i32, i32, i32, float }

		declare [10000 x %V] @decompiler_undefined_function()

		declare void @decompiler_prevent_removal([10000 x %V]*)

		define i32 @main(i32 %argc, i8** %argv) {
		  %a = alloca [10000 x %V], align 8
		  %a_x = call [10000 x %V] @decompiler_undefined_function()
		  store [10000 x %V] %a_x, [10000 x %V]* %a, align 8
		  call void @decompiler_prevent_removal([10000 x %V]* nonnull %a)
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstCombinePassTests, handleExpressionInSwitchCondition)
{
	parseInput(R"(
		@gv = global i32 0

		define i32 @fnv() {
		br label %lab_1
		lab_1:
		  %a = add i32 0, 0
		br label %lab_2
		lab_2:
		  switch i32 add (i32 ptrtoint (i32* @gv to i32), i32 -63), label %lab_3 [
			i32 0, label %lab_1
			i32 34, label %lab_2
		  ]
		br label %lab_3
		lab_3:
		  ret i32 123
		}
	)");

	runOnModule();

	std::string exp = R"(
		@gv = global i32 0

		define i32 @fnv() {
		  br label %lab_1

		lab_1:                                            ; preds = %lab_2, %0
		  br label %lab_2

		lab_2:                                            ; preds = %lab_2, %lab_1
		  switch i32 add (i32 ptrtoint (i32* @gv to i32), i32 -63), label %lab_3 [
			i32 0, label %lab_1
			i32 34, label %lab_2
		  ]
														  ; No predecessors!
		  br label %lab_3

		lab_3:                                            ; preds = %1, %lab_2
		  ret i32 123
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstCombinePassTests, unreachableBasicBlocksKeep)
{
	parseInput(R"(
		; Instructions in unreachable BBs are *NOT* removed if metadata named
		; 'llvmToAsmGlobalVariableName' exits.

		@llvm2asm = global i64 0

		define void @fnc() {
				store volatile i64 123, i64* @llvm2asm, !asm !1
				ret void
				store volatile i64 456, i64* @llvm2asm, !asm !2
				ret void
				store volatile i64 789, i64* @llvm2asm, !asm !3
				ret void
		}

		!llvmToAsmGlobalVariableName = !{!0}

		!0 = !{!"llvm2asm"}
		!1 = !{!"name", i64 123, i64 10, !"asm", !"annotation"}
		!2 = !{!"name", i64 456, i64 10, !"asm", !"annotation"}
		!3 = !{!"name", i64 789, i64 10, !"asm", !"annotation"}
	)");

	runOnModule();

	std::string exp = R"(
		@llvm2asm = global i64 0

		define void @fnc() {

		; 7b
		  store volatile i64 123, i64* @llvm2asm, align 8, !asm !1
		  ret void
														  ; No predecessors!

		; 1c8
		  store volatile i64 456, i64* @llvm2asm, !asm !2
		  ret void
														  ; No predecessors!

		; 315
		  store volatile i64 789, i64* @llvm2asm, !asm !3
		  ret void
		}

		!llvmToAsmGlobalVariableName = !{!0}

		!0 = !{!"llvm2asm"}
		!1 = !{!"name", i64 123, i64 10, !"asm", !"annotation"}
		!2 = !{!"name", i64 456, i64 10, !"asm", !"annotation"}
		!3 = !{!"name", i64 789, i64 10, !"asm", !"annotation"}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(InstCombinePassTests, unreachableBasicBlocksRemove)
{
	parseInput(R"(
		; Instructions in unreachable BBs are removed if metadata named
		; 'llvmToAsmGlobalVariableName' does not exit.

		@llvm2asm = global i64 0

		define void @fnc() {
				store volatile i64 123, i64* @llvm2asm, !asm !0
				ret void
				store volatile i64 456, i64* @llvm2asm, !asm !1
				ret void
				store volatile i64 789, i64* @llvm2asm, !asm !2
				ret void
		}

		!0 = !{!"name", i64 123, i64 10, !"asm", !"annotation"}
		!1 = !{!"name", i64 456, i64 10, !"asm", !"annotation"}
		!2 = !{!"name", i64 789, i64 10, !"asm", !"annotation"}
	)");

	runOnModule();

	std::string exp = R"(
		@llvm2asm = global i64 0

		define void @fnc() {

		; 7b
		  store volatile i64 123, i64* @llvm2asm, align 8, !asm !0
		  ret void
														  ; No predecessors!
		  ret void
														  ; No predecessors!
		  ret void
		}

		!0 = !{!"name", i64 123, i64 10, !"asm", !"annotation"}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
