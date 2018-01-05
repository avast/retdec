/**
* @file tests/bin2llvmir/utils/tests/simplifycfg_tests.cpp
* @brief Tests for the @c CFGSimplifyPass pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* This is checking that LLVM's -simplifycfg is behaving as expected.
* If this fails, something in LLVM changed and we need to react, because
* otherwise it will start to screw up our code.
*/

#include "../lib/Transforms/Scalar/SimplifyCFGPass.cpp"
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
class CFGSimplifyPassTests: public LlvmIrTests
{
	protected:
		void runOnModule()
		{
			LlvmIrTests::runOnModule<CFGSimplifyPass>();
		}
};

TEST_F(CFGSimplifyPassTests, unreachableBasicBlocksKeep)
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
		  store volatile i64 123, i64* @llvm2asm, !asm !1
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

TEST_F(CFGSimplifyPassTests, unreachableBasicBlocksRemove)
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
		  store volatile i64 123, i64* @llvm2asm, !asm !0
		  ret void
		}

		!0 = !{!"name", i64 123, i64 10, !"asm", !"annotation"}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
