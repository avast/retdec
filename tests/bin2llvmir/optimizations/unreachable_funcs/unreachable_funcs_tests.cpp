/**
* @file tests/bin2llvmir/optimizations/unreachable_funcs/tests/unreachable_funcs_tests.cpp
* @brief Tests for the @c NeverReturningFuncs pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

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
class UnreachableFuncsTests: public LlvmIrTests
{
	protected:
		void runOnModule()
		{
			LlvmIrTests::runOnModule<UnreachableFuncs>();
		}
};

TEST_F(UnreachableFuncsTests, addressOfFunc01)
{
	parseInput(R"(
		; Address of functions is taken. So don't optimize these functions.

		@fmt = private constant [4 x i8] c"%p\0A\00"
		@glob = internal unnamed_addr global i32* bitcast (void ()* @func2 to i32*)

		declare i32 @printf(i8*, ...)

		; Can't be optimized, address of this function is taken.
		define void @func1() {
		bb:
		  ret void
		}

		; Can't be optimized, address of this function is taken.
		define void @func2() {
		bb:
		  ret void
		}

		; Can be optimized.
		define void @func3() {
		bb:
		  ret void
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %x = load i32*, i32** @glob
		  %tmp = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @fmt, i32 0, i32 0), i32* bitcast (void ()* @func1 to i32*))
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		@fmt = private constant [4 x i8] c"%p\0A\00"
		@glob = internal unnamed_addr global i32* bitcast (void ()* @func2 to i32*)

		declare i32 @printf(i8*, ...)

		define void @func1() {
		bb:
		  ret void
		}

		define void @func2() {
		bb:
		  ret void
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %x = load i32*, i32** @glob
		  %tmp = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @fmt, i32 0, i32 0), i32* bitcast (void ()* @func1 to i32*))
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, funcInGlobalVarInit)
{
	parseInput(R"(
		; Checks that a function is not marked as unreachable (= removed) when it is
		; used in the initializer of a global variable.

		%vtable_type = type { i32 (i32)* }

		@vtable = global %vtable_type { i32 (i32)* @handle }

		; Even though this function is unreachable, we cannot remove it since it is
		; used in the initializer of the global variable above.
		define i32 @handle(i32 %i) {
		  ret i32 %i
		}

		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		%vtable_type = type { i32 (i32)* }

		@vtable = global %vtable_type { i32 (i32)* @handle }

		define i32 @handle(i32 %i) {
		  ret i32 %i
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, indirectCall01)
{
	parseInput(R"(
		; Testing the indirect call of function.

		@glob0 = internal global i32 5, align 4

		; Can't be called indirectly. Different type. So remove.
		define void @func1(i32 %a) #0 {
		bb:
		  call void @calledFromIndirectlyCalledFunc()
		  ret void
		}

		; Can't be called indirectly. Different type. So remove.
		define void @func2(i32 %a) #0 {
		bb:
		  ret void
		}

		; Can be called indirectly. So don't remove.
		define i32 @func3(i32 %a) #0 {
		bb:
		  call void @calledFromIndirectlyCalledFunc()
		  ret i32 0
		}

		; Is called from indirectly called function. So don't remove.
		define i32 @funcCalledFromIndirectlyCalledFunction() #0 {
		bb:
		  call void @funcLast()
		  ret i32 0
		}

		; The last function that can be called. So don't remove.
		define void @funcLast() {
		bb:
		  ret void
		}

		; Can't be optimized because this function is called
		; from potential indirectly called function that can't
		; be removed.
		define void @calledFromIndirectlyCalledFunc() {
		bb:
		  br label %bb1
		bb1:
		  %tmp1 = phi i32 (...)* [ bitcast (i32 ()* @funcCalledFromIndirectlyCalledFunction to i32 (...)*), %bb ]
		  %tmp2 = bitcast i32 (...)* %tmp1 to i32 (...)*
		  %tmp3 = call i32 (...) %tmp2() #2
		  ret void
		}

		; Has more than one argument so we know that this function is not called indirectly. So remove.
		define i32 @func4(i32 %a, i32 %b) #0 {
		bb:
		  ret i32 0
		}

		; Can't be called indirectly. Different return type. So remove.
		define void @funcVarArg1(i32, ...) #0 {
		bb:
		  ret void
		}

		; Can be called indirectly. So don't remove.
		define i32 @funcVarArg2(i32, ...) #0 {
		bb:
		  ret i32 0
		}

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func3 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func3 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5, align 4

		define i32 @func3(i32 %a) {
		bb:
		  call void @calledFromIndirectlyCalledFunc()
		  ret i32 0
		}

		define i32 @funcCalledFromIndirectlyCalledFunction() {
		bb:
		  call void @funcLast()
		  ret i32 0
		}

		define void @funcLast() {
		bb:
		  ret void
		}

		define void @calledFromIndirectlyCalledFunc() {
		bb:
		  br label %bb1

		bb1:                                              ; preds = %bb
		  %tmp1 = phi i32 (...)* [ bitcast (i32 ()* @funcCalledFromIndirectlyCalledFunction to i32 (...)*), %bb ]
		  %tmp2 = bitcast i32 (...)* %tmp1 to i32 (...)*
		  %tmp3 = call i32 (...) %tmp2()
		  ret void
		}

		define i32 @funcVarArg2(i32, ...) {
		bb:
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func3 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func3 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, mainAndFuncs01)
{
	parseInput(R"(
		; Main function and two functions that are not called.

		; Can be optimized.
		define void @func1() {
		bb:
		  ret void
		}

		; Can be optimized.
		define void @func2() {
		bb:
		  ret void
		}

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, mainAndFuncs02)
{
	parseInput(R"(
		; Main function and two functions that are not called with definition.
		; One function without definition that is not called.

		; Can be optimized.
		define void @func1() {
		bb:
		  call void @func2()
		  ret void
		}

		; Can be optimized.
		define void @func2() {
		bb:
		  call void @func1()
		  call void @func3()
		  ret void
		}

		; Can't be optimized.
		declare void @func3()

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		declare void @func3()

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, mainAndFuncs03)
{
	parseInput(R"(
		; Main function and two functions that are called with definition.
		; One function without definition is called.

		; Can't be optimized.
		define void @func1() {
		bb:
		  ret void
		}

		; Can't be optimized.
		define void @func2() {
		bb:
		  ret void
		}

		; Can't be optimized.
		declare void @func3()

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call void @func1()
		  call void @func2()
		  call void @func3()
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		define void @func1() {
		bb:
		  ret void
		}

		define void @func2() {
		bb:
		  ret void
		}

		declare void @func3()

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  call void @func1()
		  call void @func2()
		  call void @func3()
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, mainAndFuncs04)
{
	parseInput(R"(
		; Main function calls function and that function calls another function.
		; One function is not called.

		; Can't be optimized.
		define void @func1() {
		bb:
		  call void @func2()
		  ret void
		}

		; Can't be optimized.
		define void @func2() {
		bb:
		  ret void
		}

		; Can be optimized.
		define void @func3() {
		bb:
		  ret void
		}

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call void @func1()
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		define void @func1() {
		bb:
		  call void @func2()
		  ret void
		}

		define void @func2() {
		bb:
		  ret void
		}

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  call void @func1()
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, mainOnlyDeclaration)
{
	parseInput(R"(
		; When the main function is just a declaration (i.e. it has no body), behave
		; like there is no main function. This is needed when decompiling shared
		; libraries containing an import of main.

		; Can't be optimized (see above).
		define void @func() {
		bb:
		  ret void
		}

		; Can't be optimized.
		declare i32 @main(i32 %arg1, i8** nocapture %arg2)
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		define void @func() {
		bb:
		  ret void
		}

		declare i32 @main(i32, i8** nocapture)
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, noMain01)
{
	parseInput(R"(
		; No main. Nothing to remove.

		; Can't be optimized.
		define i32 @func() {
		bb0:
		  br label %bb1

		bb1:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @func() {
		bb0:
		  br label %bb1

		bb1:                                              ; preds = %bb0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, noMain02)
{
	parseInput(R"(
		; No main. Nothing to remove. Contains declared function that can't be optimized.

		; Can't be optimized.
		define i32 @func1() {
		bb0:
		  br label %bb1

		bb1:
		  ret i32 0
		}

		; Can't be optimized.
		declare void @func2()
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @func1() {
		bb0:
		  br label %bb1

		bb1:                                              ; preds = %bb0
		  ret i32 0
		}

		declare void @func2()
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, onlyMain01)
{
	parseInput(R"(
		; Only main function. Nothing to remove to remove.

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(UnreachableFuncsTests, onlyMain02)
{
	parseInput(R"(
		; Only main function and some declarations. Nothing to remove to remove.

		; Can't be optimized.
		declare void @func()

		; Can't be optimized.
		declare void @func2()

		; Can't be optimized.
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  ret i32 0
		}
	)");
	ConfigProvider::addConfigJsonString(module.get(), R"({
		"mainAddress" : "0x1000",
		"functions" :
		[
			{
				"startAddr" : "0x1000",
				"name" : "main"
			}
		]
	})");

	runOnModule();

	std::string exp = R"(
		declare void @func()

		declare void @func2()

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
