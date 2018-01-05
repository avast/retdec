/**
* @file tests/bin2llvmir/optimizations/never_returning_funcs/tests/never_returning_funcs_tests.cpp
* @brief Tests for the @c NeverReturningFuncs pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/never_returning_funcs/never_returning_funcs.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c ParamReturn pass.
 */
class NeverReturningFuncsTests: public LlvmIrTests
{
	protected:
		NeverReturningFuncs pass;
};

TEST_F(NeverReturningFuncsTests, funcNeverReturns01)
{
	parseInput(R"(
		; Main function with call of all functions that never returns.

		; Function that never returns.
		declare void @exit(i32 %status)

		; Function that never returns.
		declare void @abort()

		; Function that never returns. First parameter is so hard to simulate
		; so use any type.
		declare void @longjmp(i32 %env, i32 %val);

		; Function that never returns.
		declare void @_Exit(i64 %status);

		; Function that never returns.
		declare void @quick_exit(i32 %status);

		; Function that never returns.
		declare void @thrd_exit(i32 %res);

		; Function that never returns.
		declare void @ExitProcess(i32 %res);

		; Function that never returns.
		declare void @ExitThread(i32 %res);

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @longjmp(i32 1, i32 2)
		  br i1 1, label %left, label %right

		left:
		  call void @thrd_exit(i32 2);
		  br label %left1

		right:
		  call void @exit(i32 2)
		  %x = add i32 0, 2
		  call void @abort()
		  br label %right1

		left1:
		  call void @_Exit(i64 3)
		  br label %left2

		right1:
		  call void @quick_exit(i32 2)
		  br label %right2

		left2:
		  call void @ExitProcess(i32 2)
		  ret i32 0

		right2:
		  call void @ExitThread(i32 2)
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		declare void @exit(i32)

		declare void @abort()

		declare void @longjmp(i32, i32)

		declare void @_Exit(i64)

		declare void @quick_exit(i32)

		declare void @thrd_exit(i32)

		declare void @ExitProcess(i32)

		declare void @ExitThread(i32)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @longjmp(i32 1, i32 2)
		  unreachable

		left:                                             ; No predecessors!
		  call void @thrd_exit(i32 2)
		  unreachable

		right:                                            ; No predecessors!
		  call void @exit(i32 2)
		  unreachable

		left1:                                            ; No predecessors!
		  call void @_Exit(i64 3)
		  unreachable

		right1:                                           ; No predecessors!
		  call void @quick_exit(i32 2)
		  unreachable

		left2:                                            ; No predecessors!
		  call void @ExitProcess(i32 2)
		  unreachable

		right2:                                           ; No predecessors!
		  call void @ExitThread(i32 2)
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(NeverReturningFuncsTests, funcNeverReturns02)
{
	parseInput(R"(
		; Main function with call of function that never returns.
		; But PHI node is used in basic block which is jumped by
		; branch instruction so is need to remove predecessor basic
		; block.

		; Function that never returns.
		declare void @exit(i32 %status)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br i1 1, label %left, label %right

		left:
		  call void @exit(i32 2)
		  br label %main1

		right:
		  br label %main1

		main1:
		  %X = phi i32 [ 1, %left ], [ 2 , %right ]
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		declare void @exit(i32)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main0
		  call void @exit(i32 2)
		  unreachable

		right:                                            ; preds = %main0
		  br label %main1

		main1:                                            ; preds = %right
		  %X = phi i32 [ 2, %right ]
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(NeverReturningFuncsTests, funcNeverReturns03)
{
	parseInput(R"(
		; Main function with call of functin that never returns. Also tests if phi instruction
		; is removed correctly because last basic block predecessor was removed.

		; Function that never returns.
		declare void @exit(i32 %status)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @exit(i32 1)
		  br label %main1

		main1:
		  %A = phi i32 [ 1, %main0]
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		declare void @exit(i32)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @exit(i32 1)
		  unreachable

		main1:                                            ; No predecessors!
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(NeverReturningFuncsTests, funcNeverReturnsIncorrectTypes01)
{
	parseInput(R"(
		; Main function with call of all functions that have name of functions
		; that never returns but has different return type or different parameters types.

		; Function that returns. Missing parameter.
		declare void @exit()

		; Function that returns. Bad return type.
		declare i32 @abort()

		; Function that returns. Different second parameter.
		declare void @longjmp(i32 %env, double %val);

		; Function that returns. Different return type.
		declare double @_Exit(i64 %status);

		; Function that returns. Different return type.
		declare i32 @quick_exit(i32 %status);

		; Function that returns. Has more than one standard parameter.
		declare void @thrd_exit(i32 %res, i32 %sec);

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @longjmp(i32 1, double 2.0)
		  br i1 1, label %left, label %right

		left:
		  call void @thrd_exit(i32 2, i32 2);
		  br label %left1

		right:
		  call void @exit()
		  %x = add i32 0, 2
		  call i32 @abort()
		  br label %right1

		left1:
		  call double @_Exit(i64 3)
		  ret i32 0

		right1:
		  call i32 @quick_exit(i32 2)
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		declare void @exit()

		declare i32 @abort()

		declare void @longjmp(i32, double)

		declare double @_Exit(i64)

		declare i32 @quick_exit(i32)

		declare void @thrd_exit(i32, i32)

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @longjmp(i32 1, double 2.000000e+00)
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main0
		  call void @thrd_exit(i32 2, i32 2)
		  br label %left1

		right:                                            ; preds = %main0
		  call void @exit()
		  %x = add i32 0, 2
		  %0 = call i32 @abort()
		  br label %right1

		left1:                                            ; preds = %left
		  %1 = call double @_Exit(i64 3)
		  ret i32 0

		right1:                                           ; preds = %right
		  %2 = call i32 @quick_exit(i32 2)
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(NeverReturningFuncsTests, funcNeverReturnsWithDef01)
{
	parseInput(R"(
		; Main function with call of all functions that has type and name
		; as function that never returns but have definition.

		; Function that returns because have definition.
		define void @exit(i32 %status) {
		  ret void
		}

		; Function that returns because have definition.
		define void @abort() {
		  ret void
		}

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br i1 1, label %left, label %right

		left:
		  call void @abort()
		  ret i32 0

		right:
		  call void @exit(i32 2)
		  %x = add i32 0, 2
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		define void @exit(i32 %status) {
		  ret void
		}

		define void @abort() {
		  ret void
		}

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main0
		  call void @abort()
		  ret i32 0

		right:                                            ; preds = %main0
		  call void @exit(i32 2)
		  %x = add i32 0, 2
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(NeverReturningFuncsTests, funcReturns01)
{
	parseInput(R"(
		; Main function with call of normal function. Nothing to optimize.

		; Normal function that returns.
		define void @func(i32 %status) {
		  ret void
		}

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @func(i32 2)
		  ret i32 0
		}
	)");

	runOnFunctionCustom(pass, module.get());

	std::string exp = R"(
		define void @func(i32 %status) {
		  ret void
		}

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call void @func(i32 2)
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
