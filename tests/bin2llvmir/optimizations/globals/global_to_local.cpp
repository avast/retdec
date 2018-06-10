/**
* @file tests/bin2llvmir/optimizations/globals/tests/global_to_local.cpp
* @brief Tests for the @c GlobalToLocal pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/globals/global_to_local.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c UnreachableFuncs pass.
 */
class GlobalToLocalTests: public LlvmIrTests
{
	protected:
		void runOnModule()
		{
			LlvmIrTests::runOnModule<GlobalToLocal>();
		}
};

//
// aggressive (default)
//

TEST_F(GlobalToLocalTests, addrTaken01)
{
	parseInput(R"(
		; Check if global variable whose address is taken is not optimized.

		@glob0 = internal unnamed_addr global i32 0 ; Address taken, not optimize.
		@glob1 = internal unnamed_addr global i32 0 ; Address taken, not optimize.
		@glob2 = internal unnamed_addr global i32 0 ; Address taken, not optimize.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = alloca i32*
		  store i32* @glob2, i32** %x ; Can't optimize. Here is the take of address.
		  br label %main1

		main1:
		  call i32* @alfa(i32* @glob1) ; Can't optimize. Here is the take of address.
		  br label %main2

		main2:
		  %c = load i32*, i32** %x
		  call i32* @alfa(i32* %c)
		  ret i32 0
		}

		define i32* @alfa(i32* %g) {
		alfa1:
		  ret i32* @glob0 ; Can't optimize. Here is the take of address.
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = alloca i32*
		  store i32* @glob2, i32** %x
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32* @alfa(i32* @glob1)
		  br label %main2

		main2:                                            ; preds = %main1
		  %c = load i32*, i32** %x
		  %1 = call i32* @alfa(i32* %c)
		  ret i32 0
		}

		define i32* @alfa(i32* %g) {
		alfa1:
		  ret i32* @glob0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, aggType01)
{
	parseInput(R"(
		; Check if aggregate types like for example structures are not optimized.
		; In this case we don't need to do something with @struct_constant because
		; implementation of this optimization checks if a global variable is an
		; aggregate type and if yes then we can't optimize something for example
		; delete the declaration for this global variable.

		%struct = type { i32, i8 }
		@struct_constant = internal constant %struct { i32 16, i8 4 } ; Aggregate type: structure, not optimize.
		@array = external global [256 x i64], align 8 ; Aggregate type: array, not optimize.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = load i64, i64* getelementptr inbounds ([256 x i64], [256 x i64]* @array, i32 1, i32 0)
		  %z = getelementptr inbounds %struct, %struct* @struct_constant, i32 0, i32 0
		  br label %main1

		main1:
		  br label %main2

		main2:
		  ret i32 0
		}
			)");

			runOnModule();

			std::string exp = R"(
		%struct = type { i32, i8 }

		@struct_constant = internal constant %struct { i32 16, i8 4 }
		@array = external global [256 x i64], align 8

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = load i64, i64* getelementptr inbounds ([256 x i64], [256 x i64]* @array, i32 1, i32 0)
		  %z = getelementptr inbounds %struct, %struct* @struct_constant, i32 0, i32 0
		  br label %main1

		main1:                                            ; preds = %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle01)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0 ; Can be optimized.
		  call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  store i32 8, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  %yy = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0 and store i32 8, i32* @glob0.
		  store i32 3, i32* @glob0 ; Can be optimized.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 2, i32* @glob0 ; Can be optimized.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		define void @top() {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 5, i32* %glob0.global-to-local
		  %0 = call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 8, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* %glob0.global-to-local
		  store i32 3, i32* %glob0.global-to-local
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  store i32 2, i32* %glob0.global-to-local
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle02)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0 ; Can't be optimized. Has use %yy = load i32, i32* @glob0 in another function.
		  call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  %yy = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 5, i32* @glob0.
		  store i32 3, i32* @glob0 ; Can be optimized.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 2, i32* @glob0 ; Can't be optimized, because use %yy = load i32, i32* @glob0 can't be optimized.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0
		  %0 = call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  %glob0.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* @glob0
		  store i32 3, i32* %glob0.global-to-local
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  store i32 2, i32* @glob0
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle03)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal global i32 0

		define i32 @main() {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  %yy = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal global i32 0.
		  store i32 3, i32* @glob0 ; Can be optimized.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 2, i32* @glob0 ; Can be optimized.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main() {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 0, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* %glob0.global-to-local
		  store i32 3, i32* %glob0.global-to-local
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  store i32 2, i32* %glob0.global-to-local
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle04)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency. Cycle dependency is on same basic block.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0 ; Can be optimized.
		  call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  store i32 8, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  br label %cycleBB

		cycleBB:
		  %z = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0 and store i32 8, i32* @glob0.
		  store i32 2, i32* @glob0 ; Can be optimized.
		  %x = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0.
		  br i1 1, label %cycleBB, label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define void @top() {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 5, i32* %glob0.global-to-local
		  %0 = call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 8, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br label %cycleBB

		cycleBB:                                          ; preds = %cycleBB, %main1
		  %z = load i32, i32* %glob0.global-to-local
		  store i32 2, i32* %glob0.global-to-local
		  %x = load i32, i32* %glob0.global-to-local
		  br i1 true, label %cycleBB, label %main2

		main2:                                            ; preds = %cycleBB
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle05)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency. Cycle dependency is on same basic block.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0 ; Can't be optimized. Has use %z = load i32, i32* @glob0 in another function.
		  call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  br label %main1

		main1:
		  br label %cycleBB

		cycleBB:
		  %z = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 5, i32* @glob0.
		  store i32 2, i32* @glob0 ; Can't be optimized. Because use %z = load i32, i32* @glob0 can't be optimized.
		  %x = load i32, i32* @glob0 ; Can't be optimized. Because use %z = load i32, i32* @glob0 can't be optimized.
		  br i1 1, label %cycleBB, label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  store i32 5, i32* @glob0
		  %0 = call i32 @main()
		  ret void
		}

		define i32 @main() {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  br label %cycleBB

		cycleBB:                                          ; preds = %cycleBB, %main1
		  %z = load i32, i32* @glob0
		  store i32 2, i32* @glob0
		  %x = load i32, i32* @glob0
		  br i1 true, label %cycleBB, label %main2

		main2:                                            ; preds = %cycleBB
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle06)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  %yy = load i32, i32* @glob0 ; Can be optimized, use for store i32 3, i32* @glob0 and store i32 4, i32* @glob0.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  %zz = load i32, i32* @glob0, align 4
		  store i32 2, i32* @glob0 ; Can be optimized.
		  store i32 3, i32* @glob0 ; Can be optimized.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 4, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* %glob0.global-to-local
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  %zz = load i32, i32* %glob0.global-to-local, align 4
		  store i32 2, i32* %glob0.global-to-local
		  store i32 3, i32* %glob0.global-to-local
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle07)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency. Cycle dependency is on same basic block.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 0, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* %glob0.global-to-local, align 4
		  store i32 3, i32* %glob0.global-to-local
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, cycle08)
{
	parseInput(R"(
		; Optimizing in basic blocks that have cycle dependency. Cycle dependency is on same basic block.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main() {
		main0:
		  store i32 4, i32* @glob0 ; Can't be optimized. Because use %z = load i32, i32* @glob0 can't be optimized.
		  br label %main1

		main1:
		  %z = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0 and store i32 4, i32* @glob0.
		  br label %cycleBB

		cycleBB:
		  store i32 2, i32* @glob0 ; Can be optimized.
		  br i1 1, label %main2, label %main1

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main() {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 4, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  %z = load i32, i32* %glob0.global-to-local
		  br label %cycleBB

		cycleBB:                                          ; preds = %main1
		  store i32 2, i32* %glob0.global-to-local
		  br i1 true, label %main2, label %main1

		main2:                                            ; preds = %cycleBB
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, funcsWithCall01)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 5
		@glob1 = internal unnamed_addr global i32 6

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 1, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0 ; Can be optimized, use for store i32 1, i32* @glob0.
		  br label %main2

		main2:
		  call i32 @alfa()
		  %ll = load i32, i32* @glob1 ; Can't be optimized. Used in another function for store i32 5, i32* @glob3.
		  store i32 2, i32* @glob0 ; Can be optimized.
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1 ; Can't be optimized. Has use %ll = load i32, i32* @glob1 in another function.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob1 = internal unnamed_addr global i32 6

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 1, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* %glob0.global-to-local
		  br label %main2

		main2:                                            ; preds = %main1
		  %0 = call i32 @alfa()
		  %ll = load i32, i32* @glob1
		  store i32 2, i32* %glob0.global-to-local
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, moreSuccs04)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.
		; Situation where one load is assigned for two stores and this load can't be optimized.

		@glob0 = internal unnamed_addr global i32 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br i1 1, label %first, label %second

		first:
		  store i32 1, i32* @glob0 ; Can't be optimized, because use %y = load i32, i32* @glob0 can't be optimized.
		  br label %main2

		second:
		  store i32 2, i32* @glob0 ; Can't be optimized. Has use %x = load i32, i32* @glob0 in another function.
		  br label %main2

		main2:
		  call void @func()
		  %y = load i32, i32* @glob0 ; Can't be optimized, because store i32 1, i32* @glob0 can't be optimized.
		  ret i32 0
		}

		define void @func() {
		bb:
		  %x = load i32, i32* @glob0
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %first, label %second

		first:                                            ; preds = %main1
		  store i32 1, i32* @glob0
		  br label %main2

		second:                                           ; preds = %main1
		  store i32 2, i32* @glob0
		  br label %main2

		main2:                                            ; preds = %second, %first
		  call void @func()
		  %y = load i32, i32* @glob0
		  ret i32 0
		}

		define void @func() {
		bb:
		  %x = load i32, i32* @glob0
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, funcsWithCall02)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 5
		@glob1 = internal unnamed_addr global i32 2
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 6

		declare i32 @rand() nounwind

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2 ; Can be optimized.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 5
		  store i32 %xx, i32* @glob1 ; Can be optimized.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1 ; Can be optimized, use for store i32 %xx, i32* @glob1
		  call i32 @alfa()
		  store i32 2, i32* @glob1 ; Can be optimized.
		  %ll = load i32, i32* @glob3 ; Can't be optimized. Used in another function for store i32 5, i32* @glob3.
		  store i32 4, i32* @glob3 ; Can be optimized.
		  %cc = load i32, i32* @glob3 ; Can be optimized, use for store i32 4, i32* @glob3.
		  %zz = load i32, i32* @glob2 ; Can be optimized, use for store i32 4, i32* @glob2
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1 ; Can be optimized.
		  store i32 5, i32* @glob3 ; Can't be optimized. Has use %ll = load i32, i32* @glob3 in another function.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob3 = internal unnamed_addr global i32 6

		; Function Attrs: nounwind
		declare i32 @rand() #0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  %glob1.global-to-local = alloca i32
		  %glob2.global-to-local = alloca i32
		  %glob3.global-to-local = alloca i32
		  store i32 5, i32* %glob0.global-to-local
		  store i32 4, i32* %glob2.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* %glob0.global-to-local
		  store i32 %xx, i32* %glob1.global-to-local
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* %glob1.global-to-local
		  %0 = call i32 @alfa()
		  store i32 2, i32* %glob1.global-to-local
		  %ll = load i32, i32* @glob3
		  store i32 4, i32* %glob3.global-to-local
		  %cc = load i32, i32* %glob3.global-to-local
		  %zz = load i32, i32* %glob2.global-to-local
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %glob1.global-to-local = alloca i32
		  store i32 1, i32* %glob1.global-to-local
		  store i32 5, i32* @glob3
		  unreachable
		}

		attributes #0 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, indirectCall01)
{
	parseInput(R"(
		; Testing the indirect call of function. Two functions (func1, func2) that can be called and one that can't (func3).

		@glob0 = internal global i32 5
		@glob1 = internal global i32 5

		define i32 @func1(i32 %a) #0 {
		bb:
		  %x = load i32, i32* @glob0 ; Can't be optimized. Possibly used in another function for store i32 1, i32* @glob0.
		  ret i32 0
		}

		define i32 @func2(i32 %a) #0 {
		bb:
		  store i32 4, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret i32 0
		}

		define i32 @func3(i64 %a) #0 {
		bb:
		   store i32 8, i32* @glob1, align 4 ; Can be optimized, no use. Call instruction has different argument list.
		   ret i32 0
		}

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 6, i32* @glob1, align 4 ; Can be optimized.
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  store i32 1, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  %x = load i32, i32* @glob0 ; Can't be optimized. Possibly used in another function for store i32 4, i32* @glob0.
		  %y = load i32, i32* @glob1 ; Can be optimized, use for store i32 6, i32* @glob1, align 4.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5

		define i32 @func1(i32 %a) {
		bb:
		  %x = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @func2(i32 %a) {
		bb:
		  store i32 4, i32* @glob0
		  ret i32 0
		}

		define i32 @func3(i64 %a) {
		bb:
		  %glob1.global-to-local = alloca i32
		  store i32 8, i32* %glob1.global-to-local, align 4
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %glob1.global-to-local = alloca i32
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 6, i32* %glob1.global-to-local, align 4
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  store i32 1, i32* @glob0
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  %x = load i32, i32* @glob0
		  %y = load i32, i32* %glob1.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, indirectCall02)
{
	parseInput(R"(
		; Testing the indirect call of function. We have here functions with variable arguments.

		@glob0 = internal global i32 5, align 4

		; Can't be called indirectly. Different type.
		define void @func1(i32 %a) #0 {
		bb:
		  %x = load i32, i32* @glob0 ; Can be optimized
		  store i32 1, i32* @glob0 ; Can be optimized.
		  ret void
		}

		; Can't be called indirectly. Different return type.
		define void @func2(i32 %a) #0 {
		bb:
		  store i32 2, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret void
		}

		; Can be called indirectly.
		define i32 @func3(i32 %a) #0 {
		bb:
		  store i32 3, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  %z = load i32, i32* @glob0 ; Can't be optimized, because store i32 3, i32* @glob0 can't be optimized.
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @func4(i32 %a) #0 {
		bb:
		  store i32 44, i32* @glob0 ; Can be optimized.
		  store i32 4, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret i32 0
		}

		; Has more than one argument so we know that this function is not called indirectly.
		define i32 @func5(i32 %a, i32 %b) #0 {
		bb:
		  store i32 5, i32* @glob0 ; Can be optimized.
		  ret i32 0
		}

		; Can't be called indirectly. Different return type.
		define void @funcVarArg1(i32, ...) #0 {
		bb:
		  store i32 3, i32* @glob0 ; Can be optimized.
		  ret void
		}

		; Can be called indirectly.
		define i32 @funcVarArg2(i32, ...) #0 {
		bb:
		  store i32 4, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
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
		  %tmp6 = phi i32 (...)* [ bitcast (void (i32)* @func1 to i32 (...)*), %bb3 ], [ bitcast (void (i32)* @func2 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  %x = load i32, i32* @glob0 ; Can't be optimized. Has possibly use in another functions.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5, align 4

		define void @func1(i32 %a) {
		bb:
		  %glob0.global-to-local = alloca i32
		  %x = load i32, i32* @glob0
		  store i32 1, i32* %glob0.global-to-local
		  ret void
		}

		define void @func2(i32 %a) {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  ret void
		}

		define i32 @func3(i32 %a) {
		bb:
		  store i32 3, i32* @glob0
		  %z = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @func4(i32 %a) {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 44, i32* %glob0.global-to-local
		  store i32 4, i32* @glob0
		  ret i32 0
		}

		define i32 @func5(i32 %a, i32 %b) {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 5, i32* %glob0.global-to-local
		  ret i32 0
		}

		define void @funcVarArg1(i32, ...) {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 3, i32* %glob0.global-to-local
		  ret void
		}

		define i32 @funcVarArg2(i32, ...) {
		bb:
		  store i32 4, i32* @glob0
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
		  %tmp6 = phi i32 (...)* [ bitcast (void (i32)* @func1 to i32 (...)*), %bb3 ], [ bitcast (void (i32)* @func2 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, indirectCall03)
{
	parseInput(R"(
		; Testing the indirect call of function. Two functions (func1, func2) that can be called and one that can't (func3). Two indirect calls.

		@glob0 = internal global i32 5
		@glob1 = internal global i32 5

		define i32 @func1(i32 %a) #0 {
		bb:
		  %x = load i32, i32* @glob0 ; Can't be optimized. Possibly used in another function for store i32 1, i32* @glob0.
		  ret i32 0
		}

		define i32 @func2(i32 %a) #0 {
		bb:
		  store i32 4, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret i32 0
		}

		define i32 @func3(i64 %a) #0 {
		bb:
		   store i32 8, i32* @glob1, align 4 ; Can be optimized, no use. Call instruction has different argument list.
		   ret i32 0
		}

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 6, i32* @glob1, align 4 ; Can be optimized.
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  store i32 1, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  %x = load i32, i32* @glob0 ; Can't be optimized. Possibly used in another function for store i32 4, i32* @glob0.
		  %y = load i32, i32* @glob1 ; Can be optimized, use for store i32 6, i32* @glob1, align 4.
		  %tmp9 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5

		define i32 @func1(i32 %a) {
		bb:
		  %x = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @func2(i32 %a) {
		bb:
		  store i32 4, i32* @glob0
		  ret i32 0
		}

		define i32 @func3(i64 %a) {
		bb:
		  %glob1.global-to-local = alloca i32
		  store i32 8, i32* %glob1.global-to-local, align 4
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %glob1.global-to-local = alloca i32
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 6, i32* %glob1.global-to-local, align 4
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  store i32 1, i32* @glob0
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  %x = load i32, i32* @glob0
		  %y = load i32, i32* %glob1.global-to-local
		  %tmp9 = call i32 (i32, ...) %tmp7(i32 %argc)
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, indirectCall04)
{
	parseInput(R"(
		; Testing the indirect call of function. Two functions (func1, func2) that can be called and one that can't (func3). Two indirect calls
		; and one is in another function.

		@glob0 = internal global i32 5

		define i32 @func1(i32 %a) #0 {
		bb:
		  %x = load i32, i32* @glob0 ; Can't be optimized. Possibly used in another function for store i32 1, i32* @glob0.
		  ret i32 0
		}

		define i32 @func2(i32 %a) #0 {
		bb:
		  store i32 4, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret i32 0
		}

		define i32 @func3(i64 %a) #0 {
		bb:
		   ret i32 0
		}

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  store i32 1, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  br label %bb1

		bb1:
		  call void @funcWithIndirectCall()
		  br i1 1, label %bb2, label %bb3

		bb2:
		  br label %bb5

		bb3:
		  br label %bb5

		bb5:
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb2 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb3 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  ret i32 0
		}

		define void @funcWithIndirectCall() {
		bb:
		  br i1 1, label %left, label %right

		left:
		  br label %bb1

		right:
		  br label %bb1

		bb1:
		  %tmp1 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %left ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %right ]
		  %tmp2 = bitcast i32 (...)* %tmp1 to i32 (i32, ...)*
		  %tmp3 = call i32 (i32, ...) %tmp2(i32 1) #2
		  store i32 1, i32* @glob0 ; Can't be optimized. Has possible use %x = load i32, i32* @glob0 in another function.
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5

		define i32 @func1(i32 %a) {
		bb:
		  %x = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @func2(i32 %a) {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 4, i32* %glob0.global-to-local
		  ret i32 0
		}

		define i32 @func3(i64 %a) {
		bb:
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  store i32 1, i32* @glob0
		  br label %bb1

		bb1:                                              ; preds = %bb
		  call void @funcWithIndirectCall()
		  br i1 true, label %bb2, label %bb3

		bb2:                                              ; preds = %bb1
		  br label %bb5

		bb3:                                              ; preds = %bb1
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb2
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb2 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb3 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  ret i32 0
		}

		define void @funcWithIndirectCall() {
		bb:
		  br i1 true, label %left, label %right

		left:                                             ; preds = %bb
		  br label %bb1

		right:                                            ; preds = %bb
		  br label %bb1

		bb1:                                              ; preds = %right, %left
		  %tmp1 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %left ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %right ]
		  %tmp2 = bitcast i32 (...)* %tmp1 to i32 (i32, ...)*
		  %tmp3 = call i32 (i32, ...) %tmp2(i32 1)
		  store i32 1, i32* @glob0
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, moreSuccs01)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = private unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 0, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  store i32 1, i32* @glob1 ; Can be optimized.
		  %x = load i32, i32* @glob1 ; Can be optimized, use for store i32 1, i32* @glob1.
		  br label %main2

		right:
		  br label %main2

		main2:
		  %y = load i32, i32* @glob0 ; Can be optimized, use for store i32 0, i32* @glob0.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  %glob1.global-to-local = alloca i32
		  store i32 0, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 1, i32* %glob1.global-to-local
		  %x = load i32, i32* %glob1.global-to-local
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %y = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, moreSuccs02)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 3 ; Can be at the end erased and replaced by store.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  store i32 0, i32* @glob0 ; Can be optimized.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  br label %main2

		right:
		  br label %main2

		main2:
		  %y = load i32, i32* @glob0 ; Can be optimized, use for store i32 0, i32* @glob0.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 3, i32* %glob0.global-to-local
		  %x = load i32, i32* %glob0.global-to-local
		  store i32 0, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %y = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, moreSuccs03)
{
	parseInput(R"(
		; Some basic block has more than one successor (3 successors) and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 0, i32* @glob0 ; Can be optimized.
		  %x = load i32, i32* @glob0 ; ; Can be optimized, use for store i32 0, i32* @glob0.
		  br label %main1

		main1:
		  switch i32 %x, label %first [ i32 0, label %first
											i32 1, label %second
											i32 2, label %third ]

		first:
		  store i32 1, i32* @glob0 ; Can be optimized.
		  br label %main2

		second:
		  store i32 1, i32* @glob0 ; Can be optimized.
		  br label %main2

		third:
		  store i32 1, i32* @glob0 ; Can be optimized.
		  ret i32 0

		main2:
		  %y = load i32, i32* @glob0 ; Can be optimized, use for store i32 1, i32* @glob0.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 0, i32* %glob0.global-to-local
		  %x = load i32, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  switch i32 %x, label %first [
			i32 0, label %first
			i32 1, label %second
			i32 2, label %third
		  ]

		first:                                            ; preds = %main1, %main1
		  store i32 1, i32* %glob0.global-to-local
		  br label %main2

		second:                                           ; preds = %main1
		  store i32 1, i32* %glob0.global-to-local
		  br label %main2

		third:                                            ; preds = %main1
		  store i32 1, i32* %glob0.global-to-local
		  ret i32 0

		main2:                                            ; preds = %second, %first
		  %y = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern01)
{
	parseInput(R"(
		; Simple pattern. No use of tmp variable. Optimize pattern.

		@glob0 = internal unnamed_addr global i32 2

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %tmp = load i32, i32* @glob0 ; Can be optimized. Start of pattern.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  store i32 2, i32* @glob0
		  %z = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0.
		  br label %main2

		right:
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized. End of pattern.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 2, i32* %glob0.global-to-local
		  %z = load i32, i32* %glob0.global-to-local
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern02)
{
	parseInput(R"(
		; Simple pattern. Tmp variable is used. Don't optimize pattern. Normal optimize global to local.

		@glob0 = internal unnamed_addr global i32 2 ; Can be at the end erased and replaced by store.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %tmp = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  store i32 %tmp, i32* @glob0 ; Can be optimized.
		  store i32 2, i32* @glob0 ; Can be optimized.
		  %z = load i32, i32* @glob0 ; Can be optimized, use for store i32 2, i32* @glob0.
		  br label %main2

		right:
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  %tmp = load i32, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 %tmp, i32* %glob0.global-to-local
		  store i32 2, i32* %glob0.global-to-local
		  %z = load i32, i32* %glob0.global-to-local
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  store i32 %tmp, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern03)
{
	parseInput(R"(
		; Simple pattern. Pattern can't be optimized because we can't optimize all left uses in pattern.

		@glob0 = internal unnamed_addr global i32 2

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %tmp = load i32, i32* @glob0 ; This is part of pattern, but can't be deleted because we don't optimize store i32 2, i32* @glob0.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  store i32 2, i32* @glob0 ; Can't be optimized. Has use %x = load i32, i32* @glob0 in another function.
		  call void @func()
		  br label %main2

		right:
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized.
		  ret i32 0
		}

		define void @func() {
		bb:
		  %x = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 2, i32* @glob0.
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 2

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  %tmp = load i32, i32* @glob0
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 2, i32* @glob0
		  call void @func()
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  store i32 %tmp, i32* %glob0.global-to-local
		  ret i32 0
		}

		define void @func() {
		bb:
		  %x = load i32, i32* @glob0
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern04)
{
	parseInput(R"(
		; Simple pattern. Optimize pattern.

		@glob0 = internal unnamed_addr global i32 2

		define void @top() {
		bb:
		  store i32 2, i32* @glob0 ; Can be optimized.
		  call i32 @func()
		  ret void
		}

		define i32 @func() {
		main0:
		  %tmp = load i32, i32* @glob0 ; Can be optimized. Start of pattern.
		  br label %main1

		main1:
		  store i32 1, i32* @glob0 ; Can be optimized.
		  br i1 1, label %left, label %right

		left:
		  %x = load i32, i32* @glob0 ; Can be optimized, use for store i32 1, i32* @glob0.
		  store i32 %tmp, i32* @glob0 ; Can be optimized. End of pattern.
		  ret i32 0

		right:
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized. End of pattern.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define void @top() {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  %0 = call i32 @func()
		  ret void
		}

		define i32 @func() {
		main0:
		  %glob0.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %main0
		  store i32 1, i32* %glob0.global-to-local
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  %x = load i32, i32* %glob0.global-to-local
		  ret i32 0

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern05)
{
	parseInput(R"(
		; Simple pattern. Optimize pattern.

		@glob0 = internal unnamed_addr global i32 2

		define i32 @top() {
		main0:
		  %tmp = load i32, i32* @glob0 ; Can be optimized. Start of pattern.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  br label %main2

		right:
		  store i32 3, i32* @glob0 ; Can be optimized.
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized. End of pattern.
		  call void @func()
		  ret i32 0
		}

		define void @func() {
		bb:
		  %x = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 3, i32* @glob0.
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @top() {
		main0:
		  %glob0.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  br label %main2

		right:                                            ; preds = %main1
		  store i32 3, i32* %glob0.global-to-local
		  br label %main2

		main2:                                            ; preds = %right, %left
		  call void @func()
		  ret i32 0
		}

		define void @func() {
		bb:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  %x = load i32, i32* %glob0.global-to-local
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern06)
{
	parseInput(R"(
		; Simple pattern. Pattern can't be optimized because one load instruction can't be optimized.

		@glob0 = internal unnamed_addr global i32 2

		define i32 @top() {
		main0:
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  br label %main2

		right:
		  call void @func()
		  %x = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 3, i32* @glob0.
		  br label %main2

		main2:
		  %tmp = load i32, i32* @glob0 ; Can't be optimized. Start of pattern.
		  store i32 %tmp, i32* @glob0 ; Cant be optimized, because has no use. End of pattern.
		  ret i32 0
		}

		define void @func() {
		bb:
		  store i32 3, i32* @glob0 ; Can't be optimized. Has use %x = load i32 @glob function.
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 2

		define i32 @top() {
		main0:
		  %glob0.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  br label %main2

		right:                                            ; preds = %main1
		  call void @func()
		  %x = load i32, i32* @glob0
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %tmp = load i32, i32* @glob0
		  store i32 %tmp, i32* %glob0.global-to-local
		  ret i32 0
		}

		define void @func() {
		bb:
		  store i32 3, i32* @glob0
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pattern07)
{
	parseInput(R"(
		; Simple pattern. No use of tmp variable. Optimize pattern.

		@glob0 = internal unnamed_addr global i32 2

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %tmp = load i32, i32* @glob0 ; Can be optimized. Start of pattern.
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  br label %main2

		right:
		  br label %main2

		main2:
		  store i32 %tmp, i32* @glob0 ; Can be optimized. End of pattern.
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %x = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pointers01)
{
	parseInput(R"(
		; We have global variable that is a pointer. Nothing to optimize.

		@glob0 = internal global i32* null, align 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  %xx = alloca i32
		  store i32* %xx, i32** @glob0 ; Global variable is a pointer, nothing to optimize.
		  br label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32* null, align 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = alloca i32
		  store i32* %xx, i32** @glob0
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, pointers02)
{
	parseInput(R"(
		; We have one global variable that is a pointer and second that is not.

		@glob0 = internal global i32* null, align 4
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  %xx = alloca i32, align 4
		  store i32* %xx, i32** @glob0 ; Global variable is a pointer, nothing to optimize.
		  br label %main2

		main2:
		  store i32 1, i32* @glob1 ; Can be optimized.
		  %c = load i32, i32* @glob1 ; Can be optimized, use for %c = load i32, i32* @glob1.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32* null, align 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob1.global-to-local = alloca i32
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = alloca i32, align 4
		  store i32* %xx, i32** @glob0
		  br label %main2

		main2:                                            ; preds = %main1
		  store i32 1, i32* %glob1.global-to-local
		  %c = load i32, i32* %glob1.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, privateInternal01)
{
	parseInput(R"(
		; Check if global variable which are (aren't) private/internal can be optimized (can't be optimized).
		; Also check if global variable without use is optimized.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = private unnamed_addr global i32 0
		@glob2 = global i32 0 ; Not internal, not private so don't optimize.
		@glob3 = global i32 4 ; No use, optimize.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 0, i32* @glob0 ; Can be optimized. No use.
		  br label %main1

		main1:
		  call void @alfa()
		  store i32 1, i32* @glob1 ; Can be optimized. No use.
		  br label %main2

		main2:
		  call void @alfa()
		  ret i32 0
		}

		define void @alfa() {
		alfa1:
		  store i32 2, i32* @glob2 ; Can't be optimized. Not internal or private linkage.
		  ret void
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob2 = global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  %glob1.global-to-local = alloca i32
		  store i32 0, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  call void @alfa()
		  store i32 1, i32* %glob1.global-to-local
		  br label %main2

		main2:                                            ; preds = %main1
		  call void @alfa()
		  ret i32 0
		}

		define void @alfa() {
		alfa1:
		  store i32 2, i32* @glob2
		  ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, recursion01)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between two functions alfa() and beta().

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call i32 @alfa()
		  %yy = load i32, i32* @glob0 ; Can't be optimized. Used in another function for store i32 5, i32* @glob0,

		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:
		  store i32 4, i32* @glob0 ; Can be optimized.
		  br label %ret2

		ret2:
		  store i32 5, i32* @glob0 ; Can't be optimized, use %yy = load i32, i32* @glob0 in another function.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  call i32 @alfa()
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32 @alfa()
		  %yy = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %glob0.global-to-local = alloca i32
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
		  store i32 4, i32* %glob0.global-to-local
		  br label %ret2

		ret2:                                             ; preds = %ret1
		  store i32 5, i32* @glob0
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %0 = call i32 @alfa()
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, recursion02)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between two functions alfa() and beta().

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call i32 @alfa()
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:
		  store i32 4, i32* @glob0, align 4 ; Can be optimized.
		  br label %ret2

		ret2:
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0 in another function.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 7, i32* @glob0 ; Can be optimized.
		  call i32 @alfa()
		  store i32 8, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0 in another function.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32 @alfa()
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %glob0.global-to-local = alloca i32
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
		  store i32 4, i32* %glob0.global-to-local, align 4
		  br label %ret2

		ret2:                                             ; preds = %ret1
		  store i32 5, i32* @glob0, align 4
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %glob0.global-to-local = alloca i32
		  store i32 7, i32* %glob0.global-to-local
		  %0 = call i32 @alfa()
		  store i32 8, i32* @glob0
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, recursion03)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between three functions alfa(), gamma() and beta().

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call i32 @alfa()
		  %xx = load i32, i32* @glob0 ; Can't be optimize. Used in another function for store i32 4, i32* @glob0.
		  %yy = load i32, i32* @glob1 ; Can't be optimize. Used in another function for store i32 9, i32* @glob1 and store i32 3, i32* @glob0.
		  %zz = load i32, i32* @glob2 ; Can't be optimize. Used in another function for store i32 1, i32* @glob2 and store i32 2, i32* @glob2.
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:
		  br label %ret2

		ret2:
		  store i32 1, i32* @glob2 ; Can't be optimized, use in %zz = load i32, i32* @glob2 in another function.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  store i32 9, i32* @glob1 ; Can't be optimized, use in %yy = load i32, i32* @glob1 in another function.
		  ret i32 0
		}

		define i32 @gamma() {
		gamma1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret, label %gamma2

		ret:
		  store i32 5, i32* @glob1 ; Can be optimized, value is replaced by store i32 7, i32* @glob1.
		  ret i32 0

		gamma2:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %xx = load i32, i32* @glob0 in another function.
		  call i32 @alfa()
		  store i32 2, i32* @glob2 ; Can't be optimized, use in %zz = load i32, i32* @glob2 in another function.
		  unreachable
		}

		define i32 @beta() {
		beta1:
		  store i32 3, i32* @glob0 ; Can't be optimized because use %yy = load i32, i32* @glob0 can't be optimized.
		  call i32 @gamma()
		  store i32 7, i32* @glob1 ; Can be optimized, value is replaced by store i32 9, i32* @glob1.
		  %yy = load i32, i32* @glob0 ; Can't be optimized, use in store i32 3, i32* @glob0 and store i32 4, i32* @glob0 which is in another function.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32 @alfa()
		  %xx = load i32, i32* @glob0
		  %yy = load i32, i32* @glob1
		  %zz = load i32, i32* @glob2
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
		  br label %ret2

		ret2:                                             ; preds = %ret1
		  store i32 1, i32* @glob2
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @beta()
		  store i32 9, i32* @glob1
		  ret i32 0
		}

		define i32 @gamma() {
		gamma1:
		  %glob1.global-to-local = alloca i32
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret, label %gamma2

		ret:                                              ; preds = %gamma1
		  store i32 5, i32* %glob1.global-to-local
		  ret i32 0

		gamma2:                                           ; preds = %gamma1
		  store i32 4, i32* @glob0
		  %0 = call i32 @alfa()
		  store i32 2, i32* @glob2
		  unreachable
		}

		define i32 @beta() {
		beta1:
		  %glob1.global-to-local = alloca i32
		  store i32 3, i32* @glob0
		  %0 = call i32 @gamma()
		  store i32 7, i32* %glob1.global-to-local
		  %yy = load i32, i32* @glob0
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, recursion04)
{
	parseInput(R"(
		; Testing the recursion. The recursion is self recursion on function alfa().

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  call i32 @alfa()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  br i1 2, label %ret1, label %alfa2

		alfa2:
		  call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4 ; Can be optimized, has use in store i32 3, i32* @glob0.
		  call i32 @alfa()
		  br label %ret1

		ret1:
		  store i32 3, i32* @glob0 ; Can be optimized.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %0 = call i32 @alfa()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %glob0.global-to-local = alloca i32
		  br i1 false, label %ret1, label %alfa2

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @alfa()
		  %x = load i32, i32* %glob0.global-to-local, align 4
		  %1 = call i32 @alfa()
		  br label %ret1

		ret1:                                             ; preds = %alfa2, %alfa1
		  store i32 3, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, useInDefGlob01)
{
	parseInput(R"(
		; Test where global variable is assigned in defintions of global variables
		; to another global variable.

		@globA = global i32 1, align 4 ; Can't be optimized, this global variable is assigned to another global variable.
		@globB = global i32* @globA, align 4 ; Can't be optimized, this global variable is a pointer.

		define i32 @func() {
		bb:
		  %x = load i32*, i32** @globB
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@globA = global i32 1, align 4
		@globB = global i32* @globA, align 4

		define i32 @func() {
		bb:
		  %x = load i32*, i32** @globB
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, useInOneFunc01)
{
	parseInput(R"(
		; Global variable has use only in one function and no store is used.
		; Used one AllocaInst at begin.

		@glob0 = internal unnamed_addr global i32 2 ; Can be at the end erased and replaced by store.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %x = alloca i32*
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  %z = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  br label %main2

		right:
		  br label %main2

		main2:
		  %y = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  %x = alloca i32*
		  store i32 2, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  %z = load i32, i32* %glob0.global-to-local
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %y = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, useInOneFunc02)
{
	parseInput(R"(
		; Global variable has use only in one function and no store is used.
		; Not used AllocaInst at begin.

		@glob0 = internal unnamed_addr global i32 2 ; Can be at the end erased and replaced by store.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br i1 1, label %left, label %right

		left:
		  %x = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  br label %main2

		right:
		  br label %main2

		main2:
		  %y = load i32, i32* @glob0 ; Can be optimized. Need to create store which replace @glob0 = internal unnamed_addr global i32 2.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob0.global-to-local = alloca i32
		  store i32 2, i32* %glob0.global-to-local
		  br label %main1

		main1:                                            ; preds = %main0
		  br i1 true, label %left, label %right

		left:                                             ; preds = %main1
		  %x = load i32, i32* %glob0.global-to-local
		  br label %main2

		right:                                            ; preds = %main1
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %y = load i32, i32* %glob0.global-to-local
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, useWithAddr01)
{
	parseInput(R"(
		; Test the code with IntToPtrInst. We can optimize all assigns,
		; in test, because we don't count that address 12345 is address of
		; some global variable.

		@glob1 = internal unnamed_addr global i32 0 ; Can be optimized, no use after optimization store instructions.
		@glob2 = internal unnamed_addr global i32 0 ; Can be optimized, no use after optimization store instructions.
		@glob3 = internal unnamed_addr global i32 0 ; Can be optimized, no use after optimization store instructions.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 10, i32* @glob2, align 4 ; Can be optimized, no use.
		  store i32 4, i32* @glob2, align 4 ; Can be optimized, no use.
		  store i32 5, i32* @glob1, align 4 ; Can be optimized, no use.
		  store i32 6, i32* @glob3, align 4 ; Can be optimized, no use.
		  br label %main1

		main1:
		  %xx = load i32, i32* inttoptr (i32 12345 to i32*), align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %glob1.global-to-local = alloca i32
		  %glob2.global-to-local = alloca i32
		  %glob3.global-to-local = alloca i32
		  store i32 10, i32* %glob2.global-to-local, align 4
		  store i32 4, i32* %glob2.global-to-local, align 4
		  store i32 5, i32* %glob1.global-to-local, align 4
		  store i32 6, i32* %glob3.global-to-local, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* inttoptr (i32 12345 to i32*), align 4
		  store i32 %xx, i32* %glob1.global-to-local, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(GlobalToLocalTests, volatile01)
{
	parseInput(R"(
		; Testing of not removing volatile stores and loads.

		@glob0 = internal unnamed_addr global i32 0 ; Can't be optimized.
		@glob1 = internal unnamed_addr global i32 0 ; Can't be optimized.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4 ; Can't be optimized, volatile store.
		  %x = load volatile i32, i32* @glob0 ; Can't be optimized, volatile load.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4
		  %x = load volatile i32, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// -not-aggressive
//

// TODO: This is passing even without -not-aggressive parameter.
// I have no idea how to use it from here.
TEST_F(GlobalToLocalTests, externalCall01)
{
	parseInput(R"(
		; Testing of not removing volatile stores and loads.

		@glob0 = internal unnamed_addr global i32 0 ; Can't be optimized.
		@glob1 = internal unnamed_addr global i32 0 ; Can't be optimized.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4 ; Can't be optimized, volatile store.
		  %x = load volatile i32, i32* @glob0 ; Can't be optimized, volatile load.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4
		  %x = load volatile i32, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
