/**
* @file tests/bin2llvmir/optimizations/globals/tests/dead_global_assign_tests.cpp
* @brief Tests for the @c DeadGlobalAssign pass.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/globals/dead_global_assign.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c DeadGlobalAssign pass.
 */
class DeadGlobalAssignTests: public LlvmIrTests
{
	protected:
		void runOnModule()
		{
			LlvmIrTests::runOnModule<DeadGlobalAssign>();
		}
};

//
// aggressive (default)
//

TEST_F(DeadGlobalAssignTests, addrTaken01)
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

TEST_F(DeadGlobalAssignTests, aggType01)
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

TEST_F(DeadGlobalAssignTests, complicatedRecursion01)
{
	parseInput(R"(
		; Testing the recursion. The recursion is self recursion on function function_a214().
		; This test also containts IntToPtr instruction.
		; This test is complicated because containts a lot of basic blocks which are connected in many ways.

		@regs3 = internal unnamed_addr global i32 0
		@regs4 = internal unnamed_addr global i32 0

		; Function Attrs: nounwind
		define i32 @function_a214(i32 %arg1, i32 %arg2) #0 {
		dec_entry:
		  br label %dec_label_pc_a240

		dec_label_pc_a240:
		  br label %dec_label_pc_a244

		dec_label_pc_a244:
		  %u1_a248_conv_585 = inttoptr i32 3 to i8*
		  switch i32 3, label %dec_label_pc_a508 [
			i32 3, label %dec_label_pc_a400
			i32 4, label %dec_label_pc_a2c4
			i32 5, label %dec_label_pc_a3ec
			i32 6, label %dec_label_pc_a2f8
			i32 7, label %dec_label_pc_a41c
			i32 12, label %dec_label_pc_a320
			i32 14, label %dec_label_pc_a32c
			i32 16, label %dec_label_pc_a338
			i32 17, label %dec_label_pc_a368
			i32 22, label %dec_label_pc_a2e8
		  ]

		dec_label_pc_a2c4:
		  store i32 3, i32* @regs3, align 4 ; Can be optimized, no use.
		  br label %dec_label_pc_a520

		dec_label_pc_a2d8:
		  %u1_a2d8 = load i32, i32* @regs4, align 4
		  br i1 2, label %dec_label_pc_a240, label %dec_label_pc_a520

		dec_label_pc_a2e8:
		  ret i32 1

		dec_label_pc_a2f8:
		  br i1 2, label %dec_label_pc_a520, label %dec_label_pc_a314

		dec_label_pc_a314:
		  br label %dec_label_pc_a240

		dec_label_pc_a320:
		  br label %dec_label_pc_a240

		dec_label_pc_a32c:
		  br label %dec_label_pc_a240

		dec_label_pc_a338:
		  br i1 2, label %dec_label_pc_a520, label %dec_label_pc_a35c

		dec_label_pc_a35c:
		  br label %dec_label_pc_a240

		dec_label_pc_a368:
		  br i1 2, label %dec_label_pc_a3ac, label %dec_label_pc_a38c

		dec_label_pc_a38c:
		  br i1 2, label %dec_label_pc_a3ac, label %dec_label_pc_a38c

		dec_label_pc_a3ac:
		  br i1 1, label %dec_label_pc_a520, label %dec_label_pc_a3b8

		dec_label_pc_a3b8:
		  br label %dec_label_pc_a3c0

		dec_label_pc_a3c0:
		  %local_ret_203_a3c8 = call i32 @function_a214(i32 1, i32 0) #0
		  br i1 2, label %dec_label_pc_a3d4, label %dec_label_pc_a528

		dec_label_pc_a3d4:
		  br i1 2, label %dec_label_pc_a520, label %dec_label_pc_a3c0

		dec_label_pc_a3ec:
		  br label %dec_label_pc_a3f0

		dec_label_pc_a3f0:
		  br i1 2, label %dec_label_pc_a440, label %dec_label_pc_a3f0

		dec_label_pc_a400:
		  br label %dec_label_pc_a408

		dec_label_pc_a408:
		  br i1 1, label %dec_label_pc_a408, label %dec_label_pc_a414

		dec_label_pc_a414:
		  br label %dec_label_pc_a440

		dec_label_pc_a41c:
		  br label %dec_label_pc_a420

		dec_label_pc_a420:
		  br i1 1, label %dec_label_pc_a43c, label %dec_label_pc_a420

		dec_label_pc_a43c:
		  br label %dec_label_pc_a440

		dec_label_pc_a440:
		  br i1 1, label %dec_label_pc_a240, label %dec_label_pc_a44c

		dec_label_pc_a44c:
		  br i1 1, label %dec_label_pc_a458, label %dec_label_pc_a48c

		dec_label_pc_a458:
		  br label %dec_label_pc_a45c

		dec_label_pc_a45c:
		  br i1 1, label %dec_label_pc_a468, label %dec_label_pc_a47c

		dec_label_pc_a468:
		  br i1 1, label %dec_label_pc_a468.dec_label_pc_a47c_crit_edge, label %dec_label_pc_a528

		dec_label_pc_a468.dec_label_pc_a47c_crit_edge:
		  br label %dec_label_pc_a47c

		dec_label_pc_a47c:
		  br i1 1, label %dec_label_pc_a484, label %dec_label_pc_a520

		dec_label_pc_a484:
		  br label %dec_label_pc_a45c

		dec_label_pc_a48c:
		  br i1 1, label %dec_label_pc_a498, label %if_a490_2c9_true

		if_a490_2c9_true:
		  br i1 1, label %dec_label_pc_a520, label %dec_label_pc_a4e4.preheader

		dec_label_pc_a4e4.preheader:
		  br i1 1, label %dec_label_pc_a4f8, label %dec_label_pc_a528

		dec_label_pc_a498:
		  br label %dec_label_pc_a4a8

		dec_label_pc_a4a8:
		  br i1 1, label %dec_label_pc_a4b4, label %dec_label_pc_a4c8

		dec_label_pc_a4b4:
		  br i1 1, label %dec_label_pc_a4b4.dec_label_pc_a4c8_crit_edge, label %dec_label_pc_a528

		dec_label_pc_a4b4.dec_label_pc_a4c8_crit_edge:
		  br label %dec_label_pc_a4c8

		dec_label_pc_a4c8:
		  br i1 1, label %dec_label_pc_a4d0, label %dec_label_pc_a520

		dec_label_pc_a4d0:
		  br label %dec_label_pc_a4a8

		dec_label_pc_a4f8:
		  br i1 1, label %dec_label_pc_a500, label %dec_label_pc_a520

		dec_label_pc_a500:
		  br i1 1, label %dec_label_pc_a520, label %dec_label_pc_a500.dec_label_pc_a4e4_crit_edge

		dec_label_pc_a500.dec_label_pc_a4e4_crit_edge:
		  br i1 1, label %dec_label_pc_a4f8, label %dec_label_pc_a528

		dec_label_pc_a508:
		  br label %dec_label_pc_a240

		dec_label_pc_a520:
		  ret i32 0

		dec_label_pc_a528:
		  ret i32 1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@regs4 = internal unnamed_addr global i32 0

		define i32 @function_a214(i32 %arg1, i32 %arg2) {
		dec_entry:
		  br label %dec_label_pc_a240

		dec_label_pc_a240:                                ; preds = %dec_label_pc_a508, %dec_label_pc_a440, %dec_label_pc_a35c, %dec_label_pc_a32c, %dec_label_pc_a320, %dec_label_pc_a314, %dec_label_pc_a2d8, %dec_entry
		  br label %dec_label_pc_a244

		dec_label_pc_a244:                                ; preds = %dec_label_pc_a240
		  %u1_a248_conv_585 = inttoptr i32 3 to i8*
		  switch i32 3, label %dec_label_pc_a508 [
			i32 3, label %dec_label_pc_a400
			i32 4, label %dec_label_pc_a2c4
			i32 5, label %dec_label_pc_a3ec
			i32 6, label %dec_label_pc_a2f8
			i32 7, label %dec_label_pc_a41c
			i32 12, label %dec_label_pc_a320
			i32 14, label %dec_label_pc_a32c
			i32 16, label %dec_label_pc_a338
			i32 17, label %dec_label_pc_a368
			i32 22, label %dec_label_pc_a2e8
		  ]

		dec_label_pc_a2c4:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a520

		dec_label_pc_a2d8:                                ; No predecessors!
		  %u1_a2d8 = load i32, i32* @regs4, align 4
		  br i1 false, label %dec_label_pc_a240, label %dec_label_pc_a520

		dec_label_pc_a2e8:                                ; preds = %dec_label_pc_a244
		  ret i32 1

		dec_label_pc_a2f8:                                ; preds = %dec_label_pc_a244
		  br i1 false, label %dec_label_pc_a520, label %dec_label_pc_a314

		dec_label_pc_a314:                                ; preds = %dec_label_pc_a2f8
		  br label %dec_label_pc_a240

		dec_label_pc_a320:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a240

		dec_label_pc_a32c:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a240

		dec_label_pc_a338:                                ; preds = %dec_label_pc_a244
		  br i1 false, label %dec_label_pc_a520, label %dec_label_pc_a35c

		dec_label_pc_a35c:                                ; preds = %dec_label_pc_a338
		  br label %dec_label_pc_a240

		dec_label_pc_a368:                                ; preds = %dec_label_pc_a244
		  br i1 false, label %dec_label_pc_a3ac, label %dec_label_pc_a38c

		dec_label_pc_a38c:                                ; preds = %dec_label_pc_a38c, %dec_label_pc_a368
		  br i1 false, label %dec_label_pc_a3ac, label %dec_label_pc_a38c

		dec_label_pc_a3ac:                                ; preds = %dec_label_pc_a38c, %dec_label_pc_a368
		  br i1 true, label %dec_label_pc_a520, label %dec_label_pc_a3b8

		dec_label_pc_a3b8:                                ; preds = %dec_label_pc_a3ac
		  br label %dec_label_pc_a3c0

		dec_label_pc_a3c0:                                ; preds = %dec_label_pc_a3d4, %dec_label_pc_a3b8
		  %local_ret_203_a3c8 = call i32 @function_a214(i32 1, i32 0)
		  br i1 false, label %dec_label_pc_a3d4, label %dec_label_pc_a528

		dec_label_pc_a3d4:                                ; preds = %dec_label_pc_a3c0
		  br i1 false, label %dec_label_pc_a520, label %dec_label_pc_a3c0

		dec_label_pc_a3ec:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a3f0

		dec_label_pc_a3f0:                                ; preds = %dec_label_pc_a3f0, %dec_label_pc_a3ec
		  br i1 false, label %dec_label_pc_a440, label %dec_label_pc_a3f0

		dec_label_pc_a400:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a408

		dec_label_pc_a408:                                ; preds = %dec_label_pc_a408, %dec_label_pc_a400
		  br i1 true, label %dec_label_pc_a408, label %dec_label_pc_a414

		dec_label_pc_a414:                                ; preds = %dec_label_pc_a408
		  br label %dec_label_pc_a440

		dec_label_pc_a41c:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a420

		dec_label_pc_a420:                                ; preds = %dec_label_pc_a420, %dec_label_pc_a41c
		  br i1 true, label %dec_label_pc_a43c, label %dec_label_pc_a420

		dec_label_pc_a43c:                                ; preds = %dec_label_pc_a420
		  br label %dec_label_pc_a440

		dec_label_pc_a440:                                ; preds = %dec_label_pc_a43c, %dec_label_pc_a414, %dec_label_pc_a3f0
		  br i1 true, label %dec_label_pc_a240, label %dec_label_pc_a44c

		dec_label_pc_a44c:                                ; preds = %dec_label_pc_a440
		  br i1 true, label %dec_label_pc_a458, label %dec_label_pc_a48c

		dec_label_pc_a458:                                ; preds = %dec_label_pc_a44c
		  br label %dec_label_pc_a45c

		dec_label_pc_a45c:                                ; preds = %dec_label_pc_a484, %dec_label_pc_a458
		  br i1 true, label %dec_label_pc_a468, label %dec_label_pc_a47c

		dec_label_pc_a468:                                ; preds = %dec_label_pc_a45c
		  br i1 true, label %dec_label_pc_a468.dec_label_pc_a47c_crit_edge, label %dec_label_pc_a528

		dec_label_pc_a468.dec_label_pc_a47c_crit_edge:    ; preds = %dec_label_pc_a468
		  br label %dec_label_pc_a47c

		dec_label_pc_a47c:                                ; preds = %dec_label_pc_a468.dec_label_pc_a47c_crit_edge, %dec_label_pc_a45c
		  br i1 true, label %dec_label_pc_a484, label %dec_label_pc_a520

		dec_label_pc_a484:                                ; preds = %dec_label_pc_a47c
		  br label %dec_label_pc_a45c

		dec_label_pc_a48c:                                ; preds = %dec_label_pc_a44c
		  br i1 true, label %dec_label_pc_a498, label %if_a490_2c9_true

		if_a490_2c9_true:                                 ; preds = %dec_label_pc_a48c
		  br i1 true, label %dec_label_pc_a520, label %dec_label_pc_a4e4.preheader

		dec_label_pc_a4e4.preheader:                      ; preds = %if_a490_2c9_true
		  br i1 true, label %dec_label_pc_a4f8, label %dec_label_pc_a528

		dec_label_pc_a498:                                ; preds = %dec_label_pc_a48c
		  br label %dec_label_pc_a4a8

		dec_label_pc_a4a8:                                ; preds = %dec_label_pc_a4d0, %dec_label_pc_a498
		  br i1 true, label %dec_label_pc_a4b4, label %dec_label_pc_a4c8

		dec_label_pc_a4b4:                                ; preds = %dec_label_pc_a4a8
		  br i1 true, label %dec_label_pc_a4b4.dec_label_pc_a4c8_crit_edge, label %dec_label_pc_a528

		dec_label_pc_a4b4.dec_label_pc_a4c8_crit_edge:    ; preds = %dec_label_pc_a4b4
		  br label %dec_label_pc_a4c8

		dec_label_pc_a4c8:                                ; preds = %dec_label_pc_a4b4.dec_label_pc_a4c8_crit_edge, %dec_label_pc_a4a8
		  br i1 true, label %dec_label_pc_a4d0, label %dec_label_pc_a520

		dec_label_pc_a4d0:                                ; preds = %dec_label_pc_a4c8
		  br label %dec_label_pc_a4a8

		dec_label_pc_a4f8:                                ; preds = %dec_label_pc_a500.dec_label_pc_a4e4_crit_edge, %dec_label_pc_a4e4.preheader
		  br i1 true, label %dec_label_pc_a500, label %dec_label_pc_a520

		dec_label_pc_a500:                                ; preds = %dec_label_pc_a4f8
		  br i1 true, label %dec_label_pc_a520, label %dec_label_pc_a500.dec_label_pc_a4e4_crit_edge

		dec_label_pc_a500.dec_label_pc_a4e4_crit_edge:    ; preds = %dec_label_pc_a500
		  br i1 true, label %dec_label_pc_a4f8, label %dec_label_pc_a528

		dec_label_pc_a508:                                ; preds = %dec_label_pc_a244
		  br label %dec_label_pc_a240

		dec_label_pc_a520:                                ; preds = %dec_label_pc_a500, %dec_label_pc_a4f8, %dec_label_pc_a4c8, %if_a490_2c9_true, %dec_label_pc_a47c, %dec_label_pc_a3d4, %dec_label_pc_a3ac, %dec_label_pc_a338, %dec_label_pc_a2f8, %dec_label_pc_a2d8, %dec_label_pc_a2c4
		  ret i32 0

		dec_label_pc_a528:                                ; preds = %dec_label_pc_a500.dec_label_pc_a4e4_crit_edge, %dec_label_pc_a4b4, %dec_label_pc_a4e4.preheader, %dec_label_pc_a468, %dec_label_pc_a3c0
		  ret i32 1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle01)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
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
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0 ; Can be optimized, no use.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 2, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* @glob0, align 4
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

TEST_F(DeadGlobalAssignTests, cycle02)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0 ; Can be optimized, value is replaced by store i32 5, i32* @glob0.
		  br label %main1

		main1:
		  store i32 5, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0 ; Can be optimized, no use.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 2, i32* @glob0 ; Can be optimized, no use. Value is replaced by store i32 5, i32* @glob0.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  store i32 5, i32* @glob0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  %yy = load i32, i32* @glob0, align 4
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle03)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  store i32 5, i32* @glob0 ; Can be optimized, no use.
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 2, i32* @glob0 ; Can be optimized, value is replaced by store i32 3, i32* @glob0.
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle04)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %zz = load i32, i32* @glob0, align 4.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4
		  %yy = load i32, i32* @glob0, align 4
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  %zz = load i32, i32* @glob0, align 4
		  store i32 2, i32* @glob0 ; Can be optimized, value is replaced by store i32 2, i32* @glob0.
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %zz = load i32, i32* @glob0, align 4.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  store i32 3, i32* @glob0
		  %yy = load i32, i32* @glob0, align 4
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  %zz = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle05)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  %yy = load i32, i32* @glob0, align 4
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  store i32 3, i32* @glob0
		  br label %main2

		main2:                                            ; preds = %main1
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  %yy = load i32, i32* @glob0, align 4
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle06)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0 ; Can be optimized, value is replaced by store i32 4, i32* @glob0.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  store i32 4, i32* @glob0
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  %yy = load i32, i32* @glob0, align 4
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle07)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
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
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob0, align 4
		  store i32 3, i32* @glob0
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

TEST_F(DeadGlobalAssignTests, cycle08)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob0, align 4
		  br label %main3

		main3:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:
		  br label %main5

		main5:
		  ret i32 0

		cycleBB:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %cycleBB, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob0, align 4
		  br label %main3

		main3:                                            ; preds = %main2
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %cycleBB, label %main4

		main4:                                            ; preds = %main3
		  br label %main5

		main5:                                            ; preds = %main4
		  ret i32 0

		cycleBB:                                          ; preds = %main3
		  store i32 3, i32* @glob0
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle09)
{
	parseInput(R"(
		; Testing the function that have no basic block wihout succesors.
		; We can in this situation remove all stores.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob0 ; Can be optimized, no use.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  store i32 2, i32* @glob0 ; Can't be optimized, use in %c = load i32, i32* @glob0.
		  %c = load i32, i32* @glob0
		  store i32 3, i32* @glob0 ; Can be optimized, no use.
		  br label %main1
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main2, %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  store i32 2, i32* @glob0
		  %c = load i32, i32* @glob0
		  br label %main1
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle10)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  call void @main()
		  %x = load i32, i32* @glob0
		  ret void
		}

		define void @main() {
		bb1:
		  br label %bb2
		bb2:
		  br i1 1, label %bb5, label %bb6
		bb3:
		   br i1 1, label %bb4, label %bb7
		bb4:
		  ret void
		bb5:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0.
		  br label %bb3
		bb6:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0.
		  br label %bb3
		bb7:
		  store i32 2, i32* @glob0 ; Can be optimized, replaced by store i32 3, i32* @glob0 and store i32 4, i32* @glob0.
		  br label %bb2
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  call void @main()
		  %x = load i32, i32* @glob0
		  ret void
		}

		define void @main() {
		bb1:
		  br label %bb2

		bb2:                                              ; preds = %bb7, %bb1
		  br i1 true, label %bb5, label %bb6

		bb3:                                              ; preds = %bb6, %bb5
		  br i1 true, label %bb4, label %bb7

		bb4:                                              ; preds = %bb3
		  ret void

		bb5:                                              ; preds = %bb2
		  store i32 4, i32* @glob0
		  br label %bb3

		bb6:                                              ; preds = %bb2
		  store i32 3, i32* @glob0
		  br label %bb3

		bb7:                                              ; preds = %bb3
		  br label %bb2
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, cycle11)
{
	parseInput(R"(
		; Testing of removing the stores in basic blocks that have cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  call void @main()
		  %x = load i32, i32* @glob0
		  ret void
		}

		define void @main() {
		bb1:
		  br label %bb2
		bb2:
		  br i1 1, label %bb5, label %bb6
		bb3:
		   br i1 1, label %bb4, label %bb7
		bb4:
		  store i32 1, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0.
		  ret void
		bb5:
		  br label %bb3
		bb6:
		  store i32 1, i32* @glob0 ; Can be optimized, replaced by store i32 1, i32* @glob0.
		  br label %bb3
		bb7:
		  br label %bb2
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define void @top() {
		bb:
		  call void @main()
		  %x = load i32, i32* @glob0
		  ret void
		}

		define void @main() {
		bb1:
		  br label %bb2

		bb2:                                              ; preds = %bb7, %bb1
		  br i1 true, label %bb5, label %bb6

		bb3:                                              ; preds = %bb6, %bb5
		  br i1 true, label %bb4, label %bb7

		bb4:                                              ; preds = %bb3
		  store i32 1, i32* @glob0
		  ret void

		bb5:                                              ; preds = %bb2
		  br label %bb3

		bb6:                                              ; preds = %bb2
		  br label %bb3

		bb7:                                              ; preds = %bb3
		  br label %bb2
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, externalCall01)
{
	parseInput(R"(
		; Test with external call(rand()).
		; store i32 3, i32* @glob0 can be optimized only if we run aggressive variant of optimization.
		; In aggressive variant we assume that we don't have some use in external calls.

		@glob0 = internal unnamed_addr global i32 0

		declare i32 @rand() nounwind

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  store i32 3, i32* @glob0, align 4 ; Can be optimized because we run aggressive variant of optimization.
		  call i32 @rand()
		  br label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		; Function Attrs: nounwind
		declare i32 @rand() #0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32 @rand()
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}

		attributes #0 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall01)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		declare i32 @rand() nounwind

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1, align 4
		  call i32 @alfa()
		  store i32 2, i32* @glob1, align 4 ; Can be optimized, no use.
		  %ll = load i32, i32* @glob3, align 4
		  store i32 4, i32* @glob3, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob3, align 4.
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1, align 4 ; Can be optimized, no use.
		  store i32 5, i32* @glob3, align 4 ; Can't be optimized, use in %ll = load i32, i32* @glob3, align 4.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		; Function Attrs: nounwind
		declare i32 @rand() #0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob1, align 4
		  %0 = call i32 @alfa()
		  %ll = load i32, i32* @glob3, align 4
		  store i32 4, i32* @glob3, align 4
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 5, i32* @glob3, align 4
		  unreachable
		}

		attributes #0 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall02)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1, align 4
		  call i32 @alfa()
		  call i32 @beta()
		  store i32 2, i32* @glob1, align 4 ; Can't be optimized, use in %yy1 = load i32, i32* @glob1, align 4.
		  store i32 4, i32* @glob3, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob3, align 4.
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  %yy1 = load i32, i32* @glob1, align 4
		  %yy2 = load i32, i32* @glob1, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 7, i32* @glob3, align 4 ; Can be optimized, value is replaced by store i32 6, i32* @glob3, align 4.
		  unreachable
		}

		define i32 @beta() {
		beta:
		  store i32 6, i32* @glob3, align 4 ; Can be optimized, value is replaced by store i32 4, i32* @glob3, align 4.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob1, align 4
		  %0 = call i32 @alfa()
		  %1 = call i32 @beta()
		  store i32 2, i32* @glob1, align 4
		  store i32 4, i32* @glob3, align 4
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  %yy1 = load i32, i32* @glob1, align 4
		  %yy2 = load i32, i32* @glob1, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  unreachable
		}

		define i32 @beta() {
		beta:
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall03)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0
		@glob4 = internal unnamed_addr global i32 0 ; Can be optimized, no store to this global variable or load a value.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1, align 4
		  call i32 @alfa()
		  store i32 2, i32* @glob3, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob3, align 4.
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1, align 4 ; Can be optimized, no use.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob1, align 4
		  %0 = call i32 @alfa()
		  store i32 2, i32* @glob3, align 4
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall04)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 0 ; Can be optimized, no store to this global variable or load a value.
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0 ; Can be optimized, after removing all stores(this global variable has no use).
		@glob4 = internal unnamed_addr global i32 0 ; Can be optimized, no store to this global variable or load a value.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can be optimized, value is replaced by store i32 1, i32* @glob2, align 4.
		  br label %main1

		main1:
		  store i32 6, i32* @glob1, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob1, align 4.
		  br label %main2

		main2:
		  call i32 @alfa()
		  store i32 2, i32* @glob3, align 4 ; Can be optimized, no use.
		  %cc = load i32, i32* @glob1, align 4
		  br label %main3

		main3:
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %cc = load i32, i32* @glob1, align 4
		  store i32 1, i32* @glob1, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob1, align 4.
		  store i32 1, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  store i32 6, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %0 = call i32 @alfa()
		  %cc = load i32, i32* @glob1, align 4
		  br label %main3

		main3:                                            ; preds = %main2
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %cc = load i32, i32* @glob1, align 4
		  store i32 1, i32* @glob1, align 4
		  store i32 1, i32* @glob2, align 4
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall05)
{
	parseInput(R"(
		; Testing the call of some function that can contains some stores or loads of global variables.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can be optimized, value is replaced by store i32 10, i32* @glob2.
		  br label %main1

		main1:
		  br label %main2

		main2:
		  store i32 10, i32* @glob2 ; Can't be optimized, use in %z = load i32, i32* @glob2, align 4.
		  store i32 5, i32* @glob0 ; Can be optimized, value is replaced by store i32 2, i32* @glob0 and store i32 3, i32* @glob0.
		  store i32 7, i32* @glob1 ; Can be optimized, value is replaced by store i32 6, i32* @glob1.
		  call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4
		  %y = load i32, i32* @glob1, align 4
		  %z = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:
		  store i32 2, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0, align 4.
		  br label %alfa2

		right:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0, align 4.
		  store i32 9, i32* @glob2 ; Can't be optimized, use in %z = load i32, i32* @glob2, align 4.
		  br label %alfa2

		alfa2:
		  store i32 6, i32* @glob1 ; Can't be optimized, use in %y = load i32, i32* @glob1, align 4.
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
		  br label %main2

		main2:                                            ; preds = %main1
		  store i32 10, i32* @glob2
		  %0 = call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4
		  %y = load i32, i32* @glob1, align 4
		  %z = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:                                             ; preds = %alfa1
		  store i32 2, i32* @glob0
		  br label %alfa2

		right:                                            ; preds = %alfa1
		  store i32 3, i32* @glob0
		  store i32 9, i32* @glob2
		  br label %alfa2

		alfa2:                                            ; preds = %right, %left
		  store i32 6, i32* @glob1
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithCall06)
{
	parseInput(R"(
		; Testing the two times call with one load in the middle.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  br label %main2

		main2:
		  call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4
		  call i32 @alfa()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0, align 4.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  %0 = call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4
		  %1 = call i32 @alfa()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 3, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithoutCall01)
{
	parseInput(R"(
		; Testing two independent functions.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0
		@glob4 = internal unnamed_addr global i32 0 ; Can be optimized, no store to this global variable or load a value.

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1, align 4
		  store i32 2, i32* @glob3, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob3, align 4.
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1, align 4 ; Can be optimized, no use.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob1, align 4
		  store i32 2, i32* @glob3, align 4
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithoutCall02)
{
	parseInput(R"(
		; Testing two independent functions.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0
		@glob4 = internal unnamed_addr global i32 0 ; Can be optimized, after removing all stores(this global variable has no use).

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  store i32 5, i32* @glob4, align 4 ; Can be optimized, no use.
		  br label %main1

		main1:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  store i32 3, i32* @glob3, align 4 ; Can be optimized, value is replaced by store i32 2, i32* @glob3, align 4.
		  br label %main2

		main2:
		  %yy = load i32, i32* @glob1, align 4
		  store i32 2, i32* @glob3, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob3, align 4.
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob1, align 4 ; Can be optimized, no use.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0
		@glob3 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 4, i32* @glob2, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* @glob0, align 4
		  store i32 %xx, i32* @glob1, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  %yy = load i32, i32* @glob1, align 4
		  store i32 2, i32* @glob3, align 4
		  %cc = load i32, i32* @glob3, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, funcsWithoutCall03)
{
	parseInput(R"(
		; Testing one function that has no call.

		@glob0 = internal unnamed_addr global i32 0 ; Can be optimized, after removing all stores(this global variable has no use).

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  store i32 1, i32* @glob0, align 4 ; Can be optimized, no use.
		  br label %main2

		main2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, indirectCall01)
{
	parseInput(R"(
		; Testing the indirect call of function.

		@glob0 = internal global i32 5
		@glob1 = internal global i32 5

		; Can be reached by indirect call.
		define i32 @func1(i32 %a) #0 {
		bb:
		  store i32 1, i32* @glob0 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  %x = load i32, i32* @glob1
		  ret i32 0
		}

		; Can be reached by indirect call.
		define i32 @func2(i32 %a) #0 {
		bb:
		  store i32 2, i32* @glob0 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  store i32 4, i32* @glob1 ; Can be optimized, no use.
		  ret i32 0
		}

		; Can't be reached by indirect call.
		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0.
		  store i32 6, i32* @glob1 ; Can't be optimized, possibly use in some indirect called function.
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5
		@glob1 = internal global i32 5

		define i32 @func1(i32 %a) {
		bb:
		  store i32 1, i32* @glob0
		  %x = load i32, i32* @glob1
		  ret i32 0
		}

		define i32 @func2(i32 %a) {
		bb:
		  store i32 2, i32* @glob0
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 3, i32* @glob0
		  store i32 6, i32* @glob1
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, indirectCall02)
{
	parseInput(R"(
		; Testing the indirect call of function.

		@glob0 = internal global i32 5, align 4
		@glob1 = internal global i32 5, align 4

		; Can be called indirectly.
		define i32 @func1(i32 %a) #0 {
		bb:
		  %x = load i32, i32* @glob0
		  store i32 1, i32* @glob0, align 4 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @func2(i32 %a) #0 {
		bb:
		  store i32 2, i32* @glob0, align 4 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  store i32 2, i32* @glob1, align 4 ; Can be optimized, no use.
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @func3(i32 %a) #0 {
		bb:
		  store i32 33, i32* @glob0 ; Can be optimized, no use.
		  store i32 3, i32* @glob0, align 4 ; Can't be optimized, use in %z = load i32, i32* @glob0.
		  %z = load i32, i32* @glob0
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @func4(i32 %a) #0 {
		bb:
		  store i32 44, i32* @glob0 ; Can be optimized, no use.
		  store i32 4, i32* @glob0, align 4 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  ret i32 0
		}

		; Has more than one argument so we know that this function is not called indirectly.
		define i32 @func5(i32 %a, i32 %b) #0 {
		bb:
		  store i32 5, i32* @glob0 ; Can be optimized, no use.
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @funcVarArg1(i32, ...) #0 {
		bb:
		  store i32 3, i32* @glob0 ; Can't be optimized, possibly use in %x = load i32, i32* @glob0.
		  ret i32 0
		}

		; Can be called indirectly.
		define i32 @funcVarArg2(i32, ...) #0 {
		bb:
		  store i32 4, i32* @glob1 ; Can be optimized, no use.
		  ret i32 0
		}

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 3, i32* @glob0, align 4 ; Can't be optimized, use in %x = load i32, i32* @glob0 and also possibly use in some indirect called function.
		  store i32 6, i32* @glob1, align 4 ; Can't be optimized, possibly use in some indirect called function.
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc) #2
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32 5, align 4
		@glob1 = internal global i32 5, align 4

		define i32 @func1(i32 %a) {
		bb:
		  %x = load i32, i32* @glob0
		  store i32 1, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @func2(i32 %a) {
		bb:
		  store i32 2, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @func3(i32 %a) {
		bb:
		  store i32 3, i32* @glob0, align 4
		  %z = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @func4(i32 %a) {
		bb:
		  store i32 4, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @func5(i32 %a, i32 %b) {
		bb:
		  ret i32 0
		}

		define i32 @funcVarArg1(i32, ...) {
		bb:
		  store i32 3, i32* @glob0
		  ret i32 0
		}

		define i32 @funcVarArg2(i32, ...) {
		bb:
		  ret i32 0
		}

		define i32 @main(i32 %argc, i8** %argv) {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  store i32 3, i32* @glob0, align 4
		  store i32 6, i32* @glob1, align 4
		  br i1 %tmp, label %bb1, label %bb3

		bb1:                                              ; preds = %bb
		  br label %bb5

		bb3:                                              ; preds = %bb
		  br label %bb5

		bb5:                                              ; preds = %bb3, %bb1
		  %tmp6 = phi i32 (...)* [ bitcast (i32 (i32)* @func2 to i32 (...)*), %bb3 ], [ bitcast (i32 (i32)* @func1 to i32 (...)*), %bb1 ]
		  %tmp7 = bitcast i32 (...)* %tmp6 to i32 (i32, ...)*
		  %tmp8 = call i32 (i32, ...) %tmp7(i32 %argc)
		  %x = load i32, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, moreSuccs01)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		right:
		  store i32 4, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 5, i32* @glob0, align 4
		  br label %main2

		right:                                            ; preds = %main1
		  store i32 4, i32* @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, moreSuccs02)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 6, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main1

		main1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:
		  store i32 4, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 7, i32* @glob0, align 4.
		  store i32 7, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  %yy = load i32, i32* @glob1, align 4
		  br label %main2

		right:
		  store i32 4, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 5, i32* @glob0, align 4 ; Can be optimized, no use.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 6, i32* @glob1, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 7, i32* @glob0, align 4
		  %yy = load i32, i32* @glob1, align 4
		  br label %main2

		right:                                            ; preds = %main1
		  store i32 4, i32* @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, moreSuccs03)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.
		; Also we have here function call.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 6, i32* @glob1, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
		  br label %main1

		main1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:
		  store i32 4, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 7, i32* @glob0, align 4.
		  store i32 7, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  %yy = load i32, i32* @glob1, align 4
		  br label %main2

		right:
		  call i32 @alfa()
		  store i32 6, i32* @glob0, align 4  ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  %xx = load i32, i32* @glob0, align 4
		  store i32 5, i32* @glob0, align 4 ; Can be optimized, no use.
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 8, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 6, i32* @glob0, align 4.
		  unreachable
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 6, i32* @glob1, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:                                             ; preds = %main1
		  store i32 7, i32* @glob0, align 4
		  %yy = load i32, i32* @glob1, align 4
		  br label %main2

		right:                                            ; preds = %main1
		  %0 = call i32 @alfa()
		  store i32 6, i32* @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, moreSuccs04)
{
	parseInput(R"(
		; Some basic block has more than one successor and this successors are not in cycle dependency.

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br label %main1

		main1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:
		  %yy = load i32, i32* @glob0, align 4
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		right:
		  store i32 4, i32* @glob0, align 4 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  br label %main2

		main2:
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store i32 5, i32* @glob0, align 4
		  br label %main1

		main1:                                            ; preds = %main0
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %left, label %right

		left:                                             ; preds = %main1
		  %yy = load i32, i32* @glob0, align 4
		  store i32 5, i32* @glob0, align 4
		  br label %main2

		right:                                            ; preds = %main1
		  store i32 4, i32* @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %right, %left
		  %xx = load i32, i32* @glob0, align 4
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, pointers01)
{
	parseInput(R"(
		; We have global variable that is a pointer. Nothing to optimize.

		@glob0 = internal global i32* null, align 4

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  %xx = alloca i32, align 4
		  store i32* %xx, i32** @glob0, align 4 ; Global variable is a pointer, nothing to optimize.
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
		  %xx = alloca i32, align 4
		  store i32* %xx, i32** @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, pointers02)
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
		  store i32* %xx, i32** @glob0, align 4 ; Global variable is a pointer, nothing to optimize.
		  br label %main2

		main2:
		  store i32 1, i32* @glob1, align 4 ; Can't be optimized, use in %c = load i32, i32* @glob1.
		  %c = load i32, i32* @glob1
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal global i32* null, align 4
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = alloca i32, align 4
		  store i32* %xx, i32** @glob0, align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  store i32 1, i32* @glob1, align 4
		  %c = load i32, i32* @glob1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, privateInternal01)
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
		  br label %main1

		main1:                                            ; preds = %main0
		  call void @alfa()
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

TEST_F(DeadGlobalAssignTests, recursion01)
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
		  store i32 4, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 5, i32* @glob0, align 4.
		  br label %ret2

		ret2:
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
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
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
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
		  %0 = call i32 @alfa()
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion02)
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
		  store i32 4, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 5, i32* @glob0, align 4.
		  br label %ret2

		ret2:
		  store i32 5, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 7, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 4, i32* @glob0, align 4.
		  call i32 @alfa()
		  store i32 8, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
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
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
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
		  %0 = call i32 @alfa()
		  store i32 8, i32* @glob0, align 4
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion03)
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
		  store i32 8, i32* @glob0, align 4 ; Can be optimized, no use.
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 7, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  br i1 1, label %left, label %right

		left:
		  ret i32 0

		right:
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
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %0 = call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 7, i32* @glob0, align 4
		  br i1 true, label %left, label %right

		left:                                             ; preds = %beta1
		  ret i32 0

		right:                                            ; preds = %beta1
		  %0 = call i32 @alfa()
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion04)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between two functions alfa() and beta().

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0
		@glob2 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call i32 @alfa()
		  %yy = load i32, i32* @glob0, align 4
		  %ll = load i32, i32* @glob1, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:
		  br label %ret2

		ret2:
		  store i32 9, i32* @glob2, align 4 ; Can't be optimized, use in %cc = load i32, i32* @glob2, align 4.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  store i32 9, i32* @glob1, align 4 ; Can't be optimized, use in %ll = load i32, i32* @glob1, align 4.
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 2, i32* @glob1, align 4 ; Can be optimized, value is replaced by store i32 9, i32* @glob1, align 4.
		  store i32 7, i32* @glob0, align 4 ; Can be optimized, value is replaced by store i32 8, i32* @glob0, align 4.
		  call i32 @alfa()
		  %cc = load i32, i32* @glob2, align 4
		  store i32 8, i32* @glob0, align 4 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
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
		  %yy = load i32, i32* @glob0, align 4
		  %ll = load i32, i32* @glob1, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
		  br label %ret2

		ret2:                                             ; preds = %ret1
		  store i32 9, i32* @glob2, align 4
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @beta()
		  store i32 9, i32* @glob1, align 4
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %0 = call i32 @alfa()
		  %cc = load i32, i32* @glob2, align 4
		  store i32 8, i32* @glob0, align 4
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion05)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between three functions alfa(), gamma() and beta().

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
		  br label %ret2

		ret2:
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 3, i32* @glob0 ; Can be optimized, value is replaced by store i32 4, i32* @glob0.
		  call i32 @gamma()
		  %zz = load i32, i32* @glob0, align 4
		  unreachable
		}

		define i32 @gamma() {
		gamma1:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %zz = load i32, i32* @glob0, align 4.
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
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:                                             ; preds = %alfa1
		  br label %ret2

		ret2:                                             ; preds = %ret1
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %0 = call i32 @gamma()
		  %zz = load i32, i32* @glob0, align 4
		  unreachable
		}

		define i32 @gamma() {
		gamma1:
		  store i32 4, i32* @glob0
		  %0 = call i32 @alfa()
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion06)
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
		  %xx = load i32, i32* @glob0, align 4
		  %yy = load i32, i32* @glob1, align 4
		  %zz = load i32, i32* @glob2, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %alfa2

		ret1:
		  br label %ret2

		ret2:
		  store i32 1, i32* @glob2 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  ret i32 0

		alfa2:
		  call i32 @beta()
		  store i32 9, i32* @glob1 ; Can't be optimized, use in %yy = load i32, i32* @glob1, align 4.
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
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %xx = load i32, i32* @glob0, align 4.
		  call i32 @alfa()
		  store i32 2, i32* @glob2 ; Can't be optimized, use in %zz = load i32, i32* @glob2, align 4.
		  unreachable
		}

		define i32 @beta() {
		beta1:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  call i32 @gamma()
		  store i32 7, i32* @glob1 ; Can be optimized, value is replaced by store i32 9, i32* @glob1.
		  %yy = load i32, i32* @glob0, align 4
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
		  %xx = load i32, i32* @glob0, align 4
		  %yy = load i32, i32* @glob1, align 4
		  %zz = load i32, i32* @glob2, align 4
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
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret, label %gamma2

		ret:                                              ; preds = %gamma1
		  ret i32 0

		gamma2:                                           ; preds = %gamma1
		  store i32 4, i32* @glob0
		  %0 = call i32 @alfa()
		  store i32 2, i32* @glob2
		  unreachable
		}

		define i32 @beta() {
		beta1:
		  store i32 3, i32* @glob0
		  %0 = call i32 @gamma()
		  %yy = load i32, i32* @glob0, align 4
		  unreachable
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion07)
{
	parseInput(R"(
		; Testing the recursion. The recursion is self recursion on function alfa().

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
		  br i1 %x, label %ret, label %alfa2

		ret:
		  store i32 4, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  ret i32 0

		alfa2:
		  call i32 @alfa()
		  store i32 2, i32* @glob0 ; Can't be optimized, use in %yy = load i32, i32* @glob0, align 4.
		  ret i32 0
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
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret, label %alfa2

		ret:                                              ; preds = %alfa1
		  store i32 4, i32* @glob0
		  ret i32 0

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @alfa()
		  store i32 2, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion08)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between three functions alfa(), gamma() and beta().

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		   br label %main1
		main1:
		   call i32 @alfa()
		   ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob0 ; Can't be optimized, use in %c = load i32, i32* @glob0.
		  call i32 @beta()
		  %c = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %x =  icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %beta2

		ret1:
		  ret i32 0

		beta2:
		  store i32 2, i32* @glob0 ; Can be optimized, value is replaced by store i32 1, i32* @glob0.
		  call i32 @gamma()
		  unreachable
		}

		define i32 @gamma() {
		gamma1:
		  store i32 3, i32* @glob0 ; Can be optimized, value is replaced by store i32 1, i32* @glob0.
		  call i32 @alfa()
		  ret i32 0
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
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  store i32 1, i32* @glob0
		  %0 = call i32 @beta()
		  %c = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  %x = icmp eq i32 2, 0
		  br i1 %x, label %ret1, label %beta2

		ret1:                                             ; preds = %beta1
		  ret i32 0

		beta2:                                            ; preds = %beta1
		  %0 = call i32 @gamma()
		  unreachable
		}

		define i32 @gamma() {
		gamma1:
		  %0 = call i32 @alfa()
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion09)
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
		  %x = load i32, i32* @glob0, align 4
		  call i32 @alfa()
		  br label %ret1

		ret1:
		  store i32 3, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0, align 4.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  %0 = call i32 @alfa()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  br i1 false, label %ret1, label %alfa2

		alfa2:                                            ; preds = %alfa1
		  %0 = call i32 @alfa()
		  %x = load i32, i32* @glob0, align 4
		  %1 = call i32 @alfa()
		  br label %ret1

		ret1:                                             ; preds = %alfa2, %alfa1
		  store i32 3, i32* @glob0
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion10)
{
	parseInput(R"(
		; Testing the recursion. The recursion is between three functions alfa(), gamma() and beta().

		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  store i32 1, i32* @glob0 ; Can't be optimized, use in %x = load i32, i32* @glob0.
		  call i32 @gama()
		  br label %alfa2

		alfa2:
		  call i32 @beta()
		  %y = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  br i1 1, label %ret1, label %ret2

		ret1:
		  call i32 @alfa()
		  ret i32 0

		ret2:
		  ret i32 0
		}

		define i32 @gama() {
		gama1:
		  %z = icmp eq i32 2, 0
		  br i1 1, label %ret1, label %ret2

		ret1:
		  call i32 @alfa()
		  ret i32 0

		ret2:
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob0 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  br label %main1

		main1:                                            ; preds = %main0
		  %0 = call i32 @beta()
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
		  %x = icmp eq i32 2, 0
		  store i32 1, i32* @glob0
		  %0 = call i32 @gama()
		  br label %alfa2

		alfa2:                                            ; preds = %alfa1
		  %1 = call i32 @beta()
		  %y = load i32, i32* @glob0
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  br i1 true, label %ret1, label %ret2

		ret1:                                             ; preds = %beta1
		  %0 = call i32 @alfa()
		  ret i32 0

		ret2:                                             ; preds = %beta1
		  ret i32 0
		}

		define i32 @gama() {
		gama1:
		  %z = icmp eq i32 2, 0
		  br i1 true, label %ret1, label %ret2

		ret1:                                             ; preds = %gama1
		  %0 = call i32 @alfa()
		  ret i32 0

		ret2:                                             ; preds = %gama1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, recursion11)
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
		  store i32 1, i32* @glob0 ; Can be optimized, never ending recursion.
		  call i32 @beta()
		  ret i32 0
		}

		define i32 @beta() {
		beta1:
		  store i32 3, i32* @glob0 ; Can be optimized, never ending recursion.
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
		  %yy = load i32, i32* @glob0, align 4
		  ret i32 0
		}

		define i32 @alfa() {
		alfa1:
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

TEST_F(DeadGlobalAssignTests, useInDefGlob01)
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

TEST_F(DeadGlobalAssignTests, useWithAddr01)
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
		  br label %main1

		main1:                                            ; preds = %main0
		  %xx = load i32, i32* inttoptr (i32 12345 to i32*), align 4
		  br label %main2

		main2:                                            ; preds = %main1
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(DeadGlobalAssignTests, volatile01)
{
	parseInput(R"(
		; Testing of not removing volatile stores.

		@glob0 = internal unnamed_addr global i32 0
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4 ; Can't be optimized, volatile store.
		  store volatile i32 8, i32* @glob1, align 4 ; Can't be optimized, volatile store.
		  ret i32 0
		}
	)");

	runOnModule();

	std::string exp = R"(
		@glob1 = internal unnamed_addr global i32 0

		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
		main0:
		  store volatile i32 6, i32* @glob1, align 4
		  store volatile i32 8, i32* @glob1, align 4
		  ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// -not-aggressive
//

TEST_F(DeadGlobalAssignTests, doNotRemoveUsedStore)
{
	parseInput(R"(
		; ModuleID = 'doNotRemoveUsedStore.ll'
		;
		; This test checks that -dead-global-assign does not remove a store that is, in
		; fact, used, and its removal would result in invalid code (a missing increment
		; in a loop).
		;
		; The store that cannot be optimized is
		;
		;    store i32 %add_ab_1_40158b, i32* %ebx.global-to-local
		;
		; This .ll file was created from the following regression test:
		;
		;     nested-for-loop.c -a x86 -f pe -c gcc -C -O1
		;

		@global_var_409044.44 = constant [7 x i8] c"%d %d\0A\00"

		; Function Attrs: nounwind
		define i32 @main(i32 %argc, i8** %argv) local_unnamed_addr #0 {
		dec_label_pc_401560:
		  %ebx.global-to-local = alloca i32
		  %esi.global-to-local = alloca i32
		  %stack_var_-36_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-32_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-28_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-24_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-16_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-12_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-8_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-4_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_0_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_4_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_8_x = call i8** @__decompiler_undefined_function_1()
		  call void @___main() #0
		  store i32 0, i32* %esi.global-to-local, align 4
		  br label %dec_label_pc_40159b

		dec_label_pc_401577:                              ; preds = %dec_label_pc_40159b, %dec_label_pc_401577
		  %u4_40157b = phi i32 [ %u4_40157b9, %dec_label_pc_40159b ], [ %u2_401593, %dec_label_pc_401577 ]
		  %u4_401577 = phi i32 [ 0, %dec_label_pc_40159b ], [ %add_ab_1_40158b, %dec_label_pc_401577 ]
		  %tmp = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([7 x i8], [7 x i8]* @global_var_409044.44, i32 0, i32 0), i32 %u4_40157b, i32 %u4_401577)
		  %u2_40158b = load i32, i32* %ebx.global-to-local, align 4
		  %add_ab_1_40158b = add i32 %u2_40158b, 1
		  store i32 %add_ab_1_40158b, i32* %ebx.global-to-local, align 4 ; <------------------ This store cannot be optimized!!!
		  %condFromFlags_401591 = icmp eq i32 %add_ab_1_40158b, 10
		  %u2_401593 = load i32, i32* %esi.global-to-local, align 4
		  br i1 %condFromFlags_401591, label %dec_label_pc_401593, label %dec_label_pc_401577

		dec_label_pc_401593:                              ; preds = %dec_label_pc_401577
		  %add_ab_1_401593 = add i32 %u2_401593, 1
		  store i32 %add_ab_1_401593, i32* %esi.global-to-local, align 4
		  %condFromFlags_401599 = icmp eq i32 %add_ab_1_401593, 10
		  br i1 %condFromFlags_401599, label %dec_label_pc_4015a2, label %dec_label_pc_40159b

		dec_label_pc_40159b:                              ; preds = %dec_label_pc_401593, %dec_label_pc_401560
		  %u4_40157b9 = phi i32 [ %add_ab_1_401593, %dec_label_pc_401593 ], [ 0, %dec_label_pc_401560 ]
		  store i32 0, i32* %ebx.global-to-local, align 4
		  br label %dec_label_pc_401577

		dec_label_pc_4015a2:                              ; preds = %dec_label_pc_401593
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare void @___main() local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i32 @printf(i8*, ...) local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i32 @__decompiler_undefined_function_0() local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i8** @__decompiler_undefined_function_1() local_unnamed_addr #0

		attributes #0 = { nounwind }
	)");

	runOnModule();

	std::string exp = R"(
		@global_var_409044.44 = constant [7 x i8] c"%d %d\0A\00"

		; Function Attrs: nounwind
		define i32 @main(i32 %argc, i8** %argv) local_unnamed_addr #0 {
		dec_label_pc_401560:
		  %ebx.global-to-local = alloca i32
		  %esi.global-to-local = alloca i32
		  %stack_var_-36_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-32_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-28_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-24_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-16_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-12_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-8_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_-4_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_0_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_4_x = call i32 @__decompiler_undefined_function_0()
		  %stack_var_8_x = call i8** @__decompiler_undefined_function_1()
		  call void @___main() #0
		  store i32 0, i32* %esi.global-to-local, align 4
		  br label %dec_label_pc_40159b

		dec_label_pc_401577:                              ; preds = %dec_label_pc_40159b, %dec_label_pc_401577
		  %u4_40157b = phi i32 [ %u4_40157b9, %dec_label_pc_40159b ], [ %u2_401593, %dec_label_pc_401577 ]
		  %u4_401577 = phi i32 [ 0, %dec_label_pc_40159b ], [ %add_ab_1_40158b, %dec_label_pc_401577 ]
		  %tmp = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([7 x i8], [7 x i8]* @global_var_409044.44, i32 0, i32 0), i32 %u4_40157b, i32 %u4_401577)
		  %u2_40158b = load i32, i32* %ebx.global-to-local, align 4
		  %add_ab_1_40158b = add i32 %u2_40158b, 1
		  store i32 %add_ab_1_40158b, i32* %ebx.global-to-local, align 4
		  %condFromFlags_401591 = icmp eq i32 %add_ab_1_40158b, 10
		  %u2_401593 = load i32, i32* %esi.global-to-local, align 4
		  br i1 %condFromFlags_401591, label %dec_label_pc_401593, label %dec_label_pc_401577

		dec_label_pc_401593:                              ; preds = %dec_label_pc_401577
		  %add_ab_1_401593 = add i32 %u2_401593, 1
		  store i32 %add_ab_1_401593, i32* %esi.global-to-local, align 4
		  %condFromFlags_401599 = icmp eq i32 %add_ab_1_401593, 10
		  br i1 %condFromFlags_401599, label %dec_label_pc_4015a2, label %dec_label_pc_40159b

		dec_label_pc_40159b:                              ; preds = %dec_label_pc_401593, %dec_label_pc_401560
		  %u4_40157b9 = phi i32 [ %add_ab_1_401593, %dec_label_pc_401593 ], [ 0, %dec_label_pc_401560 ]
		  store i32 0, i32* %ebx.global-to-local, align 4
		  br label %dec_label_pc_401577

		dec_label_pc_4015a2:                              ; preds = %dec_label_pc_401593
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare void @___main() local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i32 @printf(i8*, ...) local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i32 @__decompiler_undefined_function_0() local_unnamed_addr #0

		; Function Attrs: nounwind
		declare i8** @__decompiler_undefined_function_1() local_unnamed_addr #0

		attributes #0 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

// TODO: Fails without -not-aggressive parameter.
// I have no idea how to use it from here.
//
//TEST_F(DeadGlobalAssignTests, externalCall01)
//{
//	parseInput(R"(
//		; Test with external call(rand()).
//		; store i32 3, i32* @glob0 can be optimized only if we run aggressive variant of optimization.
//		; In not aggressive variant we assume that we have some use in external calls.
//
//		@glob0 = internal unnamed_addr global i32 0
//
//		declare i32 @rand() nounwind
//
//		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
//		main0:
//		  br label %main1
//
//		main1:
//		  store i32 3, i32* @glob0, align 4 ; Can't be optimized because we run not aggressive variant of optimization
//		  call i32 @rand()
//		  br label %main2
//
//		main2:
//		  ret i32 0
//		}
//	)");
//
//	runOnModule();
//
//	std::string exp = R"(
//		@glob0 = internal unnamed_addr global i32 0
//
//		; Function Attrs: nounwind
//		declare i32 @rand() #0
//
//		define i32 @main(i32 %arg1, i8** nocapture %arg2) {
//		main0:
//		  br label %main1
//
//		main1:                                            ; preds = %main0
//		  store i32 3, i32* @glob0, align 4
//		  %0 = call i32 @rand()
//		  br label %main2
//
//		main2:                                            ; preds = %main1
//		  ret i32 0
//		}
//
//		attributes #0 = { nounwind }
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}

// TODO: Fails without -not-aggressive parameter.
// I have no idea how to use it from here.
//
//TEST_F(DeadGlobalAssignTests, externalCall02)
//{
//	parseInput(R"(
//		; Test with external call(rand()).
//		; Some assigns can be optimized only if we run aggressive variant of optimization.
//		; In not aggressive variant we assume that we have some use in external calls.
//
//		@glob0 = internal global i32 5
//
//		declare i32 @rand() nounwind
//
//		; Function Attrs: uwtable
//		define i32 @main(i32 %argc, i8** %argv) #0 {
//		bb:
//		  store i32 1, i32* @glob0 ; Can't be optimized. Has possible use in external function.
//		  br label %bb1
//
//		bb1:
//		  call void @funcWithExternalCall()
//		  br i1 1, label %bb2, label %bb3
//
//		bb2:
//		  br label %bb5
//
//		bb3:
//		  br label %bb5
//
//		bb5:
//		  call i32 @rand()
//		  ret i32 0
//		}
//
//		define void @funcWithExternalCall() {
//		bb:
//		  call i32 @rand()
//		  ret void
//		}
//	)");
//
//	runOnModule();
//
//	std::string exp = R"(
//		@glob0 = internal global i32 5
//
//		; Function Attrs: nounwind
//		declare i32 @rand() #0
//
//		define i32 @main(i32 %argc, i8** %argv) {
//		bb:
//		  store i32 1, i32* @glob0
//		  br label %bb1
//
//		bb1:                                              ; preds = %bb
//		  call void @funcWithExternalCall()
//		  br i1 true, label %bb2, label %bb3
//
//		bb2:                                              ; preds = %bb1
//		  br label %bb5
//
//		bb3:                                              ; preds = %bb1
//		  br label %bb5
//
//		bb5:                                              ; preds = %bb3, %bb2
//		  %0 = call i32 @rand()
//		  ret i32 0
//		}
//
//		define void @funcWithExternalCall() {
//		bb:
//		  %0 = call i32 @rand()
//		  ret void
//		}
//
//		attributes #0 = { nounwind }
//	)";
//	checkModuleAgainstExpectedIr(exp);
//}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
