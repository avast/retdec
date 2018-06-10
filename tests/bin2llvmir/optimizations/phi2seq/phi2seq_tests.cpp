/**
* @file tests/bin2llvmir/optimizations/phi2seq/tests/phi2seq_tests.cpp
* @brief Tests for the @c PHI2Seq optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/bin2llvmir/optimizations/phi2seq/phi2seq.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
* @brief Tests for the @c PHI2Seq optimization.
*/
class PHI2SeqTests: public LlvmIrTests
{
	protected:
		void runOnFunctions()
		{
			LlvmIrTests::runOnFunctions<PHI2Seq>();
		}

	protected:
		PHI2Seq pass;
};

TEST_F(PHI2SeqTests, OptimizerHasNonEmptyID)
{
	EXPECT_TRUE(pass.getPassName()) <<
			"the optimizer should have a non-empty ID";
}

TEST_F(PHI2SeqTests, cycleVarDepend01)
{
	parseInput(R"(
		; Testing cycle variable dependency. Block with cycle doesn't have successor on its own.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %0, %.next
		  %A = phi i32 [ %B, %.next ], [ 1, %0 ]
		  %B = phi i32 [ %C, %.next ], [ 2, %0 ]
		  %C = phi i32 [ %A, %.next ], [ 3, %0 ]
		  %2 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) nounwind
		  br label %.next

		.next:                                      ; preds = %.lr.ph
		  %3 = icmp eq i32 %A, 3
		  br i1 %3, label %._exitnode , label %.lr.ph

		._exitnode:                                      ; preds = %.lr.ph
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.next
		  %B.phi2seq.tmp = phi i32 [ %B, %.next ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre, %bb
		  %B = phi i32 [ %C, %.lr.ph.phi2seq.pre ], [ 2, %bb ]
		  %C = phi i32 [ %A, %.lr.ph.phi2seq.pre ], [ 3, %bb ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %bb ]
		  %tmp1 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) #1
		  br label %.next

		.next:                                            ; preds = %.lr.ph
		  %tmp2 = icmp eq i32 %A, 3
		  br i1 %tmp2, label %._exitnode, label %.lr.ph.phi2seq.pre

		._exitnode:                                       ; preds = %.next
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend02)
{
	parseInput(R"(
		; Testing cycle variable dependency. Block with cycle has successor on its own.

		@.str = private unnamed_addr constant [23 x i8] c"Argument %d %d %d: %s\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 0
		  br i1 %1, label %.lr.ph.preheader, label %._crit_edge

		.lr.ph.preheader:                                 ; preds = %0
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph, %.lr.ph.preheader
		  %indvars.iv = phi i64 [ %indvars.iv.next, %.lr.ph ], [ 0, %.lr.ph.preheader ]
		  %A = phi i64 [ %B, %.lr.ph ], [ 1, %.lr.ph.preheader ]
		  %B = phi i64 [ %C, %.lr.ph ], [ 2, %.lr.ph.preheader ]
		  %C = phi i64 [ %A, %.lr.ph ], [ 3, %.lr.ph.preheader ]
		  %2 = getelementptr inbounds i8*, i8** %argv, i64 %indvars.iv
		  %3 = load i8*, i8** %2, align 8
		  %A.1 = trunc i64 %A to i32
		  %B.1 = trunc i64 %B to i32
		  %C.1 = trunc i64 %C to i32
		  %4 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([23 x i8], [23 x i8]* @.str, i64 0, i64 0), i32 %A.1, i32 %B.1, i32 %C.1, i8* %3) nounwind
		  %indvars.iv.next = add i64 %indvars.iv, 1
		  %lftr.wideiv1 = trunc i64 %indvars.iv.next to i32
		  %exitcond2 = icmp eq i32 %lftr.wideiv1, %argc
		  br i1 %exitcond2, label %._crit_edge.loopexit, label %.lr.ph

		._crit_edge.loopexit:                             ; preds = %.lr.ph
		  br label %._crit_edge

		._crit_edge:                                      ; preds = %._crit_edge.loopexit, %0
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [23 x i8] c"Argument %d %d %d: %s\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 0
		  br i1 %tmp, label %.lr.ph.preheader, label %._crit_edge

		.lr.ph.preheader:                                 ; preds = %bb
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.lr.ph
		  %B.phi2seq.tmp = phi i64 [ %B, %.lr.ph ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre, %.lr.ph.preheader
		  %indvars.iv = phi i64 [ %indvars.iv.next, %.lr.ph.phi2seq.pre ], [ 0, %.lr.ph.preheader ]
		  %B = phi i64 [ %C, %.lr.ph.phi2seq.pre ], [ 2, %.lr.ph.preheader ]
		  %C = phi i64 [ %A, %.lr.ph.phi2seq.pre ], [ 3, %.lr.ph.preheader ]
		  %A = phi i64 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %.lr.ph.preheader ]
		  %tmp1 = getelementptr inbounds i8*, i8** %argv, i64 %indvars.iv
		  %tmp2 = load i8*, i8** %tmp1, align 8
		  %A.1 = trunc i64 %A to i32
		  %B.1 = trunc i64 %B to i32
		  %C.1 = trunc i64 %C to i32
		  %tmp3 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([23 x i8], [23 x i8]* @.str, i64 0, i64 0), i32 %A.1, i32 %B.1, i32 %C.1, i8* %tmp2) #1
		  %indvars.iv.next = add i64 %indvars.iv, 1
		  %lftr.wideiv1 = trunc i64 %indvars.iv.next to i32
		  %exitcond2 = icmp eq i32 %lftr.wideiv1, %argc
		  br i1 %exitcond2, label %._crit_edge.loopexit, label %.lr.ph.phi2seq.pre

		._crit_edge.loopexit:                             ; preds = %.lr.ph
		  br label %._crit_edge

		._crit_edge:                                      ; preds = %._crit_edge.loopexit, %bb
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend03)
{
	parseInput(R"(
		; Testing cycle variable dependency. Cycle is in 2 blocks.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.first

		.lr.first:                                           ; preds = %0, %.nextFirst
		  %A = phi i32 [ %B, %.nextFirst ], [ 1, %0 ]
		  %B = phi i32 [ %C, %.nextFirst ], [ 2, %0 ]
		  %C = phi i32 [ %A, %.nextFirst ], [ 3, %0 ]
		  %2 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) nounwind
		  br label %.nextFirst

		.nextFirst:                                      ; preds = %.lr.first
		  %3 = icmp eq i32 %A, 3
		  br i1 %3, label %.lr.second , label %.lr.first

		.lr.second:                                           ; preds = %.nextFirst, %.nextSec
		  %D = phi i32 [ %E, %.nextSec ], [ 1, %.nextFirst ]
		  %E = phi i32 [ %F, %.nextSec ], [ 2, %.nextFirst ]
		  %F = phi i32 [ %D, %.nextSec ], [ 3, %.nextFirst ]
		  %4 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %D, i32 %E, i32 %F) nounwind
		  br label %.nextSec

		.nextSec:                                      ; preds = %.lr.second
		  %5 = icmp eq i32 %D, 3
		  br i1 %5, label %._exitnode , label %.lr.second

		._exitnode:                                      ; preds = %.nextSec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.first

		.lr.first.phi2seq.pre:                            ; preds = %.nextFirst
		  %B.phi2seq.tmp = phi i32 [ %B, %.nextFirst ]
		  br label %.lr.first

		.lr.first:                                        ; preds = %.lr.first.phi2seq.pre, %bb
		  %B = phi i32 [ %C, %.lr.first.phi2seq.pre ], [ 2, %bb ]
		  %C = phi i32 [ %A, %.lr.first.phi2seq.pre ], [ 3, %bb ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.first.phi2seq.pre ], [ 1, %bb ]
		  %tmp1 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) #1
		  br label %.nextFirst

		.nextFirst:                                       ; preds = %.lr.first
		  %tmp2 = icmp eq i32 %A, 3
		  br i1 %tmp2, label %.lr.second, label %.lr.first.phi2seq.pre

		.lr.second.phi2seq.pre:                           ; preds = %.nextSec
		  %E.phi2seq.tmp = phi i32 [ %E, %.nextSec ]
		  br label %.lr.second

		.lr.second:                                       ; preds = %.lr.second.phi2seq.pre, %.nextFirst
		  %E = phi i32 [ %F, %.lr.second.phi2seq.pre ], [ 2, %.nextFirst ]
		  %F = phi i32 [ %D, %.lr.second.phi2seq.pre ], [ 3, %.nextFirst ]
		  %D = phi i32 [ %E.phi2seq.tmp, %.lr.second.phi2seq.pre ], [ 1, %.nextFirst ]
		  %tmp3 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %D, i32 %E, i32 %F) #1
		  br label %.nextSec

		.nextSec:                                         ; preds = %.lr.second
		  %tmp4 = icmp eq i32 %D, 3
		  br i1 %tmp4, label %._exitnode, label %.lr.second.phi2seq.pre

		._exitnode:                                       ; preds = %.nextSec
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend04)
{
	parseInput(R"(
		; Testing cycle variable dependency. Two cycles that are connected and have different predecessor basic block.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %0, %.next, %.sec
		  %A = phi i32 [ %B, %.next ], [ 1, %0 ], [ 1, %.sec ]
		  %B = phi i32 [ %C, %.next ], [ 2, %0 ], [ 1, %.sec ]
		  %C = phi i32 [ %A, %.next ], [ 3, %0 ], [ 1, %.sec ]
		  %E = phi i32 [ %B, %.next ], [ 1, %0 ], [ %F, %.sec ]
		  %F = phi i32 [ 0, %.next ], [ 2, %0 ], [ %G, %.sec ]
		  %G = phi i32 [ 0, %.next ], [ 3, %0 ], [ %E, %.sec ]

		  %2 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) nounwind
		  br label %.next

		.next:                                      ; preds = %.lr.ph
		  %3 = icmp eq i32 %A, 3
		  br i1 %3, label %.sec , label %.lr.ph

		.sec:                                      ; preds = %.next
		  %4 = icmp eq i32 %A, 3
		  br i1 %4, label %._exitnode , label %.lr.ph

		._exitnode:                                      ; preds = %.next
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.next
		  %B.phi2seq.tmp = phi i32 [ %B, %.next ]
		  br label %.lr.ph

		.lr.ph.phi2seq.pre4:                              ; preds = %.sec
		  %E.phi2seq.tmp = phi i32 [ %E, %.sec ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre4, %.lr.ph.phi2seq.pre, %bb
		  %E = phi i32 [ %B, %.lr.ph.phi2seq.pre ], [ 1, %bb ], [ %F, %.lr.ph.phi2seq.pre4 ]
		  %B = phi i32 [ %C, %.lr.ph.phi2seq.pre ], [ 2, %bb ], [ 1, %.lr.ph.phi2seq.pre4 ]
		  %C = phi i32 [ %A, %.lr.ph.phi2seq.pre ], [ 3, %bb ], [ 1, %.lr.ph.phi2seq.pre4 ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %bb ], [ 1, %.lr.ph.phi2seq.pre4 ]
		  %F = phi i32 [ 0, %.lr.ph.phi2seq.pre ], [ 2, %bb ], [ %G, %.lr.ph.phi2seq.pre4 ]
		  %G = phi i32 [ 0, %.lr.ph.phi2seq.pre ], [ 3, %bb ], [ %E.phi2seq.tmp, %.lr.ph.phi2seq.pre4 ]
		  %tmp1 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) #1
		  br label %.next

		.next:                                            ; preds = %.lr.ph
		  %tmp2 = icmp eq i32 %A, 3
		  br i1 %tmp2, label %.sec, label %.lr.ph.phi2seq.pre

		.sec:                                             ; preds = %.next
		  %tmp3 = icmp eq i32 %A, 3
		  br i1 %tmp3, label %._exitnode, label %.lr.ph.phi2seq.pre4

		._exitnode:                                       ; preds = %.sec
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend05)
{
	parseInput(R"(
		; Testing cycle variable dependency. Block with cycle doesn't have successor on its own. Cycle is thanks to different predecessor basic block.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:  ; preds = %0, %.first, %.sec
		  %A = phi i32 [ %B, %.first ], [ 1, %0 ], [ 2, %.sec ]
		  %B = phi i32 [ 3, %.first ], [ 2, %0 ], [ %A, %.sec]
		  %2 = icmp eq i32 %A, 3
		  br i1 %2, label %.first, label %.sec

		.first:                                      ; preds = %.lr.ph
		  %3 = icmp eq i32 %A, 3
		  br i1 %3, label %._exitnode , label %.lr.ph

		.sec:                                      ; preds = %.lr.ph
		  %4 = icmp eq i32 %A, 3
		  br i1 %4, label %._exitnode , label %.lr.ph

		._exitnode:                                      ; preds = %.next
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.first
		  %B.phi2seq.tmp = phi i32 [ %B, %.first ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre, %.sec, %bb
		  %B = phi i32 [ 3, %.lr.ph.phi2seq.pre ], [ 2, %bb ], [ %A, %.sec ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %bb ], [ 2, %.sec ]
		  %tmp1 = icmp eq i32 %A, 3
		  br i1 %tmp1, label %.first, label %.sec

		.first:                                           ; preds = %.lr.ph
		  %tmp2 = icmp eq i32 %A, 3
		  br i1 %tmp2, label %._exitnode, label %.lr.ph.phi2seq.pre

		.sec:                                             ; preds = %.lr.ph
		  %tmp3 = icmp eq i32 %A, 3
		  br i1 %tmp3, label %._exitnode, label %.lr.ph

		._exitnode:                                       ; preds = %.sec, %.first
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend06)
{
	parseInput(R"(
		; Testing cycle variable dependency. Two cycles with same predecessor block. Block with cycle doesn't have successor on its own.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:  ; preds = %0, %.first, %.sec
		  %A = phi i32 [ %B, %.first ], [ 1, %0 ]
		  %B = phi i32 [ %A, %.first ], [ 2, %0 ]
		  %C = phi i32 [ %D, %.first ], [ 3, %0 ]
		  %D = phi i32 [ %C, %.first ], [ 4, %0 ]
		  br label %.first

		.first:                                      ; preds = %.lr.ph
		  %2 = icmp eq i32 %A, 3
		  br i1 %2, label %._exitnode , label %.lr.ph

		._exitnode:                                      ; preds = %.next
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.first
		  %B.phi2seq.tmp = phi i32 [ %B, %.first ]
		  %D.phi2seq.tmp = phi i32 [ %D, %.first ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre, %bb
		  %B = phi i32 [ %A, %.lr.ph.phi2seq.pre ], [ 2, %bb ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %bb ]
		  %D = phi i32 [ %C, %.lr.ph.phi2seq.pre ], [ 4, %bb ]
		  %C = phi i32 [ %D.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 3, %bb ]
		  br label %.first

		.first:                                           ; preds = %.lr.ph
		  %tmp1 = icmp eq i32 %A, 3
		  br i1 %tmp1, label %._exitnode, label %.lr.ph.phi2seq.pre

		._exitnode:                                       ; preds = %.first
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, cycleVarDepend07)
{
	parseInput(R"(
		; Testing cycle variable dependency. In PHI nodes are same variables for different predecessors basic blocks.

		; Function Attrs: nounwind
		declare i8* @decompiler_undefined_6() #0

		; Function Attrs: nounwind
		define void @function_804955e(i8* %arg1, i8* %arg2, i8* %arg3) #0 {
		dec_label_pc_804955e:
		  %stack_var_-80_x = call i8* @decompiler_undefined_6()
		  %stack_var_-76_x = call i8* @decompiler_undefined_6()
		  br label %dec_label_pc_80497d2

		dec_label_pc_80497d2:                             ; preds = %dec_label_pc_804979c
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_8049933:                             ; preds = %dec_label_pc_8049928, %dec_label_pc_80498bf
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_804997d:                             ; preds = %dec_label_pc_8049933
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_804998b.outer:                       ; preds = %dec_label_pc_804997d, %dec_label_pc_8049933, %dec_label_pc_80497d2
		  %u4_80499b9_1545.ph = phi i8* [ %stack_var_-76_x, %dec_label_pc_80497d2 ], [ %u4_8049954_1463.ph, %dec_label_pc_804997d ], [ %u4_8049954_1463.ph, %dec_label_pc_8049933 ]
		  %u4_8049954_1463.ph = phi i8* [ %stack_var_-80_x, %dec_label_pc_80497d2 ], [ %u4_80499b9_1545.ph, %dec_label_pc_804997d ], [ %u4_80499b9_1545.ph, %dec_label_pc_8049933 ]
		  br label %dec_label_pc_804998b

		dec_label_pc_804998b:                             ; preds = %dec_label_pc_804998b.outer, %dec_label_pc_8049928
		  br label %dec_label_pc_8049933
		}
	)");

	runOnFunctions();

	std::string exp = R"(
		declare i8* @decompiler_undefined_6()

		define void @function_804955e(i8* %arg1, i8* %arg2, i8* %arg3) {
		dec_label_pc_804955e:
		  %stack_var_-80_x = call i8* @decompiler_undefined_6()
		  %stack_var_-76_x = call i8* @decompiler_undefined_6()
		  br label %dec_label_pc_80497d2

		dec_label_pc_80497d2:                             ; preds = %dec_label_pc_804955e
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_8049933:                             ; preds = %dec_label_pc_804998b
		  br label %dec_label_pc_804998b.outer.phi2seq.pre

		dec_label_pc_804997d:                             ; No predecessors!
		  br label %dec_label_pc_804998b.outer.phi2seq.pre1

		dec_label_pc_804998b.outer.phi2seq.pre:           ; preds = %dec_label_pc_8049933
		  %u4_80499b9_1545.ph.phi2seq.tmp = phi i8* [ %u4_80499b9_1545.ph, %dec_label_pc_8049933 ]
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_804998b.outer.phi2seq.pre1:          ; preds = %dec_label_pc_804997d
		  %u4_80499b9_1545.ph.phi2seq.tmp2 = phi i8* [ %u4_80499b9_1545.ph, %dec_label_pc_804997d ]
		  br label %dec_label_pc_804998b.outer

		dec_label_pc_804998b.outer:                       ; preds = %dec_label_pc_804998b.outer.phi2seq.pre1, %dec_label_pc_804998b.outer.phi2seq.pre, %dec_label_pc_80497d2
		  %u4_80499b9_1545.ph = phi i8* [ %stack_var_-76_x, %dec_label_pc_80497d2 ], [ %u4_8049954_1463.ph, %dec_label_pc_804998b.outer.phi2seq.pre1 ], [ %u4_8049954_1463.ph, %dec_label_pc_804998b.outer.phi2seq.pre ]
		  %u4_8049954_1463.ph = phi i8* [ %stack_var_-80_x, %dec_label_pc_80497d2 ], [ %u4_80499b9_1545.ph.phi2seq.tmp2, %dec_label_pc_804998b.outer.phi2seq.pre1 ], [ %u4_80499b9_1545.ph.phi2seq.tmp, %dec_label_pc_804998b.outer.phi2seq.pre ]
		  br label %dec_label_pc_804998b

		dec_label_pc_804998b:                             ; preds = %dec_label_pc_804998b.outer
		  br label %dec_label_pc_8049933
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, nonCycleAndCycleVarDepend01)
{
	parseInput(R"(
		; Testing cycle variable dependency with no cycle variable dependency.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %0, %.next
		  %A = phi i32 [ %B, %.next ], [ 1, %0 ]
		  %B = phi i32 [ %C, %.next ], [ 2, %0 ]
		  %C = phi i32 [ %A, %.next ], [ 3, %0 ]
		  %D = phi i32 [ %A, %.next ], [ 4, %0 ]
		  %F = phi i32 [ %B, %.next ], [ 5, %0 ]
		  %E = phi i32 [ %D, %.next ], [ 6, %0 ]
		  %2 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) nounwind
		  br label %.next

		.next:                                      ; preds = %.lr.ph
		  %3 = icmp eq i32 %A, 3
		  br i1 %3, label %._exitnode , label %.lr.ph

		._exitnode:                                      ; preds = %.next
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph.phi2seq.pre:                               ; preds = %.next
		  %B.phi2seq.tmp = phi i32 [ %B, %.next ]
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.lr.ph.phi2seq.pre, %bb
		  %F = phi i32 [ %B, %.lr.ph.phi2seq.pre ], [ 5, %bb ]
		  %B = phi i32 [ %C, %.lr.ph.phi2seq.pre ], [ 2, %bb ]
		  %C = phi i32 [ %A, %.lr.ph.phi2seq.pre ], [ 3, %bb ]
		  %E = phi i32 [ %D, %.lr.ph.phi2seq.pre ], [ 6, %bb ]
		  %D = phi i32 [ %A, %.lr.ph.phi2seq.pre ], [ 4, %bb ]
		  %A = phi i32 [ %B.phi2seq.tmp, %.lr.ph.phi2seq.pre ], [ 1, %bb ]
		  %tmp1 = tail call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([20 x i8], [20 x i8]* @.str, i64 0, i64 0), i32 %A, i32 %B, i32 %C) #1
		  br label %.next

		.next:                                            ; preds = %.lr.ph
		  %tmp2 = icmp eq i32 %A, 3
		  br i1 %tmp2, label %._exitnode, label %.lr.ph.phi2seq.pre

		._exitnode:                                       ; preds = %.next
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, nonCycleVarDepend01)
{
	parseInput(R"(
		; Testing non-cycle variable dependency.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:       ; preds = %0
		  %G = phi i32 [ %A, %.sec ], [ 1, %0 ]
		  %B = phi i32 [ 3, %.sec ], [ 1, %0 ]
		  %A = phi i32 [ %B, %.sec ], [ 1, %0 ]
		  %C = phi i32 [ %A, %.sec ], [ 1, %0 ]
		  %D = phi i32 [ %C, %.sec ], [ 1, %0 ]
		  %E = phi i32 [ 2, %.sec ], [ 1, %0 ]
		  %H = phi i32 [ %G, %.sec ], [ 1, %0 ]
		  %F = phi i32 [ %H, %.sec ], [ 1, %0 ]
		  br label %.sec

		.sec:
		  %2 = icmp sgt i32 %A, 2
		  br i1 %2, label %.lr.ph, label %.sec

		._exitnode:                                      ; preds = %.sec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.sec, %bb
		  %D = phi i32 [ %C, %.sec ], [ 1, %bb ]
		  %C = phi i32 [ %A, %.sec ], [ 1, %bb ]
		  %F = phi i32 [ %H, %.sec ], [ 1, %bb ]
		  %H = phi i32 [ %G, %.sec ], [ 1, %bb ]
		  %G = phi i32 [ %A, %.sec ], [ 1, %bb ]
		  %A = phi i32 [ %B, %.sec ], [ 1, %bb ]
		  %B = phi i32 [ 3, %.sec ], [ 1, %bb ]
		  %E = phi i32 [ 2, %.sec ], [ 1, %bb ]
		  br label %.sec

		.sec:                                             ; preds = %.sec, %.lr.ph
		  %tmp1 = icmp sgt i32 %A, 2
		  br i1 %tmp1, label %.lr.ph, label %.sec

		._exitnode:                                       ; No predecessors!
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, nonCycleVarDepend02)
{
	parseInput(R"(
		; Testing non-cycle variable dependency. One variable is assigned two times.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:       ; preds = %0, %.exitnode
		  %F = phi i32 [ %D, %.sec ], [ 1, %0 ]
		  %C = phi i32 [ %D, %.sec ], [ 1, %0 ]
		  %A = phi i32 [ %D, %.sec ], [ 2, %0 ]
		  %D = phi i32 [ 1, %.sec ], [ 1, %0 ]
		  br label %.sec

		.sec:
		  %2 = icmp sgt i32 %A, 2
		  br i1 %2, label %.lr.ph, label %.sec

		._exitnode:                                      ; preds = %.lr.sec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.sec, %bb
		  %A = phi i32 [ %D, %.sec ], [ 2, %bb ]
		  %C = phi i32 [ %D, %.sec ], [ 1, %bb ]
		  %F = phi i32 [ %D, %.sec ], [ 1, %bb ]
		  %D = phi i32 [ 1, %.sec ], [ 1, %bb ]
		  br label %.sec

		.sec:                                             ; preds = %.sec, %.lr.ph
		  %tmp1 = icmp sgt i32 %A, 2
		  br i1 %tmp1, label %.lr.ph, label %.sec

		._exitnode:                                       ; No predecessors!
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, nonCycleVarDepend03)
{
	parseInput(R"(
		; Testing non-cycle variable dependency. Simple test.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:       ; preds = %0
		  %C = phi i32 [ 1, %.sec ], [ 1, %0 ]
		  %B = phi i32 [ %C, %.sec ], [ 1, %0 ]
		  %A = phi i32 [ %B, %.sec ], [ 1, %0 ]
		  br label %.sec

		.sec:
		  %2 = icmp sgt i32 %A, 2
		  br i1 %2, label %.lr.ph, label %.sec

		._exitnode:                                      ; preds = %.lr.sec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.sec, %bb
		  %A = phi i32 [ %B, %.sec ], [ 1, %bb ]
		  %B = phi i32 [ %C, %.sec ], [ 1, %bb ]
		  %C = phi i32 [ 1, %.sec ], [ 1, %bb ]
		  br label %.sec

		.sec:                                             ; preds = %.sec, %.lr.ph
		  %tmp1 = icmp sgt i32 %A, 2
		  br i1 %tmp1, label %.lr.ph, label %.sec

		._exitnode:                                       ; No predecessors!
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, nonCycleVarDepend04)
{
	parseInput(R"(
		; Testing non-cycle variable dependency.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:       ; preds = %0
		  %A = phi i32 [ 16, %.sec ], [ 1, %0 ]
		  %B = phi i32 [ %A, %.sec ], [ 1, %0 ]
		  br label %.sec

		.sec:
		  %2 = icmp sgt i32 %A, 2
		  br i1 %2, label %.lr.ph, label %.sec

		._exitnode:                                      ; preds = %.sec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.sec, %bb
		  %B = phi i32 [ %A, %.sec ], [ 1, %bb ]
		  %A = phi i32 [ 16, %.sec ], [ 1, %bb ]
		  br label %.sec

		.sec:                                             ; preds = %.sec, %.lr.ph
		  %tmp1 = icmp sgt i32 %A, 2
		  br i1 %tmp1, label %.lr.ph, label %.sec

		._exitnode:                                       ; No predecessors!
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(PHI2SeqTests, testOrderNoDependency01)
{
	parseInput(R"(
		; Testing if order is changed when no dependency of variables occured.

		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		define i32 @main(i32 %argc, i8** nocapture %argv) uwtable {
		  %1 = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:       ; preds = %0, %.sec
		  %G = phi i32 [ 1, %.sec ], [ 1, %0 ]
		  %C = phi i32 [ 3, %.sec ], [ 1, %0 ]
		  %D = phi i32 [ 4, %.sec ], [ 1, %0 ]
		  %B = phi i32 [ 5, %.sec ], [ 1, %0 ]
		  %A = phi i32 [ 4, %.sec ], [ 1, %0 ]
		  br label %.sec

		.sec:
		  %2 = icmp sgt i32 %G, 1
		  br i1 %2, label %.lr.ph, label %._exitnode

		._exitnode:                                      ; preds = %.lr.sec
		  ret i32 0
		}

		declare i32 @printf(i8* nocapture, ...) nounwind
	)");

	runOnFunctions();

	std::string exp = R"(
		@.str = private unnamed_addr constant [20 x i8] c"Argument %d %d %d:\0A\00", align 1

		; Function Attrs: uwtable
		define i32 @main(i32 %argc, i8** nocapture %argv) #0 {
		bb:
		  %tmp = icmp sgt i32 %argc, 1
		  br label %.lr.ph

		.lr.ph:                                           ; preds = %.sec, %bb
		  %G = phi i32 [ 1, %.sec ], [ 1, %bb ]
		  %C = phi i32 [ 3, %.sec ], [ 1, %bb ]
		  %D = phi i32 [ 4, %.sec ], [ 1, %bb ]
		  %B = phi i32 [ 5, %.sec ], [ 1, %bb ]
		  %A = phi i32 [ 4, %.sec ], [ 1, %bb ]
		  br label %.sec

		.sec:                                             ; preds = %.lr.ph
		  %tmp1 = icmp sgt i32 %G, 1
		  br i1 %tmp1, label %.lr.ph, label %._exitnode

		._exitnode:                                       ; preds = %.sec
		  ret i32 0
		}

		; Function Attrs: nounwind
		declare i32 @printf(i8* nocapture, ...) #1

		attributes #0 = { uwtable }
		attributes #1 = { nounwind }
	)";
	checkModuleAgainstExpectedIr(exp);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
