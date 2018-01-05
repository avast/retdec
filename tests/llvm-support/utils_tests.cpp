/**
 * @file tests/llvm-support/utils_tests.cpp
 * @brief Tests for the @c utils module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/llvm-support/tests/llvmir_tests.h"
#include "retdec/llvm-support/utils.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace llvm_support {
namespace tests {

/**
 * @brief Tests for the @c utils module.
 */
class UtilsTests: public LlvmIrTests
{

};

//
// skipCasts()
//

TEST_F(UtilsTests, skipCastsSkipsCastInstructionsAndReturnsFirstNonCastValue)
{
	parseInput(R"(
		@r = global i32 0
		define void @func() {
			%a = load i32, i32* @r
			%b = bitcast i32 %a to float
			%c = fpext float %b to double
			%d = fptoui double %c to i32
			%e = inttoptr i32 %d to i32*
			ret void
		}
	)");
	Value* e = getValueByName("e");
	Value* a = getValueByName("a");

	Value* r = skipCasts(e);

	EXPECT_EQ(a, r);
}

//
// skipConstantExprs()
//

TEST_F(UtilsTests, skipConstantExprsSkipsOneExpression)
{
	parseInput(R"(
		@gv = constant [6 x i8] c"abcdef"
		declare i32 @scanf(i8*, ...)
		define void @func() {
			%a = call i32 (i8*, ...) @scanf(i8* getelementptr inbounds ([6 x i8], [6 x i8]* @gv, i32 0, i32 0))
			ret void
		}
	)");
	Value* gv = getValueByName("gv");
	CallInst* a = dyn_cast<CallInst>(getValueByName("a"));

	Value* s = skipCasts(a->getArgOperand(0));

	EXPECT_EQ(gv, s);
}

} // namespace tests
} // namespace llvm_support
} // namespace retdec
