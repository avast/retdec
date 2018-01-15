/**
* @file tests/llvmir2hll/analysis/null_pointer_analysis_tests.cpp
* @brief Tests for the @c null_pointer_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/null_pointer_analysis.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c null_pointer_analysis module.
*/
class NullPointerAnalysisTests: public TestsWithModule {};

TEST_F(NullPointerAnalysisTests,
EmptyFunctionDoesNotUseAnyNullPointers) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	// Run the analysis and verify the result.
	EXPECT_FALSE(NullPointerAnalysis::useNullPointers(module));
}

TEST_F(NullPointerAnalysisTests,
NonEmptyFunctionWithoutNullPointersDoesNotUseThem) {
	// Set-up the module.
	//
	// void test() {
	//    int *a = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", PointerType::create(IntType::create(32))));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstInt::create(32, 1)));
	testFunc->setBody(varDefA);

	// Run the analysis and verify the result.
	EXPECT_FALSE(NullPointerAnalysis::useNullPointers(module));
}

TEST_F(NullPointerAnalysisTests,
FunctionWithNullPointersUseThem) {
	// Set-up the module.
	//
	// void test() {
	//    int *a = 0;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", PointerType::create(IntType::create(32))));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ConstNullPointer::create(
		PointerType::create(IntType::create(32)))));
	testFunc->setBody(varDefA);

	// Run the analysis and verify the result.
	EXPECT_TRUE(NullPointerAnalysis::useNullPointers(module));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
