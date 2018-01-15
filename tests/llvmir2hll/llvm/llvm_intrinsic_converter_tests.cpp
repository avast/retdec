/**
* @file tests/llvmir2hll/llvm/llvm_intrinsic_converter_tests.cpp
* @brief Tests for the @c llvm_intrinsic_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/llvm/llvm_intrinsic_converter.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for LLVMIntrinsicConverter.
*/
class LLVMIntrinsicConverterTests: public TestsWithModule {
protected:
	void scenarioIsConvertedTo(const std::string &origName,
		const std::string &expectedName);
};

void LLVMIntrinsicConverterTests::scenarioIsConvertedTo(const std::string &origName,
		const std::string &expectedName) {
	auto func = addFuncDecl(origName);

	LLVMIntrinsicConverter::convert(module);

	ASSERT_EQ(expectedName, func->getName());
	ASSERT_TRUE(module->funcExists(func));
}

TEST_F(LLVMIntrinsicConverterTests,
LLVMFabs32IsConvertedIntoFabsfFromMathH) {
	SCOPED_TRACE("");
	scenarioIsConvertedTo("llvm.fabs.f32", "fabsf");
}

TEST_F(LLVMIntrinsicConverterTests,
LLVMFabs64IsConvertedIntoFabsFromMathH) {
	SCOPED_TRACE("");
	scenarioIsConvertedTo("llvm.fabs.f64", "fabs");
}

TEST_F(LLVMIntrinsicConverterTests,
LLVMFabs80IsConvertedIntoFabslFromMathH) {
	SCOPED_TRACE("");
	scenarioIsConvertedTo("llvm.fabs.f80", "fabsl");
}

TEST_F(LLVMIntrinsicConverterTests,
LLVMFabs128IsConvertedIntoFabslFromMathH) {
	SCOPED_TRACE("");
	scenarioIsConvertedTo("llvm.fabs.f128", "fabsl");
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
