/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter_tests.cpp
* @brief Tests for the @c orig_llvmir2bir_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converter_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c orig_llvmir2bir_converter module.
*/
class OrigLLVMIR2BIRConverterTests: public LLVMIR2BIRConverterTests {
protected:
	ShPtr<Module> convertLLVMIR2BIR(const std::string &code);
};

ShPtr<Module> OrigLLVMIR2BIRConverterTests::convertLLVMIR2BIR(
		const std::string &code) {
	return LLVMIR2BIRConverterTests::convertLLVMIR2BIR<OrigLLVMIR2BIRConverter>(code);
}

//
// Global variables.
//

TEST_F(OrigLLVMIR2BIRConverterTests,
IntegralGlobalVariableWithInitializerIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 0
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gType = cast<IntType>(g->getType());
	ASSERT_TRUE(gType);
	ASSERT_EQ(32, gType->getSize());
	auto gInit = cast<ConstInt>(module->getInitForGlobalVar(g));
	ASSERT_TRUE(gInit);
	ASSERT_EQ(0, gInit->getValue());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
