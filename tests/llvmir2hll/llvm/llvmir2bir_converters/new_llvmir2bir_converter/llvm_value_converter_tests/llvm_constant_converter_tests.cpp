/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_constant_converter_tests.cpp
* @brief Tests for the @c llvm_constant_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/ADT/APFloat.h>
#include <llvm/IR/Constants.h>

#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_constant_converter module.
*/
class LLVMConstantConverterTests: public TestsWithLLVMValueConverter {};

TEST_F(LLVMConstantConverterTests,
NonZeroHalfConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::IEEEhalf, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

TEST_F(LLVMConstantConverterTests,
NonZeroFloatConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::IEEEsingle, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

TEST_F(LLVMConstantConverterTests,
NonZeroDoubleConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::IEEEdouble, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

TEST_F(LLVMConstantConverterTests,
NonZeroX86_FP80ConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::x87DoubleExtended, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

TEST_F(LLVMConstantConverterTests,
NonZeroFP128ConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::IEEEquad, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

TEST_F(LLVMConstantConverterTests,
NonZeroPPC_FP128ConstantIsConvertedCorrectly) {
	auto llvmAPFloatValue = llvm::APFloat(llvm::APFloat::PPCDoubleDouble, "3.1415");
	auto llvmConstant = llvm::ConstantFP::get(context, llvmAPFloatValue);

	auto birConstant = converter->convertConstantToExpression(llvmConstant);

	auto birFloatConstant = cast<ConstFloat>(birConstant);
	ASSERT_TRUE(birFloatConstant);
	ASSERT_TRUE(birFloatConstant->isEqualTo(ConstFloat::create(llvmAPFloatValue)));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
