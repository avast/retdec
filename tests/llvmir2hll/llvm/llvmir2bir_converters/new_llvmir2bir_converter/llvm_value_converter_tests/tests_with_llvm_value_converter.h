/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.h
* @brief A base class for all test fixtures using the @c LLVMValueConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_TESTS_LLVM_VALUE_CONVERTER_TESTS_TESTS_WITH_LLVM_VALUE_CONVERTER_H
#define BACKEND_BIR_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_TESTS_LLVM_VALUE_CONVERTER_TESTS_TESTS_WITH_LLVM_VALUE_CONVERTER_H

#include <llvm/IR/LLVMContext.h>

#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using ::testing::AssertionResult;

namespace retdec {
namespace llvmir2hll {

class BinaryOpExpr;
class LLVMValueConverter;
class TernaryOpExpr;
class VariablesManager;

namespace tests {

/**
* @brief A base class for all test fixtures using the LLVMValueConverter.
*/
class TestsWithLLVMValueConverter: public TestsWithModule {
protected:
	TestsWithLLVMValueConverter();
	~TestsWithLLVMValueConverter();

	/// @name Helper assertions
	/// @{
	AssertionResult areBinaryOperandsInCorrectOrder(ShPtr<BinaryOpExpr> expr);
	AssertionResult areTernaryOperandsInCorrectOrder(ShPtr<TernaryOpExpr> expr);
	/// @}

	/// Context for the LLVM module.
	llvm::LLVMContext context;

	/// Variables manager.
	ShPtr<VariablesManager> variablesManager;

	/// A converter from LLVM values to values in BIR.
	ShPtr<LLVMValueConverter> converter;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
