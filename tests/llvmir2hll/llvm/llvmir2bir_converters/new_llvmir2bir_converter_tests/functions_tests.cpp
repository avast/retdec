/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/functions_tests.cpp
* @brief Tests for functions conversion in @c NewLLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for functions conversion in @c NewLLVMIR2BIRConverter.
*/
class NewLLVMIR2BIRConverterFunctionsTests: public NewLLVMIR2BIRConverterBaseTests {};

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionDeclarationIsCorrectlyAddedToModuleAsDeclaration) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @function()
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(f->isDeclaration());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionDefinitionIsCorrectlyAddedToModuleAsDefinition) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function() {
			ret i32 0
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(f->isDefinition());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
AvailableExternallyLinkageFunctionIsNotAddedToModule) {
	auto module = convertLLVMIR2BIR(R"(
		define available_externally i32 @function() {
			ret i32 0
		}
	)");

	ASSERT_FALSE(module->hasFuncWithName(("function")));
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionReturnValueIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @function()
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isa<VoidType>(f->getRetType()));
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionDefinitionParametersAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function(i32 %num, i8* %str) {
			ret i32 0
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_EQ(2, f->getNumOfParams());
	auto param1 = f->getParam(1);
	ASSERT_EQ("num"s, param1->getName());
	auto param1Type = cast<IntType>(param1->getType());
	ASSERT_TRUE(param1Type);
	ASSERT_EQ(32, param1Type->getSize());
	auto param2 = f->getParam(2);
	ASSERT_EQ("str"s, param2->getName());
	auto param2Type = cast<PointerType>(param2->getType());
	ASSERT_TRUE(param2Type);
	auto param2ContainedType = cast<IntType>(param2Type->getContainedType());
	ASSERT_TRUE(param2ContainedType);
	ASSERT_EQ(8, param2ContainedType->getSize());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionDeclarationParametersAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @function(i32, i8*)
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_EQ(2, f->getNumOfParams());
	auto param1 = f->getParam(1);
	ASSERT_TRUE(param1->hasName());
	ASSERT_TRUE(isa<IntType>(param1->getType()));
	auto param2 = f->getParam(2);
	ASSERT_TRUE(param2->hasName());
	ASSERT_TRUE(isa<PointerType>(param2->getType()));
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionWithoutVariableArgumentsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @func1(i32)
	)");

	auto f = module->getFuncByName("func1");
	ASSERT_TRUE(f);
	ASSERT_FALSE(f->isVarArg());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionWithVariableArgumentsIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @func2(i32, ...)
	)");

	auto f = module->getFuncByName("func2");
	ASSERT_TRUE(f);
	ASSERT_TRUE(f->isVarArg());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionWithInvalidIdentifierNameHasValidIdentifierNameAfterConversion) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @$example.func1()
	)");

	auto f = *(module->func_begin());
	ASSERT_TRUE(f);
	ASSERT_EQ("_24_example_func1", f->getName());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
FunctionParameterWithInvalidIdentifierNameHasValidIdentifierNameAfterConversion) {
	auto module = convertLLVMIR2BIR(R"(
		define void @function(i32 %$example_param1) {
			ret void
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto param = f->getParam(1);
	ASSERT_EQ("_24_example_param1", param->getName());
}

TEST_F(NewLLVMIR2BIRConverterFunctionsTests,
LocalVariableWithInvalidIdentifierNameHasValidIdentifierNameAfterConversion) {
	auto module = convertLLVMIR2BIR(R"(
		declare i32 @test()

		define i32 @function() {
			%$example.variable1 = call i32 @test()
			ret i32 %$example.variable1
		}
	)");

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varSet = f->getLocalVars();
	auto var = *(varSet.begin());
	ASSERT_EQ("_24_example_variable1", var->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
