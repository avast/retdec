/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/glob_vars_tests.cpp
* @brief Tests for global variables conversion in @c NewLLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for global variables conversion in @c NewLLVMIR2BIRConverter.
*/
class NewLLVMIR2BIRConverterGlobVarsTests: public NewLLVMIR2BIRConverterBaseTests {};

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableWithInitializerIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 0
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto type = cast<IntType>(g->getType());
	ASSERT_TRUE(type);
	auto gInit = module->getInitForGlobalVar(g);
	ASSERT_TRUE(gInit);
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableWithoutInitializerIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		@g = external global i32
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gInit = module->getInitForGlobalVar(g);
	ASSERT_FALSE(gInit);
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
PrivateGlobalVariableIsConvertedCorrectlyAsInternal) {
	auto module = convertLLVMIR2BIR(R"(
		@g = private global i32 1
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	ASSERT_TRUE(g->isInternal());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
InternalGlobalVariableIsConvertedCorrectlyAsInternal) {
	auto module = convertLLVMIR2BIR(R"(
		@g = internal global i32 1
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	ASSERT_TRUE(g->isInternal());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
ExternalGlobalVariableIsConvertedCorrectlyAsExternal) {
	auto module = convertLLVMIR2BIR(R"(
		@g = external global i32
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	ASSERT_TRUE(g->isExternal());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
DefaultLinkageGlobalVariableIsConvertedCorrectlyAsExternal) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32 1
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	ASSERT_TRUE(g->isExternal());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
StringGlobalConstantIsNotAddedToModule) {
	auto module = convertLLVMIR2BIR(R"(
		@g = constant [12 x i8] c"hello world\00"
	)");

	ASSERT_FALSE(module->hasGlobalVar("g"));
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
StringGlobalVariableIsAddedToModule) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global [12 x i8] c"hello world\00"
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gInit = cast<ConstString>(module->getInitForGlobalVar(g));
	ASSERT_TRUE(gInit);
	ASSERT_EQ("hello world"s, gInit->getValueAsEscapedCString());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
WideStringGlobalConstantIsNotAddedToModule) {
	EXPECT_CALL(*configMock, isGlobalVarStoringWideString("g"))
		.WillRepeatedly(Return(true));

	auto module = convertLLVMIR2BIR(R"(
		@g = constant [6 x i16] [i16 225, i16 269, i16 345, i16 353, i16 382, i16 0]
	)");

	ASSERT_FALSE(module->hasGlobalVar("g"));
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableContainingReferenceToAnotherGlobalVariableWithStringIsAddedToModuleAsString) {
	auto module = convertLLVMIR2BIR(R"(
		@str = constant [12 x i8] c"hello world\00"
		@g = global [12 x i8]* @str
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gInit = cast<ConstString>(module->getInitForGlobalVar(g));
	ASSERT_TRUE(gInit);
	ASSERT_EQ("hello world"s, gInit->getValueAsEscapedCString());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableContainingReferenceToAnotherGlobalVariableIsAddedToModuleAsAddressOp) {
	auto module = convertLLVMIR2BIR(R"(
		@num = global i32 1
		@g = global i32* @num
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gInit = cast<AddressOpExpr>(module->getInitForGlobalVar(g));
	ASSERT_TRUE(gInit);
	ASSERT_BIR_EQ(module->getGlobalVarByName("num"), gInit->getOperand());
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableContainingReferenceToFunctionIsAddedToModuleAsAddressOp) {
	auto module = convertLLVMIR2BIR(R"(
		@g = global i32(i32)* @test

		declare i32 @test(i32)
	)");

	auto g = module->getGlobalVarByName("g");
	ASSERT_TRUE(g);
	auto gInit = cast<Variable>(module->getInitForGlobalVar(g));
	ASSERT_TRUE(gInit);
	ASSERT_BIR_EQ(module->getFuncByName("test")->getAsVar(), gInit);
}

TEST_F(NewLLVMIR2BIRConverterGlobVarsTests,
GlobalVariableWithInvalidIdentifierNameHasValidIdentifierNameAfterConversion) {
	auto module = convertLLVMIR2BIR(R"(
		@$example.global1 = external global i32
	)");

	auto g = *(module->global_var_begin());
	ASSERT_TRUE(g);
	ASSERT_EQ("_24_example_global1", g->getVar()->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
