/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_constant_converter_tests_by_llvmir.cpp
* @brief Tests for the @c llvm_constant_converter module using LLVM IR text
*        representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_constant_converter module using LLVM IR text
*        representation.
*/
class LLVMConstantConverterTestsByLLVMIR: public NewLLVMIR2BIRConverterBaseTests {
protected:
	ShPtr<Constant> convertLLVMIRConstant2BIR(const std::string &c);
};

/**
* @brief Converts the given LLVM IR constant @a type into a BIR constant.
*/
ShPtr<Constant> LLVMConstantConverterTestsByLLVMIR::convertLLVMIRConstant2BIR(
		const std::string &c) {
	auto module = convertLLVMIR2BIR("@g = constant " + c);
	auto g = module->getGlobalVarByName("g");
	return ucast<Constant>(module->getInitForGlobalVar(g));
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
TrueBooleanConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i1 true");

	auto birBoolConstant = cast<ConstBool>(birConstant);
	ASSERT_TRUE(birBoolConstant);
	ASSERT_TRUE(birBoolConstant->isTrue());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
FalseBooleanConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i1 false");

	auto birBoolConstant = cast<ConstBool>(birConstant);
	ASSERT_TRUE(birBoolConstant);
	ASSERT_TRUE(birBoolConstant->isFalse());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
FalseBooleanUsingZeroInitializerIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i1 zeroinitializer");

	auto birBoolConstant = cast<ConstBool>(birConstant);
	ASSERT_TRUE(birBoolConstant);
	ASSERT_TRUE(birBoolConstant->isFalse());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
FalseBooleanUsingUndefIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i1 undef");

	auto birBoolConstant = cast<ConstBool>(birConstant);
	ASSERT_TRUE(birBoolConstant);
	ASSERT_TRUE(birBoolConstant->isFalse());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInt8ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i8 0");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isZero());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
PositiveInt8ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i8 1");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isOne());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NegativeInt8ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i8 -1");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isNegativeOne());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInt16ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i16 0");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isZero());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInt32ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i32 0");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isZero());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInt64ConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i64 0");

	auto birIntConstant = cast<ConstInt>(birConstant);
	ASSERT_TRUE(birIntConstant);
	ASSERT_TRUE(birIntConstant->isZero());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NullPointerConstantIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i32* null");

	ASSERT_TRUE(isa<ConstNullPointer>(birConstant));
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NullPointerConstantUsingZeroInitializerIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i32* zeroinitializer");

	ASSERT_TRUE(isa<ConstNullPointer>(birConstant));
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NullPointerConstantUsingUndefIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("i32* undef");

	ASSERT_TRUE(isa<ConstNullPointer>(birConstant));
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInitializedConstantArrayIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("[2 x i32] zeroinitializer");

	auto birArrayConstant = cast<ConstArray>(birConstant);
	ASSERT_TRUE(birArrayConstant);
	ASSERT_FALSE(birArrayConstant->isInitialized());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInitializedConstantArrayUsingUndefIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("[2 x i32] undef");

	auto birArrayConstant = cast<ConstArray>(birConstant);
	ASSERT_TRUE(birArrayConstant);
	ASSERT_FALSE(birArrayConstant->isInitialized());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NonZeroConstantArrayIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR("[2 x i32] [i32 1, i32 2]");

	ASSERT_EQ("[1, 2]"s, birConstant->getTextRepr());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NonZeroConstantMultidimensionalArrayIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR(
		"[2 x [2 x i32]] [[2 x i32] [i32 1, i32 2], [2 x i32] [i32 3, i32 4]]");

	ASSERT_EQ("[[1, 2], [3, 4]]"s, birConstant->getTextRepr());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInitializedConstantStructIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR(
		"{ i32, double } zeroinitializer");

	ASSERT_EQ("{'0': 0, '1': 0.0e+0}"s, birConstant->getTextRepr());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
ZeroInitializedConstantStructUsingUndefIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR(
		"{ i32, double } undef");

	ASSERT_EQ("{'0': 0, '1': 0.0e+0}"s, birConstant->getTextRepr());
}

TEST_F(LLVMConstantConverterTestsByLLVMIR,
NonZeroConstantStructIsConvertedCorrectly) {
	auto birConstant = convertLLVMIRConstant2BIR(
		"{ i32, double } { i32 1, double 2.5 }");

	ASSERT_EQ("{'0': 1, '1': 2.5e+0}"s, birConstant->getTextRepr());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
