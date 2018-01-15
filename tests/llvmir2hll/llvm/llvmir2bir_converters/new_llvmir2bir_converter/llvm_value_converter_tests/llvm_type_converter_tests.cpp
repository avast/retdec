/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/llvm_type_converter_tests.cpp
* @brief Tests for the @c llvm_type_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c llvm_type_converter module.
*/
class LLVMTypeConverterTests: public NewLLVMIR2BIRConverterBaseTests {
protected:
	ShPtr<Type> convertLLVMIRType2BIRType(const std::string &type,
		const std::string &typeName = "");

	template<class T>
	void sizedTypeIsConvertedCorrectly(const std::string &type, unsigned size);

	void intTypeIsConvertedCorrectly(unsigned size);
	void fpTypeIsConvertedCorrectly(const std::string &type, unsigned size);
};

/**
* @brief Converts the given LLVM IR type @a type into a BIR type.
*
* @param[in] type Tested type in LLVM IR.
* @param[in] typeName Optional name for type.
*/
ShPtr<Type> LLVMTypeConverterTests::convertLLVMIRType2BIRType(
		const std::string &type, const std::string &typeName) {
	std::string llvmIR = "";
	std::string globType = type;
	if (!typeName.empty()) {
		globType = "%" + typeName;
		llvmIR += globType + " = type " + type + "\n";
	}

	llvmIR += "declare " + globType + " @func()";

	auto module = convertLLVMIR2BIR(llvmIR);
	auto func = module->getFuncByName("func");
	return func->getRetType();
}

/**
* @brief Create a test scenario for sized type.
*
* @param[in] type Tested type in LLVM IR.
* @param[in] size Expected size of tested type in bits.
*
* @tparam T Class that represents tested type in BIR.
*/
template<class T>
void LLVMTypeConverterTests::sizedTypeIsConvertedCorrectly(
		const std::string &type, unsigned size) {
	auto birType = convertLLVMIRType2BIRType(type);

	auto birSizedType = cast<T>(birType);
	ASSERT_TRUE(birSizedType);
	ASSERT_EQ(size, birSizedType->getSize());
}

/**
* @brief Create a test scenario for integer type.
*
* @param[in] size Size of tested integer type in bits.
*/
void LLVMTypeConverterTests::intTypeIsConvertedCorrectly(unsigned size) {
	std::string type = "i" + std::to_string(size);
	SCOPED_TRACE("intTypeIsConvertedCorrectly");
	sizedTypeIsConvertedCorrectly<IntType>(type, size);
}

/**
* @brief Create a test scenario for floating-point type.
*
* @param[in] type Tested floating-point type in LLVM IR.
* @param[in] size Size of tested float type in bits.
*/
void LLVMTypeConverterTests::fpTypeIsConvertedCorrectly(
		const std::string &type, unsigned size) {
	SCOPED_TRACE("fpTypeIsConvertedCorrectly");
	sizedTypeIsConvertedCorrectly<FloatType>(type, size);
}

TEST_F(LLVMTypeConverterTests,
BooleanTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("i1");

	auto birIntType = cast<IntType>(birType);
	ASSERT_TRUE(birIntType);
	ASSERT_TRUE(birIntType->isBool());
}

TEST_F(LLVMTypeConverterTests,
Int8TypeIsConvertedCorrectly) {
	SCOPED_TRACE("Int8TypeIsConvertedCorrectly");
	intTypeIsConvertedCorrectly(8);
}

TEST_F(LLVMTypeConverterTests,
Int16TypeIsConvertedCorrectly) {
	SCOPED_TRACE("Int16TypeIsConvertedCorrectly");
	intTypeIsConvertedCorrectly(16);
}

TEST_F(LLVMTypeConverterTests,
Int32TypeIsConvertedCorrectly) {
	SCOPED_TRACE("Int32TypeIsConvertedCorrectly");
	intTypeIsConvertedCorrectly(32);
}

TEST_F(LLVMTypeConverterTests,
Int64TypeIsConvertedCorrectly) {
	SCOPED_TRACE("Int64TypeIsConvertedCorrectly");
	intTypeIsConvertedCorrectly(64);
}

TEST_F(LLVMTypeConverterTests,
HalfTypeIsConvertedCorrectly) {
	SCOPED_TRACE("HalfTypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("half", 16);
}

TEST_F(LLVMTypeConverterTests,
FloatTypeIsConvertedCorrectly) {
	SCOPED_TRACE("FloatTypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("float", 32);
}

TEST_F(LLVMTypeConverterTests,
DoubleTypeIsConvertedCorrectly) {
	SCOPED_TRACE("DoubleTypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("double", 64);
}

TEST_F(LLVMTypeConverterTests,
X86_FP80TypeIsConvertedCorrectly) {
	SCOPED_TRACE("X86_FP80TypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("x86_fp80", 80);
}

TEST_F(LLVMTypeConverterTests,
FP128TypeIsConvertedCorrectly) {
	SCOPED_TRACE("FP128TypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("fp128", 128);
}

TEST_F(LLVMTypeConverterTests,
PPC_FP128TypeIsConvertedCorrectly) {
	SCOPED_TRACE("PPC_FP128TypeIsConvertedCorrectly");
	fpTypeIsConvertedCorrectly("ppc_fp128", 128);
}

TEST_F(LLVMTypeConverterTests,
IntArrayTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("[10 x i32]");

	auto birArrayType = cast<ArrayType>(birType);
	ASSERT_TRUE(birArrayType);
	ASSERT_EQ(ArrayType::Dimensions({10}), birArrayType->getDimensions());
	ASSERT_TRUE(isa<IntType>(birArrayType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
FPArrayTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("[10 x double]");

	auto birArrayType = cast<ArrayType>(birType);
	ASSERT_TRUE(birArrayType);
	ASSERT_EQ(ArrayType::Dimensions({10}), birArrayType->getDimensions());
	ASSERT_TRUE(isa<FloatType>(birArrayType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
IntMultidimensionalArrayTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("[10 x [20 x [30 x i32]]]");

	auto birArrayType = cast<ArrayType>(birType);
	ASSERT_TRUE(birArrayType);
	ASSERT_EQ(ArrayType::Dimensions({10, 20, 30}), birArrayType->getDimensions());
	ASSERT_TRUE(isa<IntType>(birArrayType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
FPMultidimensionalArrayTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("[10 x [20 x [30 x double]]]");

	auto birArrayType = cast<ArrayType>(birType);
	ASSERT_TRUE(birArrayType);
	ASSERT_EQ(ArrayType::Dimensions({10, 20, 30}), birArrayType->getDimensions());
	ASSERT_TRUE(isa<FloatType>(birArrayType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
StructTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("{ i32, double }", "my_struct");

	auto birStructType = cast<StructType>(birType);
	ASSERT_TRUE(birStructType);
	ASSERT_EQ("my_struct"s, birStructType->getName());
	auto birStructElemTypes = birStructType->getElementTypes();
	ASSERT_EQ(2, birStructElemTypes.size());
	ASSERT_TRUE(isa<IntType>(birStructElemTypes[0]));
	ASSERT_TRUE(isa<FloatType>(birStructElemTypes[1]));
}

TEST_F(LLVMTypeConverterTests,
StructTypeWithoutNameIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("{ i32, double }");

	auto birStructType = cast<StructType>(birType);
	ASSERT_TRUE(birStructType);
	ASSERT_FALSE(birStructType->hasName());
}

TEST_F(LLVMTypeConverterTests,
RecursiveStructTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("{ i32, %my_struct* }", "my_struct");

	auto birStructType = cast<StructType>(birType);
	ASSERT_TRUE(birStructType);
	ASSERT_EQ("my_struct"s, birStructType->getName());
	auto birStructElemTypes = birStructType->getElementTypes();
	ASSERT_EQ(2, birStructElemTypes.size());
	ASSERT_TRUE(isa<IntType>(birStructElemTypes[0]));
	auto birStructElem2Type = cast<PointerType>(birStructElemTypes[1]);
	ASSERT_TRUE(birStructElem2Type);
	auto birContainedStruct = cast<StructType>(birStructElem2Type->getContainedType());
	ASSERT_TRUE(birStructType->isEqualTo(birContainedStruct));
}

TEST_F(LLVMTypeConverterTests,
IntPointerTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("i32*");

	auto birPointerType = cast<PointerType>(birType);
	ASSERT_TRUE(birPointerType);
	ASSERT_TRUE(isa<IntType>(birPointerType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
FPPointerTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("double*");

	auto birPointerType = cast<PointerType>(birType);
	ASSERT_TRUE(birPointerType);
	ASSERT_TRUE(isa<FloatType>(birPointerType->getContainedType()));
}

TEST_F(LLVMTypeConverterTests,
FunctionPointerTypeWithoutVariableArgumentsIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("i32 (double)*");

	auto birPointerType = cast<PointerType>(birType);
	ASSERT_TRUE(birPointerType);
	auto birFuncType = cast<FunctionType>(birPointerType->getContainedType());
	ASSERT_TRUE(birFuncType);
	ASSERT_TRUE(isa<IntType>(birFuncType->getRetType()));
	ASSERT_EQ(1, birFuncType->getNumOfParams());
	ASSERT_FALSE(birFuncType->isVarArg());
	ASSERT_TRUE(isa<FloatType>(birFuncType->getParam(1)));
}

TEST_F(LLVMTypeConverterTests,
FunctionPointerTypeWithVariableArgumentsIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("i32 (double, ...)*");

	auto birPointerType = cast<PointerType>(birType);
	ASSERT_TRUE(birPointerType);
	auto birFuncType = cast<FunctionType>(birPointerType->getContainedType());
	ASSERT_TRUE(birFuncType);
	ASSERT_TRUE(birFuncType->isVarArg());
}

TEST_F(LLVMTypeConverterTests,
VoidTypeIsConvertedCorrectly) {
	auto birType = convertLLVMIRType2BIRType("void");

	ASSERT_TRUE(isa<VoidType>(birType));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
