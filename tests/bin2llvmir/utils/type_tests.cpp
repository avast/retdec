/**
 * @file tests/bin2llvmir/utils/tests/type_tests.cpp
 * @brief Tests for the @c type utils module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/string.h"
#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c type module.
 */
class TypeTests: public LlvmIrTests
{

};

//
// stringToLlvmType()
//

TEST_F(TypeTests, stringToLlvmTypeCreatesPrimitiveTypes)
{
	EXPECT_EQ(Type::getVoidTy(context), stringToLlvmType(context, "void"));
	EXPECT_EQ(Type::getLabelTy(context), stringToLlvmType(context, "label"));
	EXPECT_EQ(Type::getHalfTy(context), stringToLlvmType(context, "half"));
	EXPECT_EQ(Type::getFloatTy(context), stringToLlvmType(context, "float"));
	EXPECT_EQ(Type::getDoubleTy(context), stringToLlvmType(context, "double"));
	EXPECT_EQ(Type::getMetadataTy(context), stringToLlvmType(context, "metadata"));
	EXPECT_EQ(Type::getX86_FP80Ty(context), stringToLlvmType(context, "x86_fp80"));
	EXPECT_EQ(Type::getFP128Ty(context), stringToLlvmType(context, "fp128"));
	EXPECT_EQ(Type::getPPC_FP128Ty(context), stringToLlvmType(context, "ppc_fp128"));
	EXPECT_EQ(Type::getX86_MMXTy(context), stringToLlvmType(context, "x86_mmx"));

	EXPECT_EQ(Type::getIntNTy(context, 1), stringToLlvmType(context, "i1"));
	EXPECT_EQ(Type::getIntNTy(context, 5), stringToLlvmType(context, "i5"));
	EXPECT_EQ(Type::getIntNTy(context, 8), stringToLlvmType(context, "i8"));
	EXPECT_EQ(Type::getIntNTy(context, 16), stringToLlvmType(context, "i16"));
	EXPECT_EQ(Type::getIntNTy(context, 23), stringToLlvmType(context, "i23"));
	EXPECT_EQ(Type::getIntNTy(context, 32), stringToLlvmType(context, "i32"));
	EXPECT_EQ(Type::getIntNTy(context, 49), stringToLlvmType(context, "i49"));
	EXPECT_EQ(Type::getIntNTy(context, 64), stringToLlvmType(context, "i64"));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesPointerTypes)
{
	EXPECT_EQ(
			PointerType::get(
					Type::getInt32Ty(context),
					DEFAULT_ADDR_SPACE),
			stringToLlvmType(context, "i32*"));

	EXPECT_EQ(
			PointerType::get(
					PointerType::get(
							Type::getDoubleTy(context),
							DEFAULT_ADDR_SPACE),
					DEFAULT_ADDR_SPACE),
			stringToLlvmType(context, "double**"));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesArrayTypes)
{
	EXPECT_EQ(
			ArrayType::get(
					Type::getInt32Ty(context),
					10),
			stringToLlvmType(context, "[10 x i32]"));

	EXPECT_EQ(
			ArrayType::get(
					ArrayType::get(
							Type::getDoubleTy(context),
							20 ),
					10),
			stringToLlvmType(context, "[10 x [20 x double]]"));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesVectorTypes)
{
	EXPECT_EQ(
			VectorType::get(
					Type::getInt32Ty(context),
					10),
			stringToLlvmType(context, "<10 x i32>"));
}

TEST_F(TypeTests, stringToLlvmTypeOnlyPrimitiveTypesCanBeVectorTypeElements)
{
	EXPECT_EQ(
			nullptr,
			stringToLlvmType(context, "<10 x [20 x double]>"));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesFunctionTypes)
{
	EXPECT_EQ(
		FunctionType::get(
				Type::getVoidTy(context),
				{},
				false),
		stringToLlvmType(context, "void ()"));

	EXPECT_EQ(
		FunctionType::get(
				Type::getDoubleTy(context),
				{},
				false),
		stringToLlvmType(context, "double ()"));

	EXPECT_EQ(
		FunctionType::get(
				Type::getDoubleTy(context),
				{},
				true),
		stringToLlvmType(context, "double (...)"));

	EXPECT_EQ(
		FunctionType::get(
				Type::getDoubleTy(context),
				{Type::getIntNTy(context, 32)},
				false),
		stringToLlvmType(context, "double (i32)"));

	EXPECT_EQ(
		FunctionType::get(
				Type::getDoubleTy(context),
				std::vector<Type*>{
						Type::getIntNTy(context, 32),
						PointerType::get(
								Type::getDoubleTy(context),
								DEFAULT_ADDR_SPACE)
				},
				false),
		stringToLlvmType(context, "double (i32, double*)"));

	EXPECT_EQ(
		FunctionType::get(
				Type::getDoubleTy(context),
				std::vector<Type*>{
						Type::getIntNTy(context, 32),
						PointerType::get(
								Type::getDoubleTy(context),
								DEFAULT_ADDR_SPACE)
				},
				true),
		stringToLlvmType(context, "double (i32, double*, ...)"));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesOpaqueStructureTypes)
{
	auto* t = stringToLlvmType(context, "%s0 = type opaque");

	ASSERT_NE(nullptr, t);
	ASSERT_TRUE(t->isStructTy());

	auto* st = dyn_cast<StructType>(t);

	ASSERT_NE(nullptr, st);
	EXPECT_TRUE(st->isOpaque());
}

// TODO: in theory, these should produce empty structures, but we do not allow
// it since it is hard to work with empty strucutres (e.g. convert types).
//
//TEST_F(TypeTests, stringToLlvmTypeCreatesEmptyStructureTypes)
//{
//	EXPECT_EQ(
//		StructType::get(context),
//		stringToLlvmType(context, "{}"));
//
//	EXPECT_EQ(
//		StructType::get(context, true),
//		stringToLlvmType(context, "<{}>"));
//
//	auto* t1 = stringToLlvmType(context, "%s1 = type {}");
//	ASSERT_NE(nullptr, t1);
//	ASSERT_TRUE(t1->isStructTy());
//	auto* s1 = dyn_cast<StructType>(t1);
//	ASSERT_NE(nullptr, s1);
//	EXPECT_EQ("s1", s1->getName());
//	ASSERT_EQ(0, s1->getNumElements());
//
//	auto* t2 = stringToLlvmType(context, "%s2 = type <{}>");
//	ASSERT_NE(nullptr, t2);
//	ASSERT_TRUE(t2->isStructTy());
//	auto* s2 = dyn_cast<StructType>(t2);
//	ASSERT_NE(nullptr, s1);
//	EXPECT_TRUE(s2->isPacked());
//	EXPECT_EQ("s2", s2->getName());
//	ASSERT_EQ(0, s2->getNumElements());
//}

TEST_F(TypeTests, stringToLlvmTypeCreatesStructureTypes)
{
	EXPECT_EQ(
		StructType::get(
				context,
				std::vector<Type*>{
						Type::getIntNTy(context, 32),
						Type::getDoubleTy(context),
						Type::getFloatTy(context)
				}),
		stringToLlvmType(context, "{i32, double, float}"));

	EXPECT_EQ(
		StructType::get(
				context,
				std::vector<Type*>{
						Type::getIntNTy(context, 32),
						Type::getDoubleTy(context),
						Type::getFloatTy(context)
				},
				true),
		stringToLlvmType(context, "<{i32, double, float}>"));

	auto* t1 = stringToLlvmType(context, "%s1 = type {i32, double, float}");
	ASSERT_NE(nullptr, t1);
	ASSERT_TRUE(t1->isStructTy());
	auto* s1 = dyn_cast<StructType>(t1);
	ASSERT_NE(nullptr, s1);
	EXPECT_EQ("s1", s1->getName());
	ASSERT_EQ(3, s1->getNumElements());
	EXPECT_EQ(Type::getIntNTy(context, 32), s1->getElementType(0));
	EXPECT_EQ(Type::getDoubleTy(context), s1->getElementType(1));
	EXPECT_EQ(Type::getFloatTy(context), s1->getElementType(2));

	auto* t2 = stringToLlvmType(context, "%s2 = type <{i32, double, float}>");
	ASSERT_NE(nullptr, t2);
	ASSERT_TRUE(t2->isStructTy());
	auto* s2 = dyn_cast<StructType>(t2);
	ASSERT_NE(nullptr, s1);
	EXPECT_TRUE(s2->isPacked());
	EXPECT_EQ("s2", s2->getName());
	ASSERT_EQ(3, s2->getNumElements());
	EXPECT_EQ(Type::getIntNTy(context, 32), s2->getElementType(0));
	EXPECT_EQ(Type::getDoubleTy(context), s2->getElementType(1));
	EXPECT_EQ(Type::getFloatTy(context), s2->getElementType(2));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesEmbeddedStructureTypes)
{
	auto* t1 = stringToLlvmType(context, "%s1 = type {i32, double, float}");
	ASSERT_NE(nullptr, t1);

	auto* t2 = stringToLlvmType(context, "%s2 = type {i32, %s1, double}");
	ASSERT_NE(nullptr, t2);
	ASSERT_TRUE(t2->isStructTy());

	auto* t3 = stringToLlvmType(context, "%s3 = type {{%s1, %s2}}");
	ASSERT_NE(nullptr, t3);
	ASSERT_TRUE(t3->isStructTy());
	auto* s3 = dyn_cast<StructType>(t3);
	ASSERT_NE(nullptr, s3);
	ASSERT_EQ(1, s3->getNumElements());

	auto* t4 = s3->getElementType(0);
	ASSERT_NE(nullptr, t4);
	ASSERT_TRUE(t4->isStructTy());
	auto* s4 = dyn_cast<StructType>(t4);
	ASSERT_NE(nullptr, s4);
	ASSERT_EQ(2, s4->getNumElements());
	EXPECT_EQ(t1, s4->getElementType(0));
	EXPECT_EQ(t2, s4->getElementType(1));
}

TEST_F(TypeTests, stringToLlvmTypeCreatesComplicatedType)
{
	// Make this string as complicated as you wish.
	// We should handle everything.
	//
	std::string str =
			"{i16*, i32**, {i16, {i32(float, double)*}, half}*, "
			"[10xi32({float,double})*]}*";
	auto* t = stringToLlvmType(context, str);
	ASSERT_NE(nullptr, t);

	std::string out;
	raw_string_ostream ros(out);
	t->print(ros);
	ros.str();

	EXPECT_EQ(
			retdec::utils::removeWhitespace(str),
			retdec::utils::removeWhitespace(out));
}

TEST_F(TypeTests, stringToLlvmTypeReturnsAlreadyExistingTypeForStructureId)
{
	std::string str = "%struct = type {i16, i32}";

	auto* t1 = stringToLlvmType(context, str);
	auto* t2 = stringToLlvmType(context, "%struct");

	EXPECT_EQ(t1, t2);
}

TEST_F(TypeTests, stringToLlvmTypeReturnNullWhenTypeStringToParseIsBad)
{
	EXPECT_EQ(nullptr, stringToLlvmType(context, ""));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "123"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "hello"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "%hello")); // unknown structure
	EXPECT_EQ(nullptr, stringToLlvmType(context, "abc*"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "[a x i32]"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "[10 x [i32]"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "[10 x i32]]"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "<a x i32>"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "<10 x [i32>"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "<10 x i32]>"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "i32(abc def)"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "{ i32 i32 , i32}"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "%s = type { i32 i32 , i32}"));
}

TEST_F(TypeTests, stringToLlvmTypeReturnNullWhenInvalidElementTypesAreUsed)
{
	EXPECT_EQ(nullptr, stringToLlvmType(context, "label*"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "<10 x [10 x i32]>"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "[10 x i32(i32)]"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "label(i32)"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "metadata(i32)"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "void(i32)(i32)"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "void( i32() )"));

	EXPECT_EQ(nullptr, stringToLlvmType(context, "{void()}"));
	EXPECT_EQ(nullptr, stringToLlvmType(context, "%s = type {void()}"));
}

TEST_F(TypeTests, stringToLlvmTypeCanHandlePointerToVoid)
{
	EXPECT_EQ(
			PointerType::get(Type::getInt8Ty(context), 0),
			stringToLlvmType(context, "void*"));
}

//
// isBoolType()
//

TEST_F(TypeTests, i1IsABoolType)
{
	EXPECT_TRUE(isBoolType(Type::getInt1Ty(context)));
}

TEST_F(TypeTests, NullptrIsNotABoolTypeButFunctionDoesNotSegfault)
{
	EXPECT_FALSE(isBoolType(nullptr));
}

TEST_F(TypeTests, Onlyi1IsABoolTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isBoolType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isBoolType(Type::getInt64Ty(context)));
	EXPECT_FALSE(isBoolType(Type::getFloatTy(context)));
	EXPECT_FALSE(isBoolType(Type::getDoublePtrTy(context)));
}

//
// isCharType()
//

TEST_F(TypeTests, i8IsACharType)
{
	EXPECT_TRUE(isCharType(Type::getInt8Ty(context)));
}

TEST_F(TypeTests, NullptrIsNotACharTypeButFunctionDoesNotSegfault)
{
	EXPECT_FALSE(isCharType(nullptr));
}

TEST_F(TypeTests, Onlyi8IsACharTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isCharType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isCharType(Type::getInt64Ty(context)));
	EXPECT_FALSE(isCharType(Type::getFloatTy(context)));
	EXPECT_FALSE(isCharType(Type::getDoublePtrTy(context)));
}

//
// isStringArrayType()
//

TEST_F(TypeTests, ArrayOfi8sIsAStringArrayType)
{
	EXPECT_TRUE(isStringArrayType(ArrayType::get(Type::getInt8Ty(context), 10)));
}

TEST_F(TypeTests, NullptrIsNotAStringArrayTypeButFunctionDoesNotSegfault)
{
	EXPECT_FALSE(isStringArrayType(nullptr));
}

TEST_F(TypeTests, Onlyi8ArrayIsAStringArrayTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isStringArrayType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isStringArrayType(ArrayType::get(Type::getInt64Ty(context), 10)));
}

//
// isStringArrayPointeType()
//

TEST_F(TypeTests, PointerToArrayOfi8sIsAStringArrayPointerType)
{
	EXPECT_TRUE(isStringArrayPointeType(
			PointerType::get(
					ArrayType::get(Type::getInt8Ty(context), 10),
					0)));
}

TEST_F(TypeTests, NullptrIsNotAAStringArrayPointerButFunctionDoesNotSegfault)
{
	EXPECT_FALSE(isStringArrayPointeType(nullptr));
}

TEST_F(TypeTests, OnlyPointerToi8ArrayIsAStringArrayTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isStringArrayPointeType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isStringArrayPointeType(ArrayType::get(Type::getInt64Ty(context), 10)));
	EXPECT_FALSE(isStringArrayPointeType(
			PointerType::get(
					ArrayType::get(Type::getDoubleTy(context), 10),
					0)));
}

//
// getCharType(llvm::LLVMContext&)
// getCharType(llvm::LLVMContext*)
//

TEST_F(TypeTests, getCharTypeReturnsi8)
{
	EXPECT_TRUE(getCharType(context)->isIntegerTy(8));
	EXPECT_TRUE(getCharType(&context)->isIntegerTy(8));
}

//
// getCharPointerType(llvm::LLVMContext&)
// getCharPointerType(llvm::LLVMContext*)
//

TEST_F(TypeTests, getCharPointerTypeReturnsPointerToI8)
{
	EXPECT_TRUE(getCharPointerType(context)->getElementType()->isIntegerTy(8));
	EXPECT_TRUE(getCharPointerType(&context)->getElementType()->isIntegerTy(8));
}

//
// getVoidPointerType(llvm::LLVMContext&)
// getVoidPointerType(llvm::LLVMContext*)
//

TEST_F(TypeTests, getVoidPointerTypeTypeReturnsPointerToI8)
{
	EXPECT_TRUE(getVoidPointerType(context)->getElementType()->isIntegerTy(8));
	EXPECT_TRUE(getVoidPointerType(&context)->getElementType()->isIntegerTy(8));
}

//
// isCharPointerType()
//

TEST_F(TypeTests, PointerToi8IsACharPointerType)
{
	EXPECT_TRUE(isCharPointerType(PointerType::get(Type::getInt8Ty(context), 0)));
}

TEST_F(TypeTests, NullptrIsNotACharPointerType)
{
	EXPECT_FALSE(isCharPointerType(nullptr));
}

TEST_F(TypeTests, OnlyPointerToi8IsACharPointerTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isCharPointerType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isCharPointerType(ArrayType::get(Type::getInt8Ty(context), 10)));
	EXPECT_FALSE(isCharPointerType(PointerType::get(Type::getInt32Ty(context), 0)));
}

//
// isVoidPointerType()
//

TEST_F(TypeTests, PointerToi8IsAVoidPointerType)
{
	EXPECT_TRUE(isVoidPointerType(PointerType::get(Type::getInt8Ty(context), 0)));
}

TEST_F(TypeTests, NullptrIsNotAVoidPointerType)
{
	EXPECT_FALSE(isVoidPointerType(nullptr));
}

TEST_F(TypeTests, OnlyPointerToi8IsAVoidPointerTypeOtherTypesAreNot)
{
	EXPECT_FALSE(isVoidPointerType(Type::getInt16Ty(context)));
	EXPECT_FALSE(isVoidPointerType(ArrayType::get(Type::getInt8Ty(context), 10)));
	EXPECT_FALSE(isVoidPointerType(PointerType::get(Type::getInt32Ty(context), 0)));
}

//
// convertValueToType()
//

TEST_F(TypeTests, convertValueToTypeFloatToInt32)
{
	parseInput(R"(
		define void @fnc() {
			%a = fadd float 1.0, 2.0
			ret void
		}
	)");
	auto* a = getValueByName("a");
	auto* b = getNthInstruction<ReturnInst>();

	convertValueToType(a, Type::getInt32Ty(context), b);

	std::string exp = R"(
		define void @fnc() {
			%a = fadd float 1.0, 2.0
			%1 = bitcast float %a to i32
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeTests, convertValueToTypeInt32ToFloat)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 1, 2
			ret void
		}
	)");
	auto* a = getValueByName("a");
	auto* b = getNthInstruction<ReturnInst>();

	convertValueToType(a, Type::getFloatTy(context), b);

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 1, 2
			%1 = bitcast i32 %a to float
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeTests, convertValueToTypeFunctionToPointer)
{
	parseInput(R"(
		declare void @import()
		define void @fnc() {
			ret void
		}
	)");
	auto* import = getValueByName("import");
	auto* r = getNthInstruction<ReturnInst>();
	auto* i32 = Type::getInt32Ty(context);
	auto* t = PointerType::get(
			FunctionType::get(
					i32,
					{i32, i32},
					false), // isVarArg
			0);

	convertValueToType(import, t, r);

	std::string exp = R"(
		declare void @import()
		define void @fnc() {
			%1 = bitcast void()* @import to i32(i32, i32)*
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// convertValueToAfter()
//

TEST_F(TypeTests, convertValueToTypeAfterInt32ToDouble)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 1, 2
			%b = add i32 1, 2
			ret void
		}
	)");
	auto* a = getValueByName("a");
	auto* b = getInstructionByName("b");

	convertValueToTypeAfter(a, Type::getDoubleTy(context), b);

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 1, 2
			%b = add i32 1, 2
			%1 = sext i32 %a to i64
			%2 = bitcast i64 %1 to double
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

TEST_F(TypeTests, convertValueToTypeAfterItselfInt32ToDouble)
{
	parseInput(R"(
		define void @fnc() {
			%a = add i32 1, 2
			ret void
		}
	)");
	auto* a = getInstructionByName("a");

	convertValueToTypeAfter(a, Type::getDoubleTy(context), a);

	std::string exp = R"(
		define void @fnc() {
			%a = add i32 1, 2
			%1 = sext i32 %a to i64
			%2 = bitcast i64 %1 to double
			ret void
		}
	)";
	checkModuleAgainstExpectedIr(exp);
}

//
// parseFormatString()
//

TEST_F(TypeTests, parseFormatStringBasic)
{
	std::string format =
			"this"
			"%d %i %o %u %x %X "
			"normal"
			"%f %F %e %E %g %G %a %A "
			"text"
			"%c %C "
			"should"
			"%s %S "
			"be"
			"%p %n "
			"skipped"
			"%%";
	auto& ctx = module->getContext();
	auto ret = parseFormatString(module.get(), format);

	ASSERT_EQ(20, ret.size());
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[0]);
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[1]);
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[2]);
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[3]);
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[4]);
	EXPECT_EQ(Type::getInt32Ty(ctx), ret[5]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[6]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[7]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[8]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[9]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[10]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[11]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[12]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[13]);
	EXPECT_EQ(Type::getInt8Ty(ctx), ret[14]);
	EXPECT_EQ(Type::getInt8Ty(ctx), ret[15]);
	EXPECT_EQ(getCharPointerType(ctx), ret[16]);
	EXPECT_EQ(getCharPointerType(ctx), ret[17]);
	EXPECT_EQ(getDefaultPointerType(module.get()), ret[18]);
	EXPECT_EQ(PointerType::get(Type::getInt32Ty(ctx), 0), ret[19]);
}

TEST_F(TypeTests, parseFormatStringBasicUnknownConversionCharacterIsDefaultInt)
{
	std::string format = "%f %y %f";
	auto& ctx = module->getContext();
	auto ret = parseFormatString(module.get(), format);

	ASSERT_EQ(3, ret.size());
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[0]);
	EXPECT_EQ(getDefaultType(module.get()), ret[1]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[2]);
}

TEST_F(TypeTests, parseFormatStringReturnsPointersIfCalledFunctionIsScanf)
{
	parseInput(R"(
		declare void @scanf()
		define void @fnc() {
			ret void
		}
	)");
	auto* f = getFunctionByName("scanf");
	std::string format = "%d %i %f";
	auto& ctx = module->getContext();
	auto ret = parseFormatString(module.get(), format, f);

	ASSERT_EQ(3, ret.size());
	EXPECT_EQ(PointerType::get(Type::getInt32Ty(ctx), 0), ret[0]);
	EXPECT_EQ(PointerType::get(Type::getInt32Ty(ctx), 0), ret[1]);
	EXPECT_EQ(PointerType::get(Type::getDoubleTy(ctx), 0), ret[2]);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
