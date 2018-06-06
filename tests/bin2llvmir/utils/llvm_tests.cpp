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
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace llvm_utils {
namespace tests {

class LlvmUtilsTests : public retdec::bin2llvmir::tests::LlvmIrTests
{

};

//
// stringToLlvmType()
//

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesPrimitiveTypes)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesPointerTypes)
{
	EXPECT_EQ(
			PointerType::get(
					Type::getInt32Ty(context),
					Abi::DEFAULT_ADDR_SPACE),
			stringToLlvmType(context, "i32*"));

	EXPECT_EQ(
			PointerType::get(
					PointerType::get(
							Type::getDoubleTy(context),
							Abi::DEFAULT_ADDR_SPACE),
					Abi::DEFAULT_ADDR_SPACE),
			stringToLlvmType(context, "double**"));
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesArrayTypes)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesVectorTypes)
{
	EXPECT_EQ(
			VectorType::get(
					Type::getInt32Ty(context),
					10),
			stringToLlvmType(context, "<10 x i32>"));
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeOnlyPrimitiveTypesCanBeVectorTypeElements)
{
	EXPECT_EQ(
			nullptr,
			stringToLlvmType(context, "<10 x [20 x double]>"));
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesFunctionTypes)
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
								Abi::DEFAULT_ADDR_SPACE)
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
								Abi::DEFAULT_ADDR_SPACE)
				},
				true),
		stringToLlvmType(context, "double (i32, double*, ...)"));
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesOpaqueStructureTypes)
{
	auto* t = stringToLlvmType(context, "%s0 = type opaque");

	ASSERT_NE(nullptr, t);
	ASSERT_TRUE(t->isStructTy());

	auto* st = dyn_cast<StructType>(t);

	ASSERT_NE(nullptr, st);
	EXPECT_TRUE(st->isOpaque());
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesStructureTypes)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesEmbeddedStructureTypes)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeCreatesComplicatedType)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeReturnsAlreadyExistingTypeForStructureId)
{
	std::string str = "%struct = type {i16, i32}";

	auto* t1 = stringToLlvmType(context, str);
	auto* t2 = stringToLlvmType(context, "%struct");

	EXPECT_EQ(t1, t2);
}

TEST_F(LlvmUtilsTests, stringToLlvmTypeReturnNullWhenTypeStringToParseIsBad)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeReturnNullWhenInvalidElementTypesAreUsed)
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

TEST_F(LlvmUtilsTests, stringToLlvmTypeCanHandlePointerToVoid)
{
	EXPECT_EQ(
			PointerType::get(Type::getInt8Ty(context), 0),
			stringToLlvmType(context, "void*"));
}

//
// parseFormatString()
//

TEST_F(LlvmUtilsTests, parseFormatStringBasic)
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
	EXPECT_EQ(llvm_utils::getCharPointerType(ctx), ret[16]);
	EXPECT_EQ(llvm_utils::getCharPointerType(ctx), ret[17]);
	EXPECT_EQ(Abi::getDefaultPointerType(module.get()), ret[18]);
	EXPECT_EQ(PointerType::get(Type::getInt32Ty(ctx), 0), ret[19]);
}

TEST_F(LlvmUtilsTests, parseFormatStringBasicUnknownConversionCharacterIsDefaultInt)
{
	std::string format = "%f %y %f";
	auto& ctx = module->getContext();
	auto ret = parseFormatString(module.get(), format);

	ASSERT_EQ(3, ret.size());
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[0]);
	EXPECT_EQ(Abi::getDefaultType(module.get()), ret[1]);
	EXPECT_EQ(Type::getDoubleTy(ctx), ret[2]);
}

TEST_F(LlvmUtilsTests, parseFormatStringReturnsPointersIfCalledFunctionIsScanf)
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
} // namespace llvm_utils
} // namespace bin2llvmir
} // namespace retdec
