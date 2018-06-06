/**
* @file tests/bin2llvmir/providers/tests/lti_tests.cpp
* @brief Tests for the @c LtiProvider.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/void_type.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "bin2llvmir/utils/llvmir_tests.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  ToLlvmTypeVisitor
//=============================================================================
//

/**
 * @brief Tests for the @c Lti.
 */
class ToLlvmTypeVisitorTests: public LlvmIrTests
{
	public:
		ToLlvmTypeVisitorTests() :
			ctx(std::make_shared<retdec::ctypes::Context>()),
			config(Config::empty(module.get())),
			visitor(module.get(), &config)
		{

		}

	public:
		std::shared_ptr<retdec::ctypes::Context> ctx;
		Config config;
		ToLlvmTypeVisitor visitor;
};

TEST_F(ToLlvmTypeVisitorTests, convertArrayType)
{
	retdec::ctypes::ArrayType::Dimensions dim = {10, 20};
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::ArrayType::create(ctx, i32, dim);
	type->accept(&visitor);

	auto* ref = ArrayType::get(
			ArrayType::get(
					Type::getInt32Ty(context),
					20),
			10);
	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertArrayTypeInvalid)
{
	retdec::ctypes::ArrayType::Dimensions dim = {10};
	auto v = retdec::ctypes::VoidType::create();
	auto type = retdec::ctypes::ArrayType::create(ctx, v, dim);
	type->accept(&visitor);

	auto* ref = ArrayType::get(
			Abi::getDefaultType(module.get()),
			10);
	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertEnumType)
{
	retdec::ctypes::EnumType::Values vals =
	{
			retdec::ctypes::EnumType::Value("e0", 0),
			retdec::ctypes::EnumType::Value("e1", 1)
	};
	auto type = retdec::ctypes::EnumType::create(ctx, "TestEnum", vals);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt32Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertHalfType)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "half", 16);
	type->accept(&visitor);

	EXPECT_EQ(Type::getHalfTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertFloatType)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "float", 32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getFloatTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertDoubleType)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "double", 64);
	type->accept(&visitor);

	EXPECT_EQ(Type::getDoubleTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertFp80Type)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "fp80", 80);
	type->accept(&visitor);

	EXPECT_EQ(Type::getX86_FP80Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertFp128Type)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "fp128", 128);
	type->accept(&visitor);

	EXPECT_EQ(Type::getFP128Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertOddFloatingPointType)
{
	auto type = retdec::ctypes::FloatingPointType::create(ctx, "offFp", 54);
	type->accept(&visitor);

	EXPECT_EQ(Type::getFloatTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertFunctionType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto f = retdec::ctypes::FloatingPointType::create(ctx, "float", 32);
	retdec::ctypes::FunctionType::Parameters ps = {i32, i32};
	auto type = retdec::ctypes::FunctionType::create(ctx, f, ps);
	type->accept(&visitor);

	auto* li32 = Type::getInt32Ty(context);
	std::vector<Type*> lps = {li32, li32};
	auto* ref = FunctionType::get(
			Type::getFloatTy(context),
			lps,
			false);

	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertFunctionVarargType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto f = retdec::ctypes::FloatingPointType::create(ctx, "float", 32);
	retdec::ctypes::FunctionType::Parameters ps = {i32, i32};
	auto type = retdec::ctypes::FunctionType::create(
			ctx,
			f,
			ps,
			retdec::ctypes::CallConvention(),
			retdec::ctypes::FunctionType::VarArgness::IsVarArg);
	type->accept(&visitor);

	auto* li32 = Type::getInt32Ty(context);
	std::vector<Type*> lps = {li32, li32};
	auto* ref = FunctionType::get(
			Type::getFloatTy(context),
			lps,
			true);

	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertInt32Type)
{
	auto type = retdec::ctypes::IntegralType::create(ctx, "int32", 32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt32Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertInt64Type)
{
	auto type = retdec::ctypes::IntegralType::create(ctx, "int64", 64);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt64Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertIntNType)
{
	auto type = retdec::ctypes::IntegralType::create(ctx, "int64", 35);
	type->accept(&visitor);

	EXPECT_EQ(Type::getIntNTy(context, 35), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertPointerType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::PointerType::create(ctx, i32);
	type->accept(&visitor);

	auto* li32 = Type::getInt32Ty(context);
	auto* ref = PointerType::get(li32, 0);
	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertPointerTypeInvalid)
{
	auto v = retdec::ctypes::VoidType::create();
	auto type = retdec::ctypes::PointerType::create(ctx, v);
	type->accept(&visitor);

	auto* d = Abi::getDefaultType(module.get());
	auto* ref = PointerType::get(d, 0);
	EXPECT_EQ(ref, visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertTypedefType)
{
	auto d = retdec::ctypes::FloatingPointType::create(ctx, "double", 64);
	auto type = retdec::ctypes::TypedefedType::create(ctx, "typedef", d);
	type->accept(&visitor);

	EXPECT_EQ(Type::getDoubleTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertTypedefBoolType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::TypedefedType::create(ctx, "BOOL", i32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt1Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertTypedefWcharElfType)
{
	config.getConfig().fileFormat.setIsElf();
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::TypedefedType::create(ctx, "wchar", i32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt32Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertTypedefWcharPeType)
{
	config.getConfig().fileFormat.setIsPe();
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::TypedefedType::create(ctx, "wchar", i32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt16Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertTypedefWcharOtherType)
{
	config.getConfig().fileFormat.setIsIntelHex();
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto type = retdec::ctypes::TypedefedType::create(ctx, "wchar", i32);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt16Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertUnionType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto d = retdec::ctypes::FloatingPointType::create(ctx, "double", 64);
	retdec::ctypes::CompositeType::Members mems =
	{
			retdec::ctypes::Member("m0", i32),
			retdec::ctypes::Member("m1", d)
	};
	auto type = retdec::ctypes::UnionType::create(ctx, "TestUnion", mems);
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt32Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertUnknownType)
{
	auto type = retdec::ctypes::UnknownType::create();
	type->accept(&visitor);

	EXPECT_EQ(Type::getInt32Ty(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertVoidType)
{
	auto type = retdec::ctypes::VoidType::create();
	type->accept(&visitor);

	EXPECT_EQ(Type::getVoidTy(context), visitor.getLlvmType());
}

TEST_F(ToLlvmTypeVisitorTests, convertStructureType)
{
	auto i32 = retdec::ctypes::IntegralType::create(ctx, "int", 32);
	auto d = retdec::ctypes::FloatingPointType::create(ctx, "double", 64);
	retdec::ctypes::CompositeType::Members mems =
	{
			retdec::ctypes::Member("m0", i32),
			retdec::ctypes::Member("m1", d)
	};
	auto type = retdec::ctypes::StructType::create(ctx, "TestStruct", mems);
	type->accept(&visitor);

	auto* res = dyn_cast<StructType>(visitor.getLlvmType());
	ASSERT_NE(nullptr, res);
	EXPECT_EQ("TestStruct", res->getName());
	EXPECT_EQ(2, res->getNumElements());
	EXPECT_EQ(Type::getInt32Ty(context), res->getElementType(0));
	EXPECT_EQ(Type::getDoubleTy(context), res->getElementType(1));

	// Try to get it second time -- it should get existing structure,
	// not create a new one.
	//
	type->accept(&visitor);
	auto* res2 = visitor.getLlvmType();
	EXPECT_EQ(res, res2);
	EXPECT_FALSE(res->isOpaque());
}

TEST_F(ToLlvmTypeVisitorTests, convertStructureTypeInvalid)
{
	auto v = retdec::ctypes::VoidType::create();
	retdec::ctypes::CompositeType::Members mems =
	{
			retdec::ctypes::Member("m0", v)
	};
	auto type = retdec::ctypes::StructType::create(ctx, "TestStruct", mems);
	type->accept(&visitor);

	auto* res = dyn_cast<StructType>(visitor.getLlvmType());
	EXPECT_EQ("TestStruct", res->getName());
	EXPECT_EQ(1, res->getNumElements());
	EXPECT_EQ(Abi::getDefaultType(module.get()), res->getElementType(0));
}

TEST_F(ToLlvmTypeVisitorTests, convertRecursiveStructPtrStruct)
{
	retdec::ctypes::CompositeType::Members mems;
	auto type = retdec::ctypes::StructType::create(ctx, "TestStruct", mems);
	auto pType = retdec::ctypes::PointerType::create(ctx, type);
	mems.push_back(retdec::ctypes::Member("m0", pType));
	type->setMembers(mems);

	type->accept(&visitor);
	auto* res = dyn_cast<StructType>(visitor.getLlvmType());

	EXPECT_EQ("TestStruct", res->getName());
}

//
//=============================================================================
//  LtiTests
//=============================================================================
//

/**
 * @brief Tests for the @c Lti.
 */
class LtiTests: public LlvmIrTests
{

};

//
//=============================================================================
//  LtiProviderTests
//=============================================================================
//

/**
 * @brief Tests for the @c LtiProviderTests.
 */
class LtiProviderTests: public LlvmIrTests
{

};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
