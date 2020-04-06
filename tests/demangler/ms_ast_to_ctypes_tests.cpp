/**
 * @file tests/demangler/ms_ast_to_ctypes_tests.cpp
 * @brief Tests for the MS demangler.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <retdec/ctypes/floating_point_type.h>

#include "retdec/demangler/demangler.h"
#include "retdec/demangler/context.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/unknown_type.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class MsCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	MsCtypesTests() :
		demangler(std::make_unique<retdec::demangler::MicrosoftDemangler>()),
		module(std::make_unique<ctypes::Module>(std::make_shared<retdec::ctypes::Context>())) {}
protected:
	std::shared_ptr<ctypes::Function> mangledToCtypes(
		const std::string &mangled)
	{
		ctypesparser::CTypesParser::TypeWidths typeWidths {
			{"void", 0},
			{"bool", 1},
			{"char", 8},
			{"signed char", 8},
			{"unsigned char", 8},
			{"wchar_t", 32},
			{"short", 16},
			{"unsigned short", 16},
			{"int", 32},
			{"unsigned int", 32},
			{"long", 64},
			{"unsigned long", 64},
			{"long long", 64},
			{"unsigned long long", 64},
			{"int64_t", 64},
			{"uint64_t", 64},
			{"float", 32},
			{"double", 64},
			{"long double", 96},
			{"ptr_t", 32}
		};

		ctypesparser::CTypesParser::TypeSignedness typeSignedness {
			{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
			{"char", ctypes::IntegralType::Signess::Unsigned},
		};

		return demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, 0);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::unique_ptr<retdec::ctypes::Module> module;
};

TEST_F(MsCtypesTests, AddsFunctionsToModule)
{
	auto name1 = "?foo1@@YAHH@Z";
	auto name2 = "?foo2@@YAHH@Z";

	auto func_returned1 = mangledToCtypes(name1);
	auto func_returned2 = mangledToCtypes(name2);

	auto func_from_module1 = module->getFunctionWithName(name1);
	auto func_from_module2 = module->getFunctionWithName(name2);

	EXPECT_EQ(func_from_module1, func_returned1);
	EXPECT_EQ(func_from_module2, func_returned2);
}

TEST_F(MsCtypesTests, ReturnNullptrOnFailure)
{
	auto func = mangledToCtypes("@foo$qi");	// borland scheme
	EXPECT_EQ(func, nullptr);
}

TEST_F(MsCtypesTests, ReturnNullptrOnEmpty)
{
	auto func = mangledToCtypes("");
	EXPECT_EQ(func, nullptr);
}

TEST_F(MsCtypesTests, DeclarationIsCorrectlySet)
{
	auto func = mangledToCtypes("?foo@@YAHH@Z");
	std::string declaration = func->getDeclaration();
	EXPECT_EQ(declaration, "int __cdecl foo(int)");
}

TEST_F(MsCtypesTests, ReturnTypeIsCorrectlySet)
{
	auto func = mangledToCtypes("?foo@@YANH@Z");
	EXPECT_TRUE(func->getReturnType()->isFloatingPoint());
}

TEST_F(MsCtypesTests, Types)
{
	mangledToCtypes("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z");

	EXPECT_TRUE(module->hasFunctionWithName("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z"));

	auto func = module->getFunctionWithName("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z");

	EXPECT_EQ(func->getParameterCount(), 18);
	std::shared_ptr<ctypes::Type> param;

	param = func->getParameter(1).getType();
	EXPECT_EQ(param->getName(), "short");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(2).getType();
	EXPECT_EQ(param->getName(), "unsigned short");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(3).getType();
	EXPECT_EQ(param->getName(), "int");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(4).getType();
	EXPECT_EQ(param->getName(), "unsigned int");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(5).getType();
	EXPECT_EQ(param->getName(), "long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(6).getType();
	EXPECT_EQ(param->getName(), "unsigned long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(7).getType();
	EXPECT_EQ(param->getName(), "int64_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(8).getType();
	EXPECT_EQ(param->getName(), "uint64_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(9).getType();
	EXPECT_EQ(param->getName(), "signed char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(10).getType();
	EXPECT_EQ(param->getName(), "unsigned char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(11).getType();
	EXPECT_EQ(param->getName(), "char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(12).getType();
	EXPECT_EQ(param->getName(), "wchar_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(13).getType();
	EXPECT_EQ(param->getName(), "char16_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(14).getType();
	EXPECT_EQ(param->getName(), "char32_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(15).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "float");

	param = func->getParameter(16).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "double");

	param = func->getParameter(17).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "long double");

	param = func->getParameter(18).getType();
	EXPECT_EQ(param->getName(), "bool");
}

TEST_F(MsCtypesTests, TypeWidthsOfTypesWithKnownWidth)
{
	std::shared_ptr<ctypes::Function> func;

	func = mangledToCtypes("?foo@@YAH_J@Z");
	auto int64_type = func->getParameter(1).getType();
	EXPECT_EQ(int64_type->getBitWidth(), 64);

	func = mangledToCtypes("?foo@@YAH_K@Z");
	auto uint64_type = func->getParameter(1).getType();
	EXPECT_EQ(uint64_type->getBitWidth(), 64);

	func = mangledToCtypes("?foo@@YAH_S@Z");
	auto char16_type = func->getParameter(1).getType();
	EXPECT_EQ(char16_type->getBitWidth(), 16);

	func = mangledToCtypes("?foo@@YAH_U@Z");
	auto char32_type = func->getParameter(1).getType();
	EXPECT_EQ(char32_type->getBitWidth(), 32);
}

TEST_F(MsCtypesTests, TypeWidthsOfTypesInWidthMap)
{
	std::string mangled = "?foo@@YAHH@Z";
	unsigned int_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {{"int", int_width}};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, 0);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), int_width);
}

TEST_F(MsCtypesTests, UseDefaultTypeWidthIfWidthIsNotKnown)
{
	std::string mangled = "?foo@@YAHH@Z";
	unsigned default_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, default_width);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), default_width);
}

TEST_F(MsCtypesTests, SignednessOfTypesWithKnownSignedness)
{
	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	std::shared_ptr<ctypes::Function> func;

	func = demangler->demangleFunctionToCtypes("?foo@@YAHH@Z", module, typeWidths, typeSignedness, 0);
	auto int_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("?foo@@YAHI@Z", module, typeWidths, typeSignedness, 0);
	auto uint_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(uint_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("?foo@@YAHC@Z", module, typeWidths, typeSignedness, 0);
	auto signed_char_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("?foo@@YAHE@Z", module, typeWidths, typeSignedness, 0);
	auto unsigned_char_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(unsigned_char_type)->isSigned());
}

TEST_F(MsCtypesTests, SignednessOfTypesWithSignednessInMap)
{
	std::shared_ptr<ctypes::Function> func;
	ctypesparser::CTypesParser::TypeWidths typeWidths {};

	ctypesparser::CTypesParser::TypeSignedness typeSignednessSignedWchar
		{
			{"wchar_t", ctypes::IntegralType::Signess::Signed}
		};
	func = demangler->demangleFunctionToCtypes("?foo@@YAH_W@Z", module, typeWidths, typeSignednessSignedWchar, 0);
	auto wcharTypeSigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeSigned)->isSigned());

	ctypesparser::CTypesParser::TypeSignedness typeSignednessUnsignedWchar
		{
			{"wchar_t", ctypes::IntegralType::Signess::Unsigned}
		};
	func = demangler->demangleFunctionToCtypes("?foo@@YAH_W@Z", module, typeWidths, typeSignednessUnsignedWchar, 0);
	auto wcharTypeUnsigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeUnsigned)->isSigned());
}

TEST_F(MsCtypesTests, callConventionTest)
{
	std::shared_ptr<ctypes::Function> func;

	func = mangledToCtypes("?foo@@YAH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "cdecl");

	func = mangledToCtypes("?foo@@YBH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "cdecl");

	func = mangledToCtypes("?foo@@YCH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "pascal");

	func = mangledToCtypes("?foo@@YDH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "pascal");

	func = mangledToCtypes("?foo@@YEH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "thiscall");

	func = mangledToCtypes("?foo@@YFH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "thiscall");

	func = mangledToCtypes("?foo@@YGH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "stdcall");

	func = mangledToCtypes("?foo@@YHH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "stdcall");

	func = mangledToCtypes("?foo@@YIH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "fastcall");

	func = mangledToCtypes("?foo@@YJH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "fastcall");

	func = mangledToCtypes("?foo@@YMH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "clrcall");

	func = mangledToCtypes("?foo@@YNH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "clrcall");

	func = mangledToCtypes("?foo@@YOH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "eabi");

	func = mangledToCtypes("?foo@@YPH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "eabi");

	func = mangledToCtypes("?foo@@YQH_W@Z");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "vectorcall");
}

TEST_F(MsCtypesTests, PointerTest)
{
	auto func = mangledToCtypes("?foo@@YAHPAX@Z");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType()->isVoid());
}

TEST_F(MsCtypesTests, LValueReferenceTest)
{
	auto func = mangledToCtypes("?foo@@YAHAAH@Z");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

TEST_F(MsCtypesTests, RValueReferenceTest)
{
	auto func = mangledToCtypes("?foo@@YAH$$QAH@Z");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

// TODO demangling doesn't work yet
//TEST_F(MsCtypesTests, VarArgness)
//{
//	auto func = mangledToCtypes("?foo@@YAHHZ");
//	auto param = func->getParameter(1).getType();
//	EXPECT_TRUE(param->isIntegral());
//	EXPECT_TRUE(func->isVarArg());
//}

TEST_F(MsCtypesTests, ArrayTypeTests)
{
	// void __cdecl foo(int (*)[3][6])
	auto func = mangledToCtypes("?foo@@YAXPAY125H@Z");

	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType();
	EXPECT_TRUE(pointee->isArray());

	auto elemType = std::static_pointer_cast<ctypes::ArrayType>(pointee)->getElementType();
	EXPECT_TRUE(elemType->isIntegral());

	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensionCount(), 2);

	ctypes::ArrayType::Dimensions expectedDimensions{3,6};
	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensions(), expectedDimensions);
}

TEST_F(MsCtypesTests, FunctionPointerTests)
{
	// void __cdecl foo(int (__cdecl *)(void))
	auto func = mangledToCtypes("?f@@YAXP6AHXZ@Z");

	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType();
	EXPECT_TRUE(pointee->isFunction());

	auto funcType = std::static_pointer_cast<ctypes::FunctionType>(pointee);
	EXPECT_EQ(funcType->getParameterCount(), 1);
	EXPECT_TRUE(funcType->getParameter(1)->isVoid());
	EXPECT_EQ(static_cast<std::string>(funcType->getCallConvention()), "cdecl");
	EXPECT_TRUE(funcType->getReturnType()->isIntegral());
}

TEST_F(MsCtypesTests, NamedTypes)
{
	auto func = mangledToCtypes("?function@@YAXV?$C@$$A6AXXZ@@@Z");	// "void __cdecl function(class C<void __cdecl(void)>)"

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed());
}

TEST_F(MsCtypesTests, VoidParameter)
{
	auto func = mangledToCtypes("?ee@?$e@$$A6AXXZ@@EEAAXXZ");	// private: virtual void __cdecl e<void __cdecl(void)>::ee(void)

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_TRUE(func->getParameter(1).getType()->isVoid());
}

}	// namespace tests
}	// namespace demangler
}	// namespace retdec