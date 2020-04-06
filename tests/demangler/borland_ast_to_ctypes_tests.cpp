/**
 * @file tests/demangler/borland_ast_to_ctypes_tests.cpp
 * @brief Tests for the Borland demangler.
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

class BorlandCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	BorlandCtypesTests() :
		demangler(std::make_unique<retdec::demangler::BorlandDemangler>()),
		module(std::make_unique<ctypes::Module>(std::make_shared<retdec::ctypes::Context>())) {}
protected:
	std::shared_ptr<ctypes::Function> mangledToCtypes(
		const std::string &mangled)
	{
		ctypesparser::CTypesParser::TypeWidths typeWidths {
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

TEST_F(BorlandCtypesTests, basic)
{
	mangledToCtypes("@myFunc_int_$qi");

	EXPECT_TRUE(module->hasFunctionWithName("@myFunc_int_$qi"));

	auto func = module->getFunctionWithName("@myFunc_int_$qi");
	EXPECT_EQ(static_cast<std::string>(func->getDeclaration()), "myFunc_int_(int)");
	EXPECT_TRUE(func->getReturnType()->isUnknown());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
}

TEST_F(BorlandCtypesTests, AddsFunctionsToModule)
{
	auto name1 = "@foo1$qi";
	auto name2 = "@foo2@qi";

	auto func_returned1 = mangledToCtypes(name1);
	auto func_returned2 = mangledToCtypes(name2);

	auto func_from_module1 = module->getFunctionWithName(name1);
	auto func_from_module2 = module->getFunctionWithName(name2);

	EXPECT_EQ(func_from_module1, func_returned1);
	EXPECT_EQ(func_from_module2, func_returned2);
}

TEST_F(BorlandCtypesTests, ReturnNullptrOnFailure)
{
	auto func = mangledToCtypes("@foo$");
	EXPECT_EQ(func, nullptr);
}

TEST_F(BorlandCtypesTests, ReturnNullptrOnEmpty)
{
	auto func = mangledToCtypes("");
	EXPECT_EQ(func, nullptr);
}

TEST_F(BorlandCtypesTests, DeclarationIsCorrectlySet)
{
	auto func = mangledToCtypes("@foo$qi");
	std::string declaration = func->getDeclaration();
	EXPECT_EQ(declaration, "foo(int)");
}

TEST_F(BorlandCtypesTests, ReturnTypeIsCorrectlySet)
{
	auto func = mangledToCtypes("@%foo$i%$qi$d");
	EXPECT_TRUE(func->getReturnType()->isFloatingPoint());
}

TEST_F(BorlandCtypesTests, UnknownReturnType)
{
	auto func = mangledToCtypes("@foo$qi");
	auto returnType = func->getReturnType();
	EXPECT_TRUE(returnType->isUnknown());
}

TEST_F(BorlandCtypesTests, TypeParsingTest)
{
	auto func = mangledToCtypes("@foo$qsusiuiluljujzcuccfdgoCsCib");

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
	EXPECT_EQ(param->getName(), "long long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(8).getType();
	EXPECT_EQ(param->getName(), "unsigned long long");
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
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "float");

	param = func->getParameter(13).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "double");

	param = func->getParameter(14).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "long double");

	param = func->getParameter(15).getType();
	EXPECT_EQ(param->getName(), "bool");

	param = func->getParameter(16).getType();
	EXPECT_EQ(param->getName(), "char16_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(17).getType();
	EXPECT_EQ(param->getName(), "char32_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(18).getType();
	EXPECT_EQ(param->getName(), "wchar_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());
}

TEST_F(BorlandCtypesTests, TypeWidthsOfTypesWithKnownWidth)
{
	std::shared_ptr<ctypes::Function> func;

	func = mangledToCtypes("@foo$qCi");
	auto char32_type = func->getParameter(1).getType();
	EXPECT_EQ(char32_type->getBitWidth(), 32);

	func = mangledToCtypes("@foo$qCs");
	auto char16_type = func->getParameter(1).getType();
	EXPECT_EQ(char16_type->getBitWidth(), 16);
}

TEST_F(BorlandCtypesTests, TypeWidthsOfTypesInWidthMap)
{
	std::string mangled = "@foo$qi";
	unsigned int_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {{"int", int_width}};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, 0);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), int_width);
}

TEST_F(BorlandCtypesTests, UseDefaultTypeWidthIfWidthIsNotKnown)
{
	std::string mangled = "@foo$qi";
	unsigned default_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, default_width);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), default_width);
}

TEST_F(BorlandCtypesTests, SignednessOfTypesWithKnownSignedness)
{
	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	std::shared_ptr<ctypes::Function> func;

	func = demangler->demangleFunctionToCtypes("@foo$qi", module, typeWidths, typeSignedness, 0);
	auto int_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("@foo$qui", module, typeWidths, typeSignedness, 0);
	auto uint_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(uint_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("@foo$qzc", module, typeWidths, typeSignedness, 0);
	auto signed_char_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("@foo$quc", module, typeWidths, typeSignedness, 0);
	auto unsigned_char_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(unsigned_char_type)->isSigned());
}

TEST_F(BorlandCtypesTests, SignednessOfTypesWithSignednessInMap)
{
	std::shared_ptr<ctypes::Function> func;
	ctypesparser::CTypesParser::TypeWidths typeWidths {};

	ctypesparser::CTypesParser::TypeSignedness typeSignednessSignedWchar
	{
		{"wchar_t", ctypes::IntegralType::Signess::Signed}
	};
	func = demangler->demangleFunctionToCtypes("@foo$qb", module, typeWidths, typeSignednessSignedWchar, 0);
	auto wcharTypeSigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeSigned)->isSigned());

	ctypesparser::CTypesParser::TypeSignedness typeSignednessUnsignedWchar
	{
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned}
	};
	func = demangler->demangleFunctionToCtypes("@foo$qb", module, typeWidths, typeSignednessUnsignedWchar, 0);
	auto wcharTypeUnsigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeUnsigned)->isSigned());
}

TEST_F(BorlandCtypesTests, TemplateTypeAsParameter)
{
	auto func = mangledToCtypes(
		"@foo$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed());
	auto namedType = std::static_pointer_cast<ctypes::NamedType>(func->getParameter(1).getType());
	EXPECT_EQ(namedType->getName(), "std::basic_string<char, std::char_traits<char>, std::allocator<char>>");
}

TEST_F(BorlandCtypesTests, callConventionTest)
{
	std::shared_ptr<ctypes::Function> func;

	func = mangledToCtypes("@foo1$qqrv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "fastcall");

	func = mangledToCtypes("@foo2$qqsv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "stdcall");

	func = mangledToCtypes("@foo3$qv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "cdecl");

	func = mangledToCtypes("@foo3$Qv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "pascal");
}

TEST_F(BorlandCtypesTests, PointerTest)
{
	auto func = mangledToCtypes("@foo$qpv");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType()->isVoid());
}

TEST_F(BorlandCtypesTests, LValueReferenceTest)
{
	auto func = mangledToCtypes("@foo$qri");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

TEST_F(BorlandCtypesTests, RValueReferenceTest)
{
	auto func = mangledToCtypes("@myFunc_ref2_$qh3Tmp");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isNamed());
}

TEST_F(BorlandCtypesTests, VarArgness)
{
	auto func = mangledToCtypes("@foo$qie");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isIntegral());
	EXPECT_TRUE(func->isVarArg());
}

TEST_F(BorlandCtypesTests, ArrayTypeTests)
{
	// foo(int (*)[3][6])
	auto func = mangledToCtypes("@foo$qpa3$a6$i");

	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType();
	EXPECT_TRUE(pointee->isArray());
	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensionCount(), 2);

	ctypes::ArrayType::Dimensions expectedDimensions{3,6};
	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensions(), expectedDimensions);

	auto elemType = std::static_pointer_cast<ctypes::ArrayType>(pointee)->getElementType();
	EXPECT_TRUE(elemType->isIntegral());
}

TEST_F(BorlandCtypesTests, FunctionPointerTests)
{
	// foo(int (*)(void))
	auto func = mangledToCtypes("@foo$qpqv$i");

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

TEST_F(BorlandCtypesTests, ConstTypesParsing)
{
	auto func = mangledToCtypes("@foo1$qwxi");
	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
	EXPECT_EQ(func->getParameter(1).getType()->getName(), "int");
}

TEST_F(BorlandCtypesTests, VoidParameter)
{
	auto func = mangledToCtypes("@f$qv");	// f(void)

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_TRUE(func->getParameter(1).getType()->isVoid());
}

}	// namespace tests
}	// namespace demangler
}	// namespace retdec