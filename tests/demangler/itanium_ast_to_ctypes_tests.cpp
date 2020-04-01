/**
 * @file tests/demangler/itanium_ast_to_ctypes_tests.cpp
 * @brief Tests for the Itanium demangler.
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

class ItaniumCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	ItaniumCtypesTests() :
		demangler(std::make_unique<retdec::demangler::ItaniumDemangler>()),
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
			{"float", 32},
			{"double", 64},
			{"long double", 96},
			{"pointer", 32}
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

TEST_F(ItaniumCtypesTests, AddsFunctionsToModule)
{
	auto name1 = "_Z4foo1i";
	auto name2 = "_Z4foo2i";

	auto func_returned1 = mangledToCtypes(name1);
	auto func_returned2 = mangledToCtypes(name2);

	auto func_from_module1 = module->getFunctionWithName(name1);
	auto func_from_module2 = module->getFunctionWithName(name2);

	EXPECT_EQ(func_from_module1, func_returned1);
	EXPECT_EQ(func_from_module2, func_returned2);
}

TEST_F(ItaniumCtypesTests, ReturnNullptrOnFailure)
{
	auto func = mangledToCtypes("@foo$i");	// wrong scheme
	EXPECT_EQ(func, nullptr);
}

TEST_F(ItaniumCtypesTests, ReturnNullptrOnEmpty)
{
	auto func = mangledToCtypes("");
	EXPECT_EQ(func, nullptr);
}

TEST_F(ItaniumCtypesTests, DeclarationIsCorrectlySet)
{
	auto func = mangledToCtypes("_Z3fooi");
	std::string declaration = func->getDeclaration();
	EXPECT_EQ(declaration, "foo(int)");
}

TEST_F(ItaniumCtypesTests, ReturnTypeIsCorrectlySet)
{
	auto func = mangledToCtypes("_Z1fIiEdi");
	EXPECT_TRUE(func->getReturnType()->isFloatingPoint());
}

TEST_F(ItaniumCtypesTests, UnknownReturnType)
{
	auto func = mangledToCtypes("_Z1fi");
	auto returnType = func->getReturnType();
	EXPECT_TRUE(returnType->isUnknown());
}

TEST_F(ItaniumCtypesTests, TypeParsingTest)
{
	auto func = mangledToCtypes("_Z1fstijlmxyahcfdebDsDiw");

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

TEST_F(ItaniumCtypesTests, TypeWidthsOfTypesWithKnownWidth)
{
	std::shared_ptr<ctypes::Function> func;
	func = mangledToCtypes("_Z1fn");
	auto int128_type = func->getParameter(1).getType();
	EXPECT_EQ(int128_type->getBitWidth(), 128);

	func = mangledToCtypes("_Z1fo");
	auto uint128_type = func->getParameter(1).getType();
	EXPECT_EQ(uint128_type->getBitWidth(), 128);

	func = mangledToCtypes("_Z1fDd");
	auto dec64_type = func->getParameter(1).getType();
	EXPECT_EQ(dec64_type->getBitWidth(), 64);

	func = mangledToCtypes("_Z1fDe");
	auto dec128_type = func->getParameter(1).getType();
	EXPECT_EQ(dec128_type->getBitWidth(), 128);

	func = mangledToCtypes("_Z1fDf");
	auto dec32_type = func->getParameter(1).getType();
	EXPECT_EQ(dec32_type->getBitWidth(), 32);

	func = mangledToCtypes("_Z1fDh");
	auto dec16_type = func->getParameter(1).getType();
	EXPECT_EQ(dec16_type->getBitWidth(), 16);

	func = mangledToCtypes("_Z1fDi");
	auto char32_type = func->getParameter(1).getType();
	EXPECT_EQ(char32_type->getBitWidth(), 32);

	func = mangledToCtypes("_Z1fDs");
	auto char16_type = func->getParameter(1).getType();
	EXPECT_EQ(char16_type->getBitWidth(), 16);
}

TEST_F(ItaniumCtypesTests, TypeWidthsOfTypesInWidthMap)
{
	std::string mangled = "_Z3fooi";
	unsigned int_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {{"int", int_width}};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, 0);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), int_width);
}

TEST_F(ItaniumCtypesTests, UseDefaultTypeWidthIfWidthIsNotKnown)
{
	std::string mangled = "_Z3fooi";
	unsigned default_width = 256;

	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	auto func = demangler->demangleFunctionToCtypes(mangled, module, typeWidths, typeSignedness, default_width);

	auto int_type = func->getParameter(1).getType();
	EXPECT_EQ(int_type->getBitWidth(), default_width);
}

TEST_F(ItaniumCtypesTests, SignednessOfTypesWithKnownSignedness)
{
	ctypesparser::CTypesParser::TypeWidths typeWidths {};
	ctypesparser::CTypesParser::TypeSignedness typeSignedness {};

	std::shared_ptr<ctypes::Function> func;

	func = demangler->demangleFunctionToCtypes("_Z1fi", module, typeWidths, typeSignedness, 0);
	auto int_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("_Z1fj", module, typeWidths, typeSignedness, 0);
	auto uint_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(uint_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("_Z1fa", module, typeWidths, typeSignedness, 0);
	auto signed_char_type = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(int_type)->isSigned());

	func = demangler->demangleFunctionToCtypes("_Z1fh", module, typeWidths, typeSignedness, 0);
	auto unsigned_char_type = func->getParameter(1).getType();
	EXPECT_FALSE(std::static_pointer_cast<ctypes::IntegralType>(unsigned_char_type)->isSigned());
}

TEST_F(ItaniumCtypesTests, SignednessOfTypesWithSignednessInMap)
{
	std::shared_ptr<ctypes::Function> func;
	ctypesparser::CTypesParser::TypeWidths typeWidths {};

	ctypesparser::CTypesParser::TypeSignedness typeSignednessSignedWchar
		{
			{"char", ctypes::IntegralType::Signess::Signed}
		};
	func = demangler->demangleFunctionToCtypes("_Z1fc", module, typeWidths, typeSignednessSignedWchar, 0);
	auto wcharTypeSigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeSigned)->isSigned());

	ctypesparser::CTypesParser::TypeSignedness typeSignednessUnsignedWchar
		{
			{"char", ctypes::IntegralType::Signess::Unsigned}
		};
	func = demangler->demangleFunctionToCtypes("_Z1fc", module, typeWidths, typeSignednessUnsignedWchar, 0);
	auto wcharTypeUnsigned = func->getParameter(1).getType();
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(wcharTypeUnsigned)->isSigned());
}

TEST_F(ItaniumCtypesTests, TemplateTypeAsParameter)
{
	auto func = mangledToCtypes(
		"_Z3fooNSt12basic_stringIcSt11char_traitsIcESaIcEEE");

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed());
	auto namedType = std::static_pointer_cast<ctypes::NamedType>(func->getParameter(1).getType());
	EXPECT_EQ(namedType->getName(), "std::basic_string<char, std::char_traits<char>, std::allocator<char> >");
}

TEST_F(ItaniumCtypesTests, PointerTypeToNamedTypeParameterTest)
{
	auto func = mangledToCtypes("_Z1fKP3Bar");	// f(Bar * const);
	auto paramType = func->getParameter(1).getType();
	EXPECT_TRUE(paramType->isPointer());
	auto pointeeType = std::static_pointer_cast<ctypes::PointerType>(paramType)->getPointedType();
	EXPECT_TRUE(pointeeType->isNamed());
}

TEST_F(ItaniumCtypesTests, PointerTypeToIntTypeParameterTest)
{
	auto func = mangledToCtypes("_Z1fKPi");	// f(int * const);
	auto paramType = func->getParameter(1).getType();
	EXPECT_TRUE(paramType->isPointer());
	auto pointeeType = std::static_pointer_cast<ctypes::PointerType>(paramType)->getPointedType();
	EXPECT_TRUE(pointeeType->isIntegral());
}

TEST_F(ItaniumCtypesTests, LValueReferenceTest)
{
	auto func = mangledToCtypes("_Z1fRi");	// f(int &);
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

TEST_F(ItaniumCtypesTests, RValueReferenceTest)
{
	auto func = mangledToCtypes("_Z1fO3Bar");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isNamed());
}

TEST_F(ItaniumCtypesTests, VarArgnessTest)
{
	auto func = mangledToCtypes("_Z3fooiz");
	EXPECT_EQ(func->getParameterCount(), 1);
	auto param = func->getParameter(1);
	EXPECT_TRUE(param.getType()->isIntegral());
	EXPECT_TRUE(func->isVarArg());
}

TEST_F(ItaniumCtypesTests, ArrayTest)
{
	auto func = mangledToCtypes("_Z1fA37_A42_iPS_");

	EXPECT_EQ(func->getParameterCount(), 2);

	auto paramType = func->getParameter(1).getType();
	EXPECT_TRUE(paramType->isArray());
	auto arrayType = std::static_pointer_cast<ctypes::ArrayType>(paramType)->getElementType();
	auto dimensions = std::static_pointer_cast<ctypes::ArrayType>(paramType)->getDimensions();
	ctypes::ArrayType::Dimensions expectedDimensions{37,42};
	EXPECT_EQ(dimensions, expectedDimensions);
}

TEST_F(ItaniumCtypesTests, FunctionPointers)
{
	auto func = mangledToCtypes("_Z4foo1PFivE");

	EXPECT_EQ(func->getParameterCount(), 1);
	auto paramType = func->getParameter(1).getType();
	EXPECT_TRUE(paramType->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(paramType)->getPointedType();
	EXPECT_TRUE(pointee->isFunction());

	auto pointedFuncType = std::static_pointer_cast<ctypes::FunctionType>(pointee);
	EXPECT_TRUE(pointedFuncType->getReturnType()->isIntegral());
	EXPECT_EQ(pointedFuncType->getParameterCount(), 0);
}

TEST_F(ItaniumCtypesTests, ConstTypesParsing)
{
	auto func = mangledToCtypes("_Z1fKi");
	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
	EXPECT_EQ(func->getParameter(1).getType()->getName(), "int");
}

}	// namespace tests
}	// namespace demangler
}	// namespace retdec