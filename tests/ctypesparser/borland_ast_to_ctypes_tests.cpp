/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
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
namespace ctypesparser {
namespace tests {

class BorlandCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	BorlandCtypesTests() :
		demangler(retdec::demangler::DemanglerFactory::getDemangler("borland")),
		context(std::make_shared<retdec::ctypes::Context>()),
		module(std::make_unique<ctypes::Module>(context)) {}
protected:
	void mangledToCtypes(
		const std::string &mangled)
	{
		demangler->demangleToModule(mangled, module);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::shared_ptr<retdec::ctypes::Context> context;
	std::unique_ptr<retdec::ctypes::Module> module;
};

TEST_F(BorlandCtypesTests, basic)
{
	mangledToCtypes("@myFunc_int_$qi");

	EXPECT_TRUE(module->hasFunctionWithName("myFunc_int_"));

	auto func = module->getFunctionWithName("myFunc_int_");
	EXPECT_TRUE(func->getReturnType()->isUnknown());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
}

TEST_F(BorlandCtypesTests, TypeParsingTest)
{
	mangledToCtypes("@foo$qsusiuiluljujzcuccfdgoCsCib");

	EXPECT_TRUE(module->hasFunctionWithName("foo"));

	auto func = module->getFunctionWithName("foo");

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

TEST_F(BorlandCtypesTests, templateTypes)
{
	mangledToCtypes(
		"@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");

	EXPECT_TRUE(module
					->hasFunctionWithName("foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>>"));

	auto func =
		module->getFunctionWithName("foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>>");
	EXPECT_TRUE(func->getReturnType()->isVoid());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed());

	auto param = std::static_pointer_cast<ctypes::NamedType>(func->getParameter(1).getType());
	EXPECT_EQ(param->getName(), "std::basic_string<char, std::char_traits<char>, std::allocator<char>>");
}

TEST_F(BorlandCtypesTests, callConventionTest)
{
	std::shared_ptr<ctypes::Function> func;

	mangledToCtypes("@foo1$qqrv");
	EXPECT_TRUE(module->hasFunctionWithName("foo1"));
	func = module->getFunctionWithName("foo1");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "fastcall");

	mangledToCtypes("@foo2$qqsv");
	EXPECT_TRUE(module->hasFunctionWithName("foo2"));
	func = module->getFunctionWithName("foo2");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "stdcall");

	mangledToCtypes("@foo3$qv");
	EXPECT_TRUE(module->hasFunctionWithName("foo3"));
	func = module->getFunctionWithName("foo3");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), static_cast<std::string>(ctypes::CallConvention()));
}

TEST_F(BorlandCtypesTests, PointerAndReferenceTest)
{
	mangledToCtypes("@foo$qpv");
	EXPECT_TRUE(module->hasFunctionWithName("foo"));
	auto func = module->getFunctionWithName("foo");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType()->isVoid());
}

TEST_F(BorlandCtypesTests, VarArgness)
{
	mangledToCtypes("@foo$qri");
	EXPECT_TRUE(module->hasFunctionWithName("foo"));
	auto func = module->getFunctionWithName("foo");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec