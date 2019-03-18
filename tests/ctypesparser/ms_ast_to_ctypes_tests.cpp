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

class MsCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	MsCtypesTests() :
		demangler(retdec::demangler::DemanglerFactory::getDemangler("microsoft")),
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

TEST_F(MsCtypesTests, basic)
{
	mangledToCtypes("?foo@@YAXI@Z");	// void __cdecl foo(unsigned int)

	EXPECT_TRUE(module->hasFunctionWithName("foo"));

	auto func = module->getFunctionWithName("foo");

	EXPECT_TRUE(func->getReturnType()->isVoid());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
}

TEST_F(MsCtypesTests, Operators)
{
	mangledToCtypes("??_UTypedefNewDelete@@SAPAXI@Z");	// public: static void * __cdecl TypedefNewDelete::operator new[](unsigned int)

	EXPECT_TRUE(module->hasFunctionWithName("TypedefNewDelete::operator new[]"));
}

TEST_F(MsCtypesTests, NamedTypes)
{
	mangledToCtypes("?function@@YAXV?$C@$$A6AXXZ@@@Z");	// "void __cdecl function(class C<void __cdecl(void)>)"

	EXPECT_TRUE(module->hasFunctionWithName("function"));
	auto func = module->getFunctionWithName("function");

	EXPECT_EQ(func->getParameterCount(), 1);
	auto param = func->getParameter(1);
	EXPECT_TRUE(param.getType()->isNamed());
}

TEST_F(MsCtypesTests, TemplateTypes)
{
	mangledToCtypes("?ee@?$e@$$A6AXXZ@@EEAAXXZ");	// private: virtual void __cdecl e<void __cdecl(void)>::ee(void)
}

}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec