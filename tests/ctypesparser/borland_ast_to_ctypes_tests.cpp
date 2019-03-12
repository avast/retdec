/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"
#include "retdec/demangler/context.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/parameter.h"
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

TEST_F(BorlandCtypesTests, templateTypes)
{
	mangledToCtypes("@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");

	EXPECT_TRUE(module->hasFunctionWithName("foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>>"));

	auto func = module->getFunctionWithName("foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>>");
	EXPECT_TRUE(func->getReturnType()->isVoid());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed()); // TODO
}

}
}
}