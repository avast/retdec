/**
* @file tests/ctypes/module_tests.cpp
* @brief Tests for the @c module module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/parameter.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class ModuleTests : public Test {
	public:
		ModuleTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			f(Function::create(context, "f", intType, emptyParams)),
			module(Module(context)) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;
		Function::Parameters emptyParams;
		std::shared_ptr<Function> f;
		Module module;

};

TEST_F(ModuleTests,
HasFunctionWithNameReturnsTrueWhenFunctionIsThere)
{
	module.addFunction(f);

	EXPECT_TRUE(module.hasFunctionWithName(f->getName()));
}

TEST_F(ModuleTests,
HasFunctionWithNameReturnsFalseWhenFunctionIsNotThere)
{
	EXPECT_FALSE(module.hasFunctionWithName(f->getName()));
}

TEST_F(ModuleTests,
GetFunctionWithNameReturnsCorrectFunction)
{
	module.addFunction(f);

	EXPECT_EQ(f, module.getFunctionWithName(f->getName()));
}

TEST_F(ModuleTests,
GetFunctionWithNameReturnsNullWhenFunctionIsNotInModule)
{
	EXPECT_EQ(nullptr, module.getFunctionWithName("someName"));
}

#if DEATH_TESTS_ENABLED
TEST_F(ModuleTests,
AddFunctionCrashesOnNull)
{
	EXPECT_DEATH(
		module.addFunction(nullptr),
		"violated precondition - function cannot be null"
	);
}
#endif

TEST_F(ModuleTests,
AddFunctionSuccessfullyAddsNewFunction)
{
	module.addFunction(f);

	EXPECT_TRUE(module.hasFunctionWithName(f->getName()));
}

TEST_F(ModuleTests,
GetContextReturnsCorrectContext)
{
	auto module = Module(context);

	EXPECT_EQ(context, module.getContext());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
