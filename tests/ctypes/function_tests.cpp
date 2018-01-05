/**
* @file tests/ctypes/function_tests.cpp
* @brief Tests for the @c function module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class FunctionTests : public Test
{
	public:
		FunctionTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			paramsOneInt{Parameter("firstParamName", intType)} {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;
		Function::Parameters emptyParams;
		Function::Parameters paramsOneInt;
};

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTests,
CreateFunctionCrashesOnNullptrReturnType)
{
	EXPECT_DEATH(
		Function::create(context, "fName", nullptr, emptyParams),
		"violated precondition - returnType cannot be null"
	);
}
#endif

TEST_F(FunctionTests,
GetReturnTypeReturnsCorrectType)
{
	auto newF = Function::create(context, "newF", intType, emptyParams);

	EXPECT_EQ(intType, newF->getReturnType());
}

TEST_F(FunctionTests,
GetCallConventionReturnsCorrectConvention)
{
	auto newF = Function::create(
		context, "newF", intType, emptyParams, CallConvention("cdecl")
	);

	EXPECT_EQ(CallConvention("cdecl"), newF->getCallConvention());
}

TEST_F(FunctionTests,
CallConventionIsEmptyByDefault)
{
	auto newF = Function::create(context, "newF", intType, emptyParams);

	EXPECT_EQ(CallConvention(""), newF->getCallConvention());
}

TEST_F(FunctionTests,
CreateFunctionCreatesCorrectFunctionType)
{
	auto funcType = FunctionType::create(context, intType, {intType});

	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(funcType, newF->getType());
}

TEST_F(FunctionTests,
GetCorrectParametersCountForEmptyParameters)
{
	auto newF = Function::create(context, "newF", intType, emptyParams);

	EXPECT_EQ(0, newF->getParameterCount());
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTests,
GetParameterAtIndexOutOfRangeCrashes)
{
	auto newF = Function::create(context, "newF", intType, emptyParams);

	EXPECT_DEATH(
		newF->getParameter(2),
		"n is out of bounds"
	);
}
#endif

TEST_F(FunctionTests,
FunctionWithoutParametersDoesNotHaveParameters)
{
	auto newF = Function::create(context, "newF", intType, emptyParams);

	EXPECT_EQ(newF->parameter_begin(), newF->parameter_end());
}

TEST_F(FunctionTests,
BeginIteratorPointsToTheFirstParameter)
{
	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(newF->parameter_begin()));
}

TEST_F(FunctionTests,
ConstBeginIteratorPointsToTheFirstParameter)
{
	std::shared_ptr<const Function> newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(newF->parameter_begin()));
}

TEST_F(FunctionTests,
EndIteratorPointsPastLastParameter)
{
	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(--newF->parameter_end()));
}

TEST_F(FunctionTests,
ConstEndIteratorPointsPastLastParameter)
{
	std::shared_ptr<const Function> newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(--newF->parameter_end()));
}

TEST_F(FunctionTests,
GetNthParameterReturnsCorrectParameter)
{
	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(paramsOneInt[0], newF->getParameter(1));
}

TEST_F(FunctionTests,
GetNthParameterNameReturnsCorrectName)
{
	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ("firstParamName", newF->getParameterName(1));
}

TEST_F(FunctionTests,
GetNthParameterTypeReturnsCorrectType)
{
	auto newF = Function::create(context, "newF", intType, paramsOneInt);

	EXPECT_EQ(intType, newF->getParameterType(1));
}

TEST_F(FunctionTests,
IsVarArgReturnsTrueForVarArgFunction)
{
	auto newF = Function::create(
		context, "newF", intType, emptyParams,
		CallConvention("cdecl"), Function::VarArgness::IsVarArg
	);

	EXPECT_TRUE(newF->isVarArg());
}

TEST_F(FunctionTests,
IsVarArgReturnsFalseForNotVarArgFunction)
{
	auto newF = Function::create(
		context, "newF", intType, emptyParams,
		CallConvention("cdecl"), Function::VarArgness::IsNotVarArg
	);

	EXPECT_FALSE(newF->isVarArg());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
