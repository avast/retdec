/**
* @file tests/ctypes/function_type_tests.cpp
* @brief Tests for the @c function_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class FunctionTypeTests : public Test
{
	public:
		FunctionTypeTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			paramsOneInt{intType} {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;
		FunctionType::Parameters emptyParams;
		FunctionType::Parameters paramsOneInt;
};

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTypeTests,
CreateFunctionTypeCrashesOnNullptrContext)
{
	EXPECT_DEATH(
		FunctionType::create(nullptr, intType, emptyParams),
		"violated precondition - context cannot be null"
	);
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTypeTests,
CreateFunctionTypeCrashesOnNullptrReturnType)
{
	EXPECT_DEATH(
		FunctionType::create(context, nullptr, emptyParams),
		"violated precondition - returnType cannot be null"
	);
}
#endif

TEST_F(FunctionTypeTests,
GetReturnTypeReturnsCorrectType)
{
	auto newF = FunctionType::create(context, intType, emptyParams);

	EXPECT_EQ(intType, newF->getReturnType());
}

TEST_F(FunctionTypeTests,
GetParameterCountReturnsCorrectNumberForEmptyParameters)
{
	auto newF = FunctionType::create(context, intType, emptyParams);

	EXPECT_EQ(0, newF->getParameterCount());
}

TEST_F(FunctionTypeTests,
GetParameterCountReturnsCorrectNumberForOneParameter)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(1, newF->getParameterCount());
}

TEST_F(FunctionTypeTests,
FunctionTypeWithoutParametersDoesNotHaveParameters)
{
	auto newF = FunctionType::create(context, intType, emptyParams);

	EXPECT_EQ(newF->parameter_begin(), newF->parameter_end());
}

TEST_F(FunctionTypeTests,
BeginIteratorPointsToTheFirstParameter)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(newF->parameter_begin()));
}

TEST_F(FunctionTypeTests,
ConstBeginIteratorPointsToTheFirstParameter)
{
	std::shared_ptr<const FunctionType> newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(newF->parameter_begin()));
}

TEST_F(FunctionTypeTests,
EndIteratorPointsPastLastParameter)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(--newF->parameter_end()));
}

TEST_F(FunctionTypeTests,
ConstEndIteratorPointsPastLastParameter)
{
	std::shared_ptr<const FunctionType> newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(newF->getParameter(1), *(--newF->parameter_end()));
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTypeTests,
GetParameterTypeAtIndexOutOfRangeCrashes)
{
	auto newF = FunctionType::create(context, intType, emptyParams);

	EXPECT_DEATH(
		newF->getParameter(2),
		"n is out of bounds"
	);
}
#endif

TEST_F(FunctionTypeTests,
GetNthParameterReturnsCorrectParameter)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(paramsOneInt[0], newF->getParameter(1));
}

TEST_F(FunctionTypeTests,
GetParametersReturnsCorrectParameters)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(paramsOneInt, newF->getParameters());
}

TEST_F(FunctionTypeTests,
GetNthParameterTypeReturnsCorrectType)
{
	auto newF = FunctionType::create(context, intType, paramsOneInt);

	EXPECT_EQ(intType, newF->getParameter(1));
}

TEST_F(FunctionTypeTests,
GetCallConventionReturnsCorrectConvention)
{
	auto newType = FunctionType::create(
		context, intType, emptyParams, CallConvention("cdecl")
	);

	EXPECT_EQ(CallConvention("cdecl"), newType->getCallConvention());
}

TEST_F(FunctionTypeTests,
CallConventionIsEmptyByDefault)
{
	auto newType = FunctionType::create(context, intType, emptyParams);

	EXPECT_EQ(CallConvention(""), newType->getCallConvention());
}

TEST_F(FunctionTypeTests,
IsVarArgReturnsTrueForVarArgFunctionType)
{
	auto newF = FunctionType::create(
		context, intType, emptyParams,
		CallConvention(), FunctionType::VarArgness::IsVarArg
	);

	EXPECT_TRUE(newF->isVarArg());
}

TEST_F(FunctionTypeTests,
IsVarArgReturnsFalseForNotVarArgFunctionType)
{
	auto newF = FunctionType::create(
		context, intType, emptyParams,
		CallConvention(), FunctionType::VarArgness::IsNotVarArg
	);

	EXPECT_FALSE(newF->isVarArg());
}

TEST_F(FunctionTypeTests,
IsFunctionReturnsTrueOnFunctionType)
{
	auto funcType = FunctionType::create(
		context, intType, emptyParams
	);

	EXPECT_TRUE(funcType->isFunction());
}

TEST_F(FunctionTypeTests,
IsFunctionReturnsFalseOnNonFunctionType)
{
	EXPECT_FALSE(intType->isFunction());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
