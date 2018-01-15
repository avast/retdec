/**
* @file tests/ctypes/parameter_tests.cpp
* @brief Tests for the @c parameter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/annotation_in.h"
#include "retdec/ctypes/annotation_inout.h"
#include "retdec/ctypes/annotation_optional.h"
#include "retdec/ctypes/annotation_out.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class ParameterTests : public Test {
	public:
		ParameterTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			inAnnot(std::make_shared<AnnotationIn>("_In_")),
			outAnnot(std::make_shared<AnnotationOut>("_Out_")),
			inOutAnnot(std::make_shared<AnnotationInOut>("_Inout_")),
			optAnnot(std::make_shared<AnnotationOptional>("_In_opt_")) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;
		std::shared_ptr<AnnotationIn> inAnnot;
		std::shared_ptr<AnnotationOut> outAnnot;
		std::shared_ptr<AnnotationInOut> inOutAnnot;
		std::shared_ptr<AnnotationOptional> optAnnot;
};

TEST_F(ParameterTests,
GetNameReturnsCorrectName)
{
	Parameter param("param", intType);

	EXPECT_EQ("param", param.getName());
}

TEST_F(ParameterTests,
GetTypeReturnsCorrectType)
{
	Parameter param("param", intType);

	EXPECT_EQ(intType, param.getType());
}

TEST_F(ParameterTests,
ParameterWithoutAnnotationsDoesNotHaveAnnotations)
{
	auto param = Parameter("param", intType);

	EXPECT_EQ(param.annotation_begin(), param.annotation_end());
}

TEST_F(ParameterTests,
EndIteratorPointsPastLastAnnotation)
{
	auto param = Parameter("param", intType, {inAnnot});

	EXPECT_EQ(param.annotation_begin(), --param.annotation_end());
}

TEST_F(ParameterTests,
ConstEndIteratorPointsPastLastAnnotation)
{
	const Parameter param = Parameter("param", intType, {inAnnot});

	EXPECT_EQ(param.annotation_begin(), --param.annotation_end());
}

TEST_F(ParameterTests,
IsInReturnsTrueWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {inAnnot, inOutAnnot});

	EXPECT_TRUE(param.isIn());
}

TEST_F(ParameterTests,
IsInReturnsFalseWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {optAnnot});

	EXPECT_FALSE(param.isIn());
}

TEST_F(ParameterTests,
IsOutReturnsTrueWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {outAnnot, optAnnot});

	EXPECT_TRUE(param.isOut());
}

TEST_F(ParameterTests,
IsOutReturnsFalseWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {inAnnot, optAnnot});

	EXPECT_FALSE(param.isOut());
}

TEST_F(ParameterTests,
IsInOutReturnsTrueWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {outAnnot, inOutAnnot});

	EXPECT_TRUE(param.isInOut());
}

TEST_F(ParameterTests,
IsInOutReturnsFalseWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {outAnnot});

	EXPECT_FALSE(param.isInOut());
}

TEST_F(ParameterTests,
IsOptionalReturnsTrueWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {inAnnot, optAnnot});

	EXPECT_TRUE(param.isOptional());
}

TEST_F(ParameterTests,
IsOptionalReturnsFalseWhenParameterHasInAnnotation)
{
	auto param = Parameter("p", intType, {inAnnot});

	EXPECT_FALSE(param.isOptional());
}

TEST_F(ParameterTests,
TwoParametersAreEqualWhenNameAndTypeIsEqual)
{
	Parameter param1("param", intType);
	Parameter param2("param", intType);

	EXPECT_EQ(param1, param2);
}

TEST_F(ParameterTests,
TwoParametersAreNotEqualWhenNamesDiffer)
{
	Parameter param1("param1", intType);
	Parameter param2("param2", intType);

	EXPECT_NE(param1, param2);
}

TEST_F(ParameterTests,
TwoParametersAreNotEqualWhenTypesDiffer)
{
	auto charType = IntegralType::create(context, "char", 8);
	Parameter param1("param", intType);
	Parameter param2("param", charType);

	EXPECT_NE(param1, param2);
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
