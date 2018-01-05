/**
* @file tests/ctypes/annotation_optional_tests.cpp
* @brief Tests for the @c annotation_optional module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/annotation_optional.h"
#include "retdec/ctypes/context.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class AnnotationOptionalTests : public Test
{
	public:
		AnnotationOptionalTests():
			context(std::make_shared<Context>()),
			optionalAnnot(AnnotationOptional::create(context, "_In_opt_")) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Annotation> optionalAnnot;
};

TEST_F(AnnotationOptionalTests,
EveryUniqueAnnotationOptionalIsCreatedOnlyOnce)
{
	auto obj1 = AnnotationOptional::create(context, "_In_opt_");
	auto obj2 = AnnotationOptional::create(context, "_In_opt_");

	EXPECT_EQ(obj1, obj2);
}

TEST_F(AnnotationOptionalTests,
TwoAnnotationOptionalsWithDifferentNamesDiffer)
{
	auto obj1 = AnnotationOptional::create(context, "_In_opt_");
	auto obj2 = AnnotationOptional::create(context, "_Out_opt_");

	EXPECT_NE(obj1, obj2);
}

TEST_F(AnnotationOptionalTests,
IsInReturnsAlwaysFalsee)
{
	EXPECT_FALSE(optionalAnnot->isIn());
}

TEST_F(AnnotationOptionalTests,
IsOutReturnsAlwaysTrue)
{
	EXPECT_FALSE(optionalAnnot->isOut());
}

TEST_F(AnnotationOptionalTests,
IsInOutReturnsAlwaysFalse)
{
	EXPECT_FALSE(optionalAnnot->isInOut());
}

TEST_F(AnnotationOptionalTests,
IsOptionalReturnsAlwaysFalse)
{
	EXPECT_TRUE(optionalAnnot->isOptional());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
