/**
* @file tests/ctypes/annotation_in_tests.cpp
* @brief Tests for the @c annotation_in module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/annotation_in.h"
#include "retdec/ctypes/context.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class AnnotationInTests : public Test
{
	public:
		AnnotationInTests():
			context(std::make_shared<Context>()),
			inAnnot(AnnotationIn::create(context, "_In_")) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Annotation> inAnnot;
};

TEST_F(AnnotationInTests,
EveryUniqueAnnotationInIsCreatedOnlyOnce)
{
	auto obj1 = AnnotationIn::create(context, "_In_");
	auto obj2 = AnnotationIn::create(context, "_In_");

	EXPECT_EQ(obj1, obj2);
}

TEST_F(AnnotationInTests,
TwoAnnotationInsWithDifferentNamesDiffer)
{
	auto obj1 = AnnotationIn::create(context, "_In_");
	auto obj2 = AnnotationIn::create(context, "IN");

	EXPECT_NE(obj1, obj2);
}

TEST_F(AnnotationInTests,
IsInReturnsAlwaysTrue)
{
	EXPECT_TRUE(inAnnot->isIn());
}

TEST_F(AnnotationInTests,
IsOutReturnsAlwaysFalse)
{
	EXPECT_FALSE(inAnnot->isOut());
}

TEST_F(AnnotationInTests,
IsInOutReturnsAlwaysFalse)
{
	EXPECT_FALSE(inAnnot->isInOut());
}

TEST_F(AnnotationInTests,
IsOptionalReturnsAlwaysFalse)
{
	EXPECT_FALSE(inAnnot->isOptional());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
