/**
* @file tests/ctypes/annotation_inout_tests.cpp
* @brief Tests for the @c annotation_inout module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/annotation_inout.h"
#include "retdec/ctypes/context.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class AnnotationInOutTests : public Test
{
	public:
		AnnotationInOutTests():
			context(std::make_shared<Context>()),
			in_outAnnot(AnnotationInOut::create(context, "_Inout_")) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Annotation> in_outAnnot;
};

TEST_F(AnnotationInOutTests,
EveryUniqueAnnotationInOutIsCreatedOnlyOnce)
{
	auto obj1 = AnnotationInOut::create(context, "_Inout_");
	auto obj2 = AnnotationInOut::create(context, "_Inout_");

	EXPECT_EQ(obj1, obj2);
}

TEST_F(AnnotationInOutTests,
TwoAnnotationInOutsWithDifferentNamesDiffer)
{
	auto obj1 = AnnotationInOut::create(context, "_Inout_");
	auto obj2 = AnnotationInOut::create(context, "OUT");

	EXPECT_NE(obj1, obj2);
}

TEST_F(AnnotationInOutTests,
IsInReturnsAlwaysFalsee)
{
	EXPECT_FALSE(in_outAnnot->isIn());
}

TEST_F(AnnotationInOutTests,
IsOutReturnsAlwaysTrue)
{
	EXPECT_FALSE(in_outAnnot->isOut());
}

TEST_F(AnnotationInOutTests,
IsInOutReturnsAlwaysFalse)
{
	EXPECT_TRUE(in_outAnnot->isInOut());
}

TEST_F(AnnotationInOutTests,
IsOptionalReturnsAlwaysFalse)
{
	EXPECT_FALSE(in_outAnnot->isOptional());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
