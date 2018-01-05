/**
* @file tests/ctypes/annotation_out_tests.cpp
* @brief Tests for the @c annotation_out module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/annotation_out.h"
#include "retdec/ctypes/context.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class AnnotationOutTests : public Test
{
	public:
		AnnotationOutTests():
			context(std::make_shared<Context>()),
			outAnnot(AnnotationOut::create(context, "_Out_")) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Annotation> outAnnot;
};

TEST_F(AnnotationOutTests,
EveryUniqueAnnotationOutIsCreatedOnlyOnce)
{
	auto obj1 = AnnotationOut::create(context, "_Out_");
	auto obj2 = AnnotationOut::create(context, "_Out_");

	EXPECT_EQ(obj1, obj2);
}

TEST_F(AnnotationOutTests,
TwoAnnotationOutsWithDifferentNamesDiffer)
{
	auto obj1 = AnnotationOut::create(context, "_Out_");
	auto obj2 = AnnotationOut::create(context, "OUT");

	EXPECT_NE(obj1, obj2);
}

TEST_F(AnnotationOutTests,
IsInReturnsAlwaysFalsee)
{
	EXPECT_FALSE(outAnnot->isIn());
}

TEST_F(AnnotationOutTests,
IsOutReturnsAlwaysTrue)
{
	EXPECT_TRUE(outAnnot->isOut());
}

TEST_F(AnnotationOutTests,
IsInOutReturnsAlwaysFalse)
{
	EXPECT_FALSE(outAnnot->isInOut());
}

TEST_F(AnnotationOutTests,
IsOptionalReturnsAlwaysFalse)
{
	EXPECT_FALSE(outAnnot->isOptional());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
