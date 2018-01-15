/**
* @file tests/ctypes/floating_point_type_tests.cpp
* @brief Tests for the @c floating_point_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/integral_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class FloatingPointTypeTests : public Test
{
	public:
		FloatingPointTypeTests():
			context(std::make_shared<Context>()) {}

	protected:
		std::shared_ptr<Context> context;
};

TEST_F(FloatingPointTypeTests,
EveryUniqueFloatingPointTypeIsCreatedOnlyOnce)
{
	const std::string name = "floatingName";
	auto obj1 = FloatingPointType::create(context, name, 32);
	auto obj2 = FloatingPointType::create(context, name, 32);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(FloatingPointTypeTests,
TwoFloatingPointTypesWithDifferentNamesDiffer)
{
	auto obj1 = FloatingPointType::create(context, "name", 32);
	auto obj2 = FloatingPointType::create(context, "otherName", 32);

	EXPECT_NE(obj1, obj2);
}

TEST_F(FloatingPointTypeTests,
IsFloatingPointReturnsTrueOnFloatingPointType)
{
	EXPECT_TRUE(FloatingPointType::create(context, "float", 32)->isFloatingPoint());
}

TEST_F(FloatingPointTypeTests,
IsFloatingPointReturnsFalseOnNonFloatingPointType)
{
	EXPECT_FALSE(IntegralType::create(context, "int", 32)->isFloatingPoint());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
