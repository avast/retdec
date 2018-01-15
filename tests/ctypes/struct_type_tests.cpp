/**
* @file tests/ctypes/struct_type_tests.cpp
* @brief Tests for the @c struct_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class StructTypeTests : public Test
{
	public:
		StructTypeTests():
			context(std::make_shared<Context>()) {}

	protected:
		std::shared_ptr<Context> context;
		StructType::Members emptyMembers;
};

TEST_F(StructTypeTests,
EveryUniqueStructTypeIsCreatedOnlyOnce)
{
	const std::string name = "integralName";
	auto obj1 = StructType::create(context, name, emptyMembers);
	auto obj2 = StructType::create(context, name, emptyMembers);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(StructTypeTests,
TwoStructTypesWithDifferentNamesDiffer)
{
	auto obj1 = StructType::create(context, "name", emptyMembers);
	auto obj2 = StructType::create(context, "otherName", emptyMembers);

	EXPECT_NE(obj1, obj2);
}

TEST_F(StructTypeTests,
IsStructReturnsTrueOnStructType)
{
	EXPECT_TRUE(StructType::create(context, "s", emptyMembers)->isStruct());
}

TEST_F(StructTypeTests,
IsStructReturnsFalseOnNonStructType)
{
	EXPECT_FALSE(VoidType::create()->isStruct());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
