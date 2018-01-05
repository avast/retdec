/**
* @file tests/ctypes/union_type_tests.cpp
* @brief Tests for the @c integral_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class UnionTypeTests : public Test
{
	public:
		UnionTypeTests():
			context(std::make_shared<Context>()) {}

	protected:
		std::shared_ptr<Context> context;
		UnionType::Members emptyMembers;
};

TEST_F(UnionTypeTests,
EveryUniqueUnionTypeIsCreatedOnlyOnce)
{
	const std::string name = "integralName";
	auto obj1 = UnionType::create(context, name, emptyMembers);
	auto obj2 = UnionType::create(context, name, emptyMembers);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(UnionTypeTests,
TwoUnionTypesWithDifferentNamesDiffer)
{
	auto obj1 = UnionType::create(context, "name", emptyMembers);
	auto obj2 = UnionType::create(context, "otherName", emptyMembers);

	EXPECT_NE(obj1, obj2);
}

TEST_F(UnionTypeTests,
IsUnionReturnsTrueOnUnionType)
{
	EXPECT_TRUE(UnionType::create(context, "u", emptyMembers)->isUnion());
}

TEST_F(UnionTypeTests,
IsUnionReturnsFalseOnNonUnionType)
{
	EXPECT_FALSE(VoidType::create()->isUnion());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
