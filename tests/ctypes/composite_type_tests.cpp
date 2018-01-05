/**
* @file tests/ctypes/composite_type_tests.cpp
* @brief Tests for the @c composite type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/struct_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class CompositeTypeTests : public Test
{
	public:
		CompositeTypeTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			membersOneInt{Member("firstParamName", intType)} {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;
		StructType::Members emptyMembers;
		StructType::Members membersOneInt;
};

TEST_F(CompositeTypeTests,
GetCorrectMemberCountForEmptyMembers)
{
	auto newC = StructType::create(context, "newC", emptyMembers);

	EXPECT_EQ(0, newC->getMemberCount());
}

#if DEATH_TESTS_ENABLED
TEST_F(CompositeTypeTests,
GetMemberAtIndexOutOfRangeCrashes)
{
	auto newC = StructType::create(context, "newC", emptyMembers);

	EXPECT_DEATH(
		newC->getMember(2),
		"n is out of bounds"
	);
}
#endif

TEST_F(CompositeTypeTests,
StructTypeWithoutMembersDoesNotHaveMembers)
{
	auto newC = StructType::create(context, "newC", emptyMembers);

	EXPECT_EQ(newC->member_begin(), newC->member_end());
}

TEST_F(CompositeTypeTests,
BeginIteratorPointsToTheFirstMember)
{
	auto newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(newC->getMember(1), *(newC->member_begin()));
}

TEST_F(CompositeTypeTests,
ConstBeginIteratorPointsToTheFirstMember)
{
	std::shared_ptr<const StructType> newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(newC->getMember(1), *(newC->member_begin()));
}

TEST_F(CompositeTypeTests,
EndIteratorPointsPastLastMember)
{
	auto newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(newC->getMember(1), *(--newC->member_end()));
}

TEST_F(CompositeTypeTests,
ConstEndIteratorPointsPastLastMember)
{
	std::shared_ptr<const StructType> newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(newC->getMember(1), *(--newC->member_end()));
}

TEST_F(CompositeTypeTests,
GetNthMemberReturnsCorrectMember)
{
	auto newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(membersOneInt[0], newC->getMember(1));
}

TEST_F(CompositeTypeTests,
GetNthMemberNameReturnsCorrectName)
{
	auto newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ("firstParamName", newC->getMemberName(1));
}

TEST_F(CompositeTypeTests,
GetNthMemberTypeReturnsCorrectType)
{
	auto newC = StructType::create(context, "newC", membersOneInt);

	EXPECT_EQ(intType, newC->getMemberType(1));
}

TEST_F(CompositeTypeTests,
SetMembersOverwritesPreviousMembers)
{
	auto newS = StructType::create(context, "newC", emptyMembers);

	newS->setMembers(membersOneInt);

	EXPECT_EQ(membersOneInt[0], newS->getMember(1));
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
