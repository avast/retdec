/**
* @file tests/ctypes/member_tests.cpp
* @brief Tests for the @c member module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class MemberTests : public Test {
	public:
		MemberTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<Type> intType;

};

TEST_F(MemberTests,
GetNameReturnsCorrectName)
{
	Member member("member", intType);

	EXPECT_EQ("member", member.getName());
}

TEST_F(MemberTests,
GetTypeReturnsCorrectType)
{
	Member member("member", intType);

	EXPECT_EQ(intType, member.getType());
}

TEST_F(MemberTests,
TwoMembersAreEqualWhenNameAndTypeIsEqual)
{
	Member member1("member", intType);
	Member member2("member", intType);

	EXPECT_EQ(member1, member2);
}

TEST_F(MemberTests,
TwoMembersAreNotEqualWhenNamesDiffer)
{
	Member member1("member1", intType);
	Member member2("member2", intType);

	EXPECT_NE(member1, member2);
}

TEST_F(MemberTests,
TwoMembersAreNotEqualWhenTypesDiffer)
{
	auto charType = IntegralType::create(context, "char", 8);
	Member member1("member", intType);
	Member member2("member", charType);

	EXPECT_NE(member1, member2);
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
