/**
 * @file tests/config/calling_convention_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/calling_convention.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

class CallingConventionTests : public Test
{
	protected:
		CallingConvention cc;
};

TEST_F(CallingConventionTests, CheckAll)
{
	EXPECT_TRUE( cc.isUnknown() );
	EXPECT_FALSE( cc.isKnown() );
	EXPECT_EQ("unknown", cc.getJsonValue().asString());

	cc.setIsVoidarg();
	EXPECT_TRUE( cc.isVoidarg() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("voidarg", cc.getJsonValue().asString());

	cc.setIsCdecl();
	EXPECT_TRUE( cc.isCdecl() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("cdecl", cc.getJsonValue().asString());

	cc.setIsEllipsis();
	EXPECT_TRUE( cc.isEllipsis() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("ellipsis", cc.getJsonValue().asString());

	cc.setIsStdcall();
	EXPECT_TRUE( cc.isStdcall() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("stdcall", cc.getJsonValue().asString());

	cc.setIsPascal();
	EXPECT_TRUE( cc.isPascal() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("pascal", cc.getJsonValue().asString());

	cc.setIsFastcall();
	EXPECT_TRUE( cc.isFastcall() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("fastcall", cc.getJsonValue().asString());

	cc.setIsThiscall();
	EXPECT_TRUE( cc.isThiscall() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("thiscall", cc.getJsonValue().asString());

	cc.setIsManual();
	EXPECT_TRUE( cc.isManual() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("manual", cc.getJsonValue().asString());

	cc.setIsSpoiled();
	EXPECT_TRUE( cc.isSpoiled() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("spoiled", cc.getJsonValue().asString());

	cc.setIsSpecialE();
	EXPECT_TRUE( cc.isSpecialE() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("speciale", cc.getJsonValue().asString());

	cc.setIsSpecialP();
	EXPECT_TRUE( cc.isSpecialP() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("specialp", cc.getJsonValue().asString());

	cc.setIsSpecial();
	EXPECT_TRUE( cc.isSpecial() );
	EXPECT_TRUE( cc.isKnown() );
	EXPECT_EQ("special", cc.getJsonValue().asString());

	cc.setIsUnknown();
	EXPECT_TRUE( cc.isUnknown() );
	EXPECT_FALSE( cc.isKnown() );
}

} // namespace tests
} // namespace config
} // namespace retdec
