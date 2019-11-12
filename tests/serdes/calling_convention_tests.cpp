/**
 * @file tests/serdes/calling_convention_tests.cpp
 * @brief Tests for the calling convention module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/calling_convention.h"
#include "retdec/serdes/calling_convention.h"

using namespace ::testing;

namespace retdec {
namespace serdes {
namespace tests {

class CallingConventionTests : public Test
{
	protected:
		common::CallingConvention cc;
};

TEST_F(CallingConventionTests, CheckSerialization)
{
	// Uninitialized CC is unknown.
	EXPECT_EQ("unknown", serialize(cc).asString());

	cc.setIsUnknown();
	EXPECT_EQ("unknown", serialize(cc).asString());

	cc.setIsVoidarg();
	EXPECT_EQ("voidarg", serialize(cc).asString());

	cc.setIsCdecl();
	EXPECT_EQ("cdecl", serialize(cc).asString());

	cc.setIsEllipsis();
	EXPECT_EQ("ellipsis", serialize(cc).asString());

	cc.setIsStdcall();
	EXPECT_EQ("stdcall", serialize(cc).asString());

	cc.setIsPascal();
	EXPECT_EQ("pascal", serialize(cc).asString());

	cc.setIsFastcall();
	EXPECT_EQ("fastcall", serialize(cc).asString());

	cc.setIsThiscall();
	EXPECT_EQ("thiscall", serialize(cc).asString());

	cc.setIsManual();
	EXPECT_EQ("manual", serialize(cc).asString());

	cc.setIsSpoiled();
	EXPECT_EQ("spoiled", serialize(cc).asString());

	cc.setIsSpecialE();
	EXPECT_EQ("speciale", serialize(cc).asString());

	cc.setIsSpecialP();
	EXPECT_EQ("specialp", serialize(cc).asString());

	cc.setIsSpecial();
	EXPECT_EQ("special", serialize(cc).asString());
}

TEST_F(CallingConventionTests, CheckDeserialization)
{
	EXPECT_TRUE(cc.isUnknown());

	deserialize("", cc);
	EXPECT_TRUE(cc.isUnknown());

	deserialize("unknown", cc);
	EXPECT_TRUE(cc.isUnknown());

	deserialize("voidarg", cc);
	EXPECT_TRUE(cc.isVoidarg());

	deserialize("cdecl", cc);
	EXPECT_TRUE(cc.isCdecl());

	deserialize("ellipsis", cc);
	EXPECT_TRUE(cc.isEllipsis());

	deserialize("stdcall", cc);
	EXPECT_TRUE(cc.isStdcall());

	deserialize("pascal", cc);
	EXPECT_TRUE(cc.isPascal());

	deserialize("fastcall", cc);
	EXPECT_TRUE(cc.isFastcall());

	deserialize("thiscall", cc);
	EXPECT_TRUE(cc.isThiscall());

	deserialize("manual", cc);
	EXPECT_TRUE(cc.isManual());

	deserialize("spoiled", cc);
	EXPECT_TRUE(cc.isSpoiled());

	deserialize("speciale", cc);
	EXPECT_TRUE(cc.isSpecialE());

	deserialize("specialp", cc);
	EXPECT_TRUE(cc.isSpecialP());

	deserialize("special", cc);
	EXPECT_TRUE(cc.isSpecial());
}

} // namespace tests
} // namespace serdes
} // namespace retdec
