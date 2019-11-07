/**
 * @file tests/serdes/calling_convention_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
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

} // namespace tests
} // namespace serdes
} // namespace retdec
