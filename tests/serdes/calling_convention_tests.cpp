/**
 * @file tests/serdes/calling_convention_tests.cpp
 * @brief Tests for the calling convention module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/calling_convention.h"
#include "retdec/serdes/calling_convention.h"
#include "retdec/utils/string.h"

using namespace ::testing;

namespace retdec {
namespace serdes {
namespace tests {

class CallingConventionTests : public Test
{
	protected:
		common::CallingConvention cc;

		std::string _serialize()
		{
			rapidjson::StringBuffer sb;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

			serialize(writer, cc);
			std::string ret = sb.GetString();
			// First and last character should be '"'.
			ret = utils::trim(ret, "\"");
			return ret;
		}
};

TEST_F(CallingConventionTests, CheckSerialization)
{
	// Uninitialized CC is unknown.
	EXPECT_EQ("unknown", _serialize());

	cc.setIsUnknown();
	EXPECT_EQ("unknown", _serialize());

	cc.setIsVoidarg();
	EXPECT_EQ("voidarg", _serialize());

	cc.setIsCdecl();
	EXPECT_EQ("cdecl", _serialize());

	cc.setIsEllipsis();
	EXPECT_EQ("ellipsis", _serialize());

	cc.setIsStdcall();
	EXPECT_EQ("stdcall", _serialize());

	cc.setIsPascal();
	EXPECT_EQ("pascal", _serialize());

	cc.setIsFastcall();
	EXPECT_EQ("fastcall", _serialize());

	cc.setIsThiscall();
	EXPECT_EQ("thiscall", _serialize());

	cc.setIsManual();
	EXPECT_EQ("manual", _serialize());

	cc.setIsSpoiled();
	EXPECT_EQ("spoiled", _serialize());

	cc.setIsSpecialE();
	EXPECT_EQ("speciale", _serialize());

	cc.setIsSpecialP();
	EXPECT_EQ("specialp", _serialize());

	cc.setIsSpecial();
	EXPECT_EQ("special", _serialize());
}

TEST_F(CallingConventionTests, CheckDeserialization)
{
	EXPECT_TRUE(cc.isUnknown());

	deserialize(rapidjson::Value(""), cc);
	EXPECT_TRUE(cc.isUnknown());

	deserialize(rapidjson::Value("unknown"), cc);
	EXPECT_TRUE(cc.isUnknown());

	deserialize(rapidjson::Value("voidarg"), cc);
	EXPECT_TRUE(cc.isVoidarg());

	deserialize(rapidjson::Value("cdecl"), cc);
	EXPECT_TRUE(cc.isCdecl());

	deserialize(rapidjson::Value("ellipsis"), cc);
	EXPECT_TRUE(cc.isEllipsis());

	deserialize(rapidjson::Value("stdcall"), cc);
	EXPECT_TRUE(cc.isStdcall());

	deserialize(rapidjson::Value("pascal"), cc);
	EXPECT_TRUE(cc.isPascal());

	deserialize(rapidjson::Value("fastcall"), cc);
	EXPECT_TRUE(cc.isFastcall());

	deserialize(rapidjson::Value("thiscall"), cc);
	EXPECT_TRUE(cc.isThiscall());

	deserialize(rapidjson::Value("manual"), cc);
	EXPECT_TRUE(cc.isManual());

	deserialize(rapidjson::Value("spoiled"), cc);
	EXPECT_TRUE(cc.isSpoiled());

	deserialize(rapidjson::Value("speciale"), cc);
	EXPECT_TRUE(cc.isSpecialE());

	deserialize(rapidjson::Value("specialp"), cc);
	EXPECT_TRUE(cc.isSpecialP());

	deserialize(rapidjson::Value("special"), cc);
	EXPECT_TRUE(cc.isSpecial());
}

} // namespace tests
} // namespace serdes
} // namespace retdec
