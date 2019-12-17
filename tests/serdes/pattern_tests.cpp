/**
 * @file tests/serdes/pattern_tests.cpp
 * @brief Tests for the pattern module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/pattern.h"
#include "retdec/serdes/pattern.h"

using namespace ::testing;

namespace retdec {
namespace serdes {
namespace tests {

//
//=============================================================================
// Pattern::Match
//=============================================================================
//

class PatternMatchItemTests : public Test
{

};

TEST_F(PatternMatchItemTests, getJsonValueWorksWithFromJsonValueWithFullyDefinedMatch)
{
	auto m1 = common::Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);
	auto json = serialize(m1);
	common::Pattern::Match m2;
	deserialize(json, m2);

	EXPECT_TRUE(m2.isTypeFloatingPoint());
	EXPECT_EQ(0x1000, m2.getOffset());
	EXPECT_EQ(0x2000, m2.getAddress());
	EXPECT_EQ(0x100, m2.getSize());
	EXPECT_EQ(4, m2.getEntrySize());
}

TEST_F(PatternMatchItemTests, getJsonValueWorksWithFromJsonValueWithPartiallyDefinedMatch)
{
	auto m1 = common::Pattern::Match::floatingPoint(0x1000);
	auto json = serialize(m1);
	common::Pattern::Match m2;
	deserialize(json, m2);

	EXPECT_TRUE(m2.isTypeFloatingPoint());
	EXPECT_EQ(0x1000, m2.getOffset());
	EXPECT_FALSE(m2.isAddressDefined());
	EXPECT_FALSE(m2.isSizeDefined());
	EXPECT_FALSE(m2.isEntrySizeDefined());
}

//
//=============================================================================
// Pattern
//=============================================================================
//

class PatternTests : public Test
{

};

TEST_F(PatternTests, getJsonValueWorksWithFromJsonValueWithFullyDefinedPattern)
{
	auto p1 = common::Pattern::malwareLittle("name", "desc");
	auto json = serialize(p1);
	common::Pattern p2;
	deserialize(json, p2);

	EXPECT_TRUE(p2.isTypeMalware());
	EXPECT_TRUE(p2.isEndianLittle());
	EXPECT_EQ("name", p2.getName());
	EXPECT_EQ("desc", p2.getDescription());
}

TEST_F(PatternTests, getJsonValueWorksWithFromJsonValueWithPartiallyDefinedPattern)
{
	auto p1 = common::Pattern::malware();
	auto json = serialize(p1);
	common::Pattern p2;
	deserialize(json, p2);

	EXPECT_TRUE(p2.isTypeMalware());
	EXPECT_TRUE(p2.isEndianUnknown());
	EXPECT_EQ("", p2.getName());
	EXPECT_EQ("", p2.getDescription());
}

} // namespace tests
} // namespace serdes
} // namespace retdec
