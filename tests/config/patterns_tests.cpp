/**
 * @file tests/config/patterns_tests.cpp
 * @brief Tests for the @c patterns module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/patterns.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

//
//=============================================================================
// Pattern::Match
//=============================================================================
//

class PatternMatchItemTests : public Test
{

};

TEST_F(PatternMatchItemTests, unknownCtorCreatesUnknownMatchWithNoParams)
{
	auto m = Pattern::Match::unknown();

	EXPECT_TRUE(m.isTypeUnknown());
	EXPECT_FALSE(m.isTypeIntegral());
	EXPECT_FALSE(m.isTypeFloatingPoint());

	EXPECT_FALSE(m.isOffsetDefined());
	EXPECT_FALSE(m.isAddressDefined());
	EXPECT_FALSE(m.isSizeDefined());
	EXPECT_FALSE(m.isEntrySizeDefined());
}

TEST_F(PatternMatchItemTests, unknownCtorCreatesUnknownMatchWithAllParams)
{
	auto m = Pattern::Match::unknown(0x1000, 0x2000, 0x100, 4);

	EXPECT_TRUE(m.isTypeUnknown());
	EXPECT_FALSE(m.isTypeIntegral());
	EXPECT_FALSE(m.isTypeFloatingPoint());

	EXPECT_TRUE(m.isOffsetDefined());
	EXPECT_EQ(0x1000, m.getOffset());
	EXPECT_TRUE(m.isAddressDefined());
	EXPECT_EQ(0x2000, m.getAddress());
	EXPECT_TRUE(m.isSizeDefined());
	EXPECT_EQ(0x100, m.getSize());
	EXPECT_TRUE(m.isEntrySizeDefined());
	EXPECT_EQ(4, m.getEntrySize());
}

TEST_F(PatternMatchItemTests, integralCtorCreatesUnknownMatchWithNoParams)
{
	auto m = Pattern::Match::integral();

	EXPECT_FALSE(m.isTypeUnknown());
	EXPECT_TRUE(m.isTypeIntegral());
	EXPECT_FALSE(m.isTypeFloatingPoint());

	EXPECT_FALSE(m.isOffsetDefined());
	EXPECT_FALSE(m.isAddressDefined());
	EXPECT_FALSE(m.isSizeDefined());
	EXPECT_FALSE(m.isEntrySizeDefined());
}

TEST_F(PatternMatchItemTests, integralCtorCreatesUnknownMatchWithAllParams)
{
	auto m = Pattern::Match::integral(0x1000, 0x2000, 0x100, 4);

	EXPECT_FALSE(m.isTypeUnknown());
	EXPECT_TRUE(m.isTypeIntegral());
	EXPECT_FALSE(m.isTypeFloatingPoint());

	EXPECT_TRUE(m.isOffsetDefined());
	EXPECT_EQ(0x1000, m.getOffset());
	EXPECT_TRUE(m.isAddressDefined());
	EXPECT_EQ(0x2000, m.getAddress());
	EXPECT_TRUE(m.isSizeDefined());
	EXPECT_EQ(0x100, m.getSize());
	EXPECT_TRUE(m.isEntrySizeDefined());
	EXPECT_EQ(4, m.getEntrySize());
}

TEST_F(PatternMatchItemTests, floatingPointCtorCreatesUnknownMatchWithNoParams)
{
	auto m = Pattern::Match::floatingPoint();

	EXPECT_FALSE(m.isTypeUnknown());
	EXPECT_FALSE(m.isTypeIntegral());
	EXPECT_TRUE(m.isTypeFloatingPoint());

	EXPECT_FALSE(m.isOffsetDefined());
	EXPECT_FALSE(m.isAddressDefined());
	EXPECT_FALSE(m.isSizeDefined());
	EXPECT_FALSE(m.isEntrySizeDefined());
}

TEST_F(PatternMatchItemTests, floatingPointCtorCreatesUnknownMatchWithAllParams)
{
	auto m = Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);

	EXPECT_FALSE(m.isTypeUnknown());
	EXPECT_FALSE(m.isTypeIntegral());
	EXPECT_TRUE(m.isTypeFloatingPoint());

	EXPECT_TRUE(m.isOffsetDefined());
	EXPECT_EQ(0x1000, m.getOffset());
	EXPECT_TRUE(m.isAddressDefined());
	EXPECT_EQ(0x2000, m.getAddress());
	EXPECT_TRUE(m.isSizeDefined());
	EXPECT_EQ(0x100, m.getSize());
	EXPECT_TRUE(m.isEntrySizeDefined());
	EXPECT_EQ(4, m.getEntrySize());
}

TEST_F(PatternMatchItemTests, getJsonValueWorksWithFromJsonValueWithFullyDefinedMatch)
{
	auto m1 = Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);
	auto json = m1.getJsonValue();
	auto m2 = Pattern::Match::fromJsonValue(json);

	EXPECT_TRUE(m2.isTypeFloatingPoint());
	EXPECT_EQ(0x1000, m2.getOffset());
	EXPECT_EQ(0x2000, m2.getAddress());
	EXPECT_EQ(0x100, m2.getSize());
	EXPECT_EQ(4, m2.getEntrySize());
}

TEST_F(PatternMatchItemTests, getJsonValueWorksWithFromJsonValueWithPartiallyDefinedMatch)
{
	auto m1 = Pattern::Match::floatingPoint(0x1000);
	auto json = m1.getJsonValue();
	auto m2 = Pattern::Match::fromJsonValue(json);

	EXPECT_TRUE(m2.isTypeFloatingPoint());
	EXPECT_EQ(0x1000, m2.getOffset());
	EXPECT_FALSE(m2.isAddressDefined());
	EXPECT_FALSE(m2.isSizeDefined());
	EXPECT_FALSE(m2.isEntrySizeDefined());
}

TEST_F(PatternMatchItemTests, matchesWithUndefinedValuesAreEqual)
{
	Pattern::Match m1;
	Pattern::Match m2;

	EXPECT_TRUE(m1 == m2);
	EXPECT_FALSE(m1 != m2);
}

TEST_F(PatternMatchItemTests, matchesWithTheSameDefinedValuesAreEqual)
{
	auto m1 = Pattern::Match::floatingPoint(0x1000, 0x2000);
	auto m2 = Pattern::Match::floatingPoint(0x1000, 0x2000);

	EXPECT_TRUE(m1 == m2);
	EXPECT_FALSE(m1 != m2);
}

TEST_F(PatternMatchItemTests, matchesWithAllTheSameDefinedValuesAreEqual)
{
	auto m1 = Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);
	auto m2 = Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);

	EXPECT_TRUE(m1 == m2);
	EXPECT_FALSE(m1 != m2);
}

TEST_F(PatternMatchItemTests, matchesWithDifferentValuesAreNotEqual)
{
	auto m1 = Pattern::Match::floatingPoint(0x2000, 0x1000, 4, 0x100);
	auto m2 = Pattern::Match::floatingPoint(0x1000, 0x2000, 0x100, 4);

	EXPECT_FALSE(m1 == m2);
	EXPECT_TRUE(m1 != m2);
}

TEST_F(PatternMatchItemTests, matchesWithMixedDefinedAndUndefinedValuesAreNotEqual)
{
	auto m1 = Pattern::Match::floatingPoint(0x2000);
	auto m2 = Pattern::Match::floatingPoint(0x2000);
	m1.setSize(0x100);
	m2.setEntrySize(4);

	EXPECT_FALSE(m1 == m2);
	EXPECT_TRUE(m1 != m2);
}

//
//=============================================================================
// Pattern
//=============================================================================
//

class PatternTests : public Test
{

};

TEST_F(PatternTests, otherCtorCreatesOtherPatternWithNoParams)
{
	auto p = Pattern::other();

	EXPECT_TRUE(p.isTypeOther());
	EXPECT_FALSE(p.isTypeCrypto());
	EXPECT_FALSE(p.isTypeMalware());

	EXPECT_TRUE(p.isEndianUnknown());
	EXPECT_FALSE(p.isEndianLittle());
	EXPECT_FALSE(p.isEndianBig());

	EXPECT_EQ("", p.getName());
	EXPECT_EQ("", p.getDescription());
}

TEST_F(PatternTests, otherCtorCreatesOtherPatternWithAllParams)
{
	auto p = Pattern::other("name", "desc");

	EXPECT_TRUE(p.isTypeOther());
	EXPECT_TRUE(p.isEndianUnknown());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, otherLittleCtorCreatesOtherPatternWithAllParams)
{
	auto p = Pattern::otherLittle("name", "desc");

	EXPECT_TRUE(p.isTypeOther());
	EXPECT_TRUE(p.isEndianLittle());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, otherBigCtorCreatesOtherPatternWithAllParams)
{
	auto p = Pattern::otherBig("name", "desc");

	EXPECT_TRUE(p.isTypeOther());
	EXPECT_TRUE(p.isEndianBig());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, cryptoCtorCreatesCryptoPatternWithAllParams)
{
	auto p = Pattern::crypto("name", "desc");

	EXPECT_TRUE(p.isTypeCrypto());
	EXPECT_TRUE(p.isEndianUnknown());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, cryptoLittleCtorCreatesCryptoPatternWithAllParams)
{
	auto p = Pattern::cryptoLittle("name", "desc");

	EXPECT_TRUE(p.isTypeCrypto());
	EXPECT_TRUE(p.isEndianLittle());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, cryptoBigCtorCreatesCryptoPatternWithAllParams)
{
	auto p = Pattern::cryptoBig("name", "desc");

	EXPECT_TRUE(p.isTypeCrypto());
	EXPECT_TRUE(p.isEndianBig());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, malwareCtorCreatesMalwarePatternWithAllParams)
{
	auto p = Pattern::malware("name", "desc");

	EXPECT_TRUE(p.isTypeMalware());
	EXPECT_TRUE(p.isEndianUnknown());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, malwareLittleCtorCreatesMalwarePatternWithAllParams)
{
	auto p = Pattern::malwareLittle("name", "desc");

	EXPECT_TRUE(p.isTypeMalware());
	EXPECT_TRUE(p.isEndianLittle());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, malwareBigCtorCreatesMalwarePatternWithAllParams)
{
	auto p = Pattern::malwareBig("name", "desc");

	EXPECT_TRUE(p.isTypeMalware());
	EXPECT_TRUE(p.isEndianBig());
	EXPECT_EQ("name", p.getName());
	EXPECT_EQ("desc", p.getDescription());
}

TEST_F(PatternTests, getJsonValueWorksWithFromJsonValueWithFullyDefinedPattern)
{
	auto p1 = Pattern::malwareLittle("name", "desc");
	auto json = p1.getJsonValue();
	auto p2 = Pattern::fromJsonValue(json);

	EXPECT_TRUE(p2.isTypeMalware());
	EXPECT_TRUE(p2.isEndianLittle());
	EXPECT_EQ("name", p2.getName());
	EXPECT_EQ("desc", p2.getDescription());
}

TEST_F(PatternTests, getJsonValueWorksWithFromJsonValueWithPartiallyDefinedPattern)
{
	auto p1 = Pattern::malware();
	auto json = p1.getJsonValue();
	auto p2 = Pattern::fromJsonValue(json);

	EXPECT_TRUE(p2.isTypeMalware());
	EXPECT_TRUE(p2.isEndianUnknown());
	EXPECT_EQ("", p2.getName());
	EXPECT_EQ("", p2.getDescription());
}

TEST_F(PatternTests, defaultUninitializedPatternsAreEqual)
{
	Pattern p1;
	Pattern p2;

	EXPECT_TRUE(p1 == p2);
	EXPECT_FALSE(p1 != p2);
}

TEST_F(PatternTests, SamePatternsAreEqual)
{
	auto m = Pattern::Match::floatingPoint(0x1000, 0x2000);
	auto p1 = Pattern::malwareLittle("name", "desc");
	p1.matches.insert(m);
	auto p2 = Pattern::malwareLittle("name", "desc");
	p2.matches.insert(m);

	EXPECT_TRUE(p1 == p2);
	EXPECT_FALSE(p1 != p2);
}

TEST_F(PatternTests, SimilarPatternsWithDifferentTypesAreNotEqual)
{
	auto m = Pattern::Match::floatingPoint(0x1000, 0x2000);
	auto p1 = Pattern::malwareLittle("name", "desc");
	p1.matches.insert(m);
	auto p2 = Pattern::cryptoLittle("name", "desc");
	p2.matches.insert(m);

	EXPECT_FALSE(p1 == p2);
	EXPECT_TRUE(p1 != p2);
}

TEST_F(PatternTests, SimilarPatternsWithDifferentNamesAreNotEqual)
{
	auto m = Pattern::Match::floatingPoint(0x1000, 0x2000);
	auto p1 = Pattern::malwareLittle("name1", "desc");
	p1.matches.insert(m);
	auto p2 = Pattern::malwareLittle("name2", "desc");
	p2.matches.insert(m);

	EXPECT_FALSE(p1 == p2);
	EXPECT_TRUE(p1 != p2);
}

TEST_F(PatternTests, SimilarPatternsWithDifferentMatchesAreNotEqual)
{
	auto m1 = Pattern::Match::floatingPoint(0x1000, 0x2000);
	auto m2 = Pattern::Match::floatingPoint(0x2000, 0x4000);
	auto p1 = Pattern::malwareLittle("name", "desc");
	p1.matches.insert(m1);
	auto p2 = Pattern::malwareLittle("name", "desc");
	p2.matches.insert(m1);
	p2.matches.insert(m2);

	EXPECT_FALSE(p1 == p2);
	EXPECT_TRUE(p1 != p2);
}

//
//=============================================================================
// PatternContainer
//=============================================================================
//

class PatternContainerTests : public Test
{

};

} // namespace tests
} // namespace config
} // namespace retdec
