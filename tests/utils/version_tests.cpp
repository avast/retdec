/**
* @file tests/utils/version_tests.cpp
* @brief Tests for the @c version module.
* @copyright (c) 2021 Avast Software, licensed under the MIT license
*/

#include <regex>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "retdec/utils/version.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace version {
namespace tests {

class VersionTests : public Test {};

TEST_F(VersionTests, getCommitHashIsValidHash)
{
	EXPECT_TRUE(std::regex_match(
			getCommitHash(),
			std::regex("^[a-fA-F0-9]{40}$")
	));
}

TEST_F(VersionTests, getShortCommitHashIsValidHash)
{
	EXPECT_TRUE(std::regex_match(
			getShortCommitHash(12),
			std::regex("^[a-fA-F0-9]{12}$")
	));
}

TEST_F(VersionTests, getBuildDateIsValidDate)
{
	EXPECT_FALSE(getBuildDate().empty());
}

TEST_F(VersionTests, getVersionTagIsValidTag)
{
	EXPECT_FALSE(getVersionTag().empty());
}

TEST_F(VersionTests, getVersionStringLongContainsEverything)
{
	auto v = getVersionStringLong();

	EXPECT_THAT(v, HasSubstr(getCommitHash()));
	EXPECT_THAT(v, HasSubstr(getShortCommitHash()));
	EXPECT_THAT(v, HasSubstr(getBuildDate()));
	EXPECT_THAT(v, HasSubstr(getVersionTag()));
}

TEST_F(VersionTests, getVersionStringShortContainsEverything)
{
	auto v = getVersionStringShort();

	EXPECT_THAT(v, HasSubstr(getBuildDate()));
	EXPECT_THAT(v, HasSubstr(getVersionTag()));
}

} // namespace tests
} // namespace version
} // namespace utils
} // namespace retdec
