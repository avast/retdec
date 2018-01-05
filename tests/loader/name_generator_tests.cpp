/**
 * @file tests/loader/name_generator_tests.cpp
 * @brief Tests for the @c name_generator module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/loader/utils/name_generator.h"

using namespace ::testing;

namespace retdec {
namespace loader {
namespace tests {

class NameGeneratorTests : public Test {};

TEST_F(NameGeneratorTests,
DefaultInitializationWorks) {
	NameGenerator nameGen;

	std::string expected = "0";

	EXPECT_EQ(expected, nameGen.getNextName());
}

TEST_F(NameGeneratorTests,
CustomInitializationWorks) {
	NameGenerator nameGen("name", '0', 3);

	std::string expected = "name000";

	EXPECT_EQ(expected, nameGen.getNextName());
}

TEST_F(NameGeneratorTests,
GetNextNameWorks) {
	NameGenerator nameGen("name", '0', 3);

	std::string firstExpected = "name000";
	std::string secondExpected = "name001";

	EXPECT_EQ(firstExpected, nameGen.getNextName());
	EXPECT_EQ(secondExpected, nameGen.getNextName());
}

} // namespace loader
} // namespace retdec
} // namespace tests
