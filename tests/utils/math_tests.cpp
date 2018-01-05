/**
* @file tests/utils/math_tests.cpp
* @brief Tests for the @c math module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/math.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c math module.
*/
class MathTests: public Test {};

//
// countBits()
//

TEST_F(MathTests, countBitsCountsOK) {
	EXPECT_EQ(0, countBits(0));
	EXPECT_EQ(1, countBits(1));
	EXPECT_EQ(1, countBits(2));
	EXPECT_EQ(2, countBits(3));
	EXPECT_EQ(2, countBits(10));
	EXPECT_EQ(6, countBits(123));
	EXPECT_EQ(6, countBits(123456));
	EXPECT_EQ(16, countBits(123456789));
	EXPECT_EQ(23, countBits(1234567890123));
}

//
// bitSizeOfNumber()
//

TEST_F(MathTests, bitSizeOfNumberCountsOK) {
	EXPECT_EQ(1, bitSizeOfNumber(0));
	EXPECT_EQ(1, bitSizeOfNumber(1));
	EXPECT_EQ(2, bitSizeOfNumber(2));
	EXPECT_EQ(3, bitSizeOfNumber(4));
	EXPECT_EQ(4, bitSizeOfNumber(8));
}

} // namespace tests
} // namespace utils
} // namespace retdec
