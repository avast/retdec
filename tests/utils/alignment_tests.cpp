/**
* @file tests/utils/alignment_tests.cpp
* @brief Tests for the @c alignment module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/alignment.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

class AlignmentTests : public Test {};

TEST_F(AlignmentTests,
IsAlignedWorks) {
	std::uint64_t remainder;

	EXPECT_TRUE(isAligned(0x2000, 0x1000, remainder));
	EXPECT_EQ(0, remainder);

	EXPECT_FALSE(isAligned(0x2010, 0x1000, remainder));
	EXPECT_EQ(0x10, remainder);
}

TEST_F(AlignmentTests,
AlignDownWorks) {
	EXPECT_EQ(0x2000, alignDown(0x2FFF, 0x1000));
	EXPECT_EQ(0x2000, alignDown(0x2000, 0x1000));
}

TEST_F(AlignmentTests,
AlignUpWorks) {
	EXPECT_EQ(0x3000, alignUp(0x2FFF, 0x1000));
	EXPECT_EQ(0x3000, alignUp(0x3000, 0x1000));
}

} // namespace tests
} // namespace utils
} // namespace retdec
