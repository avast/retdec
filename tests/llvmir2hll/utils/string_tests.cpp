/**
* @file tests/llvmir2hll/utils/string_tests.cpp
* @brief Tests for the @c string module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/utils/string.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c string module.
*/
class StringTests: public Test {};

//
// getAddressFromName()
//

TEST_F(StringTests,
GetAddressFromNameHasAddressDefaultPrefix) {
	EXPECT_EQ("0x8900438", getAddressFromName("xxx_8900438"));
	EXPECT_EQ("0x8900438_1", getAddressFromName("xxx_8900438_1"));
}

TEST_F(StringTests,
GetAddressFromNameHasAddressCustomNonEmptyPrefix) {
	EXPECT_EQ("my_prefix_8900438", getAddressFromName("xxx_8900438", "my_prefix_"));
}

TEST_F(StringTests,
GetAddressFromNameHasAddressCustomEmptyPrefix) {
	EXPECT_EQ("8900438_1", getAddressFromName("xxx_8900438_1", ""));
}

TEST_F(StringTests,
GetAddressFromNameDoesNotHaveAddress) {
	EXPECT_EQ("", getAddressFromName("a"));
	EXPECT_EQ("", getAddressFromName("x_12"));
	EXPECT_EQ("", getAddressFromName("x_112_4"));
	EXPECT_EQ("", getAddressFromName("x_y_z"));
	EXPECT_EQ("", getAddressFromName("xxx_8900438_a"));
	EXPECT_EQ("", getAddressFromName("xxx_8900438_444"));
	EXPECT_EQ("", getAddressFromName("8900438"));
	EXPECT_EQ("", getAddressFromName("8900438_"));
	EXPECT_EQ("", getAddressFromName("var_8900438_"));
	EXPECT_EQ("", getAddressFromName("x_444444__12"));
}

//
// getAddressFromLabel()
//

TEST_F(StringTests,
GetAddressFromLabelDefaultAddressPrefix) {
	EXPECT_EQ("0x89004c5", getAddressFromLabel("pc_89004c5", "pc_"));
	EXPECT_EQ("0x89004c5", getAddressFromLabel("aaa_89004c5", "aaa_"));
	EXPECT_EQ("0x804aa06", getAddressFromLabel("pc_804aa06.backedge", "pc_"));
	EXPECT_EQ("0x8200", getAddressFromLabel("pc_8200.lr.ph", "pc_"));
	EXPECT_EQ("0x804abb8", getAddressFromLabel("pc_804abb8.pc_804abb8_crit_edge", "pc_"));
	EXPECT_EQ("0x0123456789abcdef", getAddressFromLabel("pc_0123456789ABCDEFG", "pc_"));
}

TEST_F(StringTests,
GetAddressFromLabelWherePrefixIsWithoutUnderscore) {
	EXPECT_EQ("0x89004c5", getAddressFromLabel("###89004c5", "###"));
}

TEST_F(StringTests,
GetAddressFromLabelCustomAddressPrefix) {
	EXPECT_EQ("#89004c5", getAddressFromLabel("pc_89004c5", "pc_", "#"));
}

TEST_F(StringTests,
GetAddressFromLabelDoesNotHaveAddress) {
	EXPECT_EQ("", getAddressFromLabel("", "pc_"));
	EXPECT_EQ("abcdefg", getAddressFromLabel("abcdefg", "pc_"));
	EXPECT_EQ("pc_zzzz", getAddressFromLabel("pc_zzzz", "pc_"));
}

//
// getOffsetFromName()
//

TEST_F(StringTests,
GetOffsetFromNameHasOffset) {
	EXPECT_EQ("-72", getOffsetFromName("stack_var_-72"));
	EXPECT_EQ("-8", getOffsetFromName("stack_var_-8"));
	EXPECT_EQ("+0", getOffsetFromName("stack_var_+0"));
	EXPECT_EQ("+4", getOffsetFromName("stack_var_+4"));
}

TEST_F(StringTests,
GetOffsetFromNameDoesNotHaveOffset) {
	EXPECT_EQ("", getOffsetFromName(""));
	EXPECT_EQ("", getOffsetFromName("stack_var"));
	EXPECT_EQ("", getOffsetFromName("stack_var_"));
	EXPECT_EQ("", getOffsetFromName("stack_var_4"));
	EXPECT_EQ("", getOffsetFromName("stack_var_b"));
	EXPECT_EQ("", getOffsetFromName("stack_var_-"));
	EXPECT_EQ("", getOffsetFromName("stack_var_+"));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
