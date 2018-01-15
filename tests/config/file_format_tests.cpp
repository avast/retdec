/**
 * @file tests/config/file_format_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/file_format.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

class FileFormatTests : public Test
{
	protected:
		FileFormat ff;
};

TEST_F(FileFormatTests, DefaultIsUnknown)
{
	EXPECT_TRUE( ff.isUnknown() );
	EXPECT_FALSE( ff.isKnown() );
	EXPECT_FALSE( ff.is32bit() );
	EXPECT_FALSE( ff.is64bit() );
}

TEST_F(FileFormatTests, TestSetGetName)
{
	ff.setName("elf");
	EXPECT_TRUE( ff.isElf() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("elf", ff.getName());

	ff.setName("elf32");
	EXPECT_TRUE( ff.isElf() );
	EXPECT_TRUE( ff.isElf32() );
	EXPECT_TRUE( ff.is32bit() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("elf", ff.getName());

	ff.setName("elf64");
	EXPECT_TRUE( ff.isElf() );
	EXPECT_TRUE( ff.isElf64() );
	EXPECT_TRUE( ff.is64bit() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("elf", ff.getName());

	ff.setName("pe");
	EXPECT_TRUE( ff.isPe() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("pe", ff.getName());

	ff.setName("pe32");
	EXPECT_TRUE( ff.isPe() );
	EXPECT_TRUE( ff.isPe32() );
	EXPECT_TRUE( ff.is32bit() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("pe", ff.getName());

	ff.setName("pe64");
	EXPECT_TRUE( ff.isPe() );
	EXPECT_TRUE( ff.isPe64() );
	EXPECT_TRUE( ff.is64bit() );
	EXPECT_TRUE( ff.isKnown() );
	EXPECT_EQ("pe", ff.getName());

	ff.setName("something else");
	EXPECT_TRUE( ff.isUnknown() );
	EXPECT_FALSE( ff.isKnown() );
	EXPECT_EQ("unknown", ff.getName());
}

TEST_F(FileFormatTests, TestSetGetFileClassBits)
{
	// uninitialized
	EXPECT_FALSE( ff.is32bit() );
	EXPECT_FALSE( ff.is64bit() );
	EXPECT_EQ(0, ff.getFileClassBits());

	// 32 bit
	ff.setIs32bit();
	EXPECT_TRUE( ff.is32bit() );
	EXPECT_FALSE( ff.is64bit() );
	EXPECT_EQ(32, ff.getFileClassBits());

	// 64 bit
	ff.setIs64bit();
	EXPECT_FALSE( ff.is32bit() );
	EXPECT_TRUE( ff.is64bit() );
	EXPECT_EQ(64, ff.getFileClassBits());
}

} // namespace tests
} // namespace config
} // namespace retdec
