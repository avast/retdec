/**
* @file tests/ctypes/header_file_tests.cpp
* @brief Tests for the @c header_file module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/ctypes/header_file.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class HeaderFileTests : public Test {};

TEST_F(HeaderFileTests,
DeafultConstructorCreatesHeaderFileWithEmptyPath)
{
	HeaderFile header_file;

	EXPECT_EQ(header_file.getPath(), "");
}

TEST_F(HeaderFileTests,
GetPathReturnsCorrectPath)
{
	EXPECT_EQ(
		"/usr/include/stdio.h",
		HeaderFile("/usr/include/stdio.h").getPath()
	);
}

TEST_F(HeaderFileTests,
GetNameOnUnixPathReturnsCorrectFileName)
{
	EXPECT_EQ(
		"stdio.h",
		HeaderFile("/usr/include/stdio.h").getName()
	);
}

TEST_F(HeaderFileTests,
GetNameOnWindowsPathReturnsCorrectFileName)
{
	EXPECT_EQ(
		"stdio.h",
		HeaderFile("C:\\some_include\\stdio.h").getName()
	);
}

TEST_F(HeaderFileTests,
GetNameReturnsEmptyNameWhenPathEndWithSlash)
{
	EXPECT_EQ(
		"",
		HeaderFile("/path/").getName()
	);
}

TEST_F(HeaderFileTests,
GetNameReturnsCorrectNameWhenNoPathSeparatorThere)
{
	EXPECT_EQ(
		"stdio.h",
		HeaderFile("stdio.h").getName()
	);
}

TEST_F(HeaderFileTests,
GetNameReturnsEmptyNameWhenPathEndWithBackslash)
{
	EXPECT_EQ(
		"",
		HeaderFile("C:\\path\\").getName()
	);
}

TEST_F(HeaderFileTests,
GetNameReturnsEmptyNameWhenPathIsEmpty)
{
	EXPECT_EQ(
		"",
		HeaderFile("").getName()
	);
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
