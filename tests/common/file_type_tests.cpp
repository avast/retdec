/**
 * @file tests/common/file_type_tests.cpp
 * @brief Tests for the file type module.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/file_type.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

class FileTypeTests : public Test
{

};

TEST_F(FileTypeTests, TestSetIsMethods)
{
	FileType ft;

	// uninitialized
	EXPECT_TRUE( ft.isUnknown() );
	EXPECT_FALSE( ft.isKnown() );

	ft.setIsShared();
	EXPECT_TRUE( ft.isShared() );
	EXPECT_TRUE( ft.isKnown() );
	EXPECT_FALSE( ft.isUnknown() );

	ft.setIsArchive();
	EXPECT_TRUE( ft.isArchive() );
	EXPECT_TRUE( ft.isKnown() );
	EXPECT_FALSE( ft.isUnknown() );

	ft.setIsObject();
	EXPECT_TRUE( ft.isObject() );
	EXPECT_TRUE( ft.isKnown() );
	EXPECT_FALSE( ft.isUnknown() );

	ft.setIsExecutable();
	EXPECT_TRUE( ft.isExecutable() );
	EXPECT_TRUE( ft.isKnown() );
	EXPECT_FALSE( ft.isUnknown() );

	ft.setIsUnknown();
	EXPECT_TRUE( ft.isUnknown() );
	EXPECT_FALSE( ft.isKnown() );
}

} // namespace tests
} // namespace common
} // namespace retdec
