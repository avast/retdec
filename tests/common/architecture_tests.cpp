/**
 * @file tests/common/architecture_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/architecture.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

class ArchitectureTests : public Test
{
	protected:
		Architecture arch;
};

TEST_F(ArchitectureTests, CheckIfArchMethodsWork)
{
	EXPECT_TRUE( arch.isUnknown() );
	EXPECT_FALSE( arch.isKnown() );
	EXPECT_EQ( "unknown", arch.getName() );

	arch.setIsMips();
	EXPECT_TRUE( arch.isMips() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "mips", arch.getName() );

	arch.setIsArm();
	EXPECT_TRUE( arch.isArm() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "arm", arch.getName() );

	arch.setIsThumb();
	EXPECT_TRUE( arch.isArm() );
	EXPECT_TRUE( arch.isThumb() );
	EXPECT_TRUE( arch.isArm32OrThumb() );
	EXPECT_FALSE( arch.isArm64() );
	EXPECT_FALSE( arch.isArm32() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "thumb", arch.getName() );

	arch.setIsArm32();
	EXPECT_TRUE( arch.isArm() );
	EXPECT_TRUE( arch.isArm32() );
	EXPECT_TRUE( arch.isArm32OrThumb() );
	EXPECT_FALSE( arch.isThumb() );
	EXPECT_FALSE( arch.isArm64() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "arm", arch.getName() );

	arch.setIsArm64();
	EXPECT_TRUE( arch.isArm() );
	EXPECT_FALSE( arch.isArm32() );
	EXPECT_FALSE( arch.isArm32OrThumb() );
	EXPECT_FALSE( arch.isThumb() );
	EXPECT_TRUE( arch.isArm64() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "aarch64", arch.getName() );

	arch.setIsX86();
	EXPECT_TRUE( arch.isX86() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "x86", arch.getName() );

	arch.setIsPpc();
	EXPECT_TRUE( arch.isPpc() );
	EXPECT_TRUE( arch.isKnown() );
	EXPECT_EQ( "powerpc", arch.getName() );

	arch.setIsUnknown();
	EXPECT_TRUE( arch.isUnknown() );
	EXPECT_FALSE( arch.isKnown() );
}

TEST_F(ArchitectureTests, CheckIfEndianMethodsWork)
{
	EXPECT_TRUE( arch.isEndianUnknown() );
	EXPECT_FALSE( arch.isEndianKnown() );

	arch.setIsEndianLittle();
	EXPECT_TRUE( arch.isEndianLittle() );
	EXPECT_TRUE( arch.isEndianKnown() );

	arch.setIsEndianBig();
	EXPECT_TRUE( arch.isEndianBig() );
	EXPECT_TRUE( arch.isEndianKnown() );

	arch.setIsEndianUnknown();
	EXPECT_TRUE( arch.isEndianUnknown() );
	EXPECT_FALSE( arch.isEndianKnown() );
}

TEST_F(ArchitectureTests, DefaultBitsizeIs32)
{
	EXPECT_EQ( 32, arch.getBitSize() );
	EXPECT_EQ( 4, arch.getByteSize() );
}

TEST_F(ArchitectureTests, SetBitsize)
{
	arch.setBitSize(64);
	EXPECT_EQ( 64, arch.getBitSize() );
	EXPECT_EQ( 8, arch.getByteSize() );
}

TEST_F(ArchitectureTests, IsArchIsCaseInsensitiveContains)
{
	arch.setName("some crazy MiPs nAme");
	EXPECT_TRUE( arch.isMips() );
}

} // namespace tests
} // namespace common
} // namespace retdec
