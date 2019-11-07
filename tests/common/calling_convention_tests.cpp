/**
 * @file tests/config/calling_convention_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/calling_convention.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

class CallingConventionTests : public Test
{
	protected:
		CallingConvention cc;
};

TEST_F(CallingConventionTests, CheckAll)
{
	// Uninitialized CC is unknown.
	EXPECT_TRUE( cc.isUnknown() );
	EXPECT_FALSE( cc.isKnown() );

	cc.setIsUnknown();
	EXPECT_TRUE( cc.isUnknown() );
	EXPECT_FALSE( cc.isKnown() );

	cc.setIsVoidarg();
	EXPECT_TRUE( cc.isVoidarg() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsCdecl();
	EXPECT_TRUE( cc.isCdecl() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsEllipsis();
	EXPECT_TRUE( cc.isEllipsis() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsStdcall();
	EXPECT_TRUE( cc.isStdcall() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsPascal();
	EXPECT_TRUE( cc.isPascal() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsFastcall();
	EXPECT_TRUE( cc.isFastcall() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsThiscall();
	EXPECT_TRUE( cc.isThiscall() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsManual();
	EXPECT_TRUE( cc.isManual() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsSpoiled();
	EXPECT_TRUE( cc.isSpoiled() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsSpecialE();
	EXPECT_TRUE( cc.isSpecialE() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsSpecialP();
	EXPECT_TRUE( cc.isSpecialP() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsSpecial();
	EXPECT_TRUE( cc.isSpecial() );
	EXPECT_TRUE( cc.isKnown() );

	cc.setIsUnknown();
	EXPECT_TRUE( cc.isUnknown() );
	EXPECT_FALSE( cc.isKnown() );
}

} // namespace tests
} // namespace common
} // namespace retdec
