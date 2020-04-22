/**
 * @file tests/config/type_tests.cpp
 * @brief Tests for the type module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/common/type.h"

using namespace ::testing;

namespace retdec {
namespace common {
namespace tests {

class TypeTests : public Test
{

};

TEST_F(TypeTests, WideStringSetGet)
{
	Type type("i32*");
	EXPECT_FALSE( type.isWideString() );

	type.setIsWideString(true);
	EXPECT_TRUE( type.isWideString() );

	type.setIsWideString(false);
	EXPECT_FALSE( type.isWideString() );
}

TEST_F(TypeTests, LlvmIrSetGet)
{
	Type type("i32*");
	EXPECT_EQ( "i32*", type.getLlvmIr() );
}

TEST_F(TypeTests, SameTypesAreNotLessThanEachOther)
{
	Type type1("double");
	Type type2("double");

	EXPECT_FALSE( type1 < type2 );
	EXPECT_FALSE( type2 < type1 );
}

TEST_F(TypeTests, DifferentTypesAreLessThanEachOther)
{
	Type type1("double");
	Type type2("float");

	EXPECT_TRUE( type1 < type2 );
	EXPECT_FALSE( type2 < type1 );
}

} // namespace tests
} // namespace common
} // namespace retdec
