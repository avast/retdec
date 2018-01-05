/**
* @file tests/ctypes/unknown_type_tests.cpp
* @brief Tests for the @c unknown_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "ctypes/unknown_type.h"
#include "ctypes/void_type.h"

using namespace ::testing;

namespace ctypes {
namespace tests {

class UnknownTypeTests : public Test {};

TEST_F(UnknownTypeTests,
CreateAlwaysReturnsSameInstance)
{
	EXPECT_EQ(UnknownType::create(), UnknownType::create());
}

TEST_F(UnknownTypeTests,
IsUnknownReturnsTrueOnUnknownType)
{
	EXPECT_TRUE(UnknownType::create()->isUnknown());
}

TEST_F(UnknownTypeTests,
IsUnknownReturnsFalseOnNonUnknownType)
{
	EXPECT_FALSE(VoidType::create()->isUnknown());
}

} // namespace tests
} // namespace ctypes
