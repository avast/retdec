/**
* @file tests/ctypes/void_type_tests.cpp
* @brief Tests for the @c void_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class VoidTypeTests : public Test {};

TEST_F(VoidTypeTests,
CreateAlwaysReturnsSameInstance)
{
	EXPECT_EQ(VoidType::create(), VoidType::create());
}

TEST_F(VoidTypeTests,
IsVoidReturnsTrueOnVoidType)
{
	EXPECT_TRUE(VoidType::create()->isVoid());
}

TEST_F(VoidTypeTests,
IsVoidReturnsFalseOnNonVoidType)
{
	EXPECT_FALSE(UnknownType::create()->isVoid());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
