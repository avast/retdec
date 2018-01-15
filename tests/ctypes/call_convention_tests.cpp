/**
* @file tests/ctypes/call_convention_tests.cpp
* @brief Tests for the @c call_convention module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/ctypes/call_convention.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class CallConventionTests : public Test {};

TEST_F(CallConventionTests,
GetStringOfCallConventionReturnsCorrectConvention)
{
	EXPECT_EQ(
		"stdcall",
		std::string(CallConvention("stdcall"))
	);
}

TEST_F(CallConventionTests,
DeafultConstructorCreatesEmptyCallConvention)
{
	CallConvention call_convention;

	EXPECT_EQ("", std::string(call_convention));
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
