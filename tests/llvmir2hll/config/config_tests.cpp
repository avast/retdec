/**
* @file tests/llvmir2hll/config/config_tests.cpp
* @brief Tests for the @c config module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/config/config.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for ConfigError.
*/
class ConfigErrorTests: public Test {};

TEST_F(ConfigErrorTests,
WhatReturnsMessagePassedToConstructor) {
	const std::string MESSAGE("my message");
	ConfigError ex(MESSAGE);

	ASSERT_EQ(MESSAGE, ex.what());
}

TEST_F(ConfigErrorTests,
GetMessageReturnsMessagePassedToConstructor) {
	const std::string MESSAGE("my message");
	ConfigError ex(MESSAGE);

	ASSERT_EQ(MESSAGE, ex.getMessage());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
