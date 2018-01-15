/**
* @file tests/utils/scope_exit_tests.cpp
* @brief Tests for the @c scope_exit module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/scope_exit.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c scope_exit module.
*/
class ScopeExitTests: public Test {};

TEST_F(ScopeExitTests,
ActionInScopeExitIsPerformedWhenBlockExitsNormally) {
	int i = 0;
	{
		SCOPE_EXIT { ++i; };
	}
	ASSERT_EQ(1, i);
}

TEST_F(ScopeExitTests,
ActionInScopeExitIsPerformedWhenBlockExitsViaException) {
	int i = 0;
	try {
		SCOPE_EXIT { ++i; };
		throw 1;
	} catch (...) {}
	ASSERT_EQ(1, i);
}

} // namespace tests
} // namespace utils
} // namespace retdec
