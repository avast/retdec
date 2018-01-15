/**
* @file tests/llvmir2hll/ir/unknown_type_tests.cpp
* @brief Tests for the @c unknown_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/unknown_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unknown_type module.
*/
class UnknownTypeTests: public Test {};

//
// create()
//

TEST_F(UnknownTypeTests,
CreateAlwaysReturnsSameInstance) {
	ASSERT_EQ(UnknownType::create(), UnknownType::create());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
