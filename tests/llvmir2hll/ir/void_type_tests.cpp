/**
* @file tests/llvmir2hll/ir/void_type_tests.cpp
* @brief Tests for the @c void_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/void_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c void_type module.
*/
class VoidTypeTests: public Test {};

//
// create()
//

TEST_F(VoidTypeTests,
CreateAlwaysReturnsSameInstance) {
	ASSERT_EQ(VoidType::create(), VoidType::create());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
