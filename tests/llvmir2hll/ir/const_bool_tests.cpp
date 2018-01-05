/**
* @file tests/llvmir2hll/ir/const_bool_tests.cpp
* @brief Tests for the @c const_bool module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_bool.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_bool module.
*/
class ConstBoolTests: public Test {};

//
// isTrue()
//

TEST_F(ConstBoolTests,
IsTrueForTrueConstBoolReturnsTrue) {
	ShPtr<ConstBool> constBool(ConstBool::create(true));

	EXPECT_TRUE(constBool->isTrue());
}

TEST_F(ConstBoolTests,
IsTrueForFalseConstBoolReturnsFalse) {
	ShPtr<ConstBool> constBool(ConstBool::create(false));

	EXPECT_FALSE(constBool->isTrue());
}

//
// isFalse()
//

TEST_F(ConstBoolTests,
IsFalseForTrueConstBoolReturnsFalse) {
	ShPtr<ConstBool> constBool(ConstBool::create(true));

	EXPECT_FALSE(constBool->isFalse());
}

TEST_F(ConstBoolTests,
IsFalseForFalseConstBoolReturnsTrue) {
	ShPtr<ConstBool> constBool(ConstBool::create(false));

	EXPECT_TRUE(constBool->isFalse());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
