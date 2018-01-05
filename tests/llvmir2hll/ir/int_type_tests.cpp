/**
* @file tests/llvmir2hll/ir/int_type_tests.cpp
* @brief Tests for the @c int_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/int_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c int_type module.
*/
class IntTypeTests: public Test {
protected:
	ShPtr<IntType> getSignedIntType(unsigned size = 32);
	ShPtr<IntType> getUnsignedIntType(unsigned size = 32);
};

/**
* @brief Returns a signed int type of the given @a size.
*/
ShPtr<IntType> IntTypeTests::getSignedIntType(unsigned size) {
	return IntType::create(size, true);
}

/**
* @brief Returns an unsigned int type of the given @a size.
*/
ShPtr<IntType> IntTypeTests::getUnsignedIntType(unsigned size) {
	return IntType::create(size, false);
}

//
// isSigned()
//

TEST_F(IntTypeTests,
IsSignedReturnsTrueWhenTypeIsSigned) {
	auto type = getSignedIntType();
	ASSERT_TRUE(type->isSigned());
}

TEST_F(IntTypeTests,
IsSignedReturnsFalseWhenTypeIsUnsigned) {
	auto type = getUnsignedIntType();
	ASSERT_FALSE(type->isSigned());
}

//
// isUnsigned()
//

TEST_F(IntTypeTests,
IsUnsignedReturnsTrueWhenTypeIsUnsigned) {
	auto type = getUnsignedIntType();
	ASSERT_TRUE(type->isUnsigned());
}

TEST_F(IntTypeTests,
IsUnsignedReturnsFalseWhenTypeIsSigned) {
	auto type = getSignedIntType();
	ASSERT_FALSE(type->isUnsigned());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
