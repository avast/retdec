/**
* @file tests/llvmir2hll/ir/array_type_tests.cpp
* @brief Tests for the @c array_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for ArrayType.
*/
class ArrayTypeTests: public Test {};

//
// hasEmptyDimensions()
//

TEST_F(ArrayTypeTests,
HasEmptyDimensionsReturnsTrueWhenDimensionsAreEmpty) {
	auto type = ArrayType::create(IntType::create(32), {});

	ASSERT_TRUE(type->hasEmptyDimensions());
}

TEST_F(ArrayTypeTests,
HasEmptyDimensionsReturnsFalseWhenDimensionsAreNotEmpty) {
	auto type = ArrayType::create(IntType::create(32), {1, 2, 3});

	ASSERT_FALSE(type->hasEmptyDimensions());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
