/**
* @file tests/llvmir2hll/ir/const_array_tests.cpp
* @brief Tests for the @c const_array module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for ConstArray.
*/
class ConstArrayTests: public Test {};

//
// isInitialized()
//

TEST_F(ConstArrayTests,
IsInitializedReturnsTrueWhenArrayIsInitialized) {
	auto type = ConstArray::create(
		ConstArray::ArrayValue{ConstInt::create(1, 32)},
		ArrayType::create(IntType::create(32), {1})
	);

	ASSERT_TRUE(type->isInitialized());
}

TEST_F(ConstArrayTests,
IsInitializedReturnsFalseWhenArrayIsUninitialized) {
	auto type = ConstArray::createUninitialized(
		ArrayType::create(IntType::create(32), {1})
	);

	ASSERT_FALSE(type->isInitialized());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
