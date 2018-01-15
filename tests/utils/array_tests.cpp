/**
* @file tests/utils/array_tests.cpp
* @brief Tests for the @c array module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/array.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c array module.
*/
class ArrayTests: public Test {};

//
// arraySize()
//

TEST_F(ArrayTests,
ArraySizeReturnsCorrectSize) {
	const std::size_t SIZE = 10;
	int array[SIZE];

	ASSERT_EQ(SIZE, arraySize(array));
}

} // namespace tests
} // namespace utils
} // namespace retdec
