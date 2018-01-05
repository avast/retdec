/**
* @file tests/tl-cpputils/const_tests.cpp
* @brief Tests for the @c const module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>

#include <gtest/gtest.h>

#include "tl-cpputils/const.h"

using namespace ::testing;

namespace tl_cpputils {
namespace tests {

/**
* @brief Tests for the @c const module.
*/
class ConstTests: public Test {};

//
// likeConstVersion()
//

TEST_F(ConstTests,
LikeConstVersionWorksCorrectly) {
	class Array {
	public:
		// A user-provided constructor is needed for the creation of 'const
		// Array' below.
		Array() {}

		// const version
		const int *getElement(std::size_t i) const {
			return &array[i];
		}

		// non-const version
		int *getElement(std::size_t i) {
			return likeConstVersion(this, &Array::getElement, i);
		}

	private:
		int array[100] = {1};
	};

	Array array;
	ASSERT_EQ(1, *array.getElement(0));

	const Array constArray;
	ASSERT_EQ(1, *constArray.getElement(0));
}

} // namespace tests
} // namespace tl_cpputils
