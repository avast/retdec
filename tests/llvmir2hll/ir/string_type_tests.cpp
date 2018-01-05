/**
* @file tests/llvmir2hll/ir/string_type_tests.cpp
* @brief Tests for the @c string_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/support/debug.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c string_type module.
*/
class StringTypeTests: public Test {};

//
// create()
//

TEST_F(StringTypeTests,
CreateReturnsSameInstancesForSameSizes) {
	auto type1 = StringType::create(16);
	auto type2 = StringType::create(16);

	ASSERT_EQ(type1, type2);
}

#if DEATH_TESTS_ENABLED
TEST_F(StringTypeTests,
CreateFailsWithViolatedPreconditionWhenSizeIsZero) {
	ASSERT_DEATH(StringType::create(0), ".*create.*Precondition.*failed.*");
}
#endif

//
// clone()
//

TEST_F(StringTypeTests,
CloneReturnsStringWithSameCharSize) {
	auto origType = StringType::create(16);

	auto clonedType = cast<StringType>(origType->clone());

	ASSERT_TRUE(clonedType);
	ASSERT_EQ(origType->getCharSize(), clonedType->getCharSize());
}

//
// isEqualTo()
//

TEST_F(StringTypeTests,
IsEqualToReturnsTrueWhenBothInstancesHaveSameSize) {
	auto type1 = StringType::create(16);
	auto type2 = StringType::create(16);

	ASSERT_TRUE(type1->isEqualTo(type2));
}

TEST_F(StringTypeTests,
IsEqualToReturnsFalseWhenBothInstancesHaveDifferentSize) {
	auto type1 = StringType::create(16);
	auto type2 = StringType::create(32);

	ASSERT_FALSE(type1->isEqualTo(type2));
}

//
// getCharSize()
//

TEST_F(StringTypeTests,
GetCharSizeReturnsCorrectValue) {
	auto type = StringType::create(16);

	ASSERT_EQ(16, type->getCharSize());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
