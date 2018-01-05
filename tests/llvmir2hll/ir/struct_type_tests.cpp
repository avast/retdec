/**
* @file tests/llvmir2hll/ir/struct_type_tests.cpp
* @brief Tests for the @c struct_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c struct_type module.
*/
class StructTypeTests: public Test {};

//
// hasName()
//

TEST_F(StructTypeTests,
hasNameAfterCreateWithNameReturnsTrue) {
	ShPtr<StructType> st(StructType::create(StructType::ElementTypes(), "MyStruct"));

	EXPECT_TRUE(st->hasName());
}

TEST_F(StructTypeTests,
hasNameAfterCreateWithNoNameReturnsFalse) {
	ShPtr<StructType> st(StructType::create(StructType::ElementTypes()));

	EXPECT_FALSE(st->hasName());
}

//
// getName()
//

TEST_F(StructTypeTests,
getNameAfterCreateWithNoElementsAndNoNameReturnsEmptyName) {
	ShPtr<StructType> st(StructType::create(StructType::ElementTypes()));

	EXPECT_TRUE(st->getName().empty());
}

TEST_F(StructTypeTests,
getNameAfterCreateWithNoElementsReturnsCorrectName) {
	const std::string refName("MyStruct");
	ShPtr<StructType> st(StructType::create(StructType::ElementTypes(), refName));

	EXPECT_EQ(refName, st->getName());
}

TEST_F(StructTypeTests,
getNameAfterCreateWithElementsReturnsCorrectName) {
	StructType::ElementTypes elementTypes;
	elementTypes.push_back(IntType::create(32));
	elementTypes.push_back(IntType::create(64));
	const std::string refName("MyStruct");
	ShPtr<StructType> st(StructType::create(elementTypes, refName));

	EXPECT_EQ(refName, st->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
