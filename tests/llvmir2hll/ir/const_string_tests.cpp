/**
* @file tests/llvmir2hll/ir/const_string_tests.cpp
* @brief Tests for the @c const_string module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/string_type.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_string module.
*/
class ConstStringTests: public Test {};

//
// create(), getValue(), getCharSize()
//

TEST_F(ConstStringTests,
CreateCanBeCalledWithValueAndCharSize) {
	const ConstString::UnderlyingStringType VALUE({'t', 'e', 's', 't'});
	const std::size_t CHAR_SIZE = 16;

	auto constant = ConstString::create(VALUE, CHAR_SIZE);

	ASSERT_EQ(VALUE, constant->getValue());
	ASSERT_EQ(CHAR_SIZE, constant->getCharSize());
}

TEST_F(ConstStringTests,
CreateCanBeCalledWith8BitString) {
	auto constant = ConstString::create("test");

	ConstString::UnderlyingStringType expectedValue({'t', 'e', 's', 't'});
	ASSERT_EQ(expectedValue, constant->getValue());
	ASSERT_EQ(8, constant->getCharSize());
}

TEST_F(ConstStringTests,
CreateCanBeCalledWithCharSizesThatAreMultipleOf8UpTo32) {
	ASSERT_EQ(8, ConstString::create({'t', 'e', 's', 't'}, 8)->getCharSize());
	ASSERT_EQ(16, ConstString::create({'t', 'e', 's', 't'}, 16)->getCharSize());
	ASSERT_EQ(32, ConstString::create({'t', 'e', 's', 't'}, 32)->getCharSize());
}

#if DEATH_TESTS_ENABLED
TEST_F(ConstStringTests,
CreateFailsWithViolatedPreconditionWhenSizeIsZero) {
	ASSERT_DEATH(ConstString::create("test", 0), ".*create.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(ConstStringTests,
CreateFailsWithViolatedPreconditionWhenSizeIsNotMultipleOf8) {
	ASSERT_DEATH(ConstString::create("test", 13), ".*create.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(ConstStringTests,
CreateFailsWithViolatedPreconditionWhenSizeIsMoreThen32) {
	ASSERT_DEATH(ConstString::create("test", 64), ".*create.*Precondition.*failed.*");
}
#endif

//
// getValueAsEscapedCString()
//

TEST_F(ConstStringTests,
GetValueAsEscapedCStringReturnsCorrectlyEscapedStringForBinaryWideStringWith16BitCharSize) {
	ASSERT_EQ(
		"\\x0001\\x0002\\x0003\\x0004\\xffff",
		ConstString::create({1, 2, 3, 4, std::numeric_limits<std::uint16_t>::max()}, 16)->getValueAsEscapedCString()
	);
}

//
// is8BitString()
//

TEST_F(ConstStringTests,
Is8BitStringReturnsTrueWhenStringIs8Bit) {
	auto constant = ConstString::create("test");

	ASSERT_TRUE(constant->is8BitString());
}

TEST_F(ConstStringTests,
Is8BitStringReturnsFalseWhenStringIsWide) {
	auto constant = ConstString::create({'t', 'e', 's', 't'}, 16);

	ASSERT_FALSE(constant->is8BitString());
}

//
// isWideString()
//

TEST_F(ConstStringTests,
IsWideStringReturnsTrueWhenStringIsWide) {
	auto constant = ConstString::create({'t', 'e', 's', 't'}, 16);

	ASSERT_TRUE(constant->isWideString());
}

TEST_F(ConstStringTests,
IsWideStringReturnsFalseWhenStringIs8Bit) {
	auto constant = ConstString::create("test");

	ASSERT_FALSE(constant->isWideString());
}

//
// getType()
//

TEST_F(ConstStringTests,
GetTypeReturnsCorrectTypeWhenInitializedWithWideString) {
	const std::size_t CHAR_SIZE = 16;

	auto constant = ConstString::create({'t', 'e', 's', 't'}, CHAR_SIZE);
	auto type = cast<StringType>(constant->getType());

	ASSERT_TRUE(type);
	ASSERT_EQ(CHAR_SIZE, type->getCharSize());
}

TEST_F(ConstStringTests,
GetTypeReturnsCorrectTypeWhenInitializedWith8BitString) {
	auto constant = ConstString::create("test");
	auto type = cast<StringType>(constant->getType());

	ASSERT_TRUE(type);
	ASSERT_EQ(8, type->getCharSize());
}

//
// clone()
//

TEST_F(ConstStringTests,
CloneReturnsConstStringWithSameValueAndSizeAndMetadata) {
	auto constant = ConstString::create("test");
	constant->setMetadata("test");
	auto clone = cast<ConstString>(constant->clone());

	ASSERT_TRUE(clone);
	ASSERT_EQ(constant->getValue(), clone->getValue());
	ASSERT_EQ(constant->getCharSize(), clone->getCharSize());
	ASSERT_EQ(constant->getMetadata(), clone->getMetadata());
}

//
// isEqualTo()
//

TEST_F(ConstStringTests,
IsEqualToReturnsTrueWhenConstantsHaveSameValueAndCharSize) {
	auto constant1 = ConstString::create("test");
	auto constant2 = ConstString::create("test");

	ASSERT_TRUE(constant1->isEqualTo(constant2));
}

TEST_F(ConstStringTests,
IsEqualToReturnsFalseWhenConstantsHaveDifferentValues) {
	auto constant1 = ConstString::create("test");
	auto constant2 = ConstString::create("hello world");

	ASSERT_FALSE(constant1->isEqualTo(constant2));
}

TEST_F(ConstStringTests,
IsEqualToReturnsFalseWhenConstantsHaveDifferentCharSizes) {
	auto constant1 = ConstString::create({'t', 'e', 's', 't'}, 16);
	auto constant2 = ConstString::create({'t', 'e', 's', 't'}, 32);

	ASSERT_FALSE(constant1->isEqualTo(constant2));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
