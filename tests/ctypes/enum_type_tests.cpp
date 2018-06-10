/**
* @file tests/ctypes/enum_type_tests.cpp
* @brief Tests for the @c enum_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/integral_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class EnumTypeTests : public Test
{
	public:
		EnumTypeTests():
			context(std::make_shared<Context>()),
			oneValue42{EnumType::Value("firstValueName", 42)} {}

	protected:
		std::shared_ptr<Context> context;
		EnumType::Values emptyValues;
		EnumType::Values oneValue42;
};

TEST_F(EnumTypeTests,
EveryUniqueEnumTypeIsCreatedOnlyOnce)
{
	const std::string name = "enumName";
	auto obj1 = EnumType::create(context, name, emptyValues);
	auto obj2 = EnumType::create(context, name, emptyValues);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(EnumTypeTests,
TwoEnumTypesWithDifferentNamesDiffer)
{
	auto obj1 = EnumType::create(context, "name", emptyValues);
	auto obj2 = EnumType::create(context, "otherName", emptyValues);

	EXPECT_NE(obj1, obj2);
}

TEST_F(EnumTypeTests,
GetCorrectValuesCountForEmptyValues)
{
	auto newE = EnumType::create(context, "newE", emptyValues);

	EXPECT_EQ(0, newE->getValueCount());
}

#if DEATH_TESTS_ENABLED
TEST_F(EnumTypeTests,
GetValueAtIndexOutOfRangeCrashes)
{
	auto newE = EnumType::create(context, "newE", emptyValues);

	EXPECT_DEATH(
		newE->getValue(2),
		"n is out of bounds"
	);
}
#endif

TEST_F(EnumTypeTests,
EnumTypeWithoutValuesDoesNotHaveValues)
{
	auto newE = EnumType::create(context, "newE", emptyValues);

	EXPECT_EQ(newE->value_begin(), newE->value_end());
}

TEST_F(EnumTypeTests,
BeginIteratorPointsToTheFirstValue)
{
	auto newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(newE->getValue(1), *(newE->value_begin()));
}

TEST_F(EnumTypeTests,
ConstBeginIteratorPointsToTheFirstValue)
{
	std::shared_ptr<const EnumType> newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(newE->getValue(1), *(newE->value_begin()));
}

TEST_F(EnumTypeTests,
EndIteratorPointsPastLastValue)
{
	auto newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(newE->getValue(1), *(--newE->value_end()));
}

TEST_F(EnumTypeTests,
ConstEndIteratorPointsPastLastValue)
{
	std::shared_ptr<const EnumType> newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(newE->getValue(1), *(--newE->value_end()));
}

TEST_F(EnumTypeTests,
GetNthValueReturnsCorrectValue)
{
	auto newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(oneValue42[0], newE->getValue(1));
}

TEST_F(EnumTypeTests,
GetNthValueNameReturnsCorrectName)
{
	auto newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ("firstValueName", newE->getValue(1).getName());
}

TEST_F(EnumTypeTests,
GetNthValueTypeReturnsCorrectType)
{
	auto newE = EnumType::create(context, "newE", oneValue42);

	EXPECT_EQ(42, newE->getValue(1).getValue());
}

TEST_F(EnumTypeTests,
TwoEnumValuesAreEqualWhenNameAndValueIsEqual)
{
	EnumType::Value value1("value", 1);
	EnumType::Value value2("value", 1);

	EXPECT_EQ(value1, value2);
}

TEST_F(EnumTypeTests,
TwoEnumValuesAreNotEqualWhenNamesDiffer)
{
	EnumType::Value value1("value1", 1);
	EnumType::Value value2("value2", 1);

	EXPECT_NE(value1, value2);
}

TEST_F(EnumTypeTests,
TwoEnumValuesAreNotEqualWhenValuesDiffer)
{
	EnumType::Value value1("value", 0);
	EnumType::Value value2("value", 10);

	EXPECT_NE(value1, value2);
}

TEST_F(EnumTypeTests,
IsEnumReturnsTrueOnEnumType)
{
	EXPECT_TRUE(EnumType::create(context, "e", oneValue42)->isEnum());
}

TEST_F(EnumTypeTests,
IsEnumReturnsFalseOnNonEnumType)
{
	EXPECT_FALSE(IntegralType::create(context, "int", 32)->isEnum());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
