/**
* @file tests/ctypes/array_type_tests.cpp
* @brief Tests for the @c array_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class ArrayTypeTests : public Test
{
	public:
		ArrayTypeTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			charType(IntegralType::create(context, "char", 8)),
			oneDimension(1, 10) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<IntegralType> intType;
		std::shared_ptr<IntegralType> charType;
		ArrayType::Dimensions oneDimension;
};

#if DEATH_TESTS_ENABLED
TEST_F(ArrayTypeTests,
CreateArrayTypeCrashesOnNullptr)
{
	EXPECT_DEATH(
		ArrayType::create(context, nullptr, oneDimension),
		"violated precondition - elementType cannot be null"
	);
}
#endif

TEST_F(ArrayTypeTests,
EveryUniqueArrayTypeIsCreatedOnlyOnce)
{
	auto arr1 = ArrayType::create(context, intType, oneDimension);
	auto arr2 = ArrayType::create(context, intType, oneDimension);

	EXPECT_EQ(arr1, arr2);
}

TEST_F(ArrayTypeTests,
TwoArrayTypesWithDifferentElementTypesDiffer)
{
	auto arr1 = ArrayType::create(context, intType, oneDimension);
	auto arr2 = ArrayType::create(context, charType, oneDimension);

	EXPECT_NE(arr1, arr2);
}

TEST_F(ArrayTypeTests,
TwoArrayTypesWithDifferentDimensionsDiffer)
{
	auto arr1 = ArrayType::create(context, intType, oneDimension);
	auto arr2 = ArrayType::create(context, charType, {10, 10});

	EXPECT_NE(arr1, arr2);
}

TEST_F(ArrayTypeTests,
GetElementTypeReturnsCorrectType)
{
	auto arr = ArrayType::create(context, intType, oneDimension);

	EXPECT_EQ(intType, arr->getElementType());
}

TEST_F(ArrayTypeTests,
getDimensionsReturnsCorrectDimensions)
{
	auto arr = ArrayType::create(context, intType, oneDimension);

	EXPECT_EQ(oneDimension, arr->getDimensions());
}

TEST_F(ArrayTypeTests,
getDimensionCountReturnsCorrectValue)
{
	auto arr = ArrayType::create(context, intType, oneDimension);

	EXPECT_EQ(1, arr->getDimensionCount());
}

TEST_F(ArrayTypeTests,
IsArrayReturnsTrueOnArrayType)
{
	EXPECT_TRUE(ArrayType::create(context, intType, oneDimension)->isArray());
}

TEST_F(ArrayTypeTests,
IsArrayReturnsFalseOnNonArrayType)
{
	EXPECT_FALSE(intType->isArray());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
