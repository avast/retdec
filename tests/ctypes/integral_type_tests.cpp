/**
* @file tests/ctypes/integral_type_tests.cpp
* @brief Tests for the @c integral_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class IntegralTypeTests : public Test
{
	public:
		IntegralTypeTests():
			context(std::make_shared<Context>()) {}

	protected:
		std::shared_ptr<Context> context;
};

TEST_F(IntegralTypeTests,
EveryUniqueIntegralTypeIsCreatedOnlyOnce)
{
	const std::string name = "integralName";
	auto obj1 = IntegralType::create(context, name, 32);
	auto obj2 = IntegralType::create(context, name, 32);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(IntegralTypeTests,
TwoIntegralTypesWithDifferentNamesDiffer)
{
	auto obj1 = IntegralType::create(context, "name", 32);
	auto obj2 = IntegralType::create(context, "otherName", 32);

	EXPECT_NE(obj1, obj2);
}

TEST_F(IntegralTypeTests,
IsSignedReturnsTrueForSignedType)
{
	auto intType = IntegralType::create(context, "int", 32, IntegralType::Signess::Signed);

	EXPECT_TRUE(intType->isSigned());
}

TEST_F(IntegralTypeTests,
IsUnsignedReturnsTrueForUnsignedType)
{
	auto intType = IntegralType::create(context, "int", 32, IntegralType::Signess::Unsigned);

	EXPECT_TRUE(intType->isUnsigned());
}

TEST_F(IntegralTypeTests,
GetBitWidthReturnsCorrectValue)
{
	EXPECT_EQ(32, IntegralType::create(context, "name", 32)->getBitWidth());
}

TEST_F(IntegralTypeTests,
IsIntegralReturnsTrueOnIntegralType)
{
	EXPECT_TRUE(IntegralType::create(context, "int", 32)->isIntegral());
}

TEST_F(IntegralTypeTests,
IsIntegralReturnsFalseOnNonIntegralType)
{
	EXPECT_FALSE(VoidType::create()->isIntegral());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
