/**
* @file tests/ctypes/pointer_type.cpp
* @brief Tests for the @c pointer_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <memory>

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/pointer_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class PointerTypeTests : public Test
{
	public:
		PointerTypeTests():
			context(std::make_shared<Context>()),
			intType(IntegralType::create(context, "int", 32)),
			charType(IntegralType::create(context, "char", 8)) {}

	protected:
		std::shared_ptr<Context> context;
		std::shared_ptr<IntegralType> intType;
		std::shared_ptr<IntegralType> charType;
};

#if DEATH_TESTS_ENABLED
TEST_F(PointerTypeTests,
CreatePointerTypeCrashesOnNullptr)
{
	EXPECT_DEATH(
		PointerType::create(context, nullptr),
		"violated precondition - pointedType cannot be null"
	);
}
#endif

TEST_F(PointerTypeTests,
EveryUniquePointerTypeIsCreatedOnlyOnce)
{
	auto obj1 = PointerType::create(context, intType);
	auto obj2 = PointerType::create(context, intType);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(PointerTypeTests,
TwoPointerTypesWithDifferentPointedTypesDiffer)
{
	auto obj1 = PointerType::create(context, intType);
	auto obj2 = PointerType::create(context, charType);

	EXPECT_NE(obj1, obj2);
}

TEST_F(PointerTypeTests,
GetPointedTypeReturnsCorrectType)
{
	auto ptr = PointerType::create(context, intType);

	EXPECT_EQ(intType, ptr->getPointedType());
}

TEST_F(PointerTypeTests,
IsPointerReturnsTrueOnPointerType)
{
	EXPECT_TRUE(PointerType::create(context, intType)->isPointer());
}

TEST_F(PointerTypeTests,
IsPointerReturnsFalseOnNonPointerType)
{
	EXPECT_FALSE(intType->isPointer());
}

TEST_F(PointerTypeTests,
CreateSetsBitWidthCorrectly)
{
	auto ptr = PointerType::create(context, intType, 33);

	EXPECT_EQ(33, ptr->getBitWidth());
}

TEST_F(PointerTypeTests,
DefaultBitWidthIsZero)
{
	auto ptr = PointerType::create(context, intType);

	EXPECT_EQ(0, ptr->getBitWidth());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
