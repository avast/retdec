/**
* @file tests/ctypes/typedefed_type_tests.cpp
* @brief Tests for the @c typedefed_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/void_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class TypedefedTypeTests : public Test
{
	public:
		TypedefedTypeTests():
			context(std::make_shared<Context>()) {}

	protected:
		std::shared_ptr<Context> context;
};

TEST_F(TypedefedTypeTests,
EveryUniqueTypedefedTypeIsCreatedOnlyOnce)
{
	const std::string name = "typedefedName";
	auto myInt = IntegralType::create(context, "int", 32);
	auto obj1 = TypedefedType::create(context, name, myInt);
	auto obj2 = TypedefedType::create(context, name, myInt);

	EXPECT_EQ(obj1, obj2);
}

TEST_F(TypedefedTypeTests,
TwoTypedefedTypesWithDifferentNamesDiffer)
{
	auto myInt = IntegralType::create(context, "int", 32);
	auto obj1 = TypedefedType::create(context, "name", myInt);
	auto obj2 = TypedefedType::create(context, "otherName", myInt);

	EXPECT_NE(obj1, obj2);
}

TEST_F(TypedefedTypeTests,
GetCorrectAliasedType)
{
	auto myInt = IntegralType::create(context, "int", 32);
	auto typedefed = TypedefedType::create(context, "myInt", myInt);

	EXPECT_EQ(myInt, typedefed->getAliasedType());
}

TEST_F(TypedefedTypeTests,
GetCorrectRealTypeWhenAliasedTypeIsNotTypedefedType)
{
	// typedef int myInt;
	auto myInt = IntegralType::create(context, "int", 32);
	auto typedefed = TypedefedType::create(context, "myInt", myInt);

	EXPECT_EQ(myInt, typedefed->getRealType());
}

TEST_F(TypedefedTypeTests,
GetCorrectRealTypeWhenAliasedTypeIsTypedefToTypedefToInt)
{
	// typedef int myInt;
	// typedef myInt secondLvl;
	// typedef secondLvl thirdLvl;
	auto myInt = IntegralType::create(context, "int", 32);
	auto tDef = TypedefedType::create(context, "myInt", myInt);
	auto tDefToTDef = TypedefedType::create(context, "secondLvl", tDef);
	auto tDefToTDefToTDef = TypedefedType::create(context, "thirdLvl", tDefToTDef);

	EXPECT_EQ(myInt, tDefToTDefToTDef->getRealType());
}

#if DEATH_TESTS_ENABLED
TEST_F(TypedefedTypeTests,
CreateTypedefedTypeCrashesOnNullptr)
{
	EXPECT_DEATH(
		TypedefedType::create(context, "typeName", nullptr),
		"violated precondition - aliasedType cannot be null"
	);
}
#endif

TEST_F(TypedefedTypeTests,
IsTypedefReturnsTrueOnTypedefedType)
{
	EXPECT_TRUE(TypedefedType::create(context, "VOID", VoidType::create())->isTypedef());
}

TEST_F(TypedefedTypeTests,
IsTypedefReturnsFalseOnNonTypedefedType)
{
	EXPECT_FALSE(VoidType::create()->isTypedef());
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
