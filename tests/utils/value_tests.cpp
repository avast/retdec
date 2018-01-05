/**
* @file tests/utils/value_tests.cpp
* @brief Tests for the @c value module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include <gtest/gtest.h>

#include "retdec/utils/value.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
 * @brief Tests for the @c Maybe class.
 */
class MaybeTests: public Test {};

TEST_F(MaybeTests, UninitializedMaybeIsUndefined)
{
	Maybe<int> v;
	EXPECT_TRUE(v.isUndefined());
	EXPECT_FALSE(v.isDefined());
}

TEST_F(MaybeTests, InitializedMaybeIsDefined)
{
	Maybe<int> v(1234);
	EXPECT_FALSE(v.isUndefined());
	EXPECT_TRUE(v.isDefined());
}

TEST_F(MaybeTests, AssignmentWorks)
{
	int val = 1234;
	Maybe<int> v;
	v = val;
	EXPECT_FALSE(v.isUndefined());
	EXPECT_TRUE(v.isDefined());
	EXPECT_EQ(val, v);
}

TEST_F(MaybeTests, GetValueWorks)
{
	int val = 1234;
	Maybe<int> v(val);
	EXPECT_EQ(val, v);
	EXPECT_EQ(val, v.getValue());
	EXPECT_EQ(v, v.getValue());
}

#if DEATH_TESTS_ENABLED
TEST_F(MaybeTests, GetValueThrowsAssertIfMaybeNotDefined)
{
	Maybe<int> v;
	ASSERT_DEATH(v.getValue(), "");
}
#endif

TEST_F(MaybeTests, BasicTransparentUsageOfMaybeValue)
{
	int val = 1234;
	Maybe<int> v;

	v = val;
	v = v + 10;;
	EXPECT_EQ(val + 10, v);

	v = val;
	v = v - 10;
	EXPECT_EQ(val - 10, v);

	v = val;
	v = v * 10;
	EXPECT_EQ(val * 10, v);

	v = val;
	int tmp = v + 10;
	EXPECT_EQ(val + 10, tmp);
}

#if DEATH_TESTS_ENABLED
TEST_F(MaybeTests, ThrowsAssertIfUndefinedMaybeIsUsed)
{
	Maybe<int> v;
	ASSERT_DEATH(v = v + 10, "");
}
#endif

TEST_F(MaybeTests, DefinedMaybeCanBePrinted)
{
	Maybe<int> v(1234);
	std::stringstream ss;
	ss << v;
	EXPECT_EQ("1234", ss.str());
}

TEST_F(MaybeTests, UndefinedMaybeCanBePrinted)
{
	Maybe<int> v;
	std::stringstream ss;
	ss << v;
	EXPECT_EQ("UNDEFINED", ss.str());
}

TEST_F(MaybeTests, UndefinedMaybesAreEqual)
{
	Maybe<int> v1;
	Maybe<int> v2;

	EXPECT_TRUE(v1 == v2);
	EXPECT_FALSE(v1 != v2);
}

TEST_F(MaybeTests, DefinedMaybeIsNotEqualToUndefinedMaybe)
{
	Maybe<int> v1(1234);
	Maybe<int> v2;

	EXPECT_TRUE(v1 != v2);
	EXPECT_FALSE(v1 == v2);
}

TEST_F(MaybeTests, DefinedMaybesWithDifferentValuesAreNotEqual)
{
	Maybe<int> v1(1234);
	Maybe<int> v2(4321);

	EXPECT_TRUE(v1 != v2);
	EXPECT_FALSE(v1 == v2);
}

TEST_F(MaybeTests, DefinedMaybesWithTheSameValuesAreEqual)
{
	Maybe<int> v1(1234);
	Maybe<int> v2(1234);

	EXPECT_TRUE(v1 == v2);
	EXPECT_FALSE(v1 != v2);
}

TEST_F(MaybeTests, DefinedMaybesSetToUndefined)
{
	Maybe<int> v(1234);
	ASSERT_TRUE(v.isDefined());
	v.setUndefined();

	EXPECT_FALSE(v.isDefined());
}

} // namespace tests
} // namespace utils
} // namespace retdec
