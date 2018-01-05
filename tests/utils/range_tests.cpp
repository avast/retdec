/**
* @file tests/utils/range_tests.cpp
* @brief Tests for the @c address module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/address.h"
#include "retdec/utils/range.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
 * @brief Tests for the @c Range class.
 */
class RangeTests: public Test
{

};

TEST_F(RangeTests, DefaultCtorCallsDefaultCtorsOnMembers)
{
	Range<Address> r;

	EXPECT_TRUE(r.getStart().isUndefined());
	EXPECT_TRUE(r.getEnd().isUndefined());
}

TEST_F(RangeTests, CtorInitializesMembers)
{
	Range<int> r(10, 20);

	EXPECT_EQ(10, r.getStart());
	EXPECT_EQ(20, r.getEnd());
}

TEST_F(RangeTests, CopyCtorCopies)
{
	Range<int> r(10, 20);
	Range<int> copy(r);

	EXPECT_EQ(10, copy.getStart());
	EXPECT_EQ(20, copy.getEnd());
}

TEST_F(RangeTests, MoveCtorMoves)
{
	Range<int> r(10, 20);
	Range<int> copy = std::move(r);

	EXPECT_EQ(10, copy.getStart());
	EXPECT_EQ(20, copy.getEnd());
}

TEST_F(RangeTests, AssignOperatorAssigns)
{
	Range<int> r(10, 20);
	Range<int> copy = r;

	EXPECT_EQ(10, copy.getStart());
	EXPECT_EQ(20, copy.getEnd());
}

TEST_F(RangeTests, getStartCheck)
{
	Range<int> r(10, 20);

	EXPECT_EQ(10, r.getStart());
}

TEST_F(RangeTests, getEndCheck)
{
	Range<int> r(10, 20);

	EXPECT_EQ(20, r.getEnd());
}

TEST_F(RangeTests, setStartCheck)
{
	Range<int> r(10, 20);
	r.setStart(15);

	EXPECT_EQ(15, r.getStart());
}

TEST_F(RangeTests, setEndCheck)
{
	Range<int> r(10, 20);
	r.setEnd(25);

	EXPECT_EQ(25, r.getEnd());
}

TEST_F(RangeTests, getSizeCheck)
{
	Range<int> r(10, 20);

	EXPECT_EQ(11, r.getSize());
}

TEST_F(RangeTests, containsValueCheck)
{
	Range<int> r(10, 15);

	EXPECT_FALSE(r.contains(-15));
	EXPECT_FALSE(r.contains(0));
	EXPECT_FALSE(r.contains(5));
	EXPECT_FALSE(r.contains(9));
	EXPECT_TRUE(r.contains(10));
	EXPECT_TRUE(r.contains(11));
	EXPECT_TRUE(r.contains(12));
	EXPECT_TRUE(r.contains(13));
	EXPECT_TRUE(r.contains(14));
	EXPECT_TRUE(r.contains(15));
	EXPECT_FALSE(r.contains(16));
	EXPECT_FALSE(r.contains(20));
}

TEST_F(RangeTests, containsRangeCheck)
{
	Range<int> r(10, 20);

	EXPECT_TRUE(r.contains(Range<int>(10, 10)));
	EXPECT_TRUE(r.contains(Range<int>(10, 15)));
	EXPECT_TRUE(r.contains(Range<int>(10, 20)));
	EXPECT_TRUE(r.contains(Range<int>(12, 18)));
	EXPECT_TRUE(r.contains(Range<int>(19, 20)));
	EXPECT_TRUE(r.contains(Range<int>(20, 20)));

	EXPECT_FALSE(r.contains(Range<int>(0, 9)));
	EXPECT_FALSE(r.contains(Range<int>(5, 10)));
	EXPECT_FALSE(r.contains(Range<int>(9, 15)));
	EXPECT_FALSE(r.contains(Range<int>(15, 21)));
	EXPECT_FALSE(r.contains(Range<int>(18, 25)));
	EXPECT_FALSE(r.contains(Range<int>(20, 21)));
	EXPECT_FALSE(r.contains(Range<int>(25, 50)));
}

TEST_F(RangeTests, operatorEqNeq)
{
	Range<int> r1(10, 20);
	Range<int> r2(10, 15);
	Range<int> r3(20, 25);
	Range<int> r4(0, 5);

	EXPECT_TRUE(r1 == r1);
	EXPECT_FALSE(r1 != r1);
}

} // namespace tests
} // namespace utils
} // namespace retdec
