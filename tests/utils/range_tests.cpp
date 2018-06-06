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

	EXPECT_EQ(10, r.getSize());
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
	EXPECT_FALSE(r.contains(15));
	EXPECT_FALSE(r.contains(16));
	EXPECT_FALSE(r.contains(20));
}

TEST_F(RangeTests, containsRangeCheck)
{
	Range<int> r(10, 20);

	EXPECT_TRUE(r.contains(Range<int>(10, 11)));
	EXPECT_TRUE(r.contains(Range<int>(10, 15)));
	EXPECT_TRUE(r.contains(Range<int>(10, 20)));
	EXPECT_TRUE(r.contains(Range<int>(12, 18)));
	EXPECT_TRUE(r.contains(Range<int>(19, 20)));

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

	EXPECT_TRUE(r1 == r1);
	EXPECT_FALSE(r1 != r1);

	EXPECT_FALSE(r1 == r2);
	EXPECT_TRUE(r1 != r2);
}

TEST_F(RangeTests, overlaps)
{
	Range<int> r(10, 20);

	Range<int> fullyBefore(0, 5);
	Range<int> partlyBefore(0, 15);
	Range<int> fullyInside(12, 18);
	Range<int> fullyInsideSmall1(10, 11);
	Range<int> fullyInsideSmall2(15, 16);
	Range<int> fullyInsideSmall3(19, 20);
	Range<int> partyAfter(15, 30);
	Range<int> fullyAfter(25, 30);
	Range<int> bedoreAndAfter(0, 30);

	EXPECT_FALSE(r.overlaps(fullyBefore));
	EXPECT_TRUE(r.overlaps(partlyBefore));
	EXPECT_TRUE(r.overlaps(fullyInside));
	EXPECT_TRUE(r.overlaps(fullyInsideSmall1));
	EXPECT_TRUE(r.overlaps(fullyInsideSmall2));
	EXPECT_TRUE(r.overlaps(fullyInsideSmall3));
	EXPECT_TRUE(r.overlaps(partyAfter));
	EXPECT_FALSE(r.overlaps(fullyAfter));
	EXPECT_TRUE(r.overlaps(bedoreAndAfter));
	EXPECT_TRUE(r.overlaps(r));
}

/**
 * @brief Tests for the @c RangeContainer class.
 */
class RangeContainerTests: public Test
{

};

TEST_F(RangeContainerTests, NewContainerIsEmpty)
{
	RangeContainer<int> c;

	EXPECT_TRUE(c.empty());
	EXPECT_EQ(0, c.size());
}

TEST_F(RangeContainerTests, InsertRangeNonOverlapping)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(10, 20));
	c.addRange(Range<int>(30, 40));
	c.addRange(Range<int>(50, 60));

	EXPECT_FALSE(c.empty());
	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(10, 20), c[0]);
	EXPECT_EQ(Range<int>(30, 40), c[1]);
	EXPECT_EQ(Range<int>(50, 60), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeFullyInOldRange)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x10, 0x40));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x20, 0x30));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x10, 0x40), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeFullyInNewRangeOne)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x10, 0x40));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x10, 0x60));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x10, 0x60), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeMergeWithStart)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x10, 0x40));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x20, 0x60));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x10, 0x60), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeMergeWithEnd)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x20, 0x40));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x10, 0x30));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x10, 0x40), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeMergeMultiple)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x7, 0x20));
	c.addRange(Range<int>(0x30, 0x40));
	c.addRange(Range<int>(0x60, 0x70));
	c.addRange(Range<int>(0x80, 0x95));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x10, 0x90));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x7, 0x95), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeMergeMultipleInside)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x0, 0x5)); // should not be affected
	c.addRange(Range<int>(0x15, 0x20));
	c.addRange(Range<int>(0x30, 0x40));
	c.addRange(Range<int>(0x60, 0x70));
	c.addRange(Range<int>(0x80, 0x85));
	c.addRange(Range<int>(0x100, 0x500)); // should not be affected

	c.addRange(Range<int>(0x10, 0x90));

	EXPECT_EQ(3, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x5), c[0]);
	EXPECT_EQ(Range<int>(0x10, 0x90), c[1]);
	EXPECT_EQ(Range<int>(0x100, 0x500), c[2]);
}

TEST_F(RangeContainerTests, InsertRangeMergeBordering)
{
	RangeContainer<int> c;
	c.addRange(Range<int>(0x6, 0x16));
	c.addRange(Range<int>(0x0, 0x6));
	c.addRange(Range<int>(0x16, 0x100));

	EXPECT_EQ(1, c.size());
	EXPECT_EQ(Range<int>(0x0, 0x100), c[0]);
}

} // namespace tests
} // namespace utils
} // namespace retdec
