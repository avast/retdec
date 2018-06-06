/**
* @file tests/utils/address_tests.cpp
* @brief Tests for the @c address module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/address.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
 * @brief Tests for the @c Address class.
 */
class AddressTests: public Test
{

};

TEST_F(AddressTests, UninitializedAddressIsUndefined)
{
	Address a;
	EXPECT_TRUE(a.isUndefined());
	EXPECT_FALSE(a.isDefined());
}

TEST_F(AddressTests, InitializedAddressIsDefined)
{
	Address a(1234);
	EXPECT_FALSE(a.isUndefined());
	EXPECT_TRUE(a.isDefined());
}

TEST_F(AddressTests, stringCtorPrefixHexa)
{
	Address a("0x1234");
	EXPECT_FALSE(a.isUndefined());
	EXPECT_TRUE(a.isDefined());
	EXPECT_EQ(0x1234, a.getValue());
}

TEST_F(AddressTests, stringCtorNoPrefixDecimal)
{
	Address a("1234");
	EXPECT_FALSE(a.isUndefined());
	EXPECT_TRUE(a.isDefined());
	EXPECT_EQ(1234, a.getValue());
}

TEST_F(AddressTests, stringCtorBadIsUndefined1)
{
	Address a("");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, stringCtorBadIsUndefined2)
{
	Address a("0x");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, stringCtorBadIsUndefined3)
{
	Address a("jak55");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, stringCtorBadIsUndefined4)
{
	Address a("55jak");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, stringCtorBadIsUndefined5)
{
	Address a("0xjak55");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, stringCtorBadIsUndefined6)
{
	Address a("0x55 jak");
	EXPECT_TRUE(a.isUndefined());
}

TEST_F(AddressTests, AssignmentWorks)
{
	unsigned val = 1234;
	Address a = val;
	EXPECT_FALSE(a.isUndefined());
	EXPECT_TRUE(a.isDefined());
	EXPECT_TRUE(a == val);
}

TEST_F(AddressTests, IncrementationWorks)
{
	unsigned val = 1234;
	Address a(val);
	a++;
	val++;
	EXPECT_TRUE(a == val);
	++a;
	++val;
	EXPECT_TRUE(a == val);
}

TEST_F(AddressTests, DecrementationWorks)
{
	unsigned val = 1234;
	Address a(val);
	a--;
	val--;
	EXPECT_TRUE(a == val);
	--a;
	--val;
	EXPECT_TRUE(a == val);
}

TEST_F(AddressTests, toHexString)
{
	EXPECT_EQ("12ab", Address(0x12ab).toHexString());
}

TEST_F(AddressTests, toHexPrefixString)
{
	EXPECT_EQ("0x12ab", Address(0x12ab).toHexPrefixString());
}

/**
 * @brief Tests for the @c AddressRange class.
 */
class AddressRangeTests: public Test
{

};

TEST_F(AddressRangeTests, DefaultCtorUndefValues)
{
	AddressRange r;

	EXPECT_TRUE(r.getStart().isUndefined());
	EXPECT_TRUE(r.getEnd().isUndefined());
}

TEST_F(AddressRangeTests, CtorOnlyFirstValue)
{
	AddressRange r(10);

	EXPECT_EQ(10, r.getStart());
	EXPECT_TRUE(r.getEnd().isUndefined());
}

TEST_F(AddressRangeTests, CtorBothValues)
{
	AddressRange r(10, 20);

	EXPECT_EQ(10, r.getStart());
	EXPECT_EQ(20, r.getEnd());
}

TEST_F(AddressRangeTests, CtorFromString)
{
	AddressRange r("0x1234-0x5678");

	EXPECT_EQ(0x1234, r.getStart());
	EXPECT_EQ(0x5678, r.getEnd());
}

TEST_F(AddressRangeTests, ComparisonWorks)
{
	AddressRange p1(10, 20);
	AddressRange p2(10, 20);
	AddressRange p3(10, 30);
	AddressRange p4(50, 100);
	AddressRange p5(100, 200);

	EXPECT_TRUE(p1 == p2);
	EXPECT_FALSE(p1 != p2);
	EXPECT_TRUE(p1 != p3);
	EXPECT_TRUE(p2 != p3);

	EXPECT_TRUE(p1 != p4);
	EXPECT_FALSE(p1 == p4);

	EXPECT_TRUE(p1 < p4);
	EXPECT_TRUE(p4 < p5);
	EXPECT_TRUE(p1 < p5);
}

TEST_F(AddressRangeTests, ContainsWorks)
{
	unsigned start = 10;
	unsigned end = 100;
	AddressRange p(start, end);

	EXPECT_FALSE( p.contains( start-1 ) );
	EXPECT_TRUE( p.contains( start ) );
	EXPECT_TRUE( p.contains( (start+end)/2 ) );
	EXPECT_TRUE( p.contains( end-1 ) );
	EXPECT_FALSE( p.contains( end ) );
	EXPECT_FALSE( p.contains( end+1 ) );
}

/**
 * @brief Tests for the @c AddressRangeContainer class.
 */
class AddressRangeContainerTests: public Test
{

};

TEST_F(AddressRangeContainerTests, NewContainerIsEmpty)
{
	AddressRangeContainer c;

	EXPECT_TRUE(c.empty()) << c;
	EXPECT_EQ(0, c.size()) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeNonOverlapping)
{
	AddressRangeContainer c;
	auto r1 = c.insert(AddressRange(10, 20));
	auto r2 = c.insert(AddressRange(30, 40));
	auto r3 = c.insert(AddressRange(50, 60));

	EXPECT_FALSE(c.empty()) << c;
	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r1.second) << c;
	EXPECT_EQ(AddressRange(10, 20), *r1.first) << c;
	EXPECT_TRUE(r2.second) << c;
	EXPECT_EQ(AddressRange(30, 40), *r2.first) << c;
	EXPECT_TRUE(r3.second) << c;
	EXPECT_EQ(AddressRange(50, 60), *r3.first) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeFullyInOldRange)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x20, 0x30);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_FALSE(r.second) << c;
	EXPECT_EQ(AddressRange(0x10, 0x40), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeFullyInNewRangeOne)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x20, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x10, 0x60);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r.second) << c;
	EXPECT_EQ(AddressRange(0x10, 0x60), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeMergeWithStart)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x20, 0x60);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r.second) << c;
	EXPECT_EQ(AddressRange(0x10, 0x60), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeMergeWithEnd)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x20, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x10, 0x30);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r.second) << c;
	EXPECT_EQ(AddressRange(0x10, 0x40), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeMergeMultiple)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x7, 0x20);
	c.insert(0x30, 0x40);
	c.insert(0x60, 0x70);
	c.insert(0x80, 0x95);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x10, 0x90);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r.second) << c;
	EXPECT_EQ(AddressRange(0x7, 0x95), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeMergeMultipleInside)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x15, 0x20);
	c.insert(0x30, 0x40);
	c.insert(0x60, 0x70);
	c.insert(0x80, 0x85);
	c.insert(0x100, 0x500); // should not be affected

	auto r = c.insert(0x10, 0x90);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(r.second) << c;
	EXPECT_EQ(AddressRange(0x10, 0x90), *r.first) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, InsertRangeMergeBordering)
{
	AddressRangeContainer c;

	c.insert(0x6, 0x16);
	c.insert(0x0, 0x6);
	c.insert(0x16, 0x100);

	EXPECT_EQ(1, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x100))) << c;
}

TEST_F(AddressRangeContainerTests, operatorEqEmpty)
{
	AddressRangeContainer c;
	EXPECT_EQ(AddressRangeContainer(), c);
}

TEST_F(AddressRangeContainerTests, operatorEq)
{
	AddressRangeContainer c;
	c.insert(0x10, 0x20);
	c.insert(0x30, 0x40);
	AddressRangeContainer r;
	r.insert(0x10, 0x20);
	r.insert(0x30, 0x40);

	EXPECT_EQ(r, c);
}

TEST_F(AddressRangeContainerTests, operatorNeq)
{
	AddressRangeContainer c;
	c.insert(0x10, 0x20);
	c.insert(0x30, 0x40);
	AddressRangeContainer r;
	r.insert(0x10, 0x20);
	r.insert(0x35, 0x40);

	EXPECT_NE(r, c);
}

TEST_F(AddressRangeContainerTests, containsGetRange)
{
	AddressRangeContainer c;
	c.insert(0x10, 0x20);
	c.insert(0x30, 0x40);

	EXPECT_TRUE(c.contains(0x10));
	EXPECT_EQ(AddressRange(0x10, 0x20), *c.getRange(0x10));
	EXPECT_TRUE(c.contains(0x15));
	EXPECT_EQ(AddressRange(0x10, 0x20), *c.getRange(0x15));
	EXPECT_TRUE(c.contains(0x19));
	EXPECT_EQ(AddressRange(0x10, 0x20), *c.getRange(0x19));
	EXPECT_TRUE(c.contains(0x30));
	EXPECT_EQ(AddressRange(0x30, 0x40), *c.getRange(0x30));

	EXPECT_FALSE(c.contains(0x0));
	EXPECT_EQ(nullptr, c.getRange(0x0));
	EXPECT_FALSE(c.contains(0x5));
	EXPECT_EQ(nullptr, c.getRange(0x5));
	EXPECT_FALSE(c.contains(0x9));
	EXPECT_EQ(nullptr, c.getRange(0x9));
	EXPECT_FALSE(c.contains(0x21));
	EXPECT_EQ(nullptr, c.getRange(0x21));
	EXPECT_FALSE(c.contains(0x29));
	EXPECT_EQ(nullptr, c.getRange(0x29));
	EXPECT_FALSE(c.contains(0x41));
	EXPECT_EQ(nullptr, c.getRange(0x41));
}

TEST_F(AddressRangeContainerTests, containsExact)
{
	AddressRangeContainer c;
	c.insert(0x10, 0x20);

	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x20)));

	EXPECT_FALSE(c.containsExact(AddressRange(0x10, 0x19)));
	EXPECT_FALSE(c.containsExact(AddressRange(0x11, 0x20)));
	EXPECT_FALSE(c.containsExact(AddressRange(0x15, 0x17)));
	EXPECT_FALSE(c.containsExact(AddressRange(0x20, 0x21)));
}

TEST_F(AddressRangeContainerTests, RemoveRangeMiss)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40); // should not be affected
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x50, 0x90);

	EXPECT_FALSE(c.empty()) << c;
	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x40))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveExactlyOldRange)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x10, 0x40);

	EXPECT_EQ(2, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemovedRangeFullyInNewExistingRange)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x60);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x20, 0x40);

	EXPECT_EQ(4, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x20))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x40, 0x60))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemovedRangeFullyInNewExistingRangeLeave1Ranges)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x60);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x11, 0x5f);

	EXPECT_EQ(4, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x11))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x5f, 0x60))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeFromStart)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x10, 0x20);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x20, 0x40))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeFromStartLeave1Range)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x10, 0x3f);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x3f, 0x40))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeFromEnd)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x20, 0x40);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x20))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeFromEndLeave1Range)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x40);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x11, 0x40);

	EXPECT_EQ(3, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x11))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeMultipleOutside)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x20);
	c.insert(0x30, 0x40);
	c.insert(0x60, 0x70);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x16, 0x64);

	EXPECT_EQ(4, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x10, 0x16))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x64, 0x70))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveRangeMultipleInside)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x5); // should not be affected
	c.insert(0x10, 0x20);
	c.insert(0x30, 0x40);
	c.insert(0x60, 0x70);
	c.insert(0x100, 0x500); // should not be affected

	c.remove(0x7, 0x90);

	EXPECT_EQ(2, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x0, 0x5))) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x100, 0x500))) << c;
}

TEST_F(AddressRangeContainerTests, RemoveAndGetRange)
{
	AddressRangeContainer c;
	c.insert(0x0, 0x100);

	c.remove(0x0, 0x50);

	EXPECT_EQ(1, c.size()) << c;
	EXPECT_TRUE(c.containsExact(AddressRange(0x50, 0x100))) << c;
	EXPECT_EQ(AddressRange(0x50, 0x100), *c.getRange(0x50));
	EXPECT_EQ(AddressRange(0x50, 0x100), *c.getRange(0x60));
	EXPECT_EQ(AddressRange(0x50, 0x100), *c.getRange(0xff));
}

} // namespace tests
} // namespace utils
} // namespace retdec
