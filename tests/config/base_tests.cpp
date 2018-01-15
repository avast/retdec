/**
 * @file tests/config/base_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/base.h"
#include "retdec/config/functions.h"
#include "retdec/config/objects.h"
#include "retdec/config/segments.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

//
//=============================================================================
//  BaseSequentialContainerTests
//=============================================================================
//

class BaseSequentialContainerTests: public Test
{
	public:
		BaseSequentialContainerTests() :
				obj1("obj1", Storage::inMemory(0x1000)),
				obj2("obj2", Storage::inRegister("reg")),
				obj3("obj3", Storage::onStack(20)),
				obj4("obj4", Storage::undefined())
		{
			EXPECT_TRUE(objs.empty());
			objs.insert(obj1);
			objs.insert(obj2);
			objs.insert(obj3);
			objs.insert(obj4);
			EXPECT_EQ(4, objs.size());
		}

	protected:
		Object obj1;
		Object obj2;
		Object obj3;
		Object obj4;
		BaseSequentialContainer<Object> objs;
};

TEST_F(BaseSequentialContainerTests, SequentialSimpleMethodsWork)
{
	EXPECT_EQ(obj1, *objs.begin());

	auto end = objs.end();
	--end;
	EXPECT_EQ(obj4, *end);

	EXPECT_EQ(4, objs.size());

	EXPECT_FALSE(objs.empty());

	EXPECT_EQ(obj1, objs.front());

	objs.clear();
	EXPECT_EQ(0, objs.size());
	EXPECT_TRUE(objs.empty());
}

TEST_F(BaseSequentialContainerTests, SequentialGetElementByIdWorks)
{
	EXPECT_EQ(obj1, *objs.getElementById(obj1.getName()));
	EXPECT_EQ(obj2, *objs.getElementById(obj2.getName()));
	EXPECT_EQ(obj3, *objs.getElementById(obj3.getName()));
	EXPECT_EQ(obj4, *objs.getElementById(obj4.getName()));
}

TEST_F(BaseSequentialContainerTests, SequentialInsertWorks)
{
	// This object is unique -> must be added.
	//
	Object obj5("obj5", Storage::inMemory(0x2000));

	EXPECT_EQ(4, objs.size());
	objs.insert(obj5);
	EXPECT_EQ(5, objs.size());

	// This object is not unique -> existing object is updated.
	//
	Object obj6(obj1.getName(), Storage::inMemory(0x4000));

	auto front = objs.front();

	EXPECT_EQ(obj1.getStorage().getAddress(), front.getStorage().getAddress());
	EXPECT_EQ(5, objs.size());
	objs.insert(obj6);
	EXPECT_EQ(5, objs.size());
	front = objs.front();
	EXPECT_EQ(obj6.getStorage().getAddress(), front.getStorage().getAddress());
}

TEST_F(BaseSequentialContainerTests, EmptyContainersAreEqual)
{
	BaseSequentialContainer<Object> c1;
	BaseSequentialContainer<Object> c2;

	EXPECT_TRUE(c1 == c2);
	EXPECT_FALSE(c1 != c2);
}

TEST_F(BaseSequentialContainerTests, DifferentSizedContainersAreNotEqual)
{
	BaseSequentialContainer<Object> c1;
	c1.insert(obj1);
	c1.insert(obj2);
	c1.insert(obj3);
	BaseSequentialContainer<Object> c2;
	c2.insert(obj1);
	c2.insert(obj2);

	EXPECT_FALSE(c1 == c2);
	EXPECT_TRUE(c1 != c2);
}

TEST_F(BaseSequentialContainerTests, SameSizedContainersWithDifferentElementsAreNotEqual)
{
	BaseSequentialContainer<Object> c1;
	c1.insert(obj1);
	c1.insert(obj2);
	BaseSequentialContainer<Object> c2;
	c2.insert(obj3);
	c2.insert(obj4);

	EXPECT_FALSE(c1 == c2);
	EXPECT_TRUE(c1 != c2);
}

TEST_F(BaseSequentialContainerTests, SameSizedContainersWithTheSameElementsAreEqual)
{
	BaseSequentialContainer<Object> c1;
	c1.insert(obj1);
	c1.insert(obj2);
	BaseSequentialContainer<Object> c2;
	c2.insert(obj1);
	c2.insert(obj2);

	EXPECT_TRUE(c1 == c2);
	EXPECT_FALSE(c1 != c2);
}

//
//=============================================================================
//  BaseAssociativeContainerTests
//=============================================================================
//

class BaseAssociativeContainerTests: public Test
{
	public:
		BaseAssociativeContainerTests() :
			fnc1("fnc1"),
			fnc2("fnc2")
		{
			fnc1.setStart(0x1000);
			fnc1.setIsStaticallyLinked();

			fnc2.setStart(0x2000);

			EXPECT_TRUE(fncs.empty());
			fncs.insert(fnc1);
			fncs.insert(fnc2);
			EXPECT_EQ(2, fncs.size());
		}

	protected:
		Function fnc1;
		Function fnc2;
		BaseAssociativeContainer<std::string, Function> fncs;
};

TEST_F(BaseAssociativeContainerTests, AssociativeSimpleMethodsWork)
{
	EXPECT_EQ(fnc1, fncs.begin()->second);

	auto end = fncs.end();
	--end;
	EXPECT_EQ(fnc2, end->second);

	EXPECT_EQ(2, fncs.size());

	EXPECT_FALSE(fncs.empty());

	fncs.clear();
	EXPECT_EQ(0, fncs.size());
	EXPECT_TRUE(fncs.empty());
}

TEST_F(BaseAssociativeContainerTests, AssociativeGetElementByIdWorks)
{
	EXPECT_EQ(fnc1, *fncs.getElementById(fnc1.getName()));
	EXPECT_EQ(fnc2, *fncs.getElementById(fnc2.getName()));
}

TEST_F(BaseAssociativeContainerTests, AssociativeInsertWorks)
{
	// This object is unique -> must be added.
	//
	Function fnc3("fnc3");
	fnc3.setStart(0x3000);

	EXPECT_EQ(2, fncs.size());
	fncs.insert(fnc3);
	EXPECT_EQ(3, fncs.size());

	// This object is not unique -> existing object is updated.
	//
	Function fnc4(fnc1.getName());
	fnc4.setStart(0x4000);
	fnc4.setIsDynamicallyLinked();

	EXPECT_TRUE(fncs.getElementById(fnc1.getName())->isStaticallyLinked());
	EXPECT_EQ(fnc1.getStart(), fncs.getElementById(fnc1.getName())->getStart());

	EXPECT_EQ(3, fncs.size());
	fncs.insert(fnc4);
	EXPECT_EQ(3, fncs.size());

	EXPECT_TRUE(fncs.getElementById(fnc1.getName())->isDynamicallyLinked());
	EXPECT_EQ(fnc4.getStart(), fncs.getElementById(fnc1.getName())->getStart());
}

//
//=============================================================================
//  BaseAssociativeContainerTests
//=============================================================================
//

class BaseSetContainerTests: public Test
{
	public:
		BaseSetContainerTests() :
				seg1(retdec::utils::Address(0x1000)),
				seg2(retdec::utils::Address(0x2000))
		{
			seg1.setName("seg1");
			seg1.setComment("comment1");

			seg2.setName("seg2");

			EXPECT_TRUE(segs.empty());
			segs.insert(seg1);
			segs.insert(seg2);
			EXPECT_EQ(2, segs.size());
		}

	protected:
		Segment seg1;
		Segment seg2;
		BaseSetContainer<Segment> segs;
};

TEST_F(BaseSetContainerTests, SetSimpleMethodsWork)
{
	EXPECT_EQ(seg1, *segs.begin());

	auto end = segs.end();
	--end;
	EXPECT_EQ(seg2, *end);

	EXPECT_EQ(2, segs.size());

	EXPECT_FALSE(segs.empty());

	segs.clear();
	EXPECT_EQ(0, segs.size());
	EXPECT_TRUE(segs.empty());
}

TEST_F(BaseSetContainerTests, SetInsertWorks)
{
	// This object is unique -> must be added.
	//
	Segment seg3(retdec::utils::Address(0x3000));
	seg3.setName("seg3");

	EXPECT_EQ(2, segs.size());
	segs.insert(seg3);
	EXPECT_EQ(3, segs.size());

	// This object is not unique -> existing object is updated.
	//
	Segment seg4(seg1.getStart());
	seg4.setName("seg4");
	seg4.setComment("comment4");

	EXPECT_EQ(seg1.getName(), segs.find(seg1)->getName());
	EXPECT_EQ(seg1.getComment(), segs.find(seg1)->getComment());

	EXPECT_EQ(3, segs.size());
	segs.insert(seg4);
	EXPECT_EQ(3, segs.size());

	EXPECT_EQ(seg4.getName(), segs.find(seg1)->getName());
	EXPECT_EQ(seg4.getComment(), segs.find(seg1)->getComment());
}

} // namespace tests
} // namespace config
} // namespace retdec
