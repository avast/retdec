/**
* @file tests/utils/container_tests.cpp
* @brief Tests for the @c container module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <map>

#include <gtest/gtest.h>

#include "retdec/utils/container.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c container module.
*/
class ContainerTests: public Test {};

//
// hasItem()
//

template<class ContainerType>
void refHasItemTestCheckWhetherContainerContainsNumbers(
		const ContainerType &container) {
	EXPECT_TRUE(hasItem(container, 1));
	EXPECT_TRUE(hasItem(container, 5));
	EXPECT_TRUE(hasItem(container, 10));
	EXPECT_FALSE(hasItem(container, 0));
	EXPECT_FALSE(hasItem(container, 11));
}

TEST_F(ContainerTests,
HasItemForList) {
	std::list<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.push_back(i);
	}

	SCOPED_TRACE("HasItemForList");
	refHasItemTestCheckWhetherContainerContainsNumbers(container);
}

TEST_F(ContainerTests,
HasItemForVector) {
	std::vector<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.push_back(i);
	}

	SCOPED_TRACE("HasItemForVector");
	refHasItemTestCheckWhetherContainerContainsNumbers(container);
}

TEST_F(ContainerTests,
HasItemForSet) {
	std::set<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.insert(i);
	}

	SCOPED_TRACE("HasItemForSet");
	refHasItemTestCheckWhetherContainerContainsNumbers(container);
}

TEST_F(ContainerTests,
HasItemForMap) {
	std::map<int, int> container;
	for (int i = 1; i <= 10; ++i) {
		container[i] = i + 1;
	}

	SCOPED_TRACE("HasItemForMap");
	refHasItemTestCheckWhetherContainerContainsNumbers(container);
}

//
// getNthItem()
//

TEST_F(ContainerTests,
GetNthItemWorksCorrectlyForVector) {
	std::vector<int> container;
	container.push_back(1);
	container.push_back(2);
	container.push_back(3);

	EXPECT_EQ(1, getNthItem(container, 1));
	EXPECT_EQ(2, getNthItem(container, 2));
	EXPECT_EQ(3, getNthItem(container, 3));
}

TEST_F(ContainerTests,
GetNthItemWorksCorrectlyForList) {
	std::list<int> container;
	container.push_back(1);
	container.push_back(2);
	container.push_back(3);

	EXPECT_EQ(1, getNthItem(container, 1));
	EXPECT_EQ(2, getNthItem(container, 2));
	EXPECT_EQ(3, getNthItem(container, 3));
}

//
// getValueOrDefault()
//

template<class ContainerType>
void refGetValueOrDefaultTestGetSomeNumbers(
		const ContainerType &container) {
	EXPECT_EQ(3, getValueOrDefault(container, 3, 5));
	EXPECT_EQ(5, getValueOrDefault(container, 0, 5));
	EXPECT_EQ(int(), getValueOrDefault(container, 11));
}

TEST_F(ContainerTests,
GetValueOrDefaultForSet) {
	std::set<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.insert(i);
	}

	SCOPED_TRACE("GetValueOrDefault");
	refGetValueOrDefaultTestGetSomeNumbers(container);
}

TEST_F(ContainerTests,
GetValueOrDefaultForList) {
	std::list<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.push_back(i);
	}

	SCOPED_TRACE("GetValueOrDefault");
	refGetValueOrDefaultTestGetSomeNumbers(container);
}

TEST_F(ContainerTests,
GetValueOrDefaultForVector) {
	std::vector<int> container;
	for (int i = 1; i <= 10; ++i) {
		container.push_back(i);
	}

	SCOPED_TRACE("GetValueOrDefault");
	refGetValueOrDefaultTestGetSomeNumbers(container);
}

//
// removeItem()
//

TEST_F(ContainerTests,
RemoveItemDoesNothingWhenThereIsNoSuchItem) {
	std::vector<int> v{1, 2, 3};

	removeItem(v, 77);

	ASSERT_EQ(3, v.size());
}

TEST_F(ContainerTests,
RemoveItemRemovesItemWhenItContainsOneOcurrenceOfItem) {
	std::vector<int> v{1, 2, 3};

	removeItem(v, 2);

	std::vector<int> refV{1, 3};
	ASSERT_EQ(refV, v);
}

TEST_F(ContainerTests,
RemoveItemRemovesAllOccurrencesOfItem) {
	std::vector<int> v{2, 1, 2, 2, 3, 2};

	removeItem(v, 2);

	std::vector<int> refV{1, 3};
	ASSERT_EQ(refV, v);
}

//
// clear()
//

template<class ContainerType>
void scenarioClearEmptiesNonEmptyContainer(ContainerType &container) {
	ASSERT_FALSE(container.empty());
	clear(container);
	ASSERT_TRUE(container.empty());
}

TEST_F(ContainerTests,
ClearForVector) {
	std::vector<int> v(100, 0);
	scenarioClearEmptiesNonEmptyContainer(v);
}

TEST_F(ContainerTests,
ClearForQueue) {
	std::queue<int> q;
	q.push(1);
	q.push(2);
	q.push(3);
	scenarioClearEmptiesNonEmptyContainer(q);
}

TEST_F(ContainerTests,
ClearForStack) {
	std::stack<int> s;
	s.push(1);
	s.push(2);
	s.push(3);
	scenarioClearEmptiesNonEmptyContainer(s);
}

//
// filter()
//

TEST_F(ContainerTests,
FilterReturnsCorrectlyFilteredContainerOfSameType) {
	std::vector<int> input{1, 2, 3, 4, 5};

	auto result = filter(
		input,
		[](auto i) { return i % 2 == 0; }
	);

	ASSERT_EQ(typeid(input), typeid(result));
	ASSERT_EQ(std::vector<int>({2, 4}), result);
}

//
// filterTo()
//

TEST_F(ContainerTests,
FilterToReturnsCorrectlyFilteredContainerOfGivenType) {
	std::vector<int> input{1, 2, 3, 4, 5};

	auto result = filterTo<std::set<int>>(
		input,
		[](auto i) { return i % 2 == 0; }
	);

	ASSERT_EQ(typeid(std::set<int>), typeid(result));
	ASSERT_EQ(std::set<int>({2, 4}), result);
}

//
// removeFromSet()
//

TEST_F(ContainerTests,
RemoveFromSetDoesNothingWhenFromSetIsAlreadyEmpty) {
	std::set<int> from{};
	std::set<int> toRemove{1, 2, 3};

	removeFromSet(from, toRemove);

	EXPECT_TRUE(from.empty());
}

TEST_F(ContainerTests,
RemoveFromSetRemovesEverythingThatIsInToRemove) {
	std::set<int> from{1, 2, 3};
	std::set<int> toRemove{2, 3, 4};

	removeFromSet(from, toRemove);

	EXPECT_EQ(std::set<int>{1}, from);
}

TEST_F(ContainerTests,
RemoveFromSetRemovesEverythingWhenToRemoveIsFrom) {
	std::set<int> from{1, 2, 3};

	removeFromSet(from, from);

	EXPECT_TRUE(from.empty());
}

//
// shareSomeItem()
//

TEST_F(ContainerTests,
ShareSomeItemTwoEmptySetsDontShareAnyItem) {
	std::set<int> s1;
	std::set<int> s2;

	EXPECT_FALSE(shareSomeItem(s1, s2));
	EXPECT_FALSE(shareSomeItem(s2, s1));
}

TEST_F(ContainerTests,
ShareSomeItemEmptySetDoesntShareAnyItemWithANonEmptySet) {
	std::set<int> s1;
	s1.insert(1);
	std::set<int> s2;

	EXPECT_FALSE(shareSomeItem(s1, s2));
	EXPECT_FALSE(shareSomeItem(s2, s1));
}

TEST_F(ContainerTests,
ShareSomeItemSetsShareASingleItem) {
	std::set<int> s1;
	s1.insert(1);
	s1.insert(2);
	s1.insert(3);

	std::set<int> s2;
	s2.insert(3);
	s2.insert(4);
	s2.insert(5);

	EXPECT_TRUE(shareSomeItem(s1, s2));
	EXPECT_TRUE(shareSomeItem(s2, s1));
}

TEST_F(ContainerTests,
ShareSomeItemSetsShareTwoItems) {
	std::set<int> s1;
	s1.insert(1);
	s1.insert(2);
	s1.insert(3);

	std::set<int> s2;
	s2.insert(2);
	s2.insert(3);
	s2.insert(4);

	EXPECT_TRUE(shareSomeItem(s1, s2));
	EXPECT_TRUE(shareSomeItem(s2, s1));
}

//
// getKeysFromMap()
//

TEST_F(ContainerTests,
GetKeysFromMapReturnsCorrectKeys) {
	std::map<std::string, int> m{
		{"a", 1},
		{"b", 2},
		{"c", 3}
	};

	ASSERT_EQ(std::set<std::string>({"a", "b", "c"}), getKeysFromMap(m));
}

//
// getValuesFromMap()
//

TEST_F(ContainerTests,
GetValuesFromMapReturnsCorrectKeys) {
	std::map<std::string, int> m{
		{"a", 1},
		{"b", 2},
		{"c", 3}
	};

	ASSERT_EQ(std::set<int>({1, 2, 3}), getValuesFromMap(m));
}

//
// mapHasKey()
//

TEST_F(ContainerTests,
MapHasKeyReturnsTrueWhenMapHasGivenKey) {
	std::map<std::string, int> m{
		{"a", 1}
	};

	ASSERT_TRUE(mapHasKey(m, "a"));
}

TEST_F(ContainerTests,
MapHasKeyReturnsFalseWhenMapDoesNotHaveGivenKey) {
	std::map<std::string, int> m;

	ASSERT_FALSE(mapHasKey(m, "a"));
}

//
// mapHasValue()
//

TEST_F(ContainerTests,
MapHasValueReturnsTrueWhenMapHasGivenValue) {
	std::map<std::string, int> m{
		{"a", 1}
	};

	ASSERT_TRUE(mapHasValue(m, 1));
}

TEST_F(ContainerTests,
MapHasValueReturnsFalseWhenMapDoesNotHaveGivenValue) {
	std::map<std::string, int> m;

	ASSERT_FALSE(mapHasValue(m, 1));
}

//
// mapGetValueOrDefault()
//

TEST_F(ContainerTests,
MapGetValueOrDefaultReturnsPassedValueWhenMapHasValue) {
	std::map<std::string, int> m{
		{"a", 1}
	};

	ASSERT_EQ(1, mapGetValueOrDefault(m, "a"));
}

TEST_F(ContainerTests,
MapGetValueOrDefaultReturnsDefaultValueWhenMapDoesNotHaveValue) {
	std::map<std::string, int> m;

	ASSERT_EQ(0, mapGetValueOrDefault(m, "a"));
}

//
// mapGetMaxValue()
//

TEST_F(ContainerTests,
MapGetMaxValueReturnsCorrectValueWhenMapIsNonEmpty) {
	std::map<std::string, int> m{
		{"a", 1},
		{"b", 2},
		{"c", 3},
		{"d", 2}
	};

	ASSERT_EQ(3, mapGetMaxValue(m));
}

TEST_F(ContainerTests,
MapGetMaxValueReturnsDefaultConstructedValueTypeWhenMapIsEmpty) {
	std::map<std::string, int> m;

	ASSERT_EQ(0, mapGetMaxValue(m));
}

//
// addToMap()
//

TEST_F(ContainerTests,
AddToMapWorksCorrectlyWhenAddingValueToNonExistingKey) {
	std::map<std::string, int> m;
	addToMap(std::string("test"), 5, m);
	EXPECT_EQ(1, m.size());
	EXPECT_EQ(5, m["test"]);
}

TEST_F(ContainerTests,
AddToMapWorksCorrectlyWhenAddingValueToExistingKey) {
	std::map<std::string, int> m;
	addToMap(std::string("test"), 5, m);
	addToMap(std::string("test"), 6, m);
	EXPECT_EQ(1, m.size());
	EXPECT_EQ(6, m["test"]);
}

//
// getMapWithSwappedKeysAndValues()
//

TEST_F(ContainerTests,
GetMapWithSwappedKeysAndValuesReturnsCorrectMapWhenOriginalMapHasDistinctValues) {
	std::map<std::string, int> m{
		{"a", 1},
		{"b", 2},
		{"c", 3}
	};

	auto swapped = getMapWithSwappedKeysAndValues(m);

	std::map<int, std::string> expected{
		{1, "a"},
		{2, "b"},
		{3, "c"}
	};
	EXPECT_EQ(expected, swapped);
}

TEST_F(ContainerTests,
GetMapWithSwappedKeysAndValuesReturnsCorrectMapWhenOriginalMapDoesNotHaveDistinctValues) {
	std::map<std::string, int> m{
		{"a", 1},
		{"b", 1},
		{"c", 1}
	};

	auto swapped = getMapWithSwappedKeysAndValues(m);

	std::map<int, std::string> expected{
		{1, "a"}
	};
	EXPECT_EQ(expected, swapped);
}

//
// Tested together since it is not possible to check if insert or clear were
// successful without find().
//
// NonIterableSet::insert()
// NonIterableSet::find()
// NonIterableSet::clear()
// NonIterableSet::has()
// NonIterableSet::hasNot()
//

TEST_F(ContainerTests,
NonIterableSetInsertsFindsAndClearsElements) {
	int i = 123;
	NonIterableSet<int*> c;

	c.insert(&i);
	EXPECT_TRUE(c.has(&i));
	EXPECT_FALSE(c.hasNot(&i));

	c.clear();
	EXPECT_FALSE(c.has(&i));
	EXPECT_TRUE(c.hasNot(&i));
}

} // namespace tests
} // namespace utils
} // namespace retdec
