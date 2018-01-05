/**
* @file tests/utils/filter_iterator_tests.cpp
* @brief Tests for the @c filter_iterator module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>

#include <gtest/gtest.h>

#include "retdec/utils/filter_iterator.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

namespace {

bool isEven(int i) {
	return i % 2 == 0;
}

} // anonymous namespace

/**
* @brief Tests for the @c filter_iterator module.
*/
class FilterIteratorTests: public Test {};

TEST_F(FilterIteratorTests,
PredicateCanBeOrdinaryFunction) {
	std::vector<int> v;

	FilterIterator<std::vector<int>::iterator> it(
		v.begin(),
		v.end(),
		isEven
	);
}

TEST_F(FilterIteratorTests,
PredicateCanBeLambdaFunction) {
	std::vector<int> v;

	FilterIterator<std::vector<int>::iterator> it(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);
}

TEST_F(FilterIteratorTests,
IterationSkipsNoElementsWhenPredicateAlwaysReturnsTrue) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> begin(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);
	FilterIterator<std::vector<int>::iterator> end(v.end());

	std::vector<int> v2(begin, end);

	ASSERT_EQ(v, v2);
}

TEST_F(FilterIteratorTests,
IterationSkipsAllElementsWhenPredicateAlwaysReturnsFalse) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> begin(
		v.begin(),
		v.end(),
		[](int i) { return false; }
	);
	FilterIterator<std::vector<int>::iterator> end(v.end());

	std::vector<int> v2(begin, end);

	ASSERT_EQ(0, v2.size());
}

TEST_F(FilterIteratorTests,
IterationSkipsElementsForWhichPredicateReturnsFalse) {
	std::vector<int> v{1, 2, 3, 4, 5, 6, 7};
	FilterIterator<std::vector<int>::iterator> begin(
		v.begin(),
		v.end(),
		isEven
	);
	FilterIterator<std::vector<int>::iterator> end(v.end());

	std::vector<int> v2(begin, end);

	ASSERT_EQ(std::vector<int>({2, 4, 6}), v2);
}

TEST_F(FilterIteratorTests,
ConstructorTakingContainerCreatesIteratorOverWholeContainer) {
	std::vector<int> v{1, 2, 3, 4, 5, 6, 7};
	FilterIterator<std::vector<int>::iterator> begin(v, isEven);
	FilterIterator<std::vector<int>::iterator> end(v.end());

	std::vector<int> v2(begin, end);

	ASSERT_EQ(std::vector<int>({2, 4, 6}), v2);
}

TEST_F(FilterIteratorTests,
IteratorPointsToFirstElementAfterCreationWhenPredicateReturnsTrueForFirstElement) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> end(v.end());

	FilterIterator<std::vector<int>::iterator> begin(
		v.begin(),
		v.end(),
		[](int i) { return i == 1; }
	);

	ASSERT_EQ(1, *begin);
}

TEST_F(FilterIteratorTests,
IteratorPointsToEndAfterCreationWhenPredicateReturnsFalseForAllElements) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> end(v.end());

	FilterIterator<std::vector<int>::iterator> begin(
		v.begin(),
		v.end(),
		[](int i) { return false; }
	);

	ASSERT_EQ(end, begin);
}

TEST_F(FilterIteratorTests,
TwoIteratorsAreEqualWhenTheyPointToSameElement) {
	std::vector<int> v{1, 2, 3};

	FilterIterator<std::vector<int>::iterator> it1(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);
	FilterIterator<std::vector<int>::iterator> it2(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);

	ASSERT_EQ(it1, it2);
}

TEST_F(FilterIteratorTests,
TwoIteratorsAreNotEqualWhenTheyDoNotPointToSameElement) {
	std::vector<int> v{1, 2, 3};

	FilterIterator<std::vector<int>::iterator> it1(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);
	FilterIterator<std::vector<int>::iterator> it2(
		v.end(),
		v.end(),
		[](int i) { return true; }
	);

	ASSERT_NE(it1, it2);
}

TEST_F(FilterIteratorTests,
TwoIteratorsAreEqualAfterAssignment) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> it1(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);
	FilterIterator<std::vector<int>::iterator> it2(v.end());

	it2 = it1;

	ASSERT_EQ(it1, it2);
}

TEST_F(FilterIteratorTests,
TwoIteratorsAreEqualWhenSecondOneIsCreatedViaCopyConstruction) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> it1(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);

	FilterIterator<std::vector<int>::iterator> it2(it1);

	ASSERT_EQ(it1, it2);
}

TEST_F(FilterIteratorTests,
TwoIteratorsAreEqualWhenSecondOneIsCreatedViaMoveConstruction) {
	std::vector<int> v{1, 2, 3};
	FilterIterator<std::vector<int>::iterator> it1(
		v.begin(),
		v.end(),
		[](int i) { return true; }
	);

	FilterIterator<std::vector<int>::iterator> it2(std::move(it1));

	ASSERT_EQ(it1, it2);
}

} // namespace tests
} // namespace utils
} // namespace retdec
