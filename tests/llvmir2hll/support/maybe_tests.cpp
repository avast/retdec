/**
* @file tests/llvmir2hll/support/maybe_tests.cpp
* @brief Tests for the @c maybe module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>
#include <utility>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c maybe module.
*/
class MaybeTests: public Test {};

TEST_F(MaybeTests,
CopyConstructionWorksCorrectly) {
	Maybe<int> i(1);
	Maybe<int> j(i);
	EXPECT_EQ(i.get(), j.get());
}

TEST_F(MaybeTests,
MoveConstructionWorksCorrectly) {
	Maybe<int> i(1);
	Maybe<int> j(std::move(i));
	EXPECT_EQ(1, j.get());
}

TEST_F(MaybeTests,
AssignmentWorksCorrectly) {
	Maybe<int> i(1);
	Maybe<int> j;
	j = i;
	EXPECT_EQ(i.get(), j.get());
}

TEST_F(MaybeTests,
MaybeWithoutValueEvaluatesToFalse) {
	EXPECT_FALSE(Maybe<int>());
	EXPECT_TRUE(!Maybe<int>());
}

TEST_F(MaybeTests,
MaybeWithValueEvaluatesToTrue) {
	EXPECT_TRUE(Maybe<int>(1));
	EXPECT_FALSE(!Maybe<int>(1));
}

TEST_F(MaybeTests,
MaybeWithValueEvaluatesToTrueAllTheTime) {
	EXPECT_TRUE(Maybe<int>(1));
	EXPECT_TRUE(Maybe<int>(1));
	EXPECT_TRUE(Maybe<int>(1));
	EXPECT_TRUE(Maybe<int>(1));
}

TEST_F(MaybeTests,
NothingEvaluatesToFalse) {
	EXPECT_FALSE(Nothing<int>());
	EXPECT_TRUE(!Nothing<int>());
}

TEST_F(MaybeTests,
JustEvaluatesToTrue) {
	EXPECT_TRUE(Just(1));
	EXPECT_FALSE(!Just(1));
}

TEST_F(MaybeTests,
GetFromMaybeWithValueReturnsCorrectValue) {
	EXPECT_EQ(1, Just(1).get());
	EXPECT_EQ("test"s, Just("test"s).get());
	EXPECT_EQ(*std::make_shared<int>(1), *Just(std::make_shared<int>(1)).get());
}

struct Point {
	Point(int x, int y): x(x), y(y) {}
	int x;
	int y;
};

TEST_F(MaybeTests,
OperatorArrowFromMaybeWithValueReturnsCorrectValue) {
	Maybe<Point> p(Just(Point(1, 2)));
	EXPECT_EQ(1, p->x);
	EXPECT_EQ(2, p->y);
}

#if DEATH_TESTS_ENABLED
TEST_F(MaybeTests,
CallingGetOnEmptyMaybeResultsInViolatedPrecondition) {
	EXPECT_DEATH(Nothing<int>().get(), ".*get.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(MaybeTests,
CallingOperatorArrowOnEmptyMaybeResultsInViolatedPrecondition) {
	// Ignore the value to prevent Clang from complaining (warning: expression
	// result unused). The value is expected to be useless because it is a
	// death test.
	EXPECT_DEATH(static_cast<void>(Nothing<Point>()->x),
		// MSVC puts a space before '->' in the assertion message, so
		// we need to put ' ?' before '->'.
		".*operator ?->.*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
