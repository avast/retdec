/**
 * @file tests/loader/overlap_resolver_tests.cpp
 * @brief Tests for the @c overlap_resolver module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/loader/utils/overlap_resolver.h"

using namespace ::testing;

namespace retdec {
namespace loader {
namespace tests {

class OverlapResolverTests : public Test {};

TEST_F(OverlapResolverTests,
NoOverlapWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(200, 300);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::None, result.getOverlap());
	EXPECT_EQ(2, result.getRanges().size());
	EXPECT_EQ(first, result.getRanges()[0]);
	EXPECT_EQ(second, result.getRanges()[1]);
}

TEST_F(OverlapResolverTests,
FullOverlapWithHugeRangeWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(0, 300);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::Full, result.getOverlap());
	EXPECT_EQ(1, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
}

TEST_F(OverlapResolverTests,
FullOverlapAtStartWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(100, 300);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::Full, result.getOverlap());
	EXPECT_EQ(1, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
}

TEST_F(OverlapResolverTests,
FullOverlapAtEndWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(0, 200);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::Full, result.getOverlap());
	EXPECT_EQ(1, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
}

TEST_F(OverlapResolverTests,
ExactFullOverlapWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(100, 200);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::Full, result.getOverlap());
	EXPECT_EQ(1, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
}

TEST_F(OverlapResolverTests,
OverlapOverStartWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(50, 150);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::OverStart, result.getOverlap());
	EXPECT_EQ(2, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(150, 200), result.getRanges()[1]);
}

TEST_F(OverlapResolverTests,
ExactOverlapOverStartWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(100, 150);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::OverStart, result.getOverlap());
	EXPECT_EQ(2, result.getRanges().size());
	EXPECT_EQ(second, result.getRanges()[0]);
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(150, 200), result.getRanges()[1]);
}

TEST_F(OverlapResolverTests,
OverlapOverEndWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(150, 250);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::OverEnd, result.getOverlap());
	EXPECT_EQ(2, result.getRanges().size());
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(100, 150), result.getRanges()[0]);
	EXPECT_EQ(second, result.getRanges()[1]);
}

TEST_F(OverlapResolverTests,
ExactOverlapOverEndWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(199, 250);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::OverEnd, result.getOverlap());
	EXPECT_EQ(2, result.getRanges().size());
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(100, 199), result.getRanges()[0]);
	EXPECT_EQ(second, result.getRanges()[1]);
}

TEST_F(OverlapResolverTests,
OverlapInMiddleWorks) {
	retdec::utils::Range<std::uint64_t> first(100, 200);
	retdec::utils::Range<std::uint64_t> second(110, 170);
	auto result = OverlapResolver::resolve(first, second);

	EXPECT_EQ(Overlap::InMiddle, result.getOverlap());
	EXPECT_EQ(3, result.getRanges().size());
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(100, 110), result.getRanges()[0]);
	EXPECT_EQ(second, result.getRanges()[1]);
	EXPECT_EQ(retdec::utils::Range<std::uint64_t>(170, 200), result.getRanges()[2]);
}

} // namespace loader
} // namespace retdec
} // namespace tests
