/**
* @file tests/utils/memory_tests.cpp
* @brief Tests for the @c memory module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/memory.h"
#include "retdec/utils/os.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c memory module.
*/
class MemoryTests: public Test {
protected:
	virtual void SetUp() override {
		// Several tests have side effects, so we need to store the original
		// total memory so we can restore it after each test.
		totalSystemMemory = getTotalSystemMemory();
	}

	virtual void TearDown() override {
		limitSystemMemory(totalSystemMemory);
	}

private:
	/// Original total memory in the system.
	std::size_t totalSystemMemory = 0;
};

TEST_F(MemoryTests,
GetTotalSystemMemoryReturnsNonZeroSize) {
	auto size = getTotalSystemMemory();

	ASSERT_GT(size, 0);
}

TEST_F(MemoryTests,
LimitSystemMemoryReturnsTrueWhenLimitingTotalSystemMemoryToNonZeroSize) {
	auto totalSize = getTotalSystemMemory();

	// This has a side effect, but the system's memory is set back to the
	// original value in TearDown().
	ASSERT_TRUE(limitSystemMemory(totalSize))
		<< "failed to limit system memory to " << totalSize;
}

TEST_F(MemoryTests,
LimitSystemMemoryReturnsFalseWhenLimitIsZero) {
	ASSERT_FALSE(limitSystemMemory(0));
}

#ifdef OS_WINDOWS
TEST_F(MemoryTests,
LimitSystemMemoryReturnsFalseOnWindowsWhenLimitIsBelowPageSize) {
	// SetInformationJobObject() requires the limit to be at least page size
	// (e.g. 4 kB = 4096 bytes). If the limit is lower, it will fail.
	ASSERT_FALSE(limitSystemMemory(100/*bytes*/));
}
#endif

TEST_F(MemoryTests,
LimitSystemMemoryToHalfOfTotalSystemMemoryReturnsTrue) {
	// This has a side effect, but the system's memory is set back to the
	// original value in TearDown().
	ASSERT_TRUE(limitSystemMemoryToHalfOfTotalSystemMemory());
}

} // namespace tests
} // namespace utils
} // namespace retdec
