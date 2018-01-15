/**
* @file tests/utils/time_tests.cpp
* @brief Tests for the @c time module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/time.h"

using namespace ::testing;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c time module.
*/
class TimeTests: public Test {};

//
// timestampToDate()
//

TEST_F(TimeTests,
CorrectTimestampToDateConversion) {
	EXPECT_EQ("2015-08-05 16:25:19", timestampToDate(std::time_t(1438784719)));
}

} // namespace tests
} // namespace utils
} // namespace retdec
