/**
* @file include/retdec/utils/test.h
* @brief Test-related macros.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* Created based on gtest's macro FRIEND_TEST.
* We can not use it directly because we would have to include gtest header in
* non-gtest-related sources, it would get propagated to modules which does
* not use gtest and we do not want them to use it.
*/

#ifndef RETDEC_UTILS_TEST_H
#define RETDEC_UTILS_TEST_H

#define GTEST_FORWARD_TEST(testCaseName, testName)\
		namespace tests { class testCaseName##_##testName##_Test; }

#define GTEST_FRIEND_TEST(testCaseName, testName)\
		friend class tests::testCaseName##_##testName##_Test

#endif
