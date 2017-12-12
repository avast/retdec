/**
* @file tests/llvmir2hll/ir/assertions.h
* @brief Testing assertions for BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_IR_TESTS_ASSERTIONS_H
#define BACKEND_BIR_IR_TESTS_ASSERTIONS_H

#include <gtest/gtest.h>

// Note: The explicit emission of objects in the following macros is necessary
//       because Google Test is unable to print BIR types (and I was unable to
//       get it to print BIR types).

/**
* @brief Prints the two given values.
*/
#define PRINT_VALUES(expected, other) \
	" -> expected `" << expected << "`, got `" << other << "`"

/**
* @brief Asserts that the two given BIR objects are identical.
*/
#define ASSERT_BIR_EQ(expected, other) \
	ASSERT_EQ(expected, other) << PRINT_VALUES(expected, other)

/**
* @brief Expects that the two given BIR objects are identical.
*/
#define EXPECT_BIR_EQ(expected, other) \
	EXPECT_EQ(expected, other) << PRINT_VALUES(expected, other)

#endif
