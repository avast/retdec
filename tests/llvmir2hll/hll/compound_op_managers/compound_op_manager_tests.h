/**
* @file tests/llvmir2hll/hll/compound_op_managers/compound_op_manager_tests.h
* @brief Base class for all CompoundOpManager test classes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_HLL_COMPOUND_OP_MANAGERS_TESTS_COMPOUND_OP_MANAGER_TESTS_H
#define BACKEND_BIR_HLL_COMPOUND_OP_MANAGERS_TESTS_COMPOUND_OP_MANAGER_TESTS_H

#include <gtest/gtest.h>

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Base class for all CompoundOpManagers tests classes.
*/
class CompoundOpManagerTests: public ::testing::Test {
protected:
	void tryToOptimizeAndCheckResult(ShPtr<AssignStmt> stmt, CompoundOpManager::
		CompoundOp expectedResult);

protected:
		ShPtr<CompoundOpManager> compoundOpManager;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
