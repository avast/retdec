/**
* @file tests/llvmir2hll/hll/output_managers/output_manager_tests.h
* @brief Base class for tests of output managers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_HLL_OUTPUT_MANAGERS_OUTPUT_MANAGER_TESTS_H
#define BACKEND_BIR_HLL_OUTPUT_MANAGERS_OUTPUT_MANAGER_TESTS_H

#include <string>

#include <gtest/gtest.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class OutputManager;

namespace tests {

/**
* @brief Tests for the @c output_manager module.
*/
class OutputManagerTests: public ::testing::Test
{
	protected:
		OutputManagerTests();

		virtual void SetUp() override;

		std::string emitCode();

	protected:
		/// Underlying string for @c codeStream.
		std::string code;

		/// Stream into which the code will be stored.
		llvm::raw_string_ostream codeStream;

		/// Manager under test.
		UPtr<OutputManager> manager;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
