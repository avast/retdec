/**
* @file tests/llvmir2hll/hll/hll_writers/hll_writer_tests.h
* @brief Base class for tests of HLL writers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_HLL_HLL_WRITERS_TESTS_HLL_WRITER_TESTS_H
#define BACKEND_BIR_HLL_HLL_WRITERS_TESTS_HLL_WRITER_TESTS_H

#include <string>

#include <gtest/gtest.h>
#include <llvm/Support/raw_ostream.h>

#include "llvmir2hll/ir/tests_with_module.h"

namespace retdec {
namespace llvmir2hll {

class HLLWriter;

namespace tests {

/**
* @brief Tests for the @c c_hll_writer module.
*/
class HLLWriterTests: public TestsWithModule {
protected:
	HLLWriterTests();

	virtual void SetUp() override;

	std::string emitCodeForCurrentModule();

protected:
	/// Underlying string for @c codeStream.
	std::string code;

	/// Stream into which the code will be stored.
	llvm::raw_string_ostream codeStream;

	/// Writer under test.
	ShPtr<HLLWriter> writer;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
