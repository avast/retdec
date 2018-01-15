/**
 * @file tests/bin2llvmir/utils/tests/llvmir_tests.h
 * @brief A base test class for all tests which works with LLVM IR strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FRONTEND_BIN2LLVMIRL_UTILS_TESTS_LLVMIR_TESTS_H
#define FRONTEND_BIN2LLVMIRL_UTILS_TESTS_LLVMIR_TESTS_H

#include <gtest/gtest.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvm-support/tests/llvmir_tests.h"
#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/loader/loader.h"

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * Base class for all unit test classes which need to parse LLVM IR strings.
 */
class LlvmIrTests : public retdec::llvm_support::tests::LlvmIrTests
{
	protected:
		/**
		 * There are some static data accessible via providers that are common
		 * to entire bin2llvmirl. This methods clears all of it.
		 */
		void clearAllStaticData()
		{
			AbiProvider::clear();
			ConfigProvider::clear();
			DebugFormatProvider::clear();
			DemanglerProvider::clear();
			FileImageProvider::clear();
			AsmInstruction::clear();
			LtiProvider::clear();
		}

		/**
		 * Run before test -- make sure test have clear environment.
		 */
		virtual void SetUp() override
		{
			retdec::llvm_support::tests::LlvmIrTests::SetUp();
			clearAllStaticData();
		}

		/**
		 * Run after test -- make sure test have clear environment.
		 */
		virtual void TearDown() override
		{
			retdec::llvm_support::tests::LlvmIrTests::TearDown();
			clearAllStaticData();
		}

		std::shared_ptr<retdec::fileformat::RawDataFormat> createFormat()
		{
			std::stringstream emptyDummySs;
			auto f = std::make_shared<retdec::fileformat::RawDataFormat>(
					emptyDummySs);
			if (f == nullptr)
			{
					throw std::runtime_error("failed to create RawDataFormat");
			}

			return f;
		}

		std::unique_ptr<retdec::loader::Image> loadFormat(
				std::unique_ptr<retdec::fileformat::RawDataFormat> format)
		{
			std::shared_ptr<retdec::fileformat::RawDataFormat> formatShared(std::move(format));
			auto image = retdec::loader::createImage(formatShared);
			if (image == nullptr)
			{
					throw std::runtime_error("failed to load RawDataImage");
			}

			return image;
		}
};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec

#endif
