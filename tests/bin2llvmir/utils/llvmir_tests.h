/**
 * @file tests/bin2llvmir/utils/llvmir_tests.h
 * @brief A base test class for all tests which works with LLVM IR strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef TESTS_BIN2LLVMIR_UTILS_LLVMIR_TESTS_H
#define TESTS_BIN2LLVMIR_UTILS_LLVMIR_TESTS_H

#include <gtest/gtest.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/loader/loader.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * Base class for all unit test classes which need to parse LLVM IR strings.
 */
class LlvmIrTests : public ::testing::Test
{
	public:
		LlvmIrTests() :
				module(_parseInput("", context))
		{

		}

	protected:
		/**
		 * There are some static data accessible via providers that are common
		 * to entire bin2llvmirl. This methods clears all of it.
		 */
		void clearAllStaticData()
		{
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
			::testing::Test::SetUp();
			clearAllStaticData();
		}

		/**
		 * Run after test -- make sure test have clear environment.
		 */
		virtual void TearDown() override
		{
			::testing::Test::TearDown();
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

		/**
		 * Parse the provided LLVM IR @c code into a LLVM module.
		 * @param code LLVM IR code string.
		 * @return LLVM module created by parsing the provided @c code.
		 */
		void parseInput(const std::string& code)
		{
			module = _parseInput(code, context);
		}

		/**
		 * Check if the IR string from @c actual LLVM module is the same
		 * as @c expected
		 * LLVM IR string.
		 * @param expected LLVM IR string.
		 */
		void checkModuleAgainstExpectedIr(std::string& expected)
		{
			llvm::LLVMContext expectedContext;
			auto expectedModule = _parseInput(expected, expectedContext);

			std::string expectedStr = llvmObjToString(expectedModule.get());
			std::string actualStr = llvmObjToString(module.get());

			ASSERT_FALSE(llvm::verifyModule(*expectedModule))
				<< "expected module is not valid:\n" << expectedStr;
			ASSERT_FALSE(verifyModule(*module))
				<< "actual module is not valid:\n" << actualStr;

			expectedStr = retdec::utils::removeComments(expectedStr, ';');
			actualStr = retdec::utils::removeComments(actualStr, ';');

			EXPECT_TRUE(
				retdec::utils::removeWhitespace(expectedStr) ==
				retdec::utils::removeWhitespace(actualStr)
			)
			<< "expected:\n"
			<< "=========\n" << expectedStr << "\n"
			<< "actual:\n"
			<< "=======\n" << actualStr << "\n";
		}

		/**
		 * Utility function to get value (i.e. global variable, function,
		 * instruction) with the specified @c n from module @c m.
		 * Values are searched in the following order:
		 *   1. globals
		 *   2. functions
		 *   3. instructions
		 * The first match is returned, therefore it is best to make sure
		 * all values in module have unique names.
		 *
		 * Typical usage:
		 *   1. create module using @c parseInput()
		 *   2. if you need some specific values to work with, get them using
		 *      this function.
		 * This is preferable to:
		 *   1. create module using @c addModuleToContext()
		 *   2. manually create objects and add them to module
		 * because manual object creation is not pretty -- it is very hard to
		 * see what the resulting module looks like.
		 */
		llvm::Value* getValueByName(const std::string& n)
		{
			for (auto& g : module->getGlobalList())
			{
				if (g.getName() == n)
				{
					return &g;
				}
			}
			for (auto& f : module->getFunctionList())
			{
				if (f.getName() == n)
				{
					return &f;
				}
			}
			for (auto& f : module->getFunctionList())
			{
				for (auto &b : f)
				for (auto &i : b)
				{
					if (i.getName() == n)
					{
						return &i;
					}
				}
			}
			throw std::runtime_error("failed to find specified value: " + n);
			return nullptr;
		}

		/**
		 * Utility function to get LLVM function.
		 * This only casts @c getValueByName() result to @c llvm::Function.
		 */
		llvm::Function* getFunctionByName(const std::string& n)
		{
			auto* v = getValueByName(n);
			return llvm::dyn_cast_or_null<llvm::Function>(v);
		}

		/**
		 * Utility function to get LLVM global variable.
		 * This only casts @c getValueByName() result to @c llvm::GlobalVariable.
		 */
		llvm::GlobalVariable* getGlobalByName(const std::string& n)
		{
			auto* v = getValueByName(n);
			return llvm::dyn_cast_or_null<llvm::GlobalVariable>(v);
		}

		/**
		 * Utility function to get LLVM instruction.
		 * This only casts @c getValueByName() result to @c llvm::Instruction.
		 */
		llvm::Instruction* getInstructionByName(const std::string& n)
		{
			auto* v = getValueByName(n);
			return llvm::dyn_cast_or_null<llvm::Instruction>(v);
		}

		/**
		 * Utility function to get @c n Nth (default zero = first) instruction
		 * of specified type from module @a m.
		 */
		template<typename T>
		T* getNthInstruction(unsigned n = 0)
		{
			unsigned cntr = 0;
			for (auto& f : *module)
			for (auto& b : f)
			for (auto& i : b)
			{
				if (auto* r = llvm::dyn_cast<T>(&i))
				{
					if (cntr == n)
					{
						return r;
					}
					else
					{
						++cntr;
					}
				}
			}

			return nullptr;
		}

		/**
		 * Utility function to get @c n Nth (default zero = first) instruction
		 * of specified type from function @a f.
		 */
		template<typename T>
		T* getNthInstruction(llvm::Function* f, unsigned n = 0)
		{
			unsigned cntr = 0;
			for (auto& b : *f)
			for (auto& i : b)
			{
				if (auto* r = llvm::dyn_cast<T>(&i))
				{
					if (cntr == n)
					{
						return r;
					}
					else
					{
						++cntr;
					}
				}
			}

			return nullptr;
		}

		// TODO: Variadic templates to accept and pass any arguments.
		template<typename T>
		void runOnFunctionCustom(T& pass, llvm::Module* m)
		{
			pass.doInitialization(*m);

			for (auto& f : m->functions())
			{
				pass.runOnFunctionCustom(f);
			}

			pass.doFinalization(*m);
		}

		// TODO: Variadic templates to accept and pass any arguments.
		// TODO: Use in all existing tests.
		template<typename T>
		void runOnModuleCustom(T& pass, llvm::Module* m)
		{
			pass.doInitialization(*m);
			pass.runOnModuleCustom(*m);
			pass.doFinalization(*m);
		}

		void initializeLlvmPassRegistry()
		{
			// See llvm/tools/opt -- There are a lot more initializations,
			// but we use only those we need here.
			llvm::PassRegistry& registry = *llvm::PassRegistry::getPassRegistry();
			llvm::initializeAnalysis(registry);
			llvm::initializeTransformUtils(registry);
		}

		template<typename T>
		void runOnModule()
		{
			initializeLlvmPassRegistry();

			llvm::legacy::PassManager passManager;
			passManager.add(new T());
			passManager.run(*module);
		}

		template<typename T>
		void runOnFunctions()
		{
			initializeLlvmPassRegistry();

			llvm::legacy::FunctionPassManager passManager(module.get());
			passManager.add(new T());

			passManager.doInitialization();
			for (llvm::Function& f : module->functions())
			{
				passManager.run(f);
			}
			passManager.doFinalization();
		}

	private:
		/**
		 * Print LLVM diagnostics error.
		 * @param err LLVM diagnostic error.
		 */
		void printLLVMIRConversionError(const llvm::SMDiagnostic& err)
		{
			err.print("", llvm::errs());
		}

		/**
		 * Parse the provided LLVM IR @c code into a LLVM module.
		 * @param code LLVM IR code string.
		 * @param ctx LLVM IR context.
		 * @return LLVM module created by parsing the provided @c code.
		 */
		std::unique_ptr<llvm::Module> _parseInput(
				const std::string& code,
				llvm::LLVMContext& ctx)
		{
			std::string c =
					"target datalayout = \"e-p:32:32:32-f80:32:32\"\n"
					+ code;
			auto mb = llvm::MemoryBuffer::getMemBuffer(c);
			if (mb == nullptr)
			{
				throw std::runtime_error("failed to create llvm::MemoryBuffer");
			}

			llvm::SMDiagnostic err;
			auto module = parseIR(mb->getMemBufferRef(), err, ctx);
			if (module == nullptr)
			{
				printLLVMIRConversionError(err);
				throw std::runtime_error("invalid LLVM IR");
			}

			return module;
		}

	protected:
		llvm::LLVMContext context;
		std::unique_ptr<llvm::Module> module;
};

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec

#endif
