/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converter_tests.h
* @brief A base class of tests for conversion of LLVM IR to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_LLVM_TESTS_LLVMIR2BIR_CONVERTER_TESTS_H
#define BACKEND_BIR_LLVM_TESTS_LLVMIR2BIR_CONVERTER_TESTS_H

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>

#include "llvmir2hll/config/config_mock.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class LLVMIR2BIRConverter;
class Module;

namespace tests {

/**
* @brief A base class of tests for conversion of LLVM IR to BIR.
*/
class LLVMIR2BIRConverterTests: public ::testing::Test {
private:
	/**
	* @brief An internal pass to perform the conversion from an LLVM IR module
	*        to a BIR module.
	*
	* @param[in] configMock A mock for the used config.
	*/
	// Due to technical reasons, this class cannot be moved into the .cpp file
	// (see the implementation of convertLLVMIR2BIR()).
	class ConversionPass: public llvm::ModulePass {
	public:
		ConversionPass(ShPtr<::testing::NiceMock<ConfigMock>> configMock);

		virtual bool runOnModule(llvm::Module &llvmModule) override;
		virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;

		void setUsedConverter(ShPtr<LLVMIR2BIRConverter> converter);
		ShPtr<Module> getConvertedModule() const;

	private:
		/// Converter to be used to convert @c llvmModule into @c birModule.
		ShPtr<LLVMIR2BIRConverter> converter;

		/// Converted module.
		ShPtr<Module> birModule;

		/// A mock for the used semantics.
		ShPtr<::testing::NiceMock<SemanticsMock>> semanticsMock;

		/// A mock for the used config.
		ShPtr<::testing::NiceMock<ConfigMock>> configMock;
	};

protected:
	LLVMIR2BIRConverterTests();

	/**
	* @brief Converts the given LLVM IR code into a BIR module by using the
	*        given converter.
	*
	* @tparam Converter LLVMIR2BIR converter to be used.
	*
	* If the LLVM IR is invalid, an error message is written to the standard
	* error and @c std::runtime_error is thrown.
	*/
	template<typename Converter>
	ShPtr<Module> convertLLVMIR2BIR(const std::string &code) {
		// We have to run the converter through a pass manager to prevent the
		// following assertion failures:
		//
		//     Pass has not been inserted into a PassManager object!
		//
		llvm::legacy::PassManager passManager;

		// Our LLVMIR2BIR converters require the LoopInfo and
		// ScalarEvolution analyses. The memory allocated below is
		// automatically deleted in the passManager's destructor.
		passManager.add(new llvm::LoopInfoWrapperPass());
		passManager.add(new llvm::ScalarEvolutionWrapperPass());
		auto conversionPass = new ConversionPass(configMock);
		passManager.add(conversionPass);

		// Peform the conversion.
		auto converter = Converter::create(conversionPass);
		converter->setOptionStrictFPUSemantics(optionStrictFPUSemantics);
		conversionPass->setUsedConverter(converter);
		llvmModule = parseLLVMIR(code);
		passManager.run(*llvmModule);
		return conversionPass->getConvertedModule();
	}

private:
	UPtr<llvm::Module> parseLLVMIR(const std::string &code);

protected:
	/// A mock for the used config.
	ShPtr<::testing::NiceMock<ConfigMock>> configMock;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;

private:
	/// Context for the LLVM module.
	// Implementation note: Do NOT use llvm::getGlobalContext() because that
	//                      would make the context same for all tests (we want
	//                      to run all tests in isolation).
	llvm::LLVMContext llvmContext;

	/// LLVM module.
	UPtr<llvm::Module> llvmModule;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
