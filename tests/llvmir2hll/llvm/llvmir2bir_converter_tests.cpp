/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converter_tests.cpp
* @brief Implementation of the base class of tests for conversion of LLVM IR
*        to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>

#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converter_tests.h"
#include "retdec/llvmir2hll/support/debug.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

namespace {

// The value is not important (LLVM only uses the address of the ID).
char MODULE_PASS_ID = 0;

void printLLVMIRConversionError(const llvm::SMDiagnostic &err) {
	err.print("", llvm::errs());
}

} // anonymous namespace

LLVMIR2BIRConverterTests::ConversionPass::ConversionPass(
		ShPtr<::testing::NiceMock<ConfigMock>> configMock):
	llvm::ModulePass(MODULE_PASS_ID),
	semanticsMock(std::make_shared<NiceMock<SemanticsMock>>()),
	configMock(configMock)
	{}

bool LLVMIR2BIRConverterTests::ConversionPass::runOnModule(
		llvm::Module &llvmModule) {
	PRECONDITION(converter, "setUsedConverter() was not called");
	birModule = converter->convert(
		&llvmModule,
		llvmModule.getModuleIdentifier(),
		semanticsMock,
		configMock
	);
	return false;
}

void LLVMIR2BIRConverterTests::ConversionPass::getAnalysisUsage(
		llvm::AnalysisUsage &au) const {
	// Our converters require the LoopInfo and ScalarEvolution analyses.
	au.addRequired<llvm::LoopInfoWrapperPass>();
	au.addRequired<llvm::ScalarEvolutionWrapperPass>();
	au.setPreservesAll();
}

/**
* @brief Sets the used LLVMIR2BIR converter.
*
* This member function has to be called before @c runOnModule().
*/
void LLVMIR2BIRConverterTests::ConversionPass::setUsedConverter(
		ShPtr<LLVMIR2BIRConverter> converter) {
	this->converter = converter;
}

/**
* @brief Returns the converted module.
*
* This member function can be called only after @c runOnModule() has run.
*/
ShPtr<Module> LLVMIR2BIRConverterTests::ConversionPass::getConvertedModule() const {
	PRECONDITION(birModule, "runOnModule() did not run");
	return birModule;
}

LLVMIR2BIRConverterTests::LLVMIR2BIRConverterTests():
	configMock(std::make_shared<NiceMock<ConfigMock>>()),
	optionStrictFPUSemantics(false) {}

/**
* @brief Parses the given LLVM IR code into an LLVM module.
*/
UPtr<llvm::Module> LLVMIR2BIRConverterTests::parseLLVMIR(const std::string &code) {
	auto mb = llvm::MemoryBuffer::getMemBuffer(code);
	llvm::SMDiagnostic err;
	auto module = llvm::parseIR(mb->getMemBufferRef(), err, llvmContext);
	if (!module) {
		printLLVMIRConversionError(err);
		throw std::runtime_error("invalid LLVM IR");
	}
	return module;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
