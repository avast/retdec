/**
* @file tests/llvmir2hll/hll/hll_writers/hll_writer_tests.cpp
* @brief Implementation of the base class for tests of HLL writers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/hll/hll_writers/c_hll_writer.h"
#include "llvmir2hll/hll/hll_writers/hll_writer_tests.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::contains;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Constructs the base class.
*/
HLLWriterTests::HLLWriterTests(): code(), codeStream(code) {}

void HLLWriterTests::SetUp() {
	TestsWithModule::SetUp();

	ON_CALL(*configMock, getDetectedCryptoPatternForGlobalVar(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getAddressRangeForFunc(_))
		.WillByDefault(Return(NO_ADDRESS_RANGE));
	ON_CALL(*configMock, getLineRangeForFunc(_))
		.WillByDefault(Return(NO_LINE_RANGE));
	ON_CALL(*configMock, isUserDefinedFunc(_))
		.WillByDefault(Return(false));
	ON_CALL(*configMock, isStaticallyLinkedFunc(_))
		.WillByDefault(Return(false));
	ON_CALL(*configMock, isDynamicallyLinkedFunc(_))
		.WillByDefault(Return(false));
	ON_CALL(*configMock, isSyscallFunc(_))
		.WillByDefault(Return(false));
	ON_CALL(*configMock, isInstructionIdiomFunc(_))
		.WillByDefault(Return(false));
	ON_CALL(*configMock, getDeclarationStringForFunc(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getCommentForFunc(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getDetectedCryptoPatternsForFunc(_))
		.WillByDefault(Return(StringSet()));
	ON_CALL(*configMock, getWrappedFunc(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getDemangledNameOfFunc(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getDebugModuleNameForFunc(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getClassNames())
		.WillByDefault(Return(StringSet()));
	ON_CALL(*configMock, getBaseClassNames(_))
		.WillByDefault(Return(StringVector()));
	ON_CALL(*configMock, getDemangledNameOfClass(_))
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getFrontendRelease())
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getNumberOfFuncsDetectedInFrontend())
		.WillByDefault(Return(0));
	ON_CALL(*configMock, getDetectedCompilerOrPacker())
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getDetectedLanguage())
		.WillByDefault(Return(""));
	ON_CALL(*configMock, getSelectedButNotFoundFuncs())
		.WillByDefault(Return(StringSet()));
	ON_CALL(*configMock, getFuncsFixedWithLLVMIRFixer())
		.WillByDefault(Return(StringSet()));

	ON_CALL(*semanticsMock, getCHeaderFileForFunc(_))
		.WillByDefault(Return(Nothing<std::string>()));
	ON_CALL(*semanticsMock, getMainFuncName())
		.WillByDefault(Return(Nothing<std::string>()));

	// By default, use CHLLWriter to test functionality that is shared between
	// HLL writers.
	writer = CHLLWriter::create(codeStream);
}

/**
* @brief Emits the current module and returns the emitted code.
*/
std::string HLLWriterTests::emitCodeForCurrentModule() {
	writer->emitTargetCode(module);
	return codeStream.str();
}

//
// Emission of classes.
//

TEST_F(HLLWriterTests,
EmitsMangledClassNamesWhenDemangledNamesAreNotAvailable) {
	ON_CALL(*configMock, getClassNames())
		.WillByDefault(Return(StringSet({"6Derived", "7Polygon"})));
	ON_CALL(*configMock, getBaseClassNames("6Derived"))
		.WillByDefault(Return(StringVector({"7Polygon"})));
	ON_CALL(*configMock, getClassForFunc("test"))
		.WillByDefault(Return("6Derived"));

	auto code = emitCodeForCurrentModule();

	// Classes in the header.
	ASSERT_TRUE(contains(code, "// 7Polygon")) << code;
	ASSERT_TRUE(contains(code, "// 6Derived (base classes: 7Polygon)")) << code;
	// Info for function test().
	ASSERT_TRUE(contains(code, "// From class:    6Derived")) << code;
}

TEST_F(HLLWriterTests,
EmitsDemangledClassNamesWhenAvailable) {
	ON_CALL(*configMock, getClassNames())
		.WillByDefault(Return(StringSet({"6Derived", "7Polygon"})));
	ON_CALL(*configMock, getBaseClassNames("6Derived"))
		.WillByDefault(Return(StringVector({"7Polygon"})));
	ON_CALL(*configMock, getClassForFunc("test"))
		.WillByDefault(Return("6Derived"));
	ON_CALL(*configMock, getDemangledNameOfClass("6Derived"))
		.WillByDefault(Return("Derived"));
	ON_CALL(*configMock, getDemangledNameOfClass("7Polygon"))
		.WillByDefault(Return("Polygon"));

	auto code = emitCodeForCurrentModule();

	// Classes in the header.
	ASSERT_TRUE(contains(code, "// Polygon")) << code;
	ASSERT_TRUE(contains(code, "// Derived (base classes: Polygon)")) << code;
	// Info for function test().
	ASSERT_TRUE(contains(code, "// From class:    Derived")) << code;
}

//
// Emission of global variables.
//

TEST_F(HLLWriterTests,
EmitsDetectedCryptoPatternInCommentAboveGlobalVariableWhenPatternWasDetected) {
	module->addGlobalVar(Variable::create("g", IntType::create(32)));
	ON_CALL(*configMock, getDetectedCryptoPatternForGlobalVar("g"))
		.WillByDefault(Return("CRC32"));

	auto code = emitCodeForCurrentModule();

	std::string expectedCodePart(
		"// Detected cryptographic pattern: CRC32\n"
		"int32_t g;"
	);
	ASSERT_TRUE(contains(code, expectedCodePart))
		<< "Actual code:\n" << code << "\n"
		<< "Expected code part:\n" << expectedCodePart;
}

//
// Emission of functions.
//

TEST_F(HLLWriterTests,
EmitsDemangledFuncNameInCommentWhenAvailable) {
	ON_CALL(*configMock, getDemangledNameOfFunc("test"))
		.WillByDefault(Return("demangled_func"));

	auto code = emitCodeForCurrentModule();

	// Info for function test().
	ASSERT_TRUE(contains(code, "// Demangled:     demangled_func")) << code;
}

TEST_F(HLLWriterTests,
EmitsFuncCommentInCommentOnSingleLineWhenThereAreNoLineBreaks) {
	ON_CALL(*configMock, getCommentForFunc("test"))
		.WillByDefault(Return("single-line comment"));

	auto code = emitCodeForCurrentModule();

	// Info for function test().
	ASSERT_TRUE(contains(code, "// Comment:       single-line comment")) << code;
}

TEST_F(HLLWriterTests,
EmitsFuncCommentInCommentInBlockWhenThereAreLineBreaks) {
	ON_CALL(*configMock, getCommentForFunc("test"))
		.WillByDefault(Return("multi-line\ncomment"));

	auto code = emitCodeForCurrentModule();

	// Info for function test().
	ASSERT_TRUE(contains(code, "// Comment:\n//     multi-line\n//     comment\n")) << code;
}

TEST_F(HLLWriterTests,
EmitsDetectedCryptoPatternsInCommentWhenAvailable) {
	ON_CALL(*configMock, getDetectedCryptoPatternsForFunc("test"))
		.WillByDefault(Return(StringSet({"CRC32", "MD5"})));

	auto code = emitCodeForCurrentModule();

	// Info for function test().
	std::string expectedCodePart(
		"// Used cryptographic patterns:\n"
		"//  - CRC32\n"
		"//  - MD5\n"
		"void test(void) {"
	);
	ASSERT_TRUE(contains(code, expectedCodePart))
		<< "Actual code:\n" << code << "\n"
		<< "Expected code part:\n" << expectedCodePart;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
