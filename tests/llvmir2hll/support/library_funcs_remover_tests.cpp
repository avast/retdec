/**
* @file tests/llvmir2hll/support/library_funcs_remover_tests.cpp
* @brief Tests for the @c library_funcs_remover module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/library_funcs_remover.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c library_funcs_remover module.
*/
class LibraryFuncsRemoverTests: public TestsWithModule {
	virtual void SetUp() override;

};

void LibraryFuncsRemoverTests::SetUp() {
	TestsWithModule::SetUp();

	// No function is exported by default.
	ON_CALL(*configMock, isExportedFunc(_))
		.WillByDefault(Return(false));
}

TEST_F(LibraryFuncsRemoverTests,
DoNotRemoveAnythingIfThereIsJustTheMainFunction) {
	// Set-up the module.
	//
	// void main() {}
	//
	testFunc->setName("main");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc(_))
		.WillByDefault(Return(Nothing<std::string>()));

	// Perform the removal.
	FuncVector removedFuncs(LibraryFuncsRemover::removeFuncs(module));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	ShPtr<Function> mainFunc(module->getFuncByName("main"));
	ASSERT_TRUE(mainFunc);
	EXPECT_TRUE(mainFunc->isDefinition());
}

TEST_F(LibraryFuncsRemoverTests,
DoNotRemoveAnythingIfThereAreNoFunctionDeclarations) {
	// Set-up the module.
	//
	// void test() {}
	// void test2() {}
	//
	addFuncDef("test2");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc(_))
		.WillByDefault(Return(Nothing<std::string>()));

	// Perform the removal.
	FuncVector removedFuncs(LibraryFuncsRemover::removeFuncs(module));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	ShPtr<Function> testFunc(module->getFuncByName("test"));
	ASSERT_TRUE(testFunc);
	EXPECT_TRUE(testFunc->isDefinition());
	ShPtr<Function> test2Func(module->getFuncByName("test2"));
	ASSERT_TRUE(test2Func);
	EXPECT_TRUE(test2Func->isDefinition());
}

TEST_F(LibraryFuncsRemoverTests,
DoNotRemoveAnythingIfThereAreFunctionDeclarationsButNoHeadersAreToBeIncluded) {
	// Set-up the module.
	//
	// void test() {}
	// void decl1();
	// void decl2();
	//
	addFuncDecl("decl1");
	addFuncDecl("decl2");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc(_))
		.WillByDefault(Return(Nothing<std::string>()));

	// Perform the removal.
	FuncVector removedFuncs(LibraryFuncsRemover::removeFuncs(module));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	ShPtr<Function> testFunc(module->getFuncByName("test"));
	ASSERT_TRUE(testFunc);
	EXPECT_TRUE(testFunc->isDefinition());
	ShPtr<Function> decl1Func(module->getFuncByName("decl1"));
	ASSERT_TRUE(decl1Func);
	EXPECT_TRUE(decl1Func->isDeclaration());
	ShPtr<Function> decl2Func(module->getFuncByName("decl2"));
	ASSERT_TRUE(decl2Func);
	EXPECT_TRUE(decl2Func->isDeclaration());
}

TEST_F(LibraryFuncsRemoverTests,
DoNotRemoveFuncMarkedAsExportedEvenIfThereIsHeaderForIt) {
	// Set-up the module.
	//
	// void test() {}
	// void printf();
	// void fprintf() {} // exported
	//
	addFuncDecl("printf");
	addFuncDef("fprintf");

	// Mark the function as exported.
	EXPECT_CALL(*configMock, isExportedFunc("fprintf"))
		.WillOnce(Return(true));

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("test"))
		.WillByDefault(Return(Nothing<std::string>()));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("fprintf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));

	// Perform the removal.
	FuncVector removedFuncs(LibraryFuncsRemover::removeFuncs(module));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	ShPtr<Function> fprintfFunc(module->getFuncByName("fprintf"));
	ASSERT_TRUE(fprintfFunc);
	EXPECT_TRUE(fprintfFunc->isDefinition());
}

TEST_F(LibraryFuncsRemoverTests,
DefinedFunctionsFromIncludedHeadersAreTurnedIntoDeclarations) {
	// Set-up the module.
	//
	// void test() {}
	// void fprintf();
	// void printf() {}   <-- will be turned into a declaration
	// void signal() {}
	//
	addFuncDecl("fprintf");
	addFuncDef("printf");
	addFuncDef("signal");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("test"))
		.WillByDefault(Return(Nothing<std::string>()));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("fprintf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("signal"))
		.WillByDefault(Return(Just<std::string>("signal.h")));

	// Perform the removal.
	FuncVector removedFuncs(LibraryFuncsRemover::removeFuncs(module));

	// Check that the output is correct.
	FuncVector refRemovedFuncs;
	refRemovedFuncs.push_back(module->getFuncByName("printf"));
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	ShPtr<Function> testFunc(module->getFuncByName("test"));
	ASSERT_TRUE(testFunc);
	EXPECT_TRUE(testFunc->isDefinition());
	ShPtr<Function> fprintfFunc(module->getFuncByName("fprintf"));
	ASSERT_TRUE(fprintfFunc);
	EXPECT_TRUE(fprintfFunc->isDeclaration());
	ShPtr<Function> printfFunc(module->getFuncByName("printf"));
	ASSERT_TRUE(printfFunc);
	EXPECT_TRUE(printfFunc->isDeclaration());
	ShPtr<Function> signalFunc(module->getFuncByName("signal"));
	ASSERT_TRUE(signalFunc);
	EXPECT_TRUE(signalFunc->isDefinition());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
