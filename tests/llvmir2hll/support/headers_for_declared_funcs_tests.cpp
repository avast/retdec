/**
* @file tests/llvmir2hll/support/headers_for_declared_funcs_tests.cpp
* @brief Tests for the @c headers_for_declared_funcs module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/llvmir2hll/support/headers_for_declared_funcs.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c headers_for_declared_funcs module.
*/
class HeadersForDeclaredFuncsTests: public TestsWithModule {
};

TEST_F(HeadersForDeclaredFuncsTests,
NoHeadersAreReturnedIfThereAreNoDeclaredFunctions) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	// Set-up the semantics.
	// -

	// Get the headers.
	StringSet headers(HeadersForDeclaredFuncs::getHeaders(module));

	// Check the result.
	StringSet refHeaders;
	EXPECT_EQ(refHeaders, headers);
}

TEST_F(HeadersForDeclaredFuncsTests,
NoHeadersAreReturnedIfThereAreDeclaredFunctionsButNoSemanticsForThem) {
	// Set-up the module.
	//
	// void test() {}
	//
	// void funcDecl1();
	// void funcDecl2();
	//
	addFuncDecl("funcDecl1");
	addFuncDecl("funcDecl2");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc(_))
		.WillByDefault(Return(Nothing<std::string>()));

	// Get the headers.
	StringSet headers(HeadersForDeclaredFuncs::getHeaders(module));

	// Check the result.
	StringSet refHeaders;
	EXPECT_EQ(refHeaders, headers);
}

TEST_F(HeadersForDeclaredFuncsTests,
HeadersForKnownFunctionDeclarationsAreReturnedCorrectly) {
	// Set-up the module.
	//
	// void test() {}
	//
	// void printf();
	// void exit();
	//
	addFuncDecl("printf");
	addFuncDecl("exit");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("exit"))
		.WillByDefault(Return(Just<std::string>("stdlib.h")));

	// Get the headers.
	StringSet headers(HeadersForDeclaredFuncs::getHeaders(module));

	// Check the result.
	StringSet refHeaders;
	refHeaders.insert("stdio.h");
	refHeaders.insert("stdlib.h");
	EXPECT_EQ(refHeaders, headers);
}

TEST_F(HeadersForDeclaredFuncsTests,
HasAssocHeaderReturnsTrueWhenFunctionHasAssociatedHeaderFile) {
	// Set-up the module.
	//
	// void test() {}
	//
	// void printf();
	//
	addFuncDecl("printf");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just<std::string>("stdio.h")));

	// Check the result.
	EXPECT_TRUE(HeadersForDeclaredFuncs::hasAssocHeader(module,
		module->getFuncByName("printf")));
}

TEST_F(HeadersForDeclaredFuncsTests,
HasAssocHeaderReturnsFalseWhenFunctionHasNoAssociatedHeaderFile) {
	// Set-up the module.
	//
	// void test() {}
	//
	// void unknown_func();
	//
	addFuncDecl("unknown_func");

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("unknown_func"))
		.WillByDefault(Return(Nothing<std::string>()));

	// Check the result.
	EXPECT_FALSE(HeadersForDeclaredFuncs::hasAssocHeader(module,
		module->getFuncByName("unknown_func")));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
