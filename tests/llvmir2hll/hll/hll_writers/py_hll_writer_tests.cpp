/**
* @file tests/llvmir2hll/hll/hll_writers/py_hll_writer_tests.cpp
* @brief Tests for the @c py_hll_writer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/hll/hll_writers/py_hll_writer.h"
#include "llvmir2hll/hll/hll_writers/hll_writer_tests.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::contains;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c py_hll_writer module.
*/
class PyHLLWriterTests: public HLLWriterTests {
protected:
	virtual void SetUp() override;
};

void PyHLLWriterTests::SetUp() {
	HLLWriterTests::SetUp();

	writer = PyHLLWriter::create(codeStream);
}

TEST_F(PyHLLWriterTests,
EmitsNonEmptyCode) {
	auto code = emitCodeForCurrentModule();

	ASSERT_FALSE(code.empty());
}

//
// Emission of strings.
//

TEST_F(PyHLLWriterTests,
Emits8BitStringLiteral) {
	//
	// void test() {
	//     printf("wide string");
	// }
	//
	auto printfFunc = addFuncDecl("printf");
	ExprVector args;
	args.push_back({ConstString::create("ascii string")});
	auto printfCallStmt = CallStmt::create(
		CallExpr::create(
			printfFunc->getAsVar(),
			args
		)
	);
	testFunc->setBody(printfCallStmt);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, "printf(\"ascii string\")")) << code;
}

TEST_F(PyHLLWriterTests,
EmitsWideStringLiteralAs8BitStringLiteral) {
	//
	// void test() {
	//     wprintf(L"wide string");
	// }
	//
	auto wprintfFunc = addFuncDecl("wprintf");
	ExprVector args;
	args.push_back(
		ConstString::create({'w', 'i', 'd', 'e', ' ', 's', 't', 'r', 'i', 'n', 'g'}, 16)
	);
	auto wprintfCallStmt = CallStmt::create(
		CallExpr::create(
			wprintfFunc->getAsVar(),
			args
		)
	);
	testFunc->setBody(wprintfCallStmt);

	auto code = emitCodeForCurrentModule();

	// Contrary to C, in Python, we emit wide string literals the same way we
	// emit 8-bit string literals.
	ASSERT_TRUE(contains(code, "wprintf(\"wide string\")")) << code;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
