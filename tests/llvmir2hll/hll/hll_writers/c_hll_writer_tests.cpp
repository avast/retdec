/**
* @file tests/llvmir2hll/hll/hll_writers/c_hll_writer_tests.cpp
* @brief Tests for the @c c_hll_writer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/hll/hll_writers/c_hll_writer.h"
#include "llvmir2hll/hll/hll_writers/hll_writer_tests.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/utils/string.h"

using namespace ::testing;

using retdec::utils::contains;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c c_hll_writer module.
*/
class CHLLWriterTests: public HLLWriterTests {
protected:
	virtual void SetUp() override;
};

void CHLLWriterTests::SetUp() {
	HLLWriterTests::SetUp();

	writer = CHLLWriter::create(codeStream);
}

TEST_F(CHLLWriterTests,
EmitsNonEmptyCode) {
	auto code = emitCodeForCurrentModule();

	ASSERT_FALSE(code.empty());
}

//
// Emission of floating-point literals.
//

TEST_F(CHLLWriterTests,
FloatLiteralIsEmittedWithCorrectSuffix) {
	//
	// float g = 0.0f;
	//
	module->addGlobalVar(
		Variable::create("g", FloatType::create(32)),
		ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEsingle, "0.0"))
	);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, " = 0.0f;")) << code;
}

TEST_F(CHLLWriterTests,
DoubleLiteralIsEmittedWithoutSuffix) {
	//
	// double g = 0.0; // (floating-point literals are double by default)
	//
	module->addGlobalVar(
		Variable::create("g", FloatType::create(64)),
		ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEdouble, "0.0"))
	);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, " = 0.0;")) << code;
}

TEST_F(CHLLWriterTests,
LongDoubleLiteralIsEmittedWithCorrectSuffix) {
	//
	// long double g = 0.0L;
	//
	module->addGlobalVar(
		Variable::create("g", FloatType::create(80)),
		ConstFloat::create(llvm::APFloat(llvm::APFloat::x87DoubleExtended, "0.0"))
	);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, " = 0.0L;")) << code;
}

//
// Emission of strings.
//

TEST_F(CHLLWriterTests,
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

	ASSERT_TRUE(contains(code, "printf(\"ascii string\");")) << code;
}

TEST_F(CHLLWriterTests,
EmitsWideStringLiteral) {
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

	ASSERT_TRUE(contains(code, "wprintf(L\"wide string\");")) << code;
}

//
// Emission of universal for loops.
//

TEST_F(CHLLWriterTests,
EmitsUForLoopStmtWithInitCondStep) {
	//
	// void test() {
	//     for (i = 0; i < 10; ++i) {
	//     }
	// }
	//
	auto varI = Variable::create("i", IntType::create(32));
	testFunc->addLocalVar(varI);
	auto loop = UForLoopStmt::create(
		AssignOpExpr::create(varI, ConstInt::create(0, 32)),
		LtOpExpr::create(varI, ConstInt::create(10, 32)),
		AssignOpExpr::create(
			varI,
			AddOpExpr::create(varI, ConstInt::create(1, 32))
		),
		EmptyStmt::create()
	);
	testFunc->setBody(loop);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, "for (i = 0; i < 10; i++)")) << code;
}

TEST_F(CHLLWriterTests,
EmitsUForLoopStmtWithoutInitCondStep) {
	//
	// void test() {
	//     for (;;) {
	//     }
	// }
	//
	auto loop = UForLoopStmt::create(
		ShPtr<Expression>(),
		ShPtr<Expression>(),
		ShPtr<Expression>(),
		EmptyStmt::create()
	);
	testFunc->setBody(loop);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, "for (;;)")) << code;
}

TEST_F(CHLLWriterTests,
EmitsVarDefOfInitOfUForLoopStmtWhenLoopHasItsInitMarked) {
	//
	// void test() {
	//     for (int32_t i = 0; ;) {
	//     }
	// }
	//
	auto varI = Variable::create("i", IntType::create(32));
	testFunc->addLocalVar(varI);
	auto loop = UForLoopStmt::create(
		AssignOpExpr::create(varI, ConstInt::create(0, 32)),
		ShPtr<Expression>(),
		ShPtr<Expression>(),
		EmptyStmt::create()
	);
	loop->markInitAsDefinition();
	testFunc->setBody(loop);

	auto code = emitCodeForCurrentModule();

	ASSERT_TRUE(contains(code, "for (int32_t i = 0;")) << code;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
