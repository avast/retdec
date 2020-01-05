/**
* @file tests/llvmir2hll/support/const_symbol_converter_tests.cpp
* @brief Tests for the @c const_symbol_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/const_symbol_converter.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_symbol_converter module.
*/
class ConstSymbolConverterTests: public TestsWithModule {
protected:
	void scenarioChangeConstantToSymbolicNamesWorksCorrectly(
		const std::string &funcName, Expression* origArg,
		const IntStringMap &refMap, Expression* refNewArg);
};

/**
* @brief Runs a test scenario, where an argument (@a origArg) of a call to the
*        given function (named @a funcName) is supposed to be converted into
*        the given expression (refNewArg).
*/
void ConstSymbolConverterTests::scenarioChangeConstantToSymbolicNamesWorksCorrectly(
		const std::string &funcName, Expression* origArg,
		const IntStringMap &refMap, Expression* refNewArg) {
	// Set-up the module.
	//
	// int funcName(int p);
	//
	// void test() {
	//     funcName(origArg);
	// }
	//
	Function* func(
		FunctionBuilder(funcName)
			.withRetType(IntType::create(32))
			.withParam(Variable::create("p", IntType::create(32)))
			.build()
	);
	module->addFunc(func);
	ExprVector funcCallArgs;
	funcCallArgs.push_back(origArg);
	CallExpr* funcCallExpr(CallExpr::create(func->getAsVar(), funcCallArgs));
	CallStmt* funcCallStmt(CallStmt::create(funcCallExpr));
	testFunc->setBody(funcCallStmt);

	// Set-up the semantics.
	ON_CALL(*semanticsMock, getSymbolicNamesForParam(funcName, 1))
		.WillByDefault(Return(refMap));

	// Perform the conversion.
	ConstSymbolConverter::convert(module);

	// Check that the output is correct.
	//
	// void test() {
	//     funcName(refNewArg);
	// }
	//
	ExprVector funcCallNewArgs(funcCallExpr->getArgs());
	EXPECT_TRUE(funcCallNewArgs.front()->isEqualTo(refNewArg)) <<
		"`" << funcCallNewArgs.front() << "` differs from `" << refNewArg << "`";
}

TEST_F(ConstSymbolConverterTests,
DoNotChangeConstantIfThereIsNoMapping) {
	ConstInt* origArg(ConstInt::create(128, 32));
	Expression* refNewArg(origArg);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";

	SCOPED_TRACE("128 -> 128");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("flock", origArg,
		refMap, refNewArg);
}

TEST_F(ConstSymbolConverterTests,
ChangeConstantWhenThereIsDirectMappingConstantToConstSymbol) {
	ConstInt* origArg(ConstInt::create(1, 32));
	Expression* refNewArg(ConstSymbol::create("LOCK_SH", origArg));
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";

	SCOPED_TRACE("1 -> LOCK_SH");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("flock", origArg,
		refMap, refNewArg);
}

TEST_F(ConstSymbolConverterTests,
IgnoreCastsBeforeArguments) {
	ConstInt* origArgAs32bInt(ConstInt::create(1, 32));
	Expression* origArg(ExtCastExpr::create(origArgAs32bInt,
		IntType::create(64)));
	Expression* refNewArg(ConstSymbol::create("LOCK_SH", origArgAs32bInt));
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";

	SCOPED_TRACE("1 -> LOCK_SH");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("flock", origArg,
		refMap, refNewArg);
}

TEST_F(ConstSymbolConverterTests,
ChangeConstantWhenArgumentIsReplacedWithBitOrOfTwoSymbolicNames) {
	ConstInt* origArg(ConstInt::create(3, 32)); // 3 -> 1 | 2
	Expression* refNewArg(BitOrOpExpr::create(
		ConstSymbol::create("LOCK_SH", ConstInt::create(1, 32)),
		ConstSymbol::create("LOCK_EX", ConstInt::create(2, 32))));
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";
	ASSERT_TRUE(refNewArg->isEqualTo(refNewArg));

	SCOPED_TRACE("3 -> LOCK_SH | LOCK_EX");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("flock", origArg,
		refMap, refNewArg);
}

TEST_F(ConstSymbolConverterTests,
ChangeConstantWhenArgumentIsReplacedWithBitOrOfThreeSymbolicNames) {
	ConstInt* origArg(ConstInt::create(7, 32)); // 7 -> 1 | 2 | 4
	Expression* refNewArg(BitOrOpExpr::create(
		BitOrOpExpr::create(
			ConstSymbol::create("LOCK_SH", ConstInt::create(1, 32)),
			ConstSymbol::create("LOCK_EX", ConstInt::create(2, 32))),
		ConstSymbol::create("LOCK_NB", ConstInt::create(4, 32))));
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";

	SCOPED_TRACE("7 -> LOCK_SH | LOCK_EX | LOCK_NB");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("flock", origArg,
		refMap, refNewArg);
}

TEST_F(ConstSymbolConverterTests,
ChangeNullPointerConstantWhenThereIsDirectMappingZeroToConstSymbol) {
	// Motivation: For
	//
	//     signal(SIGNUM, SIG_DFL);
	//
	// where SIG_DFL is, in fact, the null pointer (zero), we want
	//
	//     signal(SIGNUM, SIG_DFL)
	//
	// instead of
	//
	//     signal(SIGNUM, NULL)
	//
	ConstNullPointer* origArg(ConstNullPointer::create(
		PointerType::create(IntType::create(32)))); // The type is irrelevant.
	Expression* refNewArg(ConstSymbol::create("SIG_DFL",
		ConstInt::create(0, 32))); // See the comment in getArgAsConstInt().
	IntStringMap refMap;
	refMap[0] = "SIG_DFL";
	refMap[1] = "SIG_IGN";

	SCOPED_TRACE("0 -> SIG_DFL");
	scenarioChangeConstantToSymbolicNamesWorksCorrectly("signal", origArg,
		refMap, refNewArg);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
