/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.cpp
* @brief Implementation of TestsWithLLVMValueConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_value_converter_tests/tests_with_llvm_value_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/variables_manager.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

TestsWithLLVMValueConverter::TestsWithLLVMValueConverter():
		variablesManager(std::make_shared<VariablesManager>(module)),
		converter(LLVMValueConverter::create(module, variablesManager)) {}

TestsWithLLVMValueConverter::~TestsWithLLVMValueConverter() {}

/**
* @brief Assertion that BIR binary expression @a expr has two operands, when
*        both are variables and first is named "arg1" and second is named "arg2".
*/
AssertionResult TestsWithLLVMValueConverter::areBinaryOperandsInCorrectOrder(
		ShPtr<BinaryOpExpr> expr) {
	auto firstOp = cast<Variable>(expr->getFirstOperand());
	if (!firstOp || firstOp->getName() != "arg1"s) {
		return AssertionFailure() << expr
			<< " does not have first operand arg1";
	}

	auto secondOp = cast<Variable>(expr->getSecondOperand());
	if (!secondOp || secondOp->getName() != "arg2"s) {
		return AssertionFailure() << expr
			<< " does not have first operand arg1";
	}

	return AssertionSuccess() << expr
		<< " has first operand arg1 and second operand arg2";
}

/**
* @brief Assertion that BIR ternary expression @a expr has all operands in
*        correct order.
*
* All operands have to be variables, condition operand have to be named "cond",
* true value have to be named "true" and false value have to be named "false".
*/
AssertionResult TestsWithLLVMValueConverter::areTernaryOperandsInCorrectOrder(
		ShPtr<TernaryOpExpr> expr) {
	auto cond = cast<Variable>(expr->getCondition());
	if (!cond || cond->getName() != "cond"s) {
		return AssertionFailure() << expr
			<< " does not have condition as variable cond";
	}

	auto trueVal = cast<Variable>(expr->getTrueValue());
	if (!trueVal || trueVal->getName() != "true"s) {
		return AssertionFailure() << expr
			<< " does not have true value as variable true";
	}

	auto falseVal = cast<Variable>(expr->getFalseValue());
	if (!falseVal || falseVal->getName() != "false"s) {
		return AssertionFailure() << expr
			<< " does not have false value as variable false";
	}

	return AssertionSuccess() << expr
		<< " has condition 'cond', true value 'true' and false value 'false'";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
