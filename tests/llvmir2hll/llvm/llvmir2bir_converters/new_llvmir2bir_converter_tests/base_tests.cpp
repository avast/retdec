/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.cpp
* @brief Implementation of NewLLVMIR2BIRConverterTests.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/utils/ir.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

ShPtr<Module> NewLLVMIR2BIRConverterBaseTests::convertLLVMIR2BIR(const std::string &code) {
	return LLVMIR2BIRConverterTests::convertLLVMIR2BIR<NewLLVMIR2BIRConverter>(code);
}

/**
* @brief Returns first non-empty successor of the given statement @a statement.
*/
ShPtr<Statement> NewLLVMIR2BIRConverterBaseTests::getFirstNonEmptySuccOf(
		const ShPtr<Statement> &statement) const {
	if (!statement) {
		return nullptr;
	}

	return skipEmptyStmts(statement->getSuccessor());
}

/**
* @brief Assertion, that the given BIR expression @a expr is a constant integer
*        with value @a param.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isConstInt(
		ShPtr<Expression> expr, int param) {
	auto constInt = cast<ConstInt>(expr);
	if (!constInt) {
		return AssertionFailure() << expr << " is not ConstInt";
	}

	if (constInt->getValue() != param) {
		return AssertionFailure() << expr << " != " << param;
	}

	return AssertionSuccess() << expr << " == " << param;
}

/**
* @brief Assertion, that the given BIR statement @a statement is a call
*        statement of the function test with the given parameter @a param.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isCallOfFuncTest(
		ShPtr<Statement> statement, ShPtr<Variable> param) {
	auto callStmt = cast<CallStmt>(statement);
	if (!callStmt) {
		return AssertionFailure() << statement << " is not CallStmt";
	}

	auto callExpr = callStmt->getCall();
	auto calledExpr = cast<Variable>(callExpr->getCalledExpr());
	if (!calledExpr || calledExpr->getName() != "test"s) {
		return AssertionFailure() << statement
			<< " is not a call of function test()";
	}

	if (callExpr->getNumOfArgs() != 1) {
		return AssertionFailure() << statement
			<< " does not have one argument";
	}

	if (callExpr->getArg(1) != param) {
		return AssertionFailure() << statement
			<< " does not have first argument " << param;
	}

	return AssertionSuccess() << statement << " is call test(" << param << ")";
}

/**
* @brief Assertion, that the given BIR statement @a statement is a call
*        statement of the function test with the given integer parameter @a param.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isCallOfFuncTest(
		ShPtr<Statement> statement, int param) {
	auto callStmt = cast<CallStmt>(statement);
	if (!callStmt) {
		return AssertionFailure() << statement << " is not CallStmt";
	}

	auto callExpr = callStmt->getCall();
	auto calledExpr = cast<Variable>(callExpr->getCalledExpr());
	if (!calledExpr || calledExpr->getName() != "test"s) {
		return AssertionFailure() << statement
			<< " is not a call of function test()";
	}

	if (callExpr->getNumOfArgs() != 1) {
		return AssertionFailure() << statement
			<< " does not have one argument";
	}

	if (!isConstInt(callExpr->getArg(1), param)) {
		return AssertionFailure() << statement
			<< " does not have first argument " << param;
	}

	return AssertionSuccess() << statement << " is call test(" << param << ")";
}

/**
* @brief Assertion, that the given BIR statement @a statement is a return
*        statement with the given integer return value @a param.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isIntReturn(
		ShPtr<Statement> statement, int param) {
	auto retStmt = cast<ReturnStmt>(statement);
	if (!retStmt) {
		return AssertionFailure() << statement << " is not ReturnStmt";
	}

	auto retVal = retStmt->getRetVal();
	if (!isConstInt(retVal, param)) {
		return AssertionFailure() << statement << " returns " << retVal
			<< " instead of " << param;
	}

	return AssertionSuccess() << statement << " is return " << param;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of integer constant @a rhs to the variable @a lhs.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfConstIntToVar(
		ShPtr<Statement> statement, ShPtr<Variable> lhs, int rhs) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	if (assignStmt->getLhs() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side " << lhs;
	}

	if (!isConstInt(assignStmt->getRhs(), rhs)) {
		return AssertionFailure() << statement
			<< " does not have right hand side " << rhs;
	}

	return AssertionSuccess() << statement << " is assign of " << rhs
		<< " to " << lhs;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of variable @a rhs to the variable @a lhs.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfVarToVar(
		ShPtr<Statement> statement, ShPtr<Variable> lhs,
		ShPtr<Variable> rhs) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	if (assignStmt->getLhs() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side " << lhs;
	}

	if (assignStmt->getRhs() != rhs) {
		return AssertionFailure() << statement
			<< " does not have right hand side " << rhs;
	}

	return AssertionSuccess() << statement << " is assign of " << rhs
		<< " to " << lhs;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of variable @a rhs to the variable @a lhs dereference.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfVarToVarDeref(
		ShPtr<Statement> statement, ShPtr<Variable> lhs,
		ShPtr<Variable> rhs) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	auto assignStmtLhs = cast<DerefOpExpr>(assignStmt->getLhs());
	if (!assignStmtLhs) {
		return AssertionFailure() << statement
			<< " does not have dereference of the left hand side";
	}

	if (assignStmtLhs->getOperand() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side *" << lhs;
	}

	if (assignStmt->getRhs() != rhs) {
		return AssertionFailure() << statement
			<< " does not have right hand side " << rhs;
	}

	return AssertionSuccess() << statement << " is assign of " << rhs
		<< " to *" << lhs;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of variable @a rhs dereference to the variable @a lhs.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfVarDerefToVar(
		ShPtr<Statement> statement, ShPtr<Variable> lhs,
		ShPtr<Variable> rhs) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	if (assignStmt->getLhs() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side " << lhs;
	}

	auto assignStmtRhs = cast<DerefOpExpr>(assignStmt->getRhs());
	if (!assignStmtRhs) {
		return AssertionFailure() << statement
			<< " does not have dereference of the right hand side";
	}

	if (assignStmtRhs->getOperand() != rhs) {
		return AssertionFailure() << statement
			<< " does not have right hand side *" << rhs;
	}

	return AssertionSuccess() << statement << " is assign of *" << rhs
		<< " to " << lhs;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of add expression of variable @a rhsAddVar and integer constant
*        @a rhsAddConst to the variable @a lhs.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfAddExprToVar(
		ShPtr<Statement> statement, ShPtr<Variable> lhs,
		ShPtr<Variable> rhsAddVar, int rhsAddConst) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	if (assignStmt->getLhs() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side " << lhs;
	}

	auto assignStmtRhs = cast<AddOpExpr>(assignStmt->getRhs());
	if (!assignStmtRhs) {
		return AssertionFailure() << statement
			<< " does not have add expression on the right hand side";
	}

	if (assignStmtRhs->getFirstOperand() != rhsAddVar
			|| !isConstInt(assignStmtRhs->getSecondOperand(), rhsAddConst)) {
		return AssertionFailure() << statement
			<< " has on the right hand side " << assignStmtRhs
			<< " instead of (" << rhsAddVar << " + " << rhsAddConst << ")";
	}

	return AssertionSuccess() << statement << " is assign of " << assignStmtRhs
		<< " to " << lhs;
}

/**
* @brief Assertion, that the given BIR statement @a statement is an assignment
*        of mul expression of variable @a rhsMulVar and integer constant
*        @a rhsMulConst to the variable @a lhs.
*/
AssertionResult NewLLVMIR2BIRConverterBaseTests::isAssignOfMulExprToVar(
		ShPtr<Statement> statement, ShPtr<Variable> lhs,
		ShPtr<Variable> rhsMulVar, int rhsMulConst) {
	auto assignStmt = cast<AssignStmt>(statement);
	if (!assignStmt) {
		return AssertionFailure() << statement << " is not AssignStmt";
	}

	if (assignStmt->getLhs() != lhs) {
		return AssertionFailure() << statement
			<< " does not have left hand side " << lhs;
	}

	auto assignStmtRhs = cast<MulOpExpr>(assignStmt->getRhs());
	if (!assignStmtRhs) {
		return AssertionFailure() << statement
			<< " does not have mul expression on the right hand side";
	}

	if (assignStmtRhs->getFirstOperand() != rhsMulVar
			|| !isConstInt(assignStmtRhs->getSecondOperand(), rhsMulConst)) {
		return AssertionFailure() << statement
			<< " has on the right hand side " << assignStmtRhs
			<< " instead of (" << rhsMulVar << " * " << rhsMulConst << ")";
	}

	return AssertionSuccess() << statement << " is assign of " << assignStmtRhs
		<< " to " << lhs;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
