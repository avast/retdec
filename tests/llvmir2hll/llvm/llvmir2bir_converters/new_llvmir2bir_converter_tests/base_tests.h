/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h
* @brief A base class of tests for NewLLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_LLVM_LLVMIR2BIR_CONVERTERS_TESTS_NEW_LLVMIR2BIR_CONVERTER_TESTS_BASE_TESTS_H
#define BACKEND_BIR_LLVM_LLVMIR2BIR_CONVERTERS_TESTS_NEW_LLVMIR2BIR_CONVERTER_TESTS_BASE_TESTS_H

#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "llvmir2hll/llvm/llvmir2bir_converter_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using ::testing::AssertionFailure;
using ::testing::AssertionResult;
using ::testing::AssertionSuccess;

namespace retdec {
namespace llvmir2hll {

class Expression;
class Module;
class Statement;

namespace tests {

/**
* @brief A base class of tests for NewLLVMIR2BIRConverter.
*/
class NewLLVMIR2BIRConverterBaseTests: public LLVMIR2BIRConverterTests {
protected:
	ShPtr<Module> convertLLVMIR2BIR(const std::string &code);

	ShPtr<Statement> getFirstNonEmptySuccOf(
		const ShPtr<Statement> &statement) const;

	AssertionResult isConstInt(ShPtr<Expression> expr, int param);

	AssertionResult isCallOfFuncTest(ShPtr<Statement> statement,
		ShPtr<Variable> param);
	AssertionResult isCallOfFuncTest(ShPtr<Statement> statement, int param);
	AssertionResult isIntReturn(ShPtr<Statement> statement, int param);
	AssertionResult isAssignOfConstIntToVar(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, int rhs);
	AssertionResult isAssignOfVarToVar(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, ShPtr<Variable> rhs);
	AssertionResult isAssignOfVarToVarDeref(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, ShPtr<Variable> rhs);
	AssertionResult isAssignOfVarDerefToVar(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, ShPtr<Variable> rhs);
	AssertionResult isAssignOfAddExprToVar(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, ShPtr<Variable> rhsAddVar, int rhsAddConst);
	AssertionResult isAssignOfMulExprToVar(ShPtr<Statement> statement,
		ShPtr<Variable> lhs, ShPtr<Variable> rhsMulVar, int rhsMulConst);

	template<class T>
	AssertionResult isVarDef(ShPtr<Statement> statement, std::string name);
};

/**
* @brief Assertion, that the given BIR statement @a statement is a variable
*        definition of the variable named @a name which has type @a T.
*
* @tparam T Class that represents a required variable type.
*/
template<class T>
AssertionResult NewLLVMIR2BIRConverterBaseTests::isVarDef(
		ShPtr<Statement> statement, std::string name) {
	auto varDefStmt = cast<VarDefStmt>(statement);
	if (!varDefStmt) {
		return AssertionFailure() << varDefStmt << " is not VarDefStmt";
	}

	auto var = varDefStmt->getVar();
	if (var->getName() != name) {
		return AssertionFailure() << statement
			<< " is not a definition of variable named " << name;
	}

	if (!isa<T>(var->getType())) {
		return AssertionFailure() << statement
			<< " is not a definition of variable with expected type";
	}

	return AssertionSuccess() << statement << " is a definition of variable "
		<< name << " which has expected type";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
