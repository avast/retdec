/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converter_tests/base_tests.h
* @brief A base class of tests for conversion of LLVM IR to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_LLVM_TESTS_LLVMIR2BIR_CONVERTER_TESTS_BASE_TESTS_H
#define BACKEND_BIR_LLVM_TESTS_LLVMIR2BIR_CONVERTER_TESTS_BASE_TESTS_H

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "llvmir2hll/config/config_mock.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using ::testing::AssertionFailure;
using ::testing::AssertionResult;
using ::testing::AssertionSuccess;

namespace retdec {
namespace llvmir2hll {

class Expression;
class LLVMIR2BIRConverter;
class Module;
class Statement;

namespace tests {

/**
* @brief A base class of tests for conversion of LLVM IR to BIR.
*/
class LLVMIR2BIRConverterBaseTests: public ::testing::Test {
protected:
	/**
	* @brief An internal pass to perform the conversion from an LLVM IR module
	*        to a BIR module.
	*
	* @param[in] configMock A mock for the used config.
	*/
	// Due to technical reasons, this class cannot be moved into the .cpp file
	// (see the implementation of convertLLVMIR2BIR()).
	class ConversionPass: public llvm::ModulePass {
	public:
		ConversionPass(ShPtr<::testing::NiceMock<ConfigMock>> configMock);

		virtual bool runOnModule(llvm::Module &llvmModule) override;
		virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;

		void setUsedConverter(ShPtr<LLVMIR2BIRConverter> converter);
		ShPtr<Module> getConvertedModule() const;

	private:
		/// Converter to be used to convert @c llvmModule into @c birModule.
		ShPtr<LLVMIR2BIRConverter> converter;

		/// Converted module.
		ShPtr<Module> birModule;

		/// A mock for the used semantics.
		ShPtr<::testing::NiceMock<SemanticsMock>> semanticsMock;

		/// A mock for the used config.
		ShPtr<::testing::NiceMock<ConfigMock>> configMock;
	};

protected:
	LLVMIR2BIRConverterBaseTests();

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

	UPtr<llvm::Module> parseLLVMIR(const std::string &code);

protected:
	/// A mock for the used config.
	ShPtr<::testing::NiceMock<ConfigMock>> configMock;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;

	/// Context for the LLVM module.
	// Implementation note: Do NOT use llvm::getGlobalContext() because that
	//                      would make the context same for all tests (we want
	//                      to run all tests in isolation).
	llvm::LLVMContext llvmContext;

	/// LLVM module.
	UPtr<llvm::Module> llvmModule;
};

/**
* @brief Assertion, that the given BIR statement @a statement is a variable
*        definition of the variable named @a name which has type @a T.
*
* @tparam T Class that represents a required variable type.
*/
template<class T>
AssertionResult LLVMIR2BIRConverterBaseTests::isVarDef(
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
