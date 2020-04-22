/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converter_tests.cpp
* @brief Implementation of the base class of tests for conversion of LLVM IR
*        to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>

#include "llvmir2hll/ir/assertions.h"
#include "llvmir2hll/llvm/llvmir2bir_converter_tests/base_tests.h"
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
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

namespace {

// The value is not important (LLVM only uses the address of the ID).
char MODULE_PASS_ID = 0;

void printLLVMIRConversionError(const llvm::SMDiagnostic &err) {
	err.print("", llvm::errs());
}

} // anonymous namespace

LLVMIR2BIRConverterBaseTests::ConversionPass::ConversionPass(
		ShPtr<::testing::NiceMock<ConfigMock>> configMock):
	llvm::ModulePass(MODULE_PASS_ID),
	semanticsMock(std::make_shared<NiceMock<SemanticsMock>>()),
	configMock(configMock)
	{}

bool LLVMIR2BIRConverterBaseTests::ConversionPass::runOnModule(
		llvm::Module &llvmModule) {
	PRECONDITION(converter, "setUsedConverter() was not called");
	birModule = converter->convert(
		&llvmModule,
		llvmModule.getModuleIdentifier(),
		semanticsMock,
		configMock
	);
	return false;
}

void LLVMIR2BIRConverterBaseTests::ConversionPass::getAnalysisUsage(
		llvm::AnalysisUsage &au) const {
	// Our converters require the LoopInfo and ScalarEvolution analyses.
	au.addRequired<llvm::LoopInfoWrapperPass>();
	au.addRequired<llvm::ScalarEvolutionWrapperPass>();
	au.setPreservesAll();
}

/**
* @brief Sets the used LLVMIR2BIR converter.
*
* This member function has to be called before @c runOnModule().
*/
void LLVMIR2BIRConverterBaseTests::ConversionPass::setUsedConverter(
		ShPtr<LLVMIR2BIRConverter> converter) {
	this->converter = converter;
}

/**
* @brief Returns the converted module.
*
* This member function can be called only after @c runOnModule() has run.
*/
ShPtr<Module> LLVMIR2BIRConverterBaseTests::ConversionPass::getConvertedModule() const {
	PRECONDITION(birModule, "runOnModule() did not run");
	return birModule;
}

LLVMIR2BIRConverterBaseTests::LLVMIR2BIRConverterBaseTests():
	configMock(std::make_shared<NiceMock<ConfigMock>>()),
	optionStrictFPUSemantics(false) {}

/**
* @brief Converts the given LLVM IR code into a BIR module.
*
* If the LLVM IR is invalid, an error message is written to the standard
* error and @c std::runtime_error is thrown.
*/
ShPtr<Module> LLVMIR2BIRConverterBaseTests::convertLLVMIR2BIR(const std::string &code) {
	// We have to run the converter through a pass manager to prevent the
	// following assertion failures:
	//
	//     Pass has not been inserted into a PassManager object!
	//
	llvm::legacy::PassManager passManager;

	// Our LLVMIR2BIR converter requires the LoopInfo and
	// ScalarEvolution analyses. The memory allocated below is
	// automatically deleted in the passManager's destructor.
	passManager.add(new llvm::LoopInfoWrapperPass());
	passManager.add(new llvm::ScalarEvolutionWrapperPass());
	auto conversionPass = new ConversionPass(configMock);
	passManager.add(conversionPass);

	// Peform the conversion.
	auto converter = LLVMIR2BIRConverter::create(conversionPass);
	converter->setOptionStrictFPUSemantics(optionStrictFPUSemantics);
	conversionPass->setUsedConverter(converter);
	llvmModule = parseLLVMIR(code);
	passManager.run(*llvmModule);
	return conversionPass->getConvertedModule();
}

/**
* @brief Parses the given LLVM IR code into an LLVM module.
*/
UPtr<llvm::Module> LLVMIR2BIRConverterBaseTests::parseLLVMIR(const std::string &code) {
	auto mb = llvm::MemoryBuffer::getMemBuffer(code);
	llvm::SMDiagnostic err;
	auto module = llvm::parseIR(mb->getMemBufferRef(), err, llvmContext);
	if (!module) {
		printLLVMIRConversionError(err);
		throw std::runtime_error("invalid LLVM IR");
	}
	return module;
}

/**
* @brief Returns first non-empty successor of the given statement @a statement.
*/
ShPtr<Statement> LLVMIR2BIRConverterBaseTests::getFirstNonEmptySuccOf(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isConstInt(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isCallOfFuncTest(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isCallOfFuncTest(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isIntReturn(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfConstIntToVar(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfVarToVar(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfVarToVarDeref(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfVarDerefToVar(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfAddExprToVar(
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
AssertionResult LLVMIR2BIRConverterBaseTests::isAssignOfMulExprToVar(
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
