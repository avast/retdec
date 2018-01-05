/**
* @file tests/llvmir2hll/ir/tests_with_module.h
* @brief A base class for all test fixtures using a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_IR_TESTS_TESTS_WITH_MODULE_H
#define BACKEND_BIR_IR_TESTS_TESTS_WITH_MODULE_H

#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "llvmir2hll/config/config_mock.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "llvmir2hll/semantics/semantics_mock.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CallStmt;

namespace tests {

/**
* @brief A base class for all test fixtures using a module.
*
* This class is useful when you want to perform some tests which require an
* instance of a module in the backend IR. Then, inherit your test fixture from
* this class.
*
* For example,
* @code
* class OptimizerTests: public TestsWithModule {};
* @endcode
*
* The following member variables are created:
*  - @c module -- a module in the backend IR containing a single function
*  - @c testFunc -- a <tt>void test() {}</tt> function
*  - @c semanticsMock -- a mock for the used semantics
*  - (see the source code for other member variables)
*
* These variables may be utilized in your tests.
*/
class TestsWithModule: public ::testing::Test {
protected:
	TestsWithModule();

	ShPtr<Function> addFuncDecl(const std::string &funcName);
	ShPtr<Function> addFuncDef(const std::string &funcName);
	ShPtr<CallStmt> addCall(const std::string &callerName,
		const std::string &calleeName);

protected:
	/// Context for the LLVM module.
	// Implementation note: Do NOT use llvm::getGlobalContext() because that
	//                      would make the context same for all tests (we want
	//                      to run all tests in isolation).
	llvm::LLVMContext llvmContext;

	/// LLVM module.
	llvm::Module llvmModule;

	/// A mock for the used semantics.
	ShPtr<::testing::NiceMock<SemanticsMock>> semanticsMock;

	/// A mock for the used config.
	ShPtr<::testing::NiceMock<ConfigMock>> configMock;

	/// Module in our IR.
	ShPtr<Module> module;

	/// Testing function <tt>void test()</tt>.
	ShPtr<Function> testFunc;
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
