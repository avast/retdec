/**
* @file tests/llvmir2hll/ir/tests_with_module.cpp
* @brief Implementation of the base class for all test fixtures using a
*        module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Constructs a new test fixture.
*/
TestsWithModule::TestsWithModule():
	llvmModule("testing module", llvmContext),
	semanticsMock(std::make_shared<NiceMock<SemanticsMock>>()),
	configMock(std::make_shared<NiceMock<ConfigMock>>()),
	module(std::make_shared<Module>(&llvmModule, llvmModule.getModuleIdentifier(),
			semanticsMock, configMock)) {
		// Add an empty function `void test() {}`.
		testFunc = FunctionBuilder("test")
			.definitionWithEmptyBody()
			.build();
		module->addFunc(testFunc);
	}

/**
* @brief Adds a <tt>void funcName();</tt> function declaration to the module.
*
* @return The constructed function declaration.
*/
ShPtr<Function> TestsWithModule::addFuncDecl(const std::string &funcName) {
	ShPtr<Function> func(Function::create(VoidType::create(), funcName,
		VarVector(), VarSet(), ShPtr<Statement>(), false));
	module->addFunc(func);
	return func;
}

/**
* @brief Adds a <tt>void funcName() {}</tt> function definition to the module.
*
* @return The constructed function definition.
*/
ShPtr<Function> TestsWithModule::addFuncDef(const std::string &funcName) {
	ShPtr<Function> func(Function::create(VoidType::create(), funcName,
		VarVector(), VarSet(), EmptyStmt::create(), false));
	module->addFunc(func);
	return func;
}

/**
* @brief Appends a call to the given function at the end of the body of the
*        given function to the module.
*
* @return The constructed call.
*
* @par Preconditions
*  - the two functions have to exist; moreover, the function named @a
*    callerName has to be a definition
*/
ShPtr<CallStmt> TestsWithModule::addCall(const std::string &callerName,
		const std::string &calleeName) {
	ShPtr<Function> caller(module->getFuncByName(callerName));
	ASSERT_MSG(caller && caller->isDefinition(),
		"the function `" << callerName << "` is not defined");

	ShPtr<Function> callee(module->getFuncByName(calleeName));
	ASSERT_MSG(callee, "the function `" << calleeName << "` does not exist");

	ShPtr<CallExpr> calleeCallExpr(CallExpr::create(callee->getAsVar()));
	ShPtr<CallStmt> calleeCall(CallStmt::create(calleeCallExpr));
	if (isa<EmptyStmt>(caller->getBody())) {
		caller->setBody(calleeCall);
	} else {
		caller->setBody(Statement::mergeStatements(caller->getBody(), calleeCall));
	}
	return calleeCall;
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
