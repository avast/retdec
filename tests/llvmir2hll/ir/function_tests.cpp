/**
* @file tests/llvmir2hll/ir/function_tests.cpp
* @brief Tests for the @c function module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "llvmir2hll/support/observer_mock.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c function module.
*/
class FunctionTests: public Test {};

namespace {

/**
* @brief Returns a new function declaration.
*/
ShPtr<Function> getFuncDeclaration(const std::string &name = "func") {
	return Function::create(VoidType::create(), name, VarVector());
}

/**
* @brief Returns a new function definition.
*/
ShPtr<Function> getFuncDefinition(const std::string &name = "func") {
	return Function::create(VoidType::create(), name,
		VarVector(), VarSet(), EmptyStmt::create());
}

} // anonymous namespace

//
// getInitialName()
//

TEST_F(FunctionTests,
GetInitialNameReturnsSameValueAsGetNameAfterCreation) {
	auto func = getFuncDeclaration("func");

	ASSERT_EQ(func->getName(), func->getInitialName());
}

TEST_F(FunctionTests,
GetInitialNameReturnsCorrectValueAfterRenaming) {
	auto func = getFuncDeclaration("func");

	func->setName("my_func");

	ASSERT_EQ("func", func->getInitialName());
}

//
// getName()
//

TEST_F(FunctionTests,
GetNameReturnsCorrectValueAfterCreation) {
	auto func = getFuncDeclaration("func");

	ASSERT_EQ("func", func->getName());
}

TEST_F(FunctionTests,
GetNameReturnsCorrectValueAfterRenaming) {
	auto func = getFuncDeclaration("func");

	func->setName("my_func");

	ASSERT_EQ("my_func", func->getName());
}

//
// hasParam()
//

TEST_F(FunctionTests,
HasParamWorksCorrectly) {
	auto func = getFuncDeclaration();
	func->addParam(Variable::create("p1", IntType::create(32)));
	func->addParam(Variable::create("p2", IntType::create(32)));
	func->addParam(Variable::create("p3", IntType::create(32)));

	EXPECT_FALSE(func->hasParam(0));
	EXPECT_TRUE(func->hasParam(1));
	EXPECT_TRUE(func->hasParam(2));
	EXPECT_TRUE(func->hasParam(3));
	EXPECT_FALSE(func->hasParam(4));
}

//
// getParam()
//

TEST_F(FunctionTests,
GetParamForExistingParamReturnsThatParam) {
	auto func = getFuncDeclaration();
	auto p1 = Variable::create("p1", IntType::create(32));
	func->addParam(p1);
	auto p2 = Variable::create("p2", IntType::create(32));
	func->addParam(p2);
	auto p3 = Variable::create("p3", IntType::create(32));
	func->addParam(p3);

	EXPECT_EQ(p1, func->getParam(1));
	EXPECT_EQ(p2, func->getParam(2));
	EXPECT_EQ(p3, func->getParam(3));
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTests,
GetParamViolatedPreconditionTooLowParam) {
	auto func = getFuncDeclaration();

	EXPECT_DEATH(func->getParam(0), ".*getParam.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTests,
GetParamViolatedPreconditionTooHighParam) {
	auto func = getFuncDeclaration();

	EXPECT_DEATH(func->getParam(1), ".*getParam.*Precondition.*failed.*");
}
#endif

//
// getParamPos()
//

TEST_F(FunctionTests,
GetParamPosForExistingParamReturnsItsPosition) {
	auto func = getFuncDeclaration();
	auto p1 = Variable::create("p1", IntType::create(32));
	func->addParam(p1);
	auto p2 = Variable::create("p2", IntType::create(32));
	func->addParam(p2);
	auto p3 = Variable::create("p3", IntType::create(32));
	func->addParam(p3);

	EXPECT_EQ(1, func->getParamPos(p1));
	EXPECT_EQ(2, func->getParamPos(p2));
	EXPECT_EQ(3, func->getParamPos(p3));
}

#if DEATH_TESTS_ENABLED
TEST_F(FunctionTests,
GetParamPosViolatedPreconditionNonExistingParam) {
	auto func = getFuncDeclaration();
	auto var = Variable::create("var", IntType::create(32));

	EXPECT_DEATH(func->getParamPos(var), ".*getParamPos.*Precondition.*failed.*");
}
#endif

//
// hasLocalVar()
//

TEST_F(FunctionTests,
HasLocalVarWithIgnoringParamtersIgnoresParameters) {
	auto func = getFuncDefinition();
	auto varA = Variable::create("a", IntType::create(32));
	func->addParam(varA);

	EXPECT_FALSE(func->hasLocalVar(varA, false));
}

TEST_F(FunctionTests,
HasLocalVarWithoutIgnoringParamtersDoesNotIgnoreParameters) {
	auto func = getFuncDefinition();
	auto varA = Variable::create("a", IntType::create(32));
	func->addParam(varA);

	EXPECT_TRUE(func->hasLocalVar(varA, true));
}

//
// convertToDeclaration()
//

TEST_F(FunctionTests,
ConvertToDeclarationMakesDefinitionDeclaration) {
	auto func = getFuncDefinition();

	func->convertToDeclaration();
	ASSERT_FALSE(func->isDefinition());
}

TEST_F(FunctionTests,
ConvertToDeclarationNotifiesObserversWhenItWasDefinition) {
	auto func = getFuncDefinition();
	INSTANTIATE_OBSERVER_MOCK(observer, StrictMock, Value);
	func->addObserver(observer);

	EXPECT_CALL(*observerMock, update(cast<Value>(func), ShPtr<Value>()));
	func->convertToDeclaration();

	// The update() call is checked when the mock is destroyed.
}

TEST_F(FunctionTests,
ConvertToDeclarationDoesNotNotifyObserversWhenItWasDeclaration) {
	auto func = getFuncDeclaration();
	INSTANTIATE_OBSERVER_MOCK(observer, StrictMock, Value);
	func->addObserver(observer);

	func->convertToDeclaration();

	// The update() call is checked when the mock is destroyed.
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
